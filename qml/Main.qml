import QtQuick 2.12
import QtQuick.Layouts 1.12
import Lomiri.Components 1.3
import io.thp.pyotherside 1.4
import "pages"

/*
 * Briglia — chat client, installer & control panel for Briglia CLI on Ubuntu Touch.
 *
 * Identity migration (rename plan §5): a phone still running the CLI as
 * "ada" is detected read-only (detectInfo.legacy) and, once Briglia CLI is
 * installed, the CLI's own status block (api.migration) gates everything —
 * routeInitial() and the post-install path go to MigratePage, where the
 * user consents before `briglia setup-api migrate` moves anything.
 *
 * Navigation (settled with the owner 2026-08-29): once setup is complete the
 * app is a single shell page with Chat / Dashboard / Settings as header
 * sections — three always-alive views switched by visibility, so the chat
 * socket, scroll position and composer draft survive tab hops. A bottom
 * bar was rejected because the composer and OSK own the chat view's bottom
 * edge. Launch routes: setup unfinished → guided flow; finished → Chat.
 * Sub-screens (wizard steps, install log, scanner, viewers) still push on
 * the PageStack above the shell.
 *
 * Pages live in qml/pages/ and receive {app: root}; all state derives from
 * `briglia setup-api status` via root.refresh(), so the app stays stateless —
 * killing it mid-setup loses nothing (each section persists independently
 * in secrets.json, exactly like the terminal wizard).
 */
MainView {
    id: root
    objectName: "mainView"
    applicationName: "briglia.permaevidence"
    automaticOrientation: true
    // Resize content when the on-screen keyboard opens — without this the
    // OSK simply covers the bottom of the page (field-test finding: the
    // chat composer disappeared under the keyboard while typing).
    anchorToKeyboard: true
    width: units.gu(45)
    height: units.gu(75)

    // ---------------------------------------------------------- state
    property bool pythonReady: false
    property string fatalError: ""
    property var detectInfo: null      // briglia_bridge.detect() result
    property bool busy: false
    // Convenience view over the setup-api status payload (null until known).
    readonly property var api: detectInfo && detectInfo.status ? detectInfo.status : null
    // The CLI's migration gate (schema 2): while an old-identity install is
    // present, every mutating setup-api verb refuses — so must every flow
    // here that would call one. Read-only, never inferred from paths.
    readonly property bool migrationNeeded: api !== null && api.migration
                                            && api.migration.needed === true
    // Previous-identity ("ada") artifacts seen by the bridge: an old install
    // before Briglia exists, or its root-owned keep-awake unit after a
    // migration (the swap needs the passcode dialog, MigratePage step 2).
    readonly property var legacy: detectInfo && detectInfo.legacy ? detectInfo.legacy : null
    readonly property bool legacyInstallPresent: legacy !== null && legacy.present === true
    readonly property bool legacyWakelockPresent: legacy !== null && legacy.wakelock_unit === true

    // The project website (QR generator lives at /qr, the app page at
    // /ubuntu-touch). One constant, mirrored by briglia_bridge.WEBSITE_BASE.
    readonly property string websiteBase: "https://briglia.vercel.app"

    // ---- app self-update (the click itself, not the Briglia CLI)
    property var appSettings: ({ auto_update: false })
    property string appVersion: ""
    property string appUpdateNotice: ""
    property bool appUpdateNoticeError: false

    function setAppAutoUpdate(enabled, cb) {
        pyCall("set_app_setting", ["auto_update", enabled === true],
            function(result) {
                if (result && result.ok === true)
                    root.appSettings = result.settings;
                if (cb) cb(result);
            });
    }

    // Launch hook: the bridge does nothing (no network) unless the user
    // turned auto-update on. "Already current" stays silent; a successful
    // install or a failure surfaces on the Dashboard.
    function runAppAutoUpdate() {
        pyCall("app_auto_update", [], function(result) {
            if (!result || result.ran !== true) return;
            if (result.ok === true && result.updated === true) {
                root.appUpdateNoticeError = false;
                root.appUpdateNotice = i18n.tr(
                    "App updated to v%1 — close and reopen the app to start using it (Briglia itself keeps running).")
                    .arg(result.available);
            } else if (result.ok !== true) {
                root.appUpdateNoticeError = true;
                root.appUpdateNotice = i18n.tr("App auto-update failed: %1")
                    .arg(root.describeError(result));
            }
        });
    }

    function refresh(done) {
        if (!pythonReady) { if (done) done(); return; }
        busy = true;
        py.call("briglia_bridge.detect", [], function(result) {
            busy = false;
            detectInfo = result;
            if (done) done();
        });
    }

    // Generic bridge call: cb(result). Never throws into QML. A dotted
    // name ("qr_scan.scan_png") targets that module; bare names go to
    // briglia_bridge.
    //
    // The callback runs inside a try/catch: an async result can land after
    // the page that issued the call was popped, and a destroyed page's
    // context throws on any unqualified lookup (field-tested: a post-
    // destruction draft-save callback's `i18n` raised a ReferenceError that
    // PyOtherSide's onError then painted as a fatal "startup problem").
    // Pages guard their own callbacks (ChatPage's lifeToken); this is the
    // backstop so a missed guard degrades to a journal line, not a red box.
    function pyCall(func, args, cb) {
        if (!pythonReady) { if (cb) cb(null); return; }
        var target = func.indexOf(".") !== -1 ? func : "briglia_bridge." + func;
        py.call(target, args, function(result) {
            if (!cb) return;
            try {
                cb(result);
            } catch (e) {
                console.warn("pyCall(" + target + ") callback failed (page torn down?): " + e);
            }
        });
    }

    // Keys captured from a scanned ADAK bundle (website /qr page). Held
    // in memory only: pages pre-fill their fields from here, and the
    // normal probe-then-apply flow still validates every value before it
    // is saved. Reassigned wholesale so change signals fire.
    //
    // Lifecycle (Codex, 2026-08-28): a key that was successfully saved —
    // or whose slot the user explicitly removed — is CONSUMED from the
    // bundle, otherwise the cached secret would silently pre-fill the
    // field again later (e.g. re-saving a key the user just deleted).
    // clearScannedKeys is the user-facing "discard" action.
    property var scannedKeys: ({})
    readonly property int scannedKeyCount: {
        var n = 0;
        for (var k in scannedKeys) n++;
        return n;
    }

    function consumeScannedKeys(names) {
        var next = {};
        var changed = false;
        for (var k in scannedKeys) {
            if (names.indexOf(k) !== -1) { changed = true; continue; }
            next[k] = scannedKeys[k];
        }
        if (changed) scannedKeys = next;
    }

    function clearScannedKeys() { scannedKeys = ({}); }

    // Scanner diagnostics stick for the whole app session: a scan page
    // that closes itself within seconds leaves no time to reach the
    // switch, so the setting must survive reopening (field round 3).
    property bool scanDebug: false

    // The scan-result callback is registered HERE, never passed through
    // pushPage properties: Lomiri PageStack.push routes properties through
    // a QVariantMap, and a JS function cannot survive QVariant conversion —
    // it silently arrives as undefined (field round 4, 2026-08-28: decode,
    // delivery and "callback completed" all green while no callback ever
    // ran). A direct assignment to a `var` property keeps the JS value.
    property var scanCallback: null

    function openScan(mode, cb) {
        scanCallback = cb;
        pushPage("ScanPage.qml", {mode: mode});
    }

    function popPage() { stack.pop(); }

    // Shared by the bundle-scan entry points: stores the keys and builds
    // the confirmation text the invoking page shows.
    function acceptBundle(res) {
        scannedKeys = res.keys || {};
        var names = res.key_names || [];
        var note = i18n.tr("Loaded %1: %2. The matching fields are now pre-filled — review and save each section.")
            .arg(i18n.tr("%1 key(s)").arg(names.length)).arg(names.join(", "));
        if (res.ignored && res.ignored.length > 0)
            note += "\n" + i18n.tr("Ignored unknown entries: %1").arg(res.ignored.join(", "));
        return note;
    }

    // setup-api verbs (requests built by pages; secrets stay in-process
    // between the text field and the child's stdin).
    function apiSubscription(request, cb) { pyCall("setup_api", ["subscription", request], cb); }
    function apiProbe(request, cb)   { pyCall("setup_api", ["probe", request], cb); }
    function apiApply(request, cb)   { pyCall("setup_api", ["apply", request], cb); }
    function apiService(request, cb) { pyCall("setup_api", ["service", request], cb); }

    function describeError(result) {
        if (!result) return i18n.tr("the app backend did not answer");
        // Bridge helpers report a plain string; setup-api an {code, message}.
        if (typeof result.error === "string" && result.error !== "") return result.error;
        if (result.error && result.error.message) return result.error.message;
        if (result.error && result.error.code) return result.error.code;
        if (result.reason) return result.reason;
        return i18n.tr("unknown error");
    }

    // ---------------------------------------------------------- navigation
    function pushPage(file, props) {
        var p = props || {};
        p.app = root;
        stack.push(Qt.resolvedUrl("pages/" + file), p);
    }

    // The shell replaces whatever the stack holds. Without a section
    // argument the current tab is kept (fresh launches default to Chat) —
    // finishing a wizard re-run from Settings returns to Settings.
    function gotoShell(section) {
        if (section !== undefined) shellSections.selectedIndex = section;
        if (stack.currentPage !== shellPage) {
            stack.clear();
            stack.push(shellPage);
        }
        chatView.activate();
    }

    // Launch routing: runs only while the boot page is current, so a
    // refresh() issued from an open wizard/install page never yanks
    // navigation out from under the user.
    function routeInitial() {
        if (stack.currentPage !== bootPage) return;
        if (fatalError !== "" || detectInfo === null) return;
        if (!detectInfo.installed) return;  // boot page offers Install
        if (api === null) return;           // status unreadable — boot page shows it
        if (migrationNeeded) { openMigrate(); return; }  // consent first, never the wizard
        if (api.setup && api.setup.complete === true)
            gotoShell();
        else
            startSetup();
    }

    function openMigrate(mode) {
        pushPage("MigratePage.qml", {mode: mode || "migrate"});
    }

    function openInstall() {
        stack.push(installPage);
        installPage.start();
    }

    // Setup entry (owner request 2026-09-03): the quick path first — name +
    // one bundle scan, everything else automatic (QuickSetupPage.qml); it
    // offers the step-by-step wizard below as the alternative.
    function startSetup() {
        pushPage("QuickSetupPage.qml", {});
    }

    // Wizard: screens 3–6 then Always-on; each page calls app.wizardNext().
    property var wizardSteps: ["ProviderPage.qml", "KeysPage.qml",
                               "IdentityPage.qml", "TelegramPage.qml",
                               "AlwaysOnPage.qml"]
    property int wizardIndex: -1
    property bool wizardActive: wizardIndex >= 0

    function startWizard() {
        wizardIndex = -1;
        wizardNext();
    }

    function wizardNext() {
        wizardIndex += 1;
        if (wizardIndex >= wizardSteps.length) {
            finishWizard();
            return;
        }
        pushPage(wizardSteps[wizardIndex], {wizardMode: true});
    }

    function finishWizard() {
        wizardIndex = -1;
        clearScannedKeys();  // leftover scanned secrets end with the wizard
        apiApply({mark_complete: true}, function(result) {
            // A failed save is surfaced on the dashboard ("not finished
            // yet") rather than blocking here — the sections themselves
            // are already persisted.
            refresh(function() { gotoShell(); });
        });
    }

    // ---------------------------------------------------------- python
    // Chat page event pipe: the page installs its handler on entry and
    // clears it on exit; events arriving with no page open are dropped
    // (the conversation history is the source of truth, so nothing is lost).
    function setChatHandler(cb) { py.setHandler("chat-event", cb); }
    function clearChatHandler() { py.setHandler("chat-event", function() {}); }

    // "0.1.45" >= "0.1.45"? Numeric per-component compare; anything
    // unparseable in a component counts as 0 (a "-dev" build is instead
    // covered by the live-socket capability check where it matters).
    function versionAtLeast(version, minimum) {
        var a = String(version || "").replace(/^v/, "").split(".");
        var b = String(minimum).split(".");
        for (var i = 0; i < Math.max(a.length, b.length); i++) {
            var x = parseInt(a[i], 10); if (isNaN(x)) x = 0;
            var y = parseInt(b[i], 10); if (isNaN(y)) y = 0;
            if (x !== y) return x > y;
        }
        return true;
    }

    // Chat needs the CLI's app-chat socket (every Briglia release, 0.2.0+).
    // The live socket file outranks the version string: a -dev build serves
    // chat, a stale pre-upgrade daemon doesn't stop serving it mid-run.
    readonly property bool chatSupported: detectInfo !== null
        && detectInfo.installed === true
        && (detectInfo.chat_socket === true
            || versionAtLeast(detectInfo.version, "0.2.0"))

    Python {
        id: py
        Component.onCompleted: {
            addImportPath(Qt.resolvedUrl("../py"));
            importModule("briglia_bridge", function() {
                // qr_scan / chat_client / voice_record are stdlib-only like
                // the bridge; loading them here keeps the pages free of
                // import races.
                py.importModule("qr_scan", function() {
                    py.importModule("chat_client", function() {
                        py.importModule("voice_record", function() {
                            root.pythonReady = true;
                            root.refresh(function() { root.routeInitial(); });
                            root.pyCall("app_own_version", [], function(v) {
                                if (typeof v === "string") root.appVersion = v;
                            });
                            root.pyCall("app_settings", [], function(s) {
                                if (s) root.appSettings = s;
                                if (s && s.auto_update === true)
                                    root.runAppAutoUpdate();
                            });
                        });
                    });
                });
            });
        }
        onError: {
            // Most likely cause on a fresh port: PyOtherSide missing from
            // the image. Surface it verbatim — screenshots stay diagnosable.
            root.fatalError = traceback;
        }
    }

    PageStack {
        id: stack
        Component.onCompleted: stack.push(bootPage)
    }

    // ------------------------------------------------------------ shell
    // Home once setup is complete. The three views are declared instances
    // (never stack-managed), so they stay alive across tab switches AND
    // across wizard re-runs pushed above the shell.
    Page {
        id: shellPage
        visible: false

        // Sections-only top strip — no PageHeader (field feedback
        // 2026-08-29 round 2: the title row stole vertical space and only
        // repeated what the highlighted tab already says). Refresh rides
        // the strip's right edge on the Dashboard section.
        //
        // Declared as the Page's `header`, not a plain child: MainView keeps
        // an internal legacy AppHeader alive for any page whose `header` is
        // unset, hidden at launch but re-exposed on app-focus events — on the
        // phone that surfaced as an empty white band sliding in above the
        // tabs after the first prompt (field round 3, 2026-08-29). Page only
        // reparents the item to itself, so sibling anchors below still work.
        header: Rectangle {
            id: sectionsBar
            anchors { top: parent.top; left: parent.left; right: parent.right }
            height: shellSections.height + units.gu(0.5)
            color: theme.palette.normal.background
            Sections {
                id: shellSections
                anchors { left: parent.left; leftMargin: units.gu(2); bottom: parent.bottom }
                model: [i18n.tr("Chat"), i18n.tr("Dashboard"), i18n.tr("Settings")]
                onSelectedIndexChanged: {
                    // The dashboard is a live status display, not a cached
                    // page — landing on it refreshes rows and journal.
                    if (selectedIndex === 1) { root.refresh(); dashView.loadJournal(); }
                }
            }
            AbstractButton {
                visible: shellSections.selectedIndex === 1
                anchors { right: parent.right; rightMargin: units.gu(1); verticalCenter: parent.verticalCenter }
                width: units.gu(4)
                height: units.gu(4)
                onClicked: { root.refresh(); dashView.loadJournal(); }
                Icon {
                    anchors.centerIn: parent
                    width: units.gu(2.25)
                    height: units.gu(2.25)
                    name: "reload"
                    color: theme.palette.normal.backgroundText
                }
            }
            Rectangle {
                anchors { left: parent.left; right: parent.right; bottom: parent.bottom }
                height: units.dp(1)
                color: theme.palette.normal.base
            }
        }

        ChatPage {
            id: chatView
            app: root
            visible: shellSections.selectedIndex === 0
            anchors { top: sectionsBar.bottom; left: parent.left; right: parent.right; bottom: parent.bottom }
        }
        DashboardPage {
            id: dashView
            app: root
            visible: shellSections.selectedIndex === 1
            anchors { top: sectionsBar.bottom; left: parent.left; right: parent.right; bottom: parent.bottom }
        }
        SettingsPage {
            id: settingsView
            app: root
            visible: shellSections.selectedIndex === 2
            anchors { top: sectionsBar.bottom; left: parent.left; right: parent.right; bottom: parent.bottom }
        }
    }

    // ---------------------------------------------------------- boot
    // Pre-setup landing and error surface: fatal tracebacks, "not
    // installed" (Install button), and the fallback buttons for a user who
    // backs out of the auto-routed flow. Never seen on a healthy set-up
    // phone — routeInitial() replaces it with the shell.
    Page {
        id: bootPage
        visible: false
        header: PageHeader {
            id: welcomeHeader
            title: i18n.tr("Briglia")
        }

        Flickable {
            anchors { top: welcomeHeader.bottom; left: parent.left; right: parent.right; bottom: parent.bottom }
            contentHeight: welcomeColumn.height + units.gu(6)
            clip: true

            ColumnLayout {
                id: welcomeColumn
                anchors { top: parent.top; topMargin: units.gu(4); horizontalCenter: parent.horizontalCenter }
                width: Math.min(parent.width - units.gu(4), units.gu(50))
                spacing: units.gu(2)

                LomiriShape {
                    Layout.alignment: Qt.AlignHCenter
                    width: units.gu(12); height: units.gu(12)
                    source: Image { source: Qt.resolvedUrl("../assets/logo.png") }
                    aspect: LomiriShape.Flat
                }

                Label {
                    Layout.fillWidth: true
                    text: i18n.tr("Your personal AI agent")
                    textSize: Label.Large
                    horizontalAlignment: Text.AlignHCenter
                }

                Label {
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                    horizontalAlignment: Text.AlignHCenter
                    color: theme.palette.normal.backgroundSecondaryText
                    text: {
                        if (root.fatalError !== "")
                            // After Python is up, an onError is a runtime app
                            // bug surfacing late, not a broken installation —
                            // label it honestly so screenshots aren't misread.
                            return root.pythonReady
                                ? i18n.tr("App error — details below (Briglia itself keeps running).")
                                : i18n.tr("Startup problem — details below.");
                        if (!root.pythonReady || root.busy || root.detectInfo === null)
                            return i18n.tr("Checking this device…");
                        if (!root.detectInfo.installed && root.legacyInstallPresent)
                            return i18n.tr("An Ada CLI installation was found on this phone. Installing Briglia CLI keeps everything: after the install, the app asks before moving your Ada configuration, memory, watchers and service to Briglia.");
                        if (!root.detectInfo.installed)
                            return i18n.tr("Briglia CLI is not installed yet. One tap downloads and installs it, then a guided setup gets Briglia running — no terminal needed.");
                        if (root.migrationNeeded)
                            return i18n.tr("Briglia CLI %1 is installed. Your Ada data is still waiting to be migrated — nothing runs until you say so.").arg(root.detectInfo.version);
                        if (root.api && root.api.setup && root.api.setup.complete === true)
                            return i18n.tr("Briglia CLI %1 is installed and set up on this phone.").arg(root.detectInfo.version);
                        return i18n.tr("Briglia CLI %1 is installed. Finish the guided setup to get Briglia running.").arg(root.detectInfo.version);
                    }
                }

                ActivityIndicator {
                    Layout.alignment: Qt.AlignHCenter
                    running: root.fatalError === "" && (!root.pythonReady || root.busy || root.detectInfo === null)
                    visible: running
                }

                // PyOtherSide / bridge failure: show the traceback so a
                // screenshot is diagnosable.
                LomiriShape {
                    visible: root.fatalError !== ""
                    Layout.fillWidth: true
                    height: errorLabel.height + units.gu(2)
                    backgroundColor: theme.palette.normal.negative
                    aspect: LomiriShape.Flat
                    Label {
                        id: errorLabel
                        anchors { left: parent.left; right: parent.right; verticalCenter: parent.verticalCenter; margins: units.gu(1) }
                        wrapMode: Text.WrapAnywhere
                        color: "white"
                        textSize: Label.Small
                        text: root.fatalError
                    }
                }

                Button {
                    Layout.fillWidth: true
                    visible: root.detectInfo !== null && !root.detectInfo.installed && root.fatalError === ""
                    color: theme.palette.normal.positive
                    text: root.legacyInstallPresent
                          ? i18n.tr("Install Briglia CLI (migrates Ada data)")
                          : i18n.tr("Install Briglia CLI")
                    onClicked: root.openInstall()
                }

                Button {
                    Layout.fillWidth: true
                    visible: root.detectInfo !== null && root.detectInfo.installed === true
                             && root.migrationNeeded
                    color: theme.palette.normal.positive
                    text: i18n.tr("Migrate Ada data to Briglia")
                    onClicked: root.openMigrate()
                }

                Button {
                    Layout.fillWidth: true
                    visible: root.detectInfo !== null && root.detectInfo.installed === true
                             && root.api !== null && !root.migrationNeeded
                             && !(root.api.setup && root.api.setup.complete === true)
                    color: theme.palette.normal.positive
                    text: i18n.tr("Set up Briglia")
                    onClicked: root.startSetup()
                }

                Button {
                    Layout.fillWidth: true
                    visible: root.detectInfo !== null && root.detectInfo.installed === true
                             && root.api !== null && !root.migrationNeeded
                             && root.api.setup && root.api.setup.complete === true
                    color: theme.palette.normal.positive
                    text: i18n.tr("Open Briglia")
                    onClicked: root.gotoShell()
                }

                Button {
                    Layout.fillWidth: true
                    visible: root.fatalError === ""
                    text: i18n.tr("Check again")
                    onClicked: root.refresh(function() { root.routeInitial(); })
                }
            }
        }
    }

    // ---------------------------------------------------------- install
    Page {
        id: installPage
        visible: false
        header: PageHeader {
            id: installHeader
            title: i18n.tr("Installing Briglia CLI")
        }

        property int percent: 0
        property string message: ""
        property string stage: ""
        property bool running: false
        property bool failed: false
        // Distinct from `failed`: the CLI installed fine but the running
        // daemon could not be confirmed back on the new binary.
        property bool restartFailed: false
        // The CLI installed fine but a MANUALLY started Briglia process is
        // running (no systemd unit to restart): only the user can bounce
        // it, so the app must warn instead of navigating away silently.
        property bool manualRestartNeeded: false

        function finishAfterInstall() {
            installPage.running = false;
            stack.pop();
            // An old-identity install is present: the CLI refuses every
            // mutating verb until the explicit migration ran, so the wizard
            // would only fail — consent page instead (plan §4.2/§5).
            if (root.migrationNeeded) { root.openMigrate(); return; }
            if (root.api && root.api.setup && root.api.setup.complete === true)
                root.gotoShell();
            else
                root.startSetup();
        }

        // A running daemon keeps executing the OLD binary until restarted —
        // the update is only done once the restarted service is verified
        // healthy (both the restart verdict AND the refreshed unit state;
        // the state check also covers CLI releases whose restart verb
        // doesn't health-check yet). On failure the app STAYS here with an
        // actionable error instead of navigating away as if it worked.
        function attemptPostUpdateRestart() {
            installPage.running = true;
            installPage.restartFailed = false;
            installPage.message = i18n.tr("Restarting Briglia to load the update…");
            root.apiService({action: "restart"}, function(r) {
                root.refresh(function() {
                    var state = root.api && root.api.service && root.api.service.active
                                ? root.api.service.active : "?";
                    if (r && r.ok === true && state === "active") {
                        installPage.finishAfterInstall();
                        return;
                    }
                    installPage.running = false;
                    installPage.restartFailed = true;
                    installPage.message = (r && r.ok !== true)
                        ? i18n.tr("Briglia CLI was updated, but restarting the service failed: %1").arg(root.describeError(r))
                        : i18n.tr("Briglia CLI was updated, but the service is '%1' instead of running — the daemon may have crashed on the new version.").arg(state);
                });
            });
        }

        function start() {
            percent = 0; message = i18n.tr("Starting…"); stage = ""; failed = false; restartFailed = false; manualRestartNeeded = false; running = true;
            py.setHandler("install", function(stage_, percent_, message_) {
                installPage.stage = stage_;
                installPage.percent = percent_;
                installPage.message = message_;
            });
            py.call("briglia_bridge.install", [], function(result) {
                if (result && result.ok) {
                    root.refresh(function() {
                        var svc = root.api ? root.api.service : null;
                        if (root.migrationNeeded) {
                            // Fresh Briglia next to an unmigrated old install:
                            // there is no Briglia service to restart yet, and
                            // `service restart` would refuse anyway.
                            installPage.finishAfterInstall();
                        } else if (svc && svc.unit_installed === true && svc.active === "active") {
                            installPage.attemptPostUpdateRestart();
                        } else if (root.api && root.api.daemon_running === true) {
                            // Running, but not as the active systemd unit ⇒
                            // started by hand; the app cannot restart it.
                            installPage.running = false;
                            installPage.manualRestartNeeded = true;
                            installPage.message = i18n.tr("Briglia CLI was updated, but Briglia is running as a manually started process — it keeps executing the OLD version until you restart it yourself: send /restart to it on Telegram, or stop it in its terminal (Ctrl+C) and run `briglia` again.");
                        } else {
                            installPage.finishAfterInstall();
                        }
                    });
                } else {
                    installPage.running = false;
                    installPage.failed = true;
                    installPage.message = result && result.error
                        ? result.error : i18n.tr("Installation failed");
                }
            });
        }

        ColumnLayout {
            anchors { top: installHeader.bottom; topMargin: units.gu(4); horizontalCenter: parent.horizontalCenter }
            width: Math.min(parent.width - units.gu(4), units.gu(50))
            spacing: units.gu(2)

            ProgressBar {
                Layout.fillWidth: true
                minimumValue: 0
                maximumValue: 100
                value: installPage.percent
                indeterminate: installPage.running && installPage.percent < 3
            }

            Label {
                Layout.fillWidth: true
                wrapMode: Text.WordWrap
                horizontalAlignment: Text.AlignHCenter
                color: installPage.failed || installPage.restartFailed
                       || installPage.manualRestartNeeded
                       ? theme.palette.normal.negative
                       : theme.palette.normal.backgroundSecondaryText
                text: installPage.message
            }

            Button {
                Layout.fillWidth: true
                visible: installPage.failed
                color: theme.palette.normal.positive
                text: i18n.tr("Try again")
                onClicked: installPage.start()
            }

            Button {
                Layout.fillWidth: true
                visible: installPage.restartFailed
                color: theme.palette.normal.positive
                text: i18n.tr("Try restarting again")
                onClicked: installPage.attemptPostUpdateRestart()
            }

            Button {
                Layout.fillWidth: true
                visible: installPage.restartFailed
                text: i18n.tr("Continue anyway")
                onClicked: installPage.finishAfterInstall()
            }

            Button {
                Layout.fillWidth: true
                visible: installPage.manualRestartNeeded
                color: theme.palette.normal.positive
                text: i18n.tr("Understood — continue")
                onClicked: installPage.finishAfterInstall()
            }

            Button {
                Layout.fillWidth: true
                visible: installPage.failed
                text: i18n.tr("Back")
                onClicked: stack.pop()
            }
        }
    }
}
