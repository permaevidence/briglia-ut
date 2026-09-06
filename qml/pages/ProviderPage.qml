import QtQuick 2.12
import QtQuick.Layouts 1.12
import Lomiri.Components 1.3
import "../ScannedKeyLogic.js" as ScanLogic

/*
 * Screen 3 — main agent provider & model (UT_APP_PLAN.md §2.4 #3, and the
 * provider half of Settings #9). Probe-then-apply against setup-api; the
 * OpenCode model list comes from the status payload's catalog, never
 * hardcoded. A blank key field keeps the stored key (the wizard's "Enter
 * keeps the saved key" semantics — apply reuses it server-side, so no
 * re-probe is possible or needed).
 */
Page {
    id: page
    property var app
    property bool wizardMode: false

    readonly property var profiles: app.api && app.api.providers ? app.api.providers.profiles : null
    readonly property string activeProfile: app.api && app.api.providers && app.api.providers.active
                                            ? app.api.providers.active : ""
    readonly property var catalog: app.api && app.api.opencode_catalog ? app.api.opencode_catalog : []

    property var profileIds: app.api && app.api.subscription_setup && app.api.subscription_setup.supported === true
                             ? ["opencode", "openrouter", "custom", "local", "openai", "chatgpt"]
                             : ["opencode", "openrouter", "custom", "local"]
    readonly property string profileId: profileIds[profileSelector.selectedIndex]
    readonly property var stored: profiles && profiles[profileId] ? profiles[profileId] : null

    property bool working: false
    property string resultText: ""
    property bool resultIsError: false
    property bool savedOnce: false

    header: PageHeader {
        title: page.wizardMode ? i18n.tr("Step 1 · Main agent") : i18n.tr("Provider & model")
    }

    function fail(text) {
        working = false;
        resultIsError = true;
        resultText = text;
    }

    function currentEffort() { return effortValues[effortSelector.selectedIndex]; }
    property var effortValues: ["minimal", "low", "medium", "high", "xhigh", "max"]

    function buildApply() {
        var section = {profile: profileId, activate: true};
        if (!wizardMode)
            section.activate = activateBox.checked;
        if (keyField.text.trim() !== "")
            section.api_key = keyField.text.trim();
        if (profileId === "opencode") {
            section.model = catalog.length > 0 ? catalog[modelSelector.selectedIndex].id
                                               : modelField.text.trim();
            section.effort = currentEffort();
        } else {
            section.model = modelField.text.trim();
            section.text_only = textOnlySwitch.checked;
            if (profileId !== "local")
                section.effort = currentEffort();
        }
        if (profileId === "custom" || profileId === "local") {
            if (baseUrlField.text.trim() !== "")
                section.base_url = baseUrlField.text.trim();
        }
        return {provider: section};
    }

    // done(ok) is optional — the wizard's Continue auto-commit uses it so a
    // key scanned AFTER the first successful save can't die with the wizard.
    function save(done) {
        if (profileId === "chatgpt") { app.pushPage("SubscriptionPage.qml", {}); if (done) done(false); return; }
        resultText = ""; resultIsError = false;
        var model = profileId === "opencode" && catalog.length > 0
                    ? catalog[modelSelector.selectedIndex].id : modelField.text.trim();
        if (model === "") {
            fail(i18n.tr("A model name is required."));
            if (done) done(false);
            return;
        }
        if ((profileId === "custom" || profileId === "local")
                && baseUrlField.text.trim() === ""
                && !(stored && stored.endpoint)) {
            fail(i18n.tr("The server address (base URL) is required."));
            if (done) done(false);
            return;
        }
        var newKey = keyField.text.trim();
        if (profileId !== "local" && newKey === "" && !(stored && stored.masked_key)) {
            fail(i18n.tr("An API key is required."));
            if (done) done(false);
            return;
        }
        working = true;
        // Probe only when a NEW key (or keyless local/custom target) can be
        // probed; a kept stored key was validated when it was stored.
        var probeRequest = null;
        if (profileId === "local") {
            probeRequest = {kind: "local", base_url: baseUrlField.text.trim()
                            || (stored && stored.endpoint ? stored.endpoint : ""), model: model};
        } else if (newKey !== "") {
            probeRequest = {kind: profileId === "openai" ? "responses" : profileId, api_key: newKey};
            if (profileId === "openai") probeRequest.model = model;
            if (profileId === "openrouter") probeRequest.model = model;
            if (profileId === "custom") {
                probeRequest.base_url = baseUrlField.text.trim()
                    || (stored && stored.endpoint ? stored.endpoint : "");
                probeRequest.model = model;
            }
        }
        var doApply = function() {
            page.app.apiApply(page.buildApply(), function(result) {
                page.working = false;
                if (!result || result.ok !== true) {
                    page.fail(page.app.describeError(result));
                    if (done) done(false);
                    return;
                }
                page.savedOnce = true;
                page.resultText = i18n.tr("Saved.");
                keyField.text = "";
                page.app.consumeScannedKeys([page.profileId]);
                restartHint.lastResult = result;
                page.app.refresh();
                if (done) done(true);
            });
        };
        if (probeRequest === null) { doApply(); return; }
        resultText = i18n.tr("Checking the connection…");
        page.app.apiProbe(probeRequest, function(result) {
            if (!result || result.ok !== true) {
                page.fail(i18n.tr("Connection check failed: %1").arg(page.app.describeError(result)));
                if (done) done(false);
                return;
            }
            doApply();
        });
    }

    // Bundle-scan support: pre-fill the key field for the selected profile
    // from a scanned ADAK bundle (values still probe before saving).
    property string bundleNote: ""
    property bool bundleNoteIsError: false

    // Exact-value bundle ownership (ScannedKeyLogic.js): the field
    // follows the bundle only while it still holds the exact injected
    // value — replaced when a new bundle changes the entry, cleared when
    // the entry leaves, hand-edited text never touched.
    property string keyInjected: ""

    function syncScannedKey() {
        if (profileId === "chatgpt") { keyField.text = ""; keyInjected = ""; return; }
        var r = ScanLogic.sync(keyField.text, keyInjected,
                               app.scannedKeys ? app.scannedKeys[profileId] : "");
        if (keyField.text !== r.text) keyField.text = r.text;
        keyInjected = r.injected;
    }

    function prefillKey() { syncScannedKey(); }

    function scanBundle() {
        app.openScan("bundle", function(res) {
            if (res && res.kind === "bundle") {
                page.bundleNoteIsError = false;
                page.bundleNote = page.app.acceptBundle(res);
                page.prefillKey();
            }
        });
    }

    Connections {
        target: page.app
        onScannedKeysChanged: page.syncScannedKey()
    }

    function removeProfile() {
        working = true; resultText = ""; resultIsError = false;
        app.apiApply({provider: {profile: profileId, remove: true}}, function(result) {
            page.working = false;
            if (!result || result.ok !== true) {
                page.fail(page.app.describeError(result));
                return;
            }
            page.resultText = i18n.tr("Profile removed.");
            keyField.text = ""; modelField.text = ""; baseUrlField.text = "";
            page.app.consumeScannedKeys([page.profileId]);
            page.app.refresh();
        });
    }

    Flickable {
        anchors { top: page.header.bottom; left: parent.left; right: parent.right; bottom: parent.bottom }
        contentHeight: column.height + units.gu(6)
        clip: true

        ColumnLayout {
            id: column
            anchors { top: parent.top; topMargin: units.gu(2); horizontalCenter: parent.horizontalCenter }
            width: Math.min(parent.width - units.gu(4), units.gu(50))
            spacing: units.gu(1.5)

            Label {
                Layout.fillWidth: true
                wrapMode: Text.WordWrap
                color: theme.palette.normal.backgroundSecondaryText
                text: page.wizardMode
                      ? i18n.tr("Pick the service that runs Briglia's main intelligence. OpenCode is the recommended default.")
                      : i18n.tr("Each profile keeps its own settings. Saving the active profile applies immediately; another profile takes over only if you activate it.")
            }

            // ---- key bundle scan (typing long keys on a phone is the
            // worst part of setup; the website /qr page turns them into
            // scannable codes)
            LomiriShape {
                Layout.fillWidth: true
                visible: page.wizardMode
                aspect: LomiriShape.Flat
                backgroundColor: theme.palette.normal.foreground
                // implicitHeight, NOT height: inside a ColumnLayout only
                // implicit-size changes invalidate the layout. A plain
                // height binding gets sampled once — before the inner
                // ColumnLayout has measured its buttons — and the next
                // sibling is then laid out overlapping them (field bug,
                // Pixel 2026-08-28).
                implicitHeight: bundleColumn.height + units.gu(2)
                ColumnLayout {
                    id: bundleColumn
                    anchors { top: parent.top; topMargin: units.gu(1); left: parent.left; leftMargin: units.gu(1.5); right: parent.right; rightMargin: units.gu(1.5) }
                    spacing: units.gu(0.8)
                    Label {
                        Layout.fillWidth: true
                        wrapMode: Text.WordWrap
                        textSize: Label.Small
                        text: i18n.tr("Have your API keys on a computer? Open %1/qr there, paste them, and scan the generated codes once — every key field in this setup fills itself.").arg(page.app.websiteBase.replace("https://", ""))
                    }
                    Button {
                        Layout.fillWidth: true
                        text: i18n.tr("Scan keys from computer")
                        onClicked: page.scanBundle()
                    }
                    Button {
                        Layout.fillWidth: true
                        visible: page.app.scannedKeyCount > 0
                        text: i18n.tr("Discard scanned keys (%1)").arg(page.app.scannedKeyCount)
                        onClicked: {
                            page.app.clearScannedKeys();
                            page.bundleNoteIsError = false;
                            page.bundleNote = i18n.tr("Scanned keys discarded.");
                        }
                    }
                    Label {
                        Layout.fillWidth: true
                        visible: page.bundleNote !== ""
                        wrapMode: Text.WordWrap
                        textSize: Label.Small
                        color: page.bundleNoteIsError ? theme.palette.normal.negative
                                                      : theme.palette.normal.positive
                        text: page.bundleNote
                    }
                }
            }

            OptionSelector {
                id: profileSelector
                Layout.fillWidth: true
                model: page.profileIds.map(function(id) { return id === "chatgpt" ? i18n.tr("ChatGPT subscription") : id === "openai" ? i18n.tr("OpenAI API (separate billing)") : id === "opencode" ? i18n.tr("OpenCode (recommended)") : id === "openrouter" ? "OpenRouter" : id === "custom" ? i18n.tr("Custom endpoint") : i18n.tr("Local server"); })
                selectedIndex: {
                    var start = page.activeProfile !== "" ? page.profileIds.indexOf(page.activeProfile) : 0;
                    return start >= 0 ? start : 0;
                }
                onSelectedIndexChanged: {
                    page.resultText = ""; page.resultIsError = false;
                    keyField.text = ""; modelField.text = ""; baseUrlField.text = "";
                    page.keyInjected = "";
                    page.prefillKey();
                }
            }

            Label {
                Layout.fillWidth: true
                visible: page.stored !== null && page.stored.configured === true
                wrapMode: Text.WordWrap
                textSize: Label.Small
                color: theme.palette.normal.backgroundSecondaryText
                text: {
                    var bits = [];
                    if (page.stored) {
                        if (page.stored.model) bits.push(i18n.tr("model %1").arg(page.stored.model));
                        if (page.stored.endpoint) bits.push(page.stored.endpoint);
                        if (page.stored.masked_key) bits.push(i18n.tr("key %1").arg(page.stored.masked_key));
                        if (page.activeProfile === page.profileId) bits.push(i18n.tr("ACTIVE"));
                    }
                    return bits.length ? i18n.tr("Saved: ") + bits.join(" · ") : "";
                }
            }

            Button {
                Layout.fillWidth: true
                visible: page.profileId === "chatgpt"
                text: i18n.tr("Sign in and configure ChatGPT")
                onClicked: page.app.pushPage("SubscriptionPage.qml", {})
            }

            // ---- endpoint (custom / local)
            TextField {
                id: baseUrlField
                Layout.fillWidth: true
                visible: page.profileId === "custom" || page.profileId === "local"
                inputMethodHints: Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase | Qt.ImhUrlCharactersOnly
                placeholderText: page.stored && page.stored.endpoint
                                 ? i18n.tr("Server address — blank keeps %1").arg(page.stored.endpoint)
                                 : i18n.tr("Server address, e.g. http://192.168.1.10:1234/v1")
            }

            // ---- model
            OptionSelector {
                id: modelSelector
                Layout.fillWidth: true
                visible: page.profileId === "opencode" && page.catalog.length > 0
                model: page.catalog.map(function(entry) {
                    return entry.label + (entry.text_only ? i18n.tr(" (text only)") : "");
                })
                selectedIndex: {
                    var wanted = page.stored && page.stored.model ? page.stored.model
                                 : (page.app.api ? page.app.api.opencode_default_model : "");
                    for (var i = 0; i < page.catalog.length; i++)
                        if (page.catalog[i].id === wanted) return i;
                    return 0;
                }
            }

            TextField {
                id: modelField
                Layout.fillWidth: true
                visible: page.profileId !== "chatgpt" && (page.profileId !== "opencode" || page.catalog.length === 0)
                inputMethodHints: Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase
                placeholderText: page.stored && page.stored.model
                                 ? i18n.tr("Model — blank keeps %1").arg(page.stored.model)
                                 : i18n.tr("Model name, e.g. anthropic/claude-sonnet-5")
                onVisibleChanged: if (visible && text === "" && page.stored && page.stored.model)
                                      text = page.stored.model
            }

            // ---- key
            RowLayout {
                Layout.fillWidth: true
                visible: page.profileId !== "local" && page.profileId !== "chatgpt"
                TextField {
                    id: keyField
                    Layout.fillWidth: true
                    echoMode: TextInput.Password
                    inputMethodHints: Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase | Qt.ImhSensitiveData
                    placeholderText: page.stored && page.stored.masked_key
                                     ? i18n.tr("API key — blank keeps the saved key")
                                     : i18n.tr("API key")
                    Component.onCompleted: page.prefillKey()
                }
                Button {
                    text: i18n.tr("Scan")
                    enabled: !page.working
                    onClicked: page.app.openScan("single", function(res) {
                        if (res && res.kind === "text") {
                            keyField.text = res.text;
                            page.resultIsError = false;
                            page.resultText = i18n.tr(
                                "Scanned %1 characters into the key field — remember Verify & save.")
                                .arg(("" + res.text).length);
                        }
                    })
                }
            }

            // ---- vision + effort
            RowLayout {
                Layout.fillWidth: true
                visible: page.profileId !== "opencode" && page.profileId !== "chatgpt"
                Label {
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                    text: i18n.tr("Text-only model (cannot see images)")
                }
                Switch {
                    id: textOnlySwitch
                    checked: page.stored && page.stored.text_only === true
                }
            }

            Label {
                visible: effortSelector.visible
                text: i18n.tr("Reasoning effort")
                textSize: Label.Small
                color: theme.palette.normal.backgroundSecondaryText
            }
            OptionSelector {
                id: effortSelector
                Layout.fillWidth: true
                visible: page.profileId !== "local" && page.profileId !== "chatgpt"
                model: page.effortValues
                selectedIndex: {
                    var wanted = page.stored && page.stored.effort ? page.stored.effort : "high";
                    var i = page.effortValues.indexOf(wanted);
                    return i >= 0 ? i : 3;
                }
            }

            RowLayout {
                Layout.fillWidth: true
                visible: !page.wizardMode
                Label {
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                    text: i18n.tr("Activate this profile")
                }
                CheckBox {
                    id: activateBox
                    checked: page.activeProfile === "" || page.activeProfile === page.profileId
                }
            }

            Label {
                Layout.fillWidth: true
                visible: page.resultText !== ""
                wrapMode: Text.WordWrap
                color: page.resultIsError ? theme.palette.normal.negative
                                          : theme.palette.normal.positive
                text: page.resultText
            }

            ActivityIndicator {
                Layout.alignment: Qt.AlignHCenter
                running: page.working
                visible: running
            }

            Button {
                Layout.fillWidth: true
                enabled: !page.working
                color: theme.palette.normal.positive
                visible: page.profileId !== "chatgpt"
                text: i18n.tr("Verify & save")
                onClicked: page.save()
            }

            Button {
                Layout.fillWidth: true
                visible: !page.wizardMode && page.profileId !== "chatgpt" && page.stored !== null
                         && page.stored.configured === true
                         && page.activeProfile !== page.profileId
                enabled: !page.working
                text: i18n.tr("Remove this profile")
                onClicked: page.removeProfile()
            }

            RestartHint {
                id: restartHint
                Layout.fillWidth: true
                app: page.app
            }

            Button {
                Layout.fillWidth: true
                visible: page.wizardMode
                enabled: (page.savedOnce || (page.profileId === "chatgpt" && page.stored && page.stored.configured === true)) && !page.working
                color: theme.palette.normal.positive
                text: keyField.text.trim() !== "" ? i18n.tr("Verify, save & continue")
                                                  : i18n.tr("Continue")
                onClicked: {
                    // A key left in the field (scanned after the first save)
                    // must not die with the wizard — commit it first.
                    if (page.profileId !== "chatgpt" && keyField.text.trim() !== "")
                        page.save(function(ok) { if (ok) page.app.wizardNext(); });
                    else
                        page.app.wizardNext();
                }
            }
        }
    }
}
