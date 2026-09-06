import QtQuick 2.12
import QtQuick.Layouts 1.12
import Lomiri.Components 1.3
import Lomiri.Components.Popups 1.3

/*
 * Quick setup — the fast path (owner request, 2026-09-03): one name field,
 * one bundle scan of the website's /qr codes, and the app does the rest
 * without further questions. Every value still goes through the same
 * probe → `setup-api apply` as the step-by-step wizard; nothing here
 * persists anything the wizard would not.
 *
 * Order of work, each a row on screen that only expands when it fails:
 *   1. verify  — live probes for every scanned key (all of them, so the
 *                user sees every problem at once, not one per retry);
 *   2. save    — ONE apply carrying every section (provider, keys, name,
 *                Telegram, AgentMail); a failure names the section;
 *   3. system  — background service (+ start at boot), keep-awake, media
 *                toolchain (all mandatory on this path; the passcode is
 *                asked once and held in memory only for this run);
 *   4. finish  — mark_complete, restart if a daemon was already running.
 *
 * Contract with the bundle (docs/QR_KEYS_SPEC.md): `opencode` and both
 * Telegram entries are required (unless the phone already has them);
 * `openai`, `serper`, `jina` and `agentmail` are optional and switch the
 * matching feature on by their mere presence — AgentMail becomes the
 * email/calendar provider without a question. An `openrouter` key is
 * probed and saved as a NON-active alternative provider (a second apply:
 * setup-api takes one provider section per call, and OpenCode keeps the
 * main slot). A `custom` key cannot be saved blind — the server address
 * and model are unknown — so it stays in app.scannedKeys for Settings →
 * Provider, where the field pre-fills. Local servers are step-by-step
 * territory; "Set up step by step" starts pre-filled from the same keys.
 */
Page {
    id: page
    property var app

    header: PageHeader { title: i18n.tr("Quick setup") }

    readonly property var service: app.api && app.api.service ? app.api.service : null
    readonly property bool serviceSupported: service !== null && service.supported === true
    readonly property bool isUT: app.api && app.api.is_ubuntu_touch === true
    readonly property string storedName: app.api && app.api.identity && app.api.identity.user_name
                                         ? app.api.identity.user_name : ""
    readonly property bool providerConfigured: app.api && app.api.providers
                                               && app.api.providers.active ? true : false
    readonly property bool telegramConfigured: app.api && app.api.telegram
                                               && app.api.telegram.configured === true

    property bool useSubscription: app.api && app.api.providers && app.api.providers.active === "chatgpt"

    // "intro" (name + scan) → "run" (rows) → "done" (navigating away)
    property string phase: "intro"
    property bool running: false
    property string statusText: ""
    // Within "run": which stage a Retry resumes. verify → apply → system.
    property string stage: "verify"
    property int systemCursor: 0
    property bool daemonWasRunning: false
    // Scanned/edited secrets, memory only (same lifetime as app.scannedKeys).
    property var values: ({})
    property string userName: ""
    // Held only between the first privileged step and the end of the run.
    property string passcode: ""
    // "" is a VALID passcode (a phone set to swipe unlock has an empty
    // password and sudo accepts it), so "asked already" is a separate flag.
    property bool passcodeKnown: false
    Component.onDestruction: { passcode = ""; passcodeKnown = false; values = ({}); }

    readonly property var verifyIds: ["main", "openai", "serper", "jina", "telegram", "agentmail", "openrouter"]
    // OpenRouter needs a model to probe and to save; the CLI's own wizard
    // default (vision-capable) unless setup-api status serves one.
    function openrouterModel() {
        return app.api && app.api.openrouter_default_model ? app.api.openrouter_default_model
                                                           : "google/gemini-3-flash-preview";
    }
    function openrouterTextOnly() {
        return app.api && app.api.openrouter_default_text_only === true;
    }
    // Rows that do not want the bundle; toolchain/service/wakelock are
    // system steps, identity is saved by the same apply as the keys.
    readonly property var sectionRow: ({provider: "main", openai: "openai", serper: "serper",
                                        jina: "jina", identity: "identity", telegram: "telegram",
                                        email_calendar: "agentmail"})

    ListModel { id: steps }

    function rowIndex(sid) {
        for (var i = 0; i < steps.count; i++)
            if (steps.get(i).sid === sid) return i;
        return -1;
    }
    function rowState(sid) {
        var i = rowIndex(sid);
        return i >= 0 ? steps.get(i).state : "";
    }
    function setRow(sid, state, detail) {
        var i = rowIndex(sid);
        if (i < 0) return;
        steps.setProperty(i, "state", state);
        steps.setProperty(i, "detail", detail || "");
        recountFailed();
    }
    function addRow(sid, label, fields) {
        steps.append({sid: sid, label: label, state: "pending", detail: "", fields: fields || ""});
    }
    // Recomputed by setRow(): a binding over steps.get(i).state would not
    // wake up on setProperty.
    property bool anyFailed: false
    function recountFailed() {
        var n = 0;
        for (var i = 0; i < steps.count; i++)
            if (steps.get(i).state === "failed") n++;
        anyFailed = n > 0;
    }
    function glyph(state) {
        switch (state) {
        case "checking": return "…";
        case "verified": return "✓";
        case "ok": return "✓";
        case "failed": return "✗";
        default: return "·";
        }
    }
    function glyphColor(state) {
        if (state === "failed") return theme.palette.normal.negative;
        if (state === "ok") return theme.palette.normal.positive;
        return theme.palette.normal.backgroundSecondaryText;
    }

    function has(name) { return typeof values[name] === "string" && values[name].trim() !== ""; }
    function val(name) { return has(name) ? values[name].trim() : ""; }
    // Field edits on a failed row rewrite the value in place (no reassign:
    // nothing binds to `values`, and a reassign would rebuild the rows).
    function setValue(name, text) {
        if (values[name] === text) return;
        values[name] = text;
        // Whatever this value backed is no longer verified.
        var sid = name === "opencode" ? "main"
                  : (name.indexOf("telegram_") === 0 ? "telegram" : name);
        if (rowState(sid) === "verified") setRow(sid, "pending", "");
    }

    // ------------------------------------------------------------ entry
    function startWithBundle(res) {
        var keys = res.keys || {};
        var copy = {};
        for (var k in keys) copy[k] = keys[k];
        values = copy;
        app.acceptBundle(res);   // keeps them for the step-by-step fallback
        daemonWasRunning = app.api && app.api.daemon_running === true;
        steps.clear();
        anyFailed = false;
        addRow("main", i18n.tr("Main agent (OpenCode Go)"), "key");
        if (has("openai")) addRow("openai", i18n.tr("OpenAI"), "key");
        if (has("serper")) addRow("serper", i18n.tr("Serper web search"), "key");
        if (has("jina")) addRow("jina", i18n.tr("Jina page reading"), "key");
        addRow("telegram", i18n.tr("Telegram"), "telegram");
        if (has("agentmail")) addRow("agentmail", i18n.tr("AgentMail email & calendar"), "key");
        if (has("openrouter")) addRow("openrouter", i18n.tr("OpenRouter (alternative provider)"), "key");
        if (has("custom")) {
            // Never applied from here (no server address, no model): shown
            // so the user knows where the key went.
            addRow("custom", i18n.tr("Custom endpoint key"), "");
            setRow("custom", "ok", i18n.tr("kept for Settings → Provider → Custom endpoint, where you add the server address and model"));
        }
        addRow("identity", i18n.tr("Your name"), "");
        // The three system rows are MANDATORY on this path: a capability
        // that is missing or unreadable fails its row (pointing to the
        // guided setup, which lets you skip), it is never skipped here.
        addRow("service", i18n.tr("Background service"), "");
        addRow("wakelock", i18n.tr("Keep awake with the screen off"), "");
        addRow("toolchain", i18n.tr("Media toolchain"), "");
        addRow("finish", i18n.tr("Finishing up"), "");
        phase = "run";
        stage = "verify";
        systemCursor = 0;
        runVerify();
    }

    function scanAndStart() {
        userName = nameField.text.trim() !== "" ? nameField.text.trim() : storedName;
        app.openScan("bundle", function(res) {
            if (res && res.kind === "bundle") page.startWithBundle(res);
        });
    }

    // Sections may already be committed (and their scanned keys consumed)
    // by the time the user bails out: refresh first so the wizard sees
    // them as configured instead of asking for values that are gone.
    function stepByStep() {
        if (running) return;
        running = true;
        refreshStatus(function(ok) {
            page.running = false;
            if (!ok) {
                // Parts may already be saved: the wizard must not open on
                // stale data. Stay here; the button is the retry.
                page.statusText = i18n.tr("Could not re-read Briglia's status — tap \"Set up step by step instead\" again.");
                return;
            }
            page.app.popPage();
            page.app.startWizard();
        });
    }

    // Retry always restarts at the probe stage: a row that failed at
    // save or system time may have had its value edited meanwhile, and an
    // edited credential must be re-verified, never trusted from the field.
    // Rows already "ok" are not touched; runApply sends only
    // unsaved sections; runSystem skips finished steps.
    function retry() {
        if (running) return;
        runVerify();
    }

    // ------------------------------------------------------------ 1. verify
    function runVerify() {
        stage = "verify";
        running = true;
        statusText = i18n.tr("Checking the keys…");
        var ids = [];
        for (var i = 0; i < verifyIds.length; i++) {
            var st = rowState(verifyIds[i]);
            if (st === "pending" || st === "failed") ids.push(verifyIds[i]);
        }
        var failed = 0;
        var step = function(k) {
            if (k >= ids.length) {
                if (failed > 0) {
                    page.running = false;
                    page.statusText = i18n.tr("Fix the marked items and tap Retry — or switch to step-by-step setup.");
                    return;
                }
                page.runApply();
                return;
            }
            page.verifyOne(ids[k], function(ok) {
                if (!ok) failed++;
                step(k + 1);
            });
        };
        step(0);
    }

    function verifyOne(sid, done) {
        var probeKey = function(kind, name) {
            page.setRow(sid, "checking", "");
            page.app.apiProbe({kind: kind, api_key: page.val(name)}, function(probe) {
                if (!probe || probe.ok !== true) {
                    page.setRow(sid, "failed", i18n.tr("Key check failed: %1").arg(page.app.describeError(probe)));
                    done(false);
                    return;
                }
                var note = "";
                if (kind === "agentmail" && probe.inboxes && probe.inboxes.length > 0)
                    note = probe.inboxes[0];
                page.setRow(sid, "verified", note);
                done(true);
            });
        };
        switch (sid) {
        case "main":
            if (useSubscription) {
                if (app.api && app.api.providers && app.api.providers.active === "chatgpt" && app.api.providers.profiles.chatgpt && app.api.providers.profiles.chatgpt.configured === true) {
                    setRow(sid, "verified", i18n.tr("keeping ChatGPT subscription")); done(true);
                } else { setRow(sid, "failed", i18n.tr("Sign in and select ChatGPT before continuing.")); done(false); }
                return;
            }
            if (!has("opencode")) {
                if (providerConfigured) {
                    setRow(sid, "verified", i18n.tr("keeping the current provider"));
                    done(true);
                } else {
                    setRow(sid, "failed", i18n.tr("No OpenCode Go key in the scanned codes. Paste it below, or use step-by-step setup for OpenRouter, a custom server or a local model."));
                    done(false);
                }
                return;
            }
            probeKey("opencode", "opencode");
            return;
        case "openai": case "serper": case "jina": case "agentmail":
            probeKey(sid, sid);
            return;
        case "openrouter":
            setRow(sid, "checking", "");
            app.apiProbe({kind: "openrouter", api_key: val("openrouter"), model: openrouterModel()}, function(probe) {
                if (!probe || probe.ok !== true) {
                    page.setRow(sid, "failed", i18n.tr("Key check failed: %1").arg(page.app.describeError(probe)));
                    done(false);
                    return;
                }
                page.setRow(sid, "verified", page.openrouterModel());
                done(true);
            });
            return;
        case "telegram":
            var token = val("telegram_token"), chat = val("telegram_chat_id");
            if (token === "" && chat === "" && telegramConfigured) {
                setRow(sid, "verified", i18n.tr("keeping the current bot"));
                done(true);
                return;
            }
            if (token === "" || chat === "") {
                setRow(sid, "failed", i18n.tr("Both the bot token (@BotFather) and your numeric chat ID (@userinfobot) are needed."));
                done(false);
                return;
            }
            if (!/^-?[0-9]+$/.test(chat)) {
                setRow(sid, "failed", i18n.tr("The chat ID must be numeric (letters mean it's a username — ask @userinfobot for the number)."));
                done(false);
                return;
            }
            setRow(sid, "checking", "");
            app.apiProbe({kind: "telegram", token: token}, function(probe) {
                if (!probe || probe.ok !== true) {
                    page.setRow(sid, "failed", i18n.tr("Bot token check failed: %1").arg(page.app.describeError(probe)));
                    done(false);
                    return;
                }
                // The chat ID decides who may operate Briglia remotely:
                // resolve it with Telegram (getChat, private chats only) and
                // show the destination, not just a syntax check.
                page.app.pyCall("telegram_get_chat", [token, chat], function(dest) {
                    if (!dest || dest.ok !== true) {
                        var why = page.app.describeError(dest);
                        // A brand-new bot has never seen your chat: Telegram
                        // answers "chat not found" until you message it.
                        if (dest && dest.code === "chat_not_found")
                            why = i18n.tr("Telegram doesn't know this chat yet. Open %1 in Telegram, send /start, then tap Retry.")
                                  .arg(probe.bot_username ? "@" + probe.bot_username : i18n.tr("your bot"));
                        page.setRow(sid, "failed", why);
                        done(false);
                        return;
                    }
                    page.setRow(sid, "verified", i18n.tr("bot %1 → %2")
                                .arg(probe.bot_username ? "@" + probe.bot_username : "?")
                                .arg(dest.label));
                    done(true);
                });
            });
            return;
        default:
            done(true);
        }
    }

    // ------------------------------------------------------------ 2. save
    // One apply for everything verified. setup-api commits sections in a
    // fixed order and reports `applied`, so a failure is pinned to exactly
    // one row and a Retry re-sends only what is still unsaved.
    function buildApply() {
        var req = {};
        if (!useSubscription && rowState("main") !== "ok" && has("opencode")) {
            var model = app.api.opencode_default_model
                        || (app.api.opencode_catalog && app.api.opencode_catalog.length > 0
                            ? app.api.opencode_catalog[0].id : "");
            req.provider = {profile: "opencode", activate: true, api_key: val("opencode"),
                            model: model, effort: "high"};
        }
        var simple = ["openai", "serper", "jina"];
        for (var i = 0; i < simple.length; i++)
            if (rowIndex(simple[i]) >= 0 && rowState(simple[i]) !== "ok")
                req[simple[i]] = {api_key: val(simple[i])};
        if (rowState("identity") !== "ok")
            req.identity = {user_name: userName};
        if (rowState("telegram") !== "ok" && has("telegram_token"))
            req.telegram = {token: val("telegram_token"), chat_id: val("telegram_chat_id")};
        if (rowIndex("agentmail") >= 0 && rowState("agentmail") !== "ok")
            req.email_calendar = {provider: "agentmail", api_key: val("agentmail"), install_cli: true};
        return req;
    }

    function runApply() {
        stage = "apply";
        running = true;
        statusText = i18n.tr("Saving…");
        var req = buildApply();
        var requested = [];
        for (var section in req) {
            requested.push(section);
            setRow(sectionRow[section], "checking", "");
        }
        // Rows verified but with nothing left to send (kept current values).
        // OpenRouter is saved by its own apply below, never by this one.
        for (var v = 0; v < verifyIds.length; v++)
            if (verifyIds[v] !== "openrouter" && rowState(verifyIds[v]) === "verified")
                setRow(verifyIds[v], "ok", steps.get(rowIndex(verifyIds[v])).detail);
        if (requested.length === 0) { runExtraProviders(); return; }
        app.apiApply(req, function(result) {
            var applied = result && result.applied ? result.applied : [];
            for (var i = 0; i < requested.length; i++) {
                var row = page.sectionRow[requested[i]];
                if (applied.indexOf(requested[i]) !== -1) {
                    page.setRow(row, "ok", steps.get(page.rowIndex(row)).detail);
                    if (requested[i] === "provider") page.app.consumeScannedKeys(["opencode"]);
                    else if (requested[i] === "email_calendar") page.app.consumeScannedKeys(["agentmail"]);
                    else if (requested[i] === "telegram") page.app.consumeScannedKeys(["telegram_token", "telegram_chat_id"]);
                    else page.app.consumeScannedKeys([requested[i]]);
                }
            }
            if (!result || result.ok !== true) {
                var culprit = null;
                for (var j = 0; j < requested.length; j++)
                    if (applied.indexOf(requested[j]) === -1) { culprit = requested[j]; break; }
                for (var k = 0; k < requested.length; k++)
                    if (applied.indexOf(requested[k]) === -1 && requested[k] !== culprit)
                        page.setRow(page.sectionRow[requested[k]], "verified", "");
                if (culprit)
                    page.setRow(page.sectionRow[culprit], "failed", i18n.tr("Could not save: %1").arg(page.app.describeError(result)));
                page.running = false;
                page.statusText = i18n.tr("Fix the marked item and tap Retry.");
                return;
            }
            if (result.warnings && result.warnings.length > 0)
                for (var w = 0; w < result.warnings.length; w++)
                    if (result.warnings[w].indexOf("agentmail") === 0 && page.rowIndex("agentmail") >= 0)
                        page.setRow("agentmail", "ok", result.warnings[w]);
            page.runExtraProviders();
        });
    }

    // A scanned OpenRouter key becomes a second, NON-active provider:
    // setup-api accepts one provider section per apply and the main apply
    // carried OpenCode, so this is a separate call. activate:false keeps
    // OpenCode (or whatever was active) as the main provider; OpenRouter
    // shows up as a choice in Settings → Provider.
    function runExtraProviders() {
        if (rowIndex("openrouter") < 0 || rowState("openrouter") === "ok") { afterSaved(); return; }
        stage = "apply";
        running = true;
        statusText = i18n.tr("Saving…");
        setRow("openrouter", "checking", "");
        var model = openrouterModel();
        app.apiApply({provider: {profile: "openrouter", activate: false, api_key: val("openrouter"),
                                 model: model, effort: "high", text_only: openrouterTextOnly()}},
                     function(result) {
            if (!result || result.ok !== true) {
                page.setRow("openrouter", "failed", i18n.tr("Could not save: %1").arg(page.app.describeError(result)));
                page.running = false;
                page.statusText = i18n.tr("Fix the marked item and tap Retry.");
                return;
            }
            page.app.consumeScannedKeys(["openrouter"]);
            page.setRow("openrouter", "ok", i18n.tr("added as an alternative provider (%1) — switch to it in Settings").arg(model));
            page.afterSaved();
        });
    }

    // A refresh that comes back without a status block must never make
    // service/keep-awake look "unsupported" (and therefore skipped).
    function refreshStatus(cb) {
        app.refresh(function() { cb(page.app.api !== null); });
    }

    function afterSaved() {
        // Refresh so the system steps read the post-save status block.
        refreshStatus(function(ok) {
            if (!ok) {
                page.setRow("service", "failed", i18n.tr("Could not re-read Briglia's status after saving — tap Retry."));
                page.running = false;
                page.statusText = i18n.tr("Fix the marked item and tap Retry.");
                return;
            }
            page.runSystem(0);
        });
    }

    // ------------------------------------------------------------ 3. system
    readonly property var systemIds: ["service", "wakelock", "toolchain"]

    function runSystem(from) {
        stage = "system";
        running = true;
        var step = function(k) {
            if (k >= page.systemIds.length) { page.finishAll(); return; }
            page.systemCursor = k;
            var sid = page.systemIds[k];
            if (page.rowState(sid) === "ok") {
                step(k + 1);
                return;
            }
            var cont = function(ok) {
                if (!ok) {
                    page.running = false;
                    page.statusText = i18n.tr("Fix the marked item and tap Retry.");
                    return;
                }
                step(k + 1);
            };
            if (sid === "service") page.doService(cont);
            else if (sid === "wakelock") page.doWakelock(cont);
            else page.doToolchain(cont);
        };
        step(from);
    }

    // Passcode: one dialog per run, reused for start-at-boot and keep-awake.
    // A rejected passcode clears it so the next Retry asks again.
    property var pendingPrivileged: null
    property string pendingLabel: ""

    Component {
        id: passcodeDialog
        Dialog {
            id: dialog
            title: i18n.tr("Device passcode needed")
            text: page.pendingLabel
            TextField {
                id: passField
                echoMode: TextInput.Password
                inputMethodHints: Qt.ImhSensitiveData | Qt.ImhNoPredictiveText
                placeholderText: i18n.tr("Passcode (leave empty if the phone has none)")
            }
            Button {
                color: theme.palette.normal.positive
                text: i18n.tr("Continue")
                onClicked: {
                    var entered = passField.text;
                    passField.text = "";
                    PopupUtils.close(dialog);
                    var run = page.pendingPrivileged;
                    page.pendingPrivileged = null;
                    if (run) run(entered);
                }
            }
            Button {
                text: i18n.tr("Cancel")
                onClicked: {
                    passField.text = "";
                    PopupUtils.close(dialog);
                    var run = page.pendingPrivileged;
                    page.pendingPrivileged = null;
                    if (run) run(null);
                }
            }
        }
    }

    function withPasscode(label, run) {
        if (passcodeKnown) { run(passcode); return; }
        pendingLabel = label;
        pendingPrivileged = function(entered) {
            // null = Cancel. "" = Continue with an empty field: the phone has
            // no passcode (swipe unlock), which sudo accepts — a valid answer.
            if (entered === null) { run(null); return; }
            page.passcode = entered;
            page.passcodeKnown = true;
            run(entered);
        };
        PopupUtils.open(passcodeDialog, page);
    }

    function sudoFailed(sid, res) {
        passcode = "";
        passcodeKnown = false;
        setRow(sid, "failed", res && res.error
               ? i18n.tr("Passcode rejected or command failed: %1").arg(res.error)
               : i18n.tr("Passcode needed — tap Retry to enter it."));
    }

    function doService(done) {
        if (!serviceSupported) {
            setRow("service", "failed", i18n.tr("Background service management is not available on this system (Linux/Ubuntu Touch only). Quick setup needs it — use step-by-step setup instead."));
            done(false);
            return;
        }
        setRow("service", "checking", i18n.tr("installing…"));
        // "ok" only on evidence: the refreshed status block must show the
        // unit active AND lingering — an install verb can succeed while
        // warning that the daemon is inactive.
        var verify = function() {
            page.refreshStatus(function(fresh) {
                var s = fresh ? page.service : null;
                if (!s || s.unit_installed !== true || s.active !== "active") {
                    page.setRow("service", "failed", i18n.tr("Service installed but not running (state: %1) — check the Dashboard log, then Retry.")
                                .arg(s && s.active ? s.active : "?"));
                    done(false);
                    return;
                }
                // Positive evidence only: an absent/malformed linger field is
                // not "enabled".
                if (s.linger !== true) {
                    page.setRow("service", "failed", i18n.tr("Service running, but start at boot is not confirmed enabled — tap Retry."));
                    done(false);
                    return;
                }
                page.setRow("service", "ok", i18n.tr("running, starts at boot"));
                done(true);
            });
        };
        var afterInstall = function(lingerCommand) {
            if (!lingerCommand) { verify(); return; }
            page.withPasscode(i18n.tr("Lets Briglia start at boot and stay awake with the screen off."),
                function(pass) {
                    if (pass === null) { page.sudoFailed("service", null); done(false); return; }
                    page.setRow("service", "checking", i18n.tr("enabling start at boot…"));
                    page.app.pyCall("run_sudo_command", [lingerCommand, pass], function(res) {
                        if (!res || res.ok !== true) { page.sudoFailed("service", res); done(false); return; }
                        verify();
                    });
                });
        };
        var lingerFromStatus = service && service.linger !== true && service.linger_command
                               ? service.linger_command : "";
        if (service && service.unit_installed === true) {
            if (service.active === "active") { afterInstall(lingerFromStatus); return; }
            // Unit present but not running (a previous attempt stopped
            // short): bring it up on the freshly saved settings.
            app.apiService({action: "restart"}, function(result) {
                if (!result || result.ok !== true) {
                    page.setRow("service", "failed", page.app.describeError(result));
                    done(false);
                    return;
                }
                afterInstall(lingerFromStatus);
            });
            return;
        }
        app.apiService({action: "install"}, function(result) {
            if (!result || result.ok !== true) {
                page.setRow("service", "failed", page.app.describeError(result));
                done(false);
                return;
            }
            afterInstall(result.linger_command || lingerFromStatus);
        });
    }

    function doWakelock(done) {
        if (!isUT) {
            setRow("wakelock", "failed", i18n.tr("Keep-awake exists on Ubuntu Touch only. Quick setup needs it — use step-by-step setup instead."));
            done(false);
            return;
        }
        if (service && service.wakelock_unit_installed === true && service.wakelock_active === "active") {
            setRow("wakelock", "ok", i18n.tr("already active"));
            done(true);
            return;
        }
        if (!(app.api && app.api.wakelock_supported === true)) {
            setRow("wakelock", "failed", i18n.tr("This kernel does not support the keep-awake unit, so Briglia would stop when the screen turns off. Quick setup needs it — use step-by-step setup instead."));
            done(false);
            return;
        }
        setRow("wakelock", "checking", "");
        app.apiService({keepawake_script: true}, function(result) {
            if (!result || result.ok !== true) {
                page.setRow("wakelock", "failed", page.app.describeError(result));
                done(false);
                return;
            }
            var script = result.wakelock_install_script;
            // Same content gate as AlwaysOnPage: never run a served script
            // that could leave / writable when a middle step fails.
            if (!script || script.indexOf("trap 'mount -o remount,ro /") === -1) {
                page.setRow("wakelock", "failed", i18n.tr("This Briglia CLI release serves an unsafe keep-awake script — update Briglia CLI from the Dashboard and retry."));
                done(false);
                return;
            }
            page.withPasscode(i18n.tr("Lets Briglia start at boot and stay awake with the screen off."),
                function(pass) {
                    if (pass === null) { page.sudoFailed("wakelock", null); done(false); return; }
                    page.setRow("wakelock", "checking", i18n.tr("installing keep-awake…"));
                    page.app.pyCall("run_privileged_script", [script, pass], function(res) {
                        if (!res || res.ok !== true) { page.sudoFailed("wakelock", res); done(false); return; }
                        page.refreshStatus(function(fresh) {
                            var s = fresh ? page.service : null;
                            if (!s || s.wakelock_unit_installed !== true || s.wakelock_active !== "active") {
                                page.setRow("wakelock", "failed", i18n.tr("Keep-awake unit installed but not active (state: %1) — tap Retry.")
                                            .arg(s && s.wakelock_active ? s.wakelock_active : "?"));
                                done(false);
                                return;
                            }
                            page.setRow("wakelock", "ok", "");
                            done(true);
                        });
                    });
                });
        });
    }

    function toolchainKnown() {
        return app.api && app.api.toolchain && app.api.toolchain.tools
               && app.api.toolchain.tools.length > 0 ? true : false;
    }
    // Only meaningful when toolchainKnown(): an absent block is NOT "nothing
    // missing" — callers check toolchainKnown() first.
    function missingTools() {
        var tools = toolchainKnown() ? app.api.toolchain.tools : [];
        var missing = [];
        for (var i = 0; i < tools.length; i++)
            if (tools[i].present !== true) missing.push(tools[i].name);
        return missing;
    }

    function doToolchain(done) {
        if (!toolchainKnown()) {
            setRow("toolchain", "failed", i18n.tr("Briglia CLI did not report its media toolchain status (update Briglia CLI from the Dashboard), tap Retry — or use step-by-step setup instead."));
            done(false);
            return;
        }
        if (missingTools().length === 0) {
            setRow("toolchain", "ok", i18n.tr("already installed"));
            done(true);
            return;
        }
        setRow("toolchain", "checking", i18n.tr("downloading PDF, image, audio/video and document tools — several minutes on a phone network, keep the app open"));
        app.apiApply({toolchain: {install: true, pandoc: true, libreoffice: true}}, function(result) {
            if (!result || result.ok !== true) {
                page.setRow("toolchain", "failed", page.app.describeError(result));
                done(false);
                return;
            }
            page.refreshStatus(function(fresh) {
                var missing = fresh && page.toolchainKnown() ? page.missingTools() : ["?"];
                if (missing.length > 0) {
                    page.setRow("toolchain", "failed", i18n.tr("Install reported success but these tools are still missing: %1 — tap Retry.").arg(missing.join(", ")));
                    done(false);
                    return;
                }
                page.setRow("toolchain", "ok", "");
                done(true);
            });
        });
    }

    // ------------------------------------------------------------ 4. finish
    // Nothing is cleared and Chat does not open until mark_complete, the
    // restart (when one was due) and a final refreshed status check all
    // succeeded — a failure lands on the "Finishing up" row with Retry.
    function finalProblems() {
        var out = [];
        var a = app.api;
        if (a === null) return [i18n.tr("Briglia's status could not be read")];
        if (!(a.providers && a.providers.active)) out.push(i18n.tr("no active provider"));
        if (!(a.telegram && a.telegram.configured === true)) out.push(i18n.tr("Telegram not configured"));
        if (!(a.setup && a.setup.complete === true)) out.push(i18n.tr("setup not marked complete"));
        var s = page.service;
        if (!s || s.unit_installed !== true || s.active !== "active")
            out.push(i18n.tr("background service not running"));
        else if (s.linger !== true)
            out.push(i18n.tr("start at boot not confirmed enabled"));
        if (!(s && s.wakelock_unit_installed === true && s.wakelock_active === "active"))
            out.push(i18n.tr("keep-awake not active"));
        if (!toolchainKnown())
            out.push(i18n.tr("toolchain status unavailable"));
        else {
            var missing = missingTools();
            if (missing.length > 0) out.push(i18n.tr("toolchain missing: %1").arg(missing.join(", ")));
        }
        return out;
    }

    function finishFailed(text) {
        setRow("finish", "failed", text);
        running = false;
        statusText = i18n.tr("Fix the marked item and tap Retry.");
    }

    function finishAll() {
        stage = "finish";
        running = true;
        statusText = i18n.tr("Finishing…");
        setRow("finish", "checking", "");
        app.apiApply({mark_complete: true}, function(result) {
            if (!result || result.ok !== true) {
                page.finishFailed(i18n.tr("Could not mark the setup complete: %1").arg(page.app.describeError(result)));
                return;
            }
            var settle = function() {
                page.refreshStatus(function(fresh) {
                    var problems = fresh ? page.finalProblems() : [i18n.tr("Briglia's status could not be read")];
                    if (problems.length > 0) {
                        page.finishFailed(i18n.tr("Not finished: %1").arg(problems.join("; ")));
                        return;
                    }
                    page.setRow("finish", "ok", "");
                    page.passcode = "";
                    page.passcodeKnown = false;
                    // A custom-endpoint key was never saved here (no server
                    // address, no model): it stays in memory for Settings →
                    // Provider, where the field pre-fills. Everything else
                    // was consumed as it was saved; drop any leftovers.
                    var keepCustom = page.has("custom");
                    page.values = ({});
                    if (keepCustom)
                        page.app.consumeScannedKeys(["opencode", "openai", "serper", "jina", "telegram_token",
                                                     "telegram_chat_id", "agentmail", "openrouter"]);
                    else
                        page.app.clearScannedKeys();
                    page.running = false;
                    page.phase = "done";
                    page.app.gotoShell();
                });
            };
            // A daemon that was already running keeps the OLD settings until
            // restarted; a service installed during this run started after
            // the save and needs nothing.
            if (page.daemonWasRunning && page.service && page.service.unit_installed === true) {
                page.setRow("finish", "checking", i18n.tr("restarting Briglia…"));
                page.app.apiService({action: "restart"}, function(r) {
                    if (!r || r.ok !== true) {
                        page.finishFailed(i18n.tr("Restart failed: %1").arg(page.app.describeError(r)));
                        return;
                    }
                    settle();
                });
            } else {
                settle();
            }
        });
    }

    // ------------------------------------------------------------ UI
    Flickable {
        anchors { top: page.header.bottom; left: parent.left; right: parent.right; bottom: parent.bottom }
        contentHeight: column.height + units.gu(6)
        clip: true

        ColumnLayout {
            id: column
            anchors { top: parent.top; topMargin: units.gu(2); horizontalCenter: parent.horizontalCenter }
            width: Math.min(parent.width - units.gu(4), units.gu(50))
            spacing: units.gu(1.5)

            // ---- intro
            Label {
                Layout.fillWidth: true
                visible: page.phase === "intro"
                wrapMode: Text.WordWrap
                color: theme.palette.normal.backgroundSecondaryText
                text: i18n.tr("On your computer, open %1/qr and paste your keys: OpenCode Go, OpenAI, Serper, Jina, a Telegram bot token and your chat ID. AgentMail (an email address for Briglia) and OpenRouter (an alternative provider) are optional and switch on by themselves if present. Then scan the codes with this phone — everything is checked and saved in one go, and Briglia installs its background service, keep-awake and media toolchain. Your device passcode is asked once.")
                      .arg(page.app.websiteBase.replace("https://", ""))
            }
            OptionSelector {
                Layout.fillWidth: true
                visible: page.phase === "intro" && page.app.api && page.app.api.subscription_setup && page.app.api.subscription_setup.supported === true
                model: [i18n.tr("OpenCode Go"), i18n.tr("ChatGPT subscription")]
                selectedIndex: page.useSubscription ? 1 : 0
                onSelectedIndexChanged: page.useSubscription = selectedIndex === 1
            }
            Button {
                Layout.fillWidth: true
                visible: page.phase === "intro" && page.useSubscription
                text: i18n.tr("Sign in and select ChatGPT")
                onClicked: page.app.pushPage("SubscriptionPage.qml", {})
            }
            Label {
                Layout.fillWidth: true
                visible: page.phase === "intro" && page.useSubscription
                wrapMode: Text.WordWrap
                text: i18n.tr("No OpenCode key is needed. Sign in above first, then scan your tool and Telegram keys below. The OpenAI API key remains separate for web, voice and images.")
            }
            TextField {
                id: nameField
                Layout.fillWidth: true
                visible: page.phase === "intro"
                placeholderText: page.storedName !== ""
                                 ? i18n.tr("Your name — blank keeps \"%1\"").arg(page.storedName)
                                 : i18n.tr("Your name")
            }
            Button {
                Layout.fillWidth: true
                visible: page.phase === "intro"
                enabled: nameField.text.trim() !== "" || page.storedName !== ""
                color: theme.palette.normal.positive
                text: i18n.tr("Scan codes and set up")
                onClicked: page.scanAndStart()
            }
            Button {
                Layout.fillWidth: true
                visible: page.phase === "intro"
                text: i18n.tr("Set up step by step instead")
                onClicked: page.stepByStep()
            }
            Label {
                Layout.fillWidth: true
                visible: page.phase === "intro" && page.statusText !== ""
                wrapMode: Text.WordWrap
                color: theme.palette.normal.negative
                text: page.statusText
            }

            // ---- run
            Label {
                Layout.fillWidth: true
                visible: page.phase !== "intro" && page.statusText !== ""
                wrapMode: Text.WordWrap
                color: page.anyFailed && !page.running ? theme.palette.normal.negative
                                                       : theme.palette.normal.backgroundSecondaryText
                text: page.statusText
            }

            Repeater {
                model: steps
                delegate: ColumnLayout {
                    Layout.fillWidth: true
                    visible: page.phase !== "intro"
                    spacing: units.gu(0.4)
                    RowLayout {
                        Layout.fillWidth: true
                        Label {
                            Layout.fillWidth: true
                            wrapMode: Text.WordWrap
                            text: model.label
                        }
                        Label {
                            text: page.glyph(model.state)
                            color: page.glyphColor(model.state)
                        }
                    }
                    Label {
                        Layout.fillWidth: true
                        visible: model.detail !== ""
                        wrapMode: Text.WordWrap
                        textSize: Label.Small
                        color: model.state === "failed" ? theme.palette.normal.negative
                                                         : theme.palette.normal.backgroundSecondaryText
                        text: model.detail
                    }
                    // Only a failed row shows its input — the whole point of
                    // this page is never asking for what already worked.
                    RowLayout {
                        Layout.fillWidth: true
                        visible: model.state === "failed" && model.fields === "key"
                        TextField {
                            id: keyField
                            Layout.fillWidth: true
                            echoMode: TextInput.Password
                            inputMethodHints: Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase | Qt.ImhSensitiveData
                            placeholderText: i18n.tr("API key")
                            text: page.val(model.sid === "main" ? "opencode" : model.sid)
                            onTextChanged: page.setValue(model.sid === "main" ? "opencode" : model.sid, text)
                        }
                        Button {
                            text: i18n.tr("Scan")
                            onClicked: page.app.openScan("single", function(res) {
                                if (res && res.kind === "text") keyField.text = res.text;
                            })
                        }
                    }
                    ColumnLayout {
                        Layout.fillWidth: true
                        visible: model.state === "failed" && model.fields === "telegram"
                        spacing: units.gu(0.4)
                        RowLayout {
                            Layout.fillWidth: true
                            TextField {
                                id: tokenField
                                Layout.fillWidth: true
                                echoMode: TextInput.Password
                                inputMethodHints: Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase | Qt.ImhSensitiveData
                                placeholderText: i18n.tr("Bot token from @BotFather")
                                text: page.val("telegram_token")
                                onTextChanged: page.setValue("telegram_token", text)
                            }
                            Button {
                                text: i18n.tr("Scan")
                                onClicked: page.app.openScan("single", function(res) {
                                    if (res && res.kind === "text") tokenField.text = res.text;
                                })
                            }
                        }
                        TextField {
                            Layout.fillWidth: true
                            inputMethodHints: Qt.ImhFormattedNumbersOnly | Qt.ImhNoPredictiveText
                            placeholderText: i18n.tr("Your numeric chat ID (from @userinfobot)")
                            text: page.val("telegram_chat_id")
                            onTextChanged: page.setValue("telegram_chat_id", text)
                        }
                    }
                }
            }

            ActivityIndicator {
                Layout.alignment: Qt.AlignHCenter
                running: page.running
                visible: running
            }

            Button {
                Layout.fillWidth: true
                visible: page.phase === "run" && !page.running && page.anyFailed
                color: theme.palette.normal.positive
                text: i18n.tr("Retry")
                onClicked: page.retry()
            }
            Button {
                Layout.fillWidth: true
                visible: page.phase === "run" && !page.running && page.anyFailed
                text: i18n.tr("Set up step by step instead")
                onClicked: page.stepByStep()
            }
        }
    }
}
