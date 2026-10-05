#!/usr/bin/env python3
"""Repository invariants for the product identity (rename plan §5).

Static, offline, seconds. Pins the things a rename can silently get wrong:

  1. The click identity is ONE thing in ONE place: manifest.json's package
     name is what Main.qml's applicationName, the hook filenames and the
     publisher's derived click filename all follow.
  2. The previous identity ("ada") survives ONLY where it is meant to:
     the bridge's LEGACY_* detection block, the legacy keep-awake removal
     script, and the migration copy the user reads (MigratePage + the two
     entry points that lead there). Nowhere else in shipped files — no
     old env seam, socket path, unit name, bundle name, package id or
     website host.
  3. What must NOT change with the rename did not: the signed-envelope
     format name, the QR bundle prefix, the pinned key hexes.
  4. The migration UX is wired: routing and the post-install path consult
     the CLI's migration gate before the wizard; MigratePage reaches the
     bridge's `migrate` and `swap_legacy_wakelock`; the Dashboard offers
     the pending keep-awake swap.

Usage: python3 scripts/identity_selftest.py
"""

import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "py"))
import briglia_bridge  # noqa: E402
import release_verify  # noqa: E402

PASSED = FAILED = 0


def check(label, ok, detail=""):
    global PASSED, FAILED
    print("%s %s%s" % ("PASS" if ok else "FAIL", label,
                       "" if ok or not detail else " — " + str(detail)[:400]))
    if ok:
        PASSED += 1
    else:
        FAILED += 1


def read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


def shipped_files():
    """Everything build_click.py packages, plus the manifest."""
    out = ["manifest.json"]
    for top in ("click", "qml", "py"):
        for dirpath, _dirs, files in os.walk(os.path.join(ROOT, top)):
            for name in files:
                if name.endswith((".pyc",)) or "__pycache__" in dirpath:
                    continue
                out.append(os.path.relpath(os.path.join(dirpath, name), ROOT))
    return sorted(out)


def main():
    manifest = json.loads(read("manifest.json"))
    pkg = manifest["name"]
    hook = list(manifest["hooks"].keys())

    # ---- 1. one identity
    check("manifest: package name is briglia.permaevidence", pkg == "briglia.permaevidence", pkg)
    check("manifest: title is Briglia", manifest["title"] == "Briglia", manifest["title"])
    check("manifest: exactly one hook, named after the product",
          hook == ["briglia"], hook)
    for kind in ("apparmor", "desktop"):
        rel = manifest["hooks"][hook[0]][kind]
        check("manifest: %s hook file exists (%s)" % (kind, rel), os.path.isfile(os.path.join(ROOT, rel)), rel)
    main_qml = read("qml/Main.qml")
    m = re.search(r'applicationName:\s*"([^"]+)"', main_qml)
    check("Main.qml applicationName == manifest name", m and m.group(1) == pkg, m and m.group(1))
    desktop = read(manifest["hooks"][hook[0]]["desktop"])
    check("desktop entry names Briglia", "Name=Briglia" in desktop and "Ada" not in desktop, desktop)
    publisher = read("scripts/publish_click.sh")
    check("publisher derives the click filename from manifest.json (no hardcoded package id)",
          "PKG_NAME=" in publisher and 'CLICK="build/${PKG_NAME}_${VERSION}_all.click"' in publisher
          and "permaevidence_${VERSION}" not in publisher)
    check("publisher title/channel are Briglia's",
          'CHANNEL="briglia-ut"' in publisher and 'TITLE="Briglia for Ubuntu Touch"' in publisher)
    supersession = read("scripts/release/check-supersession.sh")
    check("publisher: --bootstrap retired (absent live envelope is a refusal, in the shared supersession check)",
          "--bootstrap)" not in publisher and "BOOTSTRAP" not in publisher and "BOOTSTRAP" not in supersession
          and "check-supersession.sh" in publisher and "bootstrap retired" in supersession)
    check("publisher: the rename-transition descriptor is gone (post-transition)",
          "LEGACY_" not in publisher and "legacy envelope" not in publisher.lower())
    check("app cache/state paths follow the package id",
          "~/.cache/briglia.permaevidence" in read("py/chat_client.py")
          and "~/.cache/briglia.permaevidence" in read("py/voice_record.py")
          and "~/.cache/briglia.permaevidence" in read("py/briglia_bridge.py")
          and "/opt/click.ubuntu.com/briglia.permaevidence" in read("py/briglia_bridge.py"))
    check("website base: QML constant == bridge constant",
          ('websiteBase: "%s"' % briglia_bridge.WEBSITE_BASE) in main_qml, briglia_bridge.WEBSITE_BASE)

    # ---- 2. the previous identity, confined
    forbidden = [
        "ada.permaevidence", "ada_bridge", "ADA_UT_", "ADA_CHAT_SOCKET", "ADA_QR_",
        "ada-app-psi", ".local/bin/ada\"", ".config/ada\"", ".local/share/ada",
        "ada.service", "ada-keepawake", "ada-cli_ada", "\"ada-cli\"", "\"ada-ut\"",
        "permaevidence/ada-cli", "permaevidence/ada-ut", ".config/ada-ut", "get-ada.sh",
    ]
    offenders = []
    for rel in shipped_files():
        text = read(rel) if not rel.endswith(".png") else ""
        for ln, line in enumerate(text.splitlines(), 1):
            for token in forbidden:
                if token in line:
                    if rel == "py/briglia_bridge.py" and "LEGACY_" in line:
                        continue  # the detection block / removal script
                    offenders.append("%s:%d %s" % (rel, ln, token))
    check("no retired identifier outside the bridge's LEGACY_ block", not offenders, offenders)

    word_ada = re.compile(r"\bAda\b")
    allowed_prose = {"qml/pages/MigratePage.qml", "qml/Main.qml", "qml/pages/DashboardPage.qml",
                     "py/briglia_bridge.py"}
    prose_offenders = []
    for rel in shipped_files():
        if rel in allowed_prose or rel.endswith(".png"):
            continue
        for ln, line in enumerate(read(rel).splitlines(), 1):
            if word_ada.search(line):
                prose_offenders.append("%s:%d" % (rel, ln))
    check("the word 'Ada' appears only on the migration surfaces", not prose_offenders, prose_offenders)
    # …and on those surfaces only in migration context, never as the product.
    for rel in ("qml/Main.qml", "qml/pages/DashboardPage.qml"):
        bad = [ln for ln, line in enumerate(read(rel).splitlines(), 1)
               if word_ada.search(line) and not re.search(r"Ada (CLI installation|data|configuration)", line)]
        check("%s: 'Ada' only in migration copy" % rel, not bad, bad)
    bridge = read("py/briglia_bridge.py")
    check("bridge: every legacy path literal sits on a LEGACY_ line",
          all("LEGACY_" in line for line in bridge.splitlines()
              if re.search(r'"[^"]*(\.config/ada|share/ada|bin/ada|ada-keepawake|systemd/user/ada)', line)))
    check("bridge: setup-api schema is exactly 2", briglia_bridge.SETUP_API_SCHEMA == 2)
    check("bridge: binary and bundle names", briglia_bridge.BRIGLIA.endswith("/.local/bin/briglia")
          and briglia_bridge.BUNDLE_NAME == "briglia-cli_briglia.resources")
    check("bridge: install journal name follows the product",
          briglia_bridge._journal_path().endswith("/.briglia-install-journal.json"))
    check("bridge: legacy removal script targets the legacy unit only",
          briglia_bridge.LEGACY_WAKELOCK_UNIT_NAME in briglia_bridge.legacy_wakelock_uninstall_script()
          and "briglia-keepawake" not in briglia_bridge.legacy_wakelock_uninstall_script())

    # ---- 3. what must not change
    check("signed-envelope format name is unchanged (historical, plan §3)",
          release_verify.FORMAT == "ada-release-envelope-v1")
    for rel in ("scripts/release/sign-envelope.sh", "scripts/release/verify-envelope.sh"):
        check("%s keeps the historical format name" % rel, "ada-release-envelope-v1" in read(rel))
        check("%s names no retired channel" % rel,
              "ada-cli" not in read(rel).replace("ada-release-envelope-v1", "")
              and "ada-ut" not in read(rel))
    for rel in ("scripts/release/sign-envelope.sh", "scripts/release/release-keygen.sh"):
        check("%s allows only the Briglia channels" % rel,
              "briglia-cli|briglia-ut" in read(rel) or "briglia-ut|briglia-cli" in read(rel))
    import qr_scan  # noqa: E402
    check("QR bundle prefix unchanged", qr_scan.BUNDLE_PREFIX == "ADAK1:")
    check("CLI key hex unchanged, keyId re-derived under briglia-cli",
          release_verify.CLI_KEYS == {"briglia-cli-release-v1-94d967bae0867c2e":
                                      "621031636aa2bb2edb64a58f2f72de7bc3559b08d717c79b4251f8b1e35b8a95"})
    check("app key hex unchanged, keyId re-derived under briglia-ut",
          release_verify.APP_KEYS == {"briglia-ut-release-v1-7bb0163ac16c5cb3":
                                      "cdfa5dba857ad9276f2630c0c7028b53ea9933cc969e69f0a1cff4727ff0b7dc"})
    check("channels/repos/trust file are Briglia's",
          release_verify.CLI_POLICY.channel == "briglia-cli"
          and release_verify.APP_POLICY.channel == "briglia-ut"
          and "permaevidence/briglia-cli/releases" in release_verify.CLI_POLICY.envelope_url
          and "permaevidence/briglia-ut/releases" in release_verify.APP_POLICY.artifact_url_prefix
          and release_verify.TRUST_FILE.endswith("/.config/briglia-ut/release_trust.json"))
    check("sequences continue across the rename (CLI ≥ 60, app ≥ 2, this build = 2)",
          release_verify.MIN_CLI_SEQUENCE >= 60 and release_verify.MIN_APP_SEQUENCE >= 2
          and release_verify.APP_RELEASE_SEQUENCE >= release_verify.MIN_APP_SEQUENCE)
    check("User-Agent follows the product", release_verify.USER_AGENT == "briglia-ut-app")
    check("committed public key file follows the product",
          os.path.isfile(os.path.join(ROOT, ".release-keys", "briglia-ut-release.pub.pem"))
          and not os.path.exists(os.path.join(ROOT, ".release-keys", "ada-ut-release.pub.pem")))
    check("manifest version is the first Briglia app release line (0.8.x)",
          manifest["version"].startswith("0.8."), manifest["version"])

    # ---- 4. migration UX wiring
    check("Main.qml: migrationNeeded derives from the CLI's status block, never from paths",
          "api.migration.needed === true" in main_qml and "readonly property bool migrationNeeded" in main_qml)
    route = main_qml.split("function routeInitial()")[1].split("function openMigrate")[0]
    check("Main.qml: routeInitial consults the migration gate BEFORE setup/wizard routing",
          "if (migrationNeeded) { openMigrate(); return; }" in route
          and route.index("migrationNeeded") < route.index("startSetup()"))
    finish = main_qml.split("function finishAfterInstall()")[1].split("}", 1)[0] + main_qml.split("function finishAfterInstall()")[1][:400]
    check("Main.qml: post-install path consults the migration gate before the wizard",
          "if (root.migrationNeeded) { root.openMigrate(); return; }" in finish)
    check("Main.qml: post-install restart is skipped while a migration is pending",
          "if (root.migrationNeeded) {" in main_qml.split("py.call(\"briglia_bridge.install\"")[1][:900])
    check("Main.qml: boot page offers the migrating install and the explicit migrate entry",
          "Install Briglia CLI (migrates Ada data)" in main_qml and "Migrate Ada data to Briglia" in main_qml)
    migrate_qml = read("qml/pages/MigratePage.qml")
    check("MigratePage: consent button reaches the bridge's migrate (forward) and rollback",
          'pyCall("migrate", [rollback === true]' in migrate_qml
          and 'text: i18n.tr("Migrate now")' in migrate_qml and 'text: i18n.tr("Roll back to Ada")' in migrate_qml)
    check("MigratePage: conflict is explained and never auto-resolved",
          "migration.conflict === true" in migrate_qml and "Check again" in migrate_qml
          and "rmtree" not in migrate_qml and "unlink" not in migrate_qml)
    check("MigratePage: keep-awake swap runs through swap_legacy_wakelock with the passcode dialog",
          'pyCall("swap_legacy_wakelock", [passcode]' in migrate_qml
          and "echoMode: TextInput.Password" in migrate_qml)
    check("MigratePage: rollback offered only before the commit point",
          '["prepared", "moved", "fixups"].indexOf(journalState) !== -1' in migrate_qml)
    dash = read("qml/pages/DashboardPage.qml")
    check("Dashboard: offers the pending migration and the pending keep-awake swap",
          'onClicked: page.app.openMigrate()' in dash and 'openMigrate("wakelock")' in dash
          and "legacyWakelockPresent" in dash)
    check("Dashboard: wizard entry hidden while a migration is pending",
          "!page.app.migrationNeeded\n                         && !(page.api.setup" in dash)
    # ---- 3b. quick setup (owner request 2026-09-03): the fast path is the
    # default entry, the wizard stays reachable, and the page never
    # persists anything outside the probe → apply → service surface.
    quick = read("qml/pages/QuickSetupPage.qml")
    check("Main.qml: startSetup pushes QuickSetupPage and every setup entry uses it",
          'pushPage("QuickSetupPage.qml"' in main_qml
          and "root.startSetup()" in main_qml.split("id: bootPage")[1]
          and "root.startSetup()" in main_qml.split("function finishAfterInstall()")[1][:800]
          and 'onClicked: page.app.startSetup()' in dash)
    check("QuickSetup: bundle scan → probes → ONE apply → mark_complete",
          'openScan("bundle"' in quick and "apiProbe({kind: kind, api_key" in quick
          and 'apiProbe({kind: "telegram", token' in quick
          and "apiApply(req," in quick and "apiApply({mark_complete: true}" in quick)
    check("QuickSetup: AgentMail auto-selected from the bundle, Telegram needs token + chat id",
          'req.email_calendar = {provider: "agentmail", api_key: val("agentmail"), install_cli: true}' in quick
          and 'req.telegram = {token: val("telegram_token"), chat_id: val("telegram_chat_id")}' in quick)
    check("QuickSetup: service, keep-awake and the full media toolchain are mandatory steps",
          '{action: "install"}' in quick and '{keepawake_script: true}' in quick
          and "trap 'mount -o remount,ro /" in quick
          and "{toolchain: {install: true, pandoc: true, libreoffice: true}}" in quick)
    check("QuickSetup: passcode via dialog only, never stored, cleared on teardown",
          "echoMode: TextInput.Password" in quick and 'Component.onDestruction: { passcode = ""' in quick
          and "set_app_setting" not in quick)
    check("QuickSetup: step-by-step fallback keeps the scanned keys and refreshes status first",
          "app.acceptBundle(res)" in quick
          and "page.app.popPage();\n            page.app.startWizard();" in quick.split("function stepByStep()")[1].split("function retry()")[0])
    # Codex round 1 (2026-09-03): completion, edited credentials, fail-open
    # system steps, Telegram destination.
    check("QuickSetup: completion checks mark_complete, the restart and a refreshed final status",
          'apiApply({mark_complete: true}, function(result) {\n            if (!result || result.ok !== true)' in quick
          and "function finalProblems()" in quick and "Restart failed" in quick
          and quick.index("page.app.gotoShell()") > quick.index("var problems = fresh ? page.finalProblems()"))
    check("QuickSetup: Retry always re-probes; an edited value drops its verification",
          "function retry() {\n        if (running) return;\n        runVerify();\n    }" in quick
          and 'if (rowState(sid) === "verified") setRow(sid, "pending", "")' in quick)
    check("QuickSetup: service/keep-awake/toolchain are ok only on refreshed evidence, refresh failure never skips",
          "s.unit_installed !== true || s.active !== \"active\"" in quick
          and 'linger === false' not in quick and quick.count('s.linger !== true') == 2
          and 's.wakelock_active !== "active"' in quick
          and "these tools are still missing" in quick
          and "Could not re-read Briglia's status after saving" in quick)
    # Codex round 2: mandatory means fail closed — no row can be skipped,
    # the final check exempts nothing, the fallback stays put on a failed
    # refresh, a fresh bot gets the /start hint.
    check("QuickSetup: system rows are unconditional and no 'skipped' state exists",
          'addRow("service"' in quick and 'addRow("wakelock"' in quick and 'addRow("toolchain"' in quick
          and 'if (isUT) addRow' not in quick and '"skipped"' not in quick)
    check("QuickSetup: unsupported service/keep-awake/toolchain-status fail the row toward guided setup",
          quick.count("use step-by-step setup instead") >= 4 and "function toolchainKnown()" in quick
          and 'i18n.tr("toolchain status unavailable")' in quick)
    check("QuickSetup: final validation exempts nothing",
          "rowState(" not in quick.split("function finalProblems()")[1].split("function finishFailed")[0])
    check("QuickSetup: fallback stays on the page when the refresh fails",
          "refreshStatus(function(ok) {\n            page.running = false;\n            if (!ok) {" in quick)
    check("QuickSetup + bridge: fresh-bot hint on chat_not_found",
          'dest.code === "chat_not_found"' in quick and "send /start, then tap Retry" in quick
          and 'result["code"] = "chat_not_found"' in read("py/briglia_bridge.py"))
    check("QuickSetup: Telegram destination verified with getChat and shown",
          'pyCall("telegram_get_chat", [token, chat]' in quick and 'i18n.tr("bot %1 → %2")' in quick)
    # Owner request 2026-09-03 (round 4): a scanned OpenRouter key is probed
    # and saved as a NON-active alternative provider by its own apply; a
    # custom-endpoint key is never applied blind and survives the finish
    # for Settings → Provider.
    verify_ids = quick.split("readonly property var verifyIds:")[1].split("\n")[0]
    check("QuickSetup: OpenRouter key → probe with a model → second apply with activate:false",
          '"openrouter"' in verify_ids and 'addRow("openrouter"' in quick
          and 'apiProbe({kind: "openrouter", api_key: val("openrouter"), model: openrouterModel()}' in quick
          and 'apiApply({provider: {profile: "openrouter", activate: false, api_key: val("openrouter")' in quick
          and 'verifyIds[v] !== "openrouter" && rowState(verifyIds[v]) === "verified"' in quick
          and quick.count("runExtraProviders()") >= 3)
    check("QuickSetup: custom-endpoint key is never applied here and is kept for Settings",
          'addRow("custom"' in quick and 'profile: "custom"' not in quick
          and 'var keepCustom = page.has("custom");' in quick
          and quick.index("var keepCustom") < quick.index("page.values = ({});\n                    if (keepCustom)"))
    bridge_src = read("py/briglia_bridge.py")
    check("bridge: telegram_get_chat refuses non-private chats, never returns the token",
          'if kind != "private":' in bridge_src and "def telegram_get_chat(token, chat_id):" in bridge_src
          and '"label": label' in bridge_src and '"token"' not in bridge_src.split("def telegram_get_chat")[1].split("def _progress")[0])
    check("Settings: both entries offered",
          'text: i18n.tr("Quick setup (scan codes)")' in read("qml/pages/SettingsPage.qml")
          and 'onClicked: page.app.startWizard()' in read("qml/pages/SettingsPage.qml"))
    identity = read("qml/pages/IdentityPage.qml")
    check("IdentityPage: persona sentence names Bree as the customizable default",
          'stays \\"Bree\\" (you can change it)' in identity)
    check("chat gate: Briglia CLI 0.2.0 baseline",
          'versionAtLeast(detectInfo.version, "0.2.0")' in main_qml
          and "Briglia CLI 0.2.0 or newer" in dash)
    readme = read("README.md")
    check("README: requires Briglia CLI ≥ v0.2.0 and documents old-app coexistence",
          "≥ v0.2.0" in readme and "ada.permaevidence" in readme and "cannot self-update" in readme)

    # ---- 4. release watcher, heartbeat, launchd installer, cutover helper (plan §6, §3.3)
    sys.path.insert(0, os.path.join(ROOT, "scripts"))
    import release_watch  # noqa: E402
    import release_heartbeat  # noqa: E402
    chans = release_watch.DEFAULT_CONFIG["channels"]
    check("watcher: exactly the two Briglia channels", sorted(chans) == ["briglia-cli", "briglia-ut"], sorted(chans))
    check("watcher: every channel declares its kind and the pinned policy of that kind carries the same channel name",
          chans["briglia-cli"].get("kind") == "cli" and chans["briglia-ut"].get("kind") == "app"
          and release_verify.CLI_POLICY.channel == "briglia-cli" and release_verify.APP_POLICY.channel == "briglia-ut"
          and set(release_watch.CHANNEL_KINDS) == {"cli", "app"})
    check("watcher: repos, installer source, publication log and website URLs follow the new identity",
          chans["briglia-cli"]["repo"] == "permaevidence/briglia-cli" and chans["briglia-ut"]["repo"] == "permaevidence/briglia-ut"
          and chans["briglia-cli"]["installer_source"] == "scripts/get-briglia.sh"
          and chans["briglia-ut"]["publication_log"] == "~/.briglia-release-keys/briglia-ut-publications.jsonl"
          # since 9ff2316 every website check probes the alias AND briglia.dev
          and briglia_bridge.WEBSITE_BASE + "/install.sh" in chans["briglia-cli"]["website_install_url"]
          and "https://briglia.dev/install.sh" in chans["briglia-cli"]["website_install_url"]
          and briglia_bridge.WEBSITE_BASE + "/ubuntu-touch" in chans["briglia-ut"]["website_page_url"]
          and "https://briglia.dev/ubuntu-touch" in chans["briglia-ut"]["website_page_url"], chans)
    check("watcher + heartbeat: one state directory, the new one",
          release_watch.DEFAULT_CONFIG["state_dir"] == "~/.config/briglia-release-watch"
          and release_heartbeat.DEFAULTS["state_dir"] == release_watch.DEFAULT_CONFIG["state_dir"])
    check("watcher/heartbeat: user agents and Telegram message prefixes",
          release_watch.USER_AGENT.startswith("briglia-release-watch/")
          and release_heartbeat.USER_AGENT.startswith("briglia-release-heartbeat/")
          and "briglia release watch" in read("scripts/release_watch.py")
          and "briglia release heartbeat" in read("scripts/release_heartbeat.py"))
    installer = read("scripts/install_release_watch.sh")
    check("launchd installer: labels, state dir, log dir and test seam follow the new identity",
          'LABEL_BASE="com.permaevidence.briglia-release-watch"' in installer
          and 'ROOT="$HOME_DIR/.config/briglia-release-watch"' in installer
          and 'LOGS="$HOME_DIR/Library/Logs/briglia-release-watch"' in installer
          and "BRIGLIA_WATCH_HOME" in installer and "ADA_WATCH_HOME" not in installer)
    keys_script = read("scripts/release/rename-keys-dir.sh")
    check("cutover helper: pins the old→new key directory and refuses over a loaded previous watcher",
          'OLD="$HOME_DIR/.ada-release-keys"' in keys_script and 'NEW="$HOME_DIR/.briglia-release-keys"' in keys_script
          and 'OLD_LABEL_BASE="com.permaevidence.ada-release-watch"' in keys_script)
    watcher_forbidden = ["ada-release-watch", "ada release watch", "ada release heartbeat", "ADA_WATCH_HOME",
                         ".ada-release-keys", "get-ada.sh", "ada-app-psi", "permaevidence/ada-", '"ada-cli"', '"ada-ut"']
    offenders = []
    for rel in ("scripts/release_watch.py", "scripts/release_heartbeat.py", "scripts/install_release_watch.sh",
                "scripts/publish_click.sh", ".github/workflows/ci.yml"):
        for ln, line in enumerate(read(rel).splitlines(), 1):
            if re.search(r"LEGACY|legacy|retired|pre-rename", line):
                continue
            for token in watcher_forbidden:
                if token in line:
                    offenders.append("%s:%d %s" % (rel, ln, token))
    check("no retired identifier in the watcher trio, publisher or CI outside legacy-transition lines", not offenders, offenders)
    ci = read(".github/workflows/ci.yml")
    check("CI runs the watcher and keys-rename batteries", "scripts/watch_selftest.py" in ci and "scripts/keys_rename_selftest.py" in ci)

    # A root-id-qualified reference to a CHILD id (`page.steps` for a
    # `ListModel { id: steps }`) resolves to undefined at runtime — ids are
    # not properties of the root object — and QML only reports it when the
    # line executes. Field-tested 2026-09-04: `page.steps.get(...)` in the
    # apply callback threw inside pyCall's try/catch, no row was ever marked
    # saved and quick setup spun forever (app 0.8.2). Every child id must be
    # referenced bare; the root may be qualified only with its own
    # properties, functions and signals (or Page/Item members).
    id_offenders = []
    qml_files = [os.path.relpath(os.path.join(d, n), ROOT)
                 for d, _ds, ns in os.walk(os.path.join(ROOT, "qml")) for n in ns if n.endswith(".qml")]
    for rel in sorted(qml_files):
        text = read(rel)
        root_match = re.search(r"^\s*id:\s*(\w+)", text, re.M)
        if not root_match:
            continue
        root = root_match.group(1)
        ids = set(re.findall(r"\bid:\s*(\w+)", text)) - {root}
        declared = (set(re.findall(r"^\s*(?:readonly\s+)?(?:default\s+)?property\s+[\w<>.]+\s+(\w+)", text, re.M))
                    | set(re.findall(r"^\s*function\s+(\w+)\s*\(", text, re.M))
                    | set(re.findall(r"^\s*signal\s+(\w+)", text, re.M)))
        for ln, line in enumerate(text.splitlines(), 1):
            for name in re.findall(r"\b" + re.escape(root) + r"\.(\w+)", line):
                if name in ids and name not in declared:
                    id_offenders.append("%s:%d %s.%s" % (rel, ln, root, name))
    check("QML: no root-qualified reference to a child id (page.steps class of bug)", not id_offenders, id_offenders)
    check("QuickSetupPage: apply callback reads the row model bare",
          'page.setRow(row, "ok", steps.get(page.rowIndex(row)).detail);' in quick
          and "page.steps" not in quick)

    # Field-tested 2026-09-04 (Pixel with swipe unlock, app 0.8.3): the
    # passcode dialog treated an empty field like Cancel, so a phone WITHOUT
    # a passcode could never pass the service/keep-awake rows. sudo accepts
    # the empty password such a phone has; "" must therefore be a valid
    # answer and "already asked" a separate flag.
    check("QuickSetupPage: an empty passcode is a valid answer (only Cancel/null aborts)",
          'if (entered === null) { run(null); return; }' in quick
          and 'entered === ""' not in quick
          and "property bool passcodeKnown: false" in quick
          and "if (passcodeKnown) { run(passcode); return; }" in quick
          and quick.count("passcodeKnown = false") >= 3
          and "leave empty if the phone has none" in quick)

    print("\nidentity selftest: %d passed, %d failed" % (PASSED, FAILED))
    sys.exit(1 if FAILED else 0)


if __name__ == "__main__":
    main()
