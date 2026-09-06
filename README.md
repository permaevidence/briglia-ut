# Briglia for Ubuntu Touch

Chat client, installer & control panel for [Briglia CLI](https://github.com/permaevidence/briglia-cli)
on Ubuntu Touch 24.04 — install, set up, talk to and manage an always-on
Briglia without ever opening the Terminal.

The app drives the CLI's machine-readable setup surface (`briglia setup-api`,
JSON over stdin/stdout, **schema 2 exactly**) — it never re-implements
validation or persistence. Requires **Briglia CLI ≥ v0.2.0** on the device
(the first release under this name, setup-api schema 2, the `migrate` verb
and the companion-app chat socket); the installer refuses anything else by
design, and a phone whose CLI still answers schema 1 is told to update the
CLI rather than shown a half-working app.

## What it does

- **Install / update the CLI** from the signed GitHub Releases channel:
  envelope verified with the pinned CLI key (anti-rollback, expiry,
  per-version asset location), tarball hashed while streaming, the staged
  binary validated (`--version`, `bundle-check`, `setup-api status` at
  schema 2) BEFORE a transactional, journaled, crash-safe swap into
  `~/.local/bin`.
- **Quick setup** (default entry, `qml/pages/QuickSetupPage.qml`): type
  your name, scan the website's `/qr` key bundle once, done. Every scanned
  key is probed live, everything is saved in ONE `setup-api apply`, then
  the background service (+ start at boot), the keep-awake unit and the
  full media toolchain (pandoc and LibreOffice included) are installed —
  all mandatory on this path (a missing or unreadable capability fails
  the row and points to the guided setup, which may skip it), passcode
  asked once and never stored. An
  AgentMail key in the bundle selects AgentMail as the email/calendar
  provider without asking; an OpenRouter key is probed and saved as a
  NON-active alternative provider (its own `apply`, `activate: false`),
  so OpenCode stays the main one and OpenRouter appears as a choice in
  Settings → Provider. Rows stay one line each and only expand (with an
  input field) when something fails. A custom-endpoint key cannot be
  saved blind (server address and model unknown): it stays in memory for
  Settings → Provider, where the field pre-fills. Local servers use the
  guided setup; the scanned keys are kept for it.
- **Guided setup** (step by step): provider & model (catalog served by setup-api),
  OpenAI/Serper/Jina keys, your name, email/calendar provider, Telegram —
  every step probes live before saving; Settings edits any value later.
- **Keys via QR** (`docs/QR_KEYS_SPEC.md`): the website's `/qr` page turns
  API keys into QR codes entirely in the browser; the app scans them with
  the camera (pure-stdlib decoder, `py/qr_scan.py`).
- **Always-on**: systemd user service + linger + the Ubuntu Touch kernel
  keep-awake unit. Root steps run scripts the CLI itself serves, under
  in-app `sudo -S` with the passcode collected in a dialog and passed on
  stdin only, never stored; a served script without the read-only-restore
  trap is refused.
- **Dashboard**: health rows, start/stop/restart, journal tail, CLI update.
- **Chat** (`qml/pages/ChatPage.qml`): a live window onto the local daemon
  over its companion-app Unix socket (`~/.local/share/briglia/app-chat.sock`,
  JSON lines, same-user-only) — history, live events, text, attachments
  through a built-in picker (paths only), voice notes, Stop, `/commands`.
- **Self-update** of the click from this repository's signed releases
  (manual check; optional auto-update, off by default).

## Moving from Ada (the previous name)

Briglia CLI is the renamed Ada CLI; this app is the renamed Ada companion
(`ada.permaevidence`). A phone that still runs `ada` is handled explicitly:

1. The boot page detects the old installation (read-only:
   `briglia_bridge.legacy_status`) and offers **Install Briglia CLI
   (migrates Ada data)** — the normal signed install.
2. Once Briglia CLI is installed, the CLI's own status block
   (`setup-api status` → `migration.needed`) gates everything: the app
   routes to **MigratePage** instead of the wizard, and nothing runs until
   you tap **Migrate now**. The move is the CLI's journaled engine
   (`briglia setup-api migrate`, the verb twin of `briglia migrate`):
   configuration, memory, watchers, Telegram and the background service
   move over; the old install is restored if it cannot complete; the old
   `ada` command stays as an alias. Old AND new directories coexisting is a
   conflict the page explains and never resolves for you.
3. Ubuntu Touch only: the keep-awake unit is a root-owned system unit, so an
   unprivileged migration records it and the app's passcode step swaps it —
   Briglia's unit installed first, the old one removed after (the phone
   never gets a chance to suspend in between). Declining is safe; the
   Dashboard offers the swap again.
4. Your assistant answers to **Bree** afterwards unless you had given it a
   custom name (it stays customizable in Settings).

The old app `ada.permaevidence` cannot self-update across package ids: it
stays installed until you remove it by hand (Settings → Apps), and its
`~/.cache/ada.permaevidence` (composer drafts only) can be deleted or
ignored. The new app never touches either.

## Stack

- QML with Lomiri Components 1.3: `qml/Main.qml` is the shell (state,
  Python bridge, wizard sequencing, launch routing, boot/Install pages);
  each screen lives in `qml/pages/` and receives `{app: root}`. The home
  screen is a single shell page with Chat / Dashboard / Settings header
  sections over three always-alive views; launch routes into the guided
  setup until it completes (or into the migration consent page while an
  old install is pending), then into Chat.
- Python backend via PyOtherSide (`py/briglia_bridge.py`): process
  spawning, downloads, setup-api round trips, legacy detection.
- Unconfined AppArmor template (required: the app writes `~/.local/bin`,
  runs `systemctl --user`, and spawns `briglia`; confinement is inherited by
  children, so there is no confined alternative).

## Build

No Clickable or Docker needed — the app is architecture-independent:

    python3 scripts/build_click.py

writes `build/briglia.permaevidence_<version>_all.click`, byte-identical
across runs (SOURCE_DATE_EPOCH honored). `clickable.yaml` is included for
people who prefer the Clickable workflow; both produce the same app.

Tests (all offline, no device):

    python3 scripts/bridge_selftest.py    # install pipeline, migrate verb, keep-awake swap
    python3 scripts/identity_selftest.py  # product-identity invariants (see below)
    python3 scripts/chat_selftest.py      # chat client + voice + QML structural sweep
    python3 scripts/qr_selftest.py        # QR decoder + generator cross-check
    python3 scripts/release_selftest.py   # signed-release verifier
    python3 scripts/publish_selftest.py   # publisher against a fake GitHub API
    python3 scripts/click_selftest.py     # packaging (LICENSE/manifest in the click)

`identity_selftest.py` is the rename's repository invariant: one package
id in one place, the previous identity confined to the bridge's `LEGACY_`
detection block and the migration copy, the signed-envelope format name
and QR prefix unchanged, key hexes unchanged with re-derived key IDs, and
the migration UX actually wired (gate consulted before the wizard, consent
page reaching the engine, Dashboard offering the pending swap).

## Install on the phone

Any one of:

1. Copy the .click over and install from the terminal:

       scp build/briglia.permaevidence_*.click phablet@<phone>:
       ssh phablet@<phone> pkcon install-local --allow-untrusted briglia.permaevidence_*.click

2. Download the .click on the phone (Morph browser) and open it — the
   OpenStore app performs local installation after an "untrusted package"
   confirmation.

3. `clickable install` from a Clickable checkout.

4. The website's Ubuntu Touch page links the latest signed GitHub Release
   (the page verifies the release envelope with the pinned app key before
   it shows a download link).

## Signed releases

Everything this app downloads is authenticated before a byte of it is
trusted (`py/release_verify.py`):

- **Briglia CLI installs/updates** read the CLI's signed release envelope
  from `github.com/permaevidence/briglia-cli/releases/latest/download/manifest.sig.json`
  and verify it with the pinned CLI release key.
- **App self-updates** read this repository's own signed envelope and
  verify it with the pinned app key (`.release-keys/briglia-ut-release.pub.pem`).

Both channels enforce: exact Ed25519 signature over a domain-separated
input (format name `ada-release-envelope-v1` — historical, deliberately
unchanged by the rename: the byte layout did not change, so neither did
the name), schema/channel/SemVer/expiry/not-before checks, assets
restricted to the pinned per-version GitHub location, authenticated size +
SHA-256 while streaming, a hard byte bound, and anti-rollback: the sequence
must be ≥ the minimum baked into this build and ≥ the highest sequence this
phone ever accepted for the same channel and location
(`~/.config/briglia-ut/release_trust.json`, locked, monotonic). Sequences
CONTINUE across the rename: the first Briglia CLI release is sequence 60
(v0.2.0), the first Briglia click sequence 2 — so pre-rename envelopes are
refused by number as well as by channel name. The signing keys did not
change; their key IDs were re-derived under the new channel names.

Ed25519 on the phone: a system OpenSSL proven against the RFC 8032
known-answer vectors is used when present; otherwise a dependency-free
verify-only implementation (also proven against the vectors). Settings
shows which one this phone uses. There are deliberately no environment
overrides for keys, URLs or the verifier.

Publishing (maintainers): `scripts/publish_click.sh` builds the click
deterministically (filename derived from `manifest.json`), checks
supersession against the authenticated live release, signs with the local
app key (`~/.briglia-release-keys/`, mode 0600, never on argv), verifies
the envelope with the committed public key AND with the app's own
verifier, publishes an immutable GitHub Release (assets, envelope last,
atomic go-live), re-downloads and byte-compares the public state, and only
then records the publication. It holds an exclusive cross-process lock,
repeats the supersession check right before the release is created, and
binds the tag to the exact reviewed HEAD commit (which must already be on
`origin/main`). Every release bumps `APP_RELEASE_SEQUENCE` in
`py/release_verify.py` together with `manifest.json`'s version. There is no
bootstrap mode: the signed app channel was bootstrapped once (v0.7.4,
2026-08-31) and an absent live envelope is a refusal, never a fresh start.

Rename transition: after the repository rename, GitHub's "latest" is still
the previous identity's envelope (channel `ada-ut`, sequence 1, v0.7.4, the
same key under its old key ID). The publisher carries a compiled legacy
descriptor that accepts exactly that state — authenticated with the
committed key under the old channel domain, field for field — and only for
the transition release (sequence 2). Every other legacy shape (foreign key,
other sequence or version, click outside the old repository path, extra
platforms, other channel) is a refusal, and once a `briglia-ut` release is
live the path is inert; the block is deleted right after v0.8.0 publishes.

`scripts/release_watch.py` / `scripts/release_heartbeat.py` /
`scripts/install_release_watch.sh` are the deterministic release-channel
watcher, its independent heartbeat and their launchd installer (labels
`com.permaevidence.briglia-release-watch.{check,heartbeat}`, state under
`~/.config/briglia-release-watch`, logs under
`~/Library/Logs/briglia-release-watch`); `scripts/watch_selftest.py` is their
battery. Every watched channel carries an explicit `kind` (`cli` | `app`)
that selects its policy and corroboration; a channel name that disagrees
with the pinned verifier is a loud `config-invalid` alert, never a skipped
check. `scripts/release/rename-keys-dir.sh` is the one-shot cutover helper
that moves the publishing Mac's key directory to the new identity (same key
material, re-derived IDs, notes beside the encrypted backups);
`scripts/keys_rename_selftest.py` proves it against a throwaway home.

## Device assumptions

- Ubuntu Touch 24.04 (framework `ubuntu-touch-24.04-1.x`, AppArmor policy
  2404.1). Verify on a device with `ls /usr/share/click/frameworks/`.
- aarch64 or x86_64 (the bridge maps `platform.machine()` to the
  briglia-cli release's `linux-arm64` / `linux-x64` builds).
- Google Workspace still needs one `gws auth login` in the Terminal
  (browser OAuth round-trip) after saving credentials in the app; the None
  and AgentMail email paths are fully terminal-free.

## License

This app is **source-available** (not open source) under the Business
Source License 1.1 — see `LICENSE`. Production use is free for individual
people, including commercial use; companies and other entities need a
commercial license (contact address in `LICENSE`). Non-production use is
free for everyone, and each released version converts to Apache-2.0 four
years after release. The app bundles no third-party code (QML + pure-stdlib
Python, including the in-house QR decoder); PyOtherSide and the Lomiri
components are system packages on the device. The app icon is original
artwork owned by the project.

External contributions are not being accepted yet while the contribution
policy (CLA) is finalized — bug reports and security reports are very
welcome.

## ChatGPT subscription (private preview)

With a compatible CLI, Provider & model offers **ChatGPT subscription** separately
from **OpenAI API**. Open the subscription page to sign in using a device code,
verify the model, select the provider, or sign out locally. Stop the background
service before selecting a new active provider; restart it after saving. Existing
model/effort choices are retained on re-login.

Quick Setup offers the same subscription page before scanning the remaining
keys. Selecting ChatGPT removes the need for an OpenCode key. OpenAI API keys
for web research, voice and images remain separate, and those tools can incur API
charges. Subscription quota currently displays as unknown. Older CLI versions
without the advertised capability keep the existing onboarding flow.

This UI needs the matching private CLI candidate. Real Pixel sign-in and service
handoff testing remain required before release.
