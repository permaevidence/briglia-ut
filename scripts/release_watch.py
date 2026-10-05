#!/usr/bin/env python3
"""Deterministic release-channel watcher (briglia-cli RELEASE_SIGNING_PLAN.md §10).

Re-verifies the two signed channels — Briglia CLI and this app — the way a
client would, then cross-checks what GitHub says about them, and alerts a
human over Telegram on ANY mismatch or inability to verify. Success is
silent. No LLM is involved: every judgement here is a byte, hash, number
or string comparison against pinned keys and a locally recorded history.

    release_watch.py check      [--config PATH]   # hourly
    release_watch.py status     [--config PATH]   # print the recorded state
    release_watch.py acknowledge-local CHANNEL TAG ENVELOPE_SHA256 [--config PATH]
        # owner-only: accept ONE break-glass local release as local provenance

The watcher watching itself is a SEPARATE program, scripts/release_heartbeat.py
(stdlib only, its own state and lock): it reads nothing from this module and
nothing from state.json — only the completion beacon `check.beacon.json`
that `check` writes atomically at the end of every completed run.

Per channel, `check`:
  1. fetches `releases/latest/download/manifest.sig.json` (bounded) and
     authenticates it with the PINNED key set (py/release_verify.py — the
     same code the phone runs: signature, schema, channel, expiry, asset
     URLs locked to the per-version release location);
  2. compares it with the newest RECORDED authorized release: identical →
     fine; strictly higher sequence → a candidate new release that must be
     corroborated before it is recorded — and its recording is announced,
     never silent; lower sequence → ROLLBACK alert; same sequence but any
     difference → alert. Corroboration (UT signing-in-CI plan §3.3, both
     channels, per-channel parameters): exactly one push run of the workflow
     at `workflow_path` (matched by path + workflow id, never by display
     name) for this tag at the recorded commit, completed/success, every
     configured required job successful (a skipped required job fails);
     above the channel's `approval_required_above_sequence` cutoff, the
     signing job executed exactly once (run attempt 1) and the run's review
     history holds exactly one approval for the signing environment's id,
     by the configured reviewer's stable user id, and no rejection — any
     error, missing field or ambiguity is "approval unverified", never
     success. At or below the cutoff the release predates the approval
     gate (CLI) or the CI pipeline (app: corroborated by the local
     publication log, as before). Above the cutoff the app's local
     publication log is never accepted: a break-glass local release is an
     alert labelled "local provenance, not phone-approved CI" until the
     owner runs `acknowledge-local`, and is then recorded as local
     provenance, never as CI-approved;
  3. asks the GitHub API: the latest release must be non-draft, immutable,
     carry the manifest's tag, and refs/tags/<tag> must still resolve to the
     recorded commit; no non-draft release may carry a higher version than
     `latest` (a confused/frozen latest pointer); EVERY non-draft release
     must be immutable and tagged v<major>.<minor>.<patch> (a release on any
     other tag was not made by the pipeline, yet could be marked latest);
  4. every asset in the manifest must be reachable at its immutable URL
     with the authenticated size (Range probe, hourly); once a day, or
     whenever the recorded release changes, every asset is downloaded in
     full with the size bound and its SHA-256 compared;
  5. CLI only: the released install.sh must be byte-identical to
     scripts/get-briglia.sh at the exact release tag;
  6. optional website checks, on EVERY configured hostname (the Vercel alias
     and the real domain briglia.dev, so a domain/DNS-only hijack is seen):
     the CLI install command must resolve (via redirect) to the released
     installer bytes; the app page must link the exact click URL from the
     app manifest;
  7. optional transition check: a legacy Blob manifest still in service must
     agree with the authoritative release;
  8. metadata expiry within the warning window is an alert.

Alert policy: a finding is sent when it first appears and re-sent every
`realert_hours` while it persists; when it clears, one recovery message is
sent. Network-class findings (the endpoint could not be reached — timeout,
DNS, connection error, HTTP 5xx/429 — as opposed to answering with
something wrong) are retried within the run and only announced after
`transient_grace_checks` consecutive failing checks; one that clears
before then is never announced, so it gets no recovery message either. Undelivered Telegram messages are queued in the state file and
retried on the next run.

Config (JSON; the installer writes the production one): see DEFAULT_CONFIG.
State: <state_dir>/state.json under an exclusive lock — the recorded
authorized releases (the per-channel rollback floor), alert bookkeeping,
queued messages. It is security state, so it is written durably (tmp +
fsync + rename + directory fsync) and every save first preserves the
previous good copy as state.json.prev. On load, a missing/corrupt/
malformed state.json is recovered from that copy (the damaged file is kept
aside and the recovery is announced); if BOTH are unusable the check
refuses to run with an empty memory — it sends one direct alert and exits
1 instead, so the rollback floor is never silently discarded. Stdlib only.
"""

import argparse
import http.client
import datetime
import fcntl
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
# Checkout layout: scripts/ next to py/. Installed snapshot layout: py/ inside
# the watcher's own directory (scripts/install_release_watch.sh).
for _cand in (os.path.join(HERE, "py"), os.path.join(os.path.dirname(HERE), "py")):
    if os.path.isfile(os.path.join(_cand, "release_verify.py")):
        sys.path.insert(0, _cand)
        break
import release_verify as rv  # noqa: E402

WATCH_VERSION = "1"
USER_AGENT = "briglia-release-watch/" + WATCH_VERSION
MAX_SMALL_FETCH = 512 * 1024          # envelopes, installers, API JSON, pages
MAX_PAGE_FETCH = 4 * 1024 * 1024
FULL_HASH_INTERVAL = 24 * 3600
RELEASE_PAGE_SIZE = 100               # one page of /releases; a full page is reported as incomplete

# Every channel entry carries an explicit `kind` (cli | app). The kind — not
# the channel NAME — selects the verification policy and the corroboration
# path, and the pinned policy's channel must equal the config key; a stale
# channel name therefore produces a loud config-invalid alert instead of a
# silently skipped branch (rename plan §6).
DEFAULT_CONFIG = {
    "state_dir": "~/.config/briglia-release-watch",
    "github_api": "https://api.github.com",
    "raw_base": "https://raw.githubusercontent.com",
    "telegram_env_file": "~/.claude/channels/telegram/.env",   # TELEGRAM_BOT_TOKEN, OWNER_CHAT_ID
    "telegram_api": "https://api.telegram.org",
    "realert_hours": 6,
    # Network-class findings (GitHub/CDN timeouts, 5xx, DNS blips) are only
    # announced once they have persisted for this many consecutive checks;
    # integrity findings are always announced on the first check.
    "transient_grace_checks": 3,
    "heartbeat_max_age_hours": 3,
    "expiry_warning_days": 30,
    "channels": {
        "briglia-cli": {
            "kind": "cli",
            "repo": "permaevidence/briglia-cli",
            "workflow_path": ".github/workflows/release-signed.yml",
            # exact job names in briglia-cli's release-signed.yml; all must
            # succeed (no weakening of the three public checks)
            "required_jobs": ["Authorize (credential-free)", "Build macOS arm64", "Build Linux x64",
                              "Build Linux arm64 (native)", "Assemble manifest", "Sign metadata",
                              "Verify candidate (macos)", "Verify candidate (linux)",
                              "Verify candidate (linux-arm64)", "Publish immutable release",
                              "Verify public channel (macos)", "Verify public channel (linux)",
                              "Verify public channel (linux-arm64)"],
            "signing_job": "Sign metadata",
            "signing_environment": "release-sign",
            "approver_user_id": 338251426,          # matteoiannius-beep — stable id, never the login
            # v0.2.49 (sequence 109) was published before the approval gate
            # and stays recorded without an invented approval.
            "approval_required_above_sequence": 109,
            "installer_asset": "install.sh",
            "installer_source": "scripts/get-briglia.sh",
            # Every URL is probed: the Vercel project alias AND the real
            # domain, so a DNS/domain-only hijack of briglia.dev alerts too.
            # A single string is still accepted (older configs).
            "website_install_url": ["https://briglia.vercel.app/install.sh",
                                    "https://briglia.dev/install.sh"],
            "legacy_blob_manifest": None,
        },
        "briglia-ut": {
            "kind": "app",
            "repo": "permaevidence/briglia-ut",
            "workflow_path": ".github/workflows/release-signed.yml",
            "required_jobs": ["Authorize (credential-free)", "Build click (Linux)",
                              "Build click (macOS, reproducibility)", "Assemble manifest", "Sign metadata",
                              "Verify candidate", "Publish immutable release", "Verify public channel"],
            "signing_job": "Sign metadata",
            "signing_environment": "release-sign",
            "approver_user_id": 338251426,
            # v0.8.5 (sequence 7) and earlier were signed locally and keep
            # their local provenance; above it the publication log is never
            # accepted.
            "approval_required_above_sequence": 7,
            "publication_log": "~/.briglia-release-keys/briglia-ut-publications.jsonl",
            "website_page_url": ["https://briglia.vercel.app/ubuntu-touch",
                                 "https://briglia.dev/ubuntu-touch"],
            "legacy_blob_manifest": None,
        },
    },
}

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
# The only tag shape the release pipeline ever publishes. Anything else on a
# non-draft release is a release created outside the pipeline (the v* tag
# ruleset does not cover it, yet it can be marked latest).
_RELEASE_TAG_RE = re.compile(r"^v\d+\.\d+\.\d+$")


def url_list(value):
    """A config URL field: None/"" → [], a string → [it], a list → itself."""
    if not value:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(u, str) and u for u in value):
        return list(dict.fromkeys(value))
    raise WatchError("URL config value must be a string or a list of strings, got %r" % (value,))


# ------------------------------------------------------------------ utils

def now_ts():
    return time.time()


def iso(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def fetch(url, max_bytes=MAX_SMALL_FETCH, headers=None, timeout=60, method="GET"):
    """Bounded fetch → (status, headers, bytes). Network errors raise."""
    h = {"User-Agent": USER_AGENT}
    h.update(headers or {})
    req = urllib.request.Request(url, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise WatchError("response from %s exceeds %d bytes" % (url, max_bytes))
            return resp.status, dict(resp.headers), data
    except urllib.error.HTTPError as exc:
        body = exc.read(max_bytes + 1) if exc.fp else b""
        return exc.code, dict(exc.headers or {}), body[:max_bytes]


class WatchError(Exception):
    def __init__(self, message, transient=False):
        super().__init__(message)
        self.transient = transient


RETRY_ATTEMPTS = 3
RETRY_DELAY = 15   # seconds between attempts within one run


def is_network_error(exc):
    """True when `exc` means "could not get an answer" (worth retrying, and
    only worth a human's attention if it persists) rather than "got a wrong
    answer". HTTPError is a URLError subclass, so it is checked first."""
    if isinstance(exc, WatchError):
        return exc.transient
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code >= 500 or exc.code == 429
    return isinstance(exc, (urllib.error.URLError, OSError, http.client.HTTPException))


def with_retries(fn, attempts=None, delay=None):
    attempts = RETRY_ATTEMPTS if attempts is None else attempts
    delay = RETRY_DELAY if delay is None else delay
    for i in range(attempts):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001
            if i == attempts - 1 or not is_network_error(exc):
                raise
            time.sleep(delay)


def gh_json(cfg, path, params=None, max_bytes=MAX_SMALL_FETCH):
    url = cfg["github_api"] + path + ("?" + urllib.parse.urlencode(params) if params else "")
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = "Bearer " + token
    def once():
        try:
            st, _, b = fetch(url, max_bytes=max_bytes, headers=headers)
        except WatchError:
            raise
        except Exception as exc:  # noqa: BLE001
            if is_network_error(exc):
                raise WatchError("GitHub API %s → %s" % (path, exc), transient=True)
            raise
        if st >= 500 or st == 429:
            raise WatchError("GitHub API %s → HTTP %s" % (path, st), transient=True)
        return st, b
    status, body = with_retries(once)
    if status != 200:
        raise WatchError("GitHub API %s → HTTP %s" % (path, status))
    try:
        return json.loads(body.decode("utf-8"))
    except ValueError:
        raise WatchError("GitHub API %s → invalid JSON" % path)


def semver_tuple(version):
    m = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", version or "")
    return tuple(int(x) for x in m.groups()) if m else None


# ------------------------------------------------------------------ state

class StateUnreadable(WatchError):
    """Neither state.json nor state.json.prev is usable."""


def _fsync_dir(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def validate_state(data):
    """Raise ValueError unless `data` has the shape the watcher relies on.
    Valid JSON of the wrong shape is as dangerous as garbage: a string
    sequence would silently disable the rollback comparison."""
    if not isinstance(data, dict):
        raise ValueError("top level is not an object")
    for key, typ in (("recorded", dict), ("full_hash_at", dict), ("active", dict),
                     ("queued", list), ("announced", dict)):
        if key in data and not isinstance(data[key], typ):
            raise ValueError("%s is not a %s" % (key, typ.__name__))
    for channel, rec in data.get("recorded", {}).items():
        if not isinstance(rec, dict):
            raise ValueError("recorded[%s] is not an object" % channel)
        if not isinstance(rec.get("sequence"), int) or isinstance(rec.get("sequence"), bool) or rec["sequence"] < 0:
            raise ValueError("recorded[%s].sequence is not a non-negative integer" % channel)
        for k in ("tag", "version", "envelope_sha256"):
            if not isinstance(rec.get(k), str) or not rec[k]:
                raise ValueError("recorded[%s].%s missing" % (channel, k))
        if not isinstance(rec.get("commit"), str) or not _SHA_RE.match(rec["commit"]):
            raise ValueError("recorded[%s].commit is not a commit sha" % channel)
        if not isinstance(rec.get("assets"), dict):
            raise ValueError("recorded[%s].assets is not an object" % channel)
    for ts in data.get("full_hash_at", {}).values():
        if not isinstance(ts, (int, float)):
            raise ValueError("full_hash_at holds a non-numeric timestamp")
    if any(not isinstance(m, str) for m in data.get("queued", [])):
        raise ValueError("queued holds a non-string entry")
    for key, a in data.get("active", {}).items():
        if not isinstance(a, dict) or not isinstance(a.get("first"), (int, float)) or not isinstance(a.get("last_sent"), (int, float)):
            raise ValueError("active[%s] malformed" % key)
    acks = data.get("local_acks", {})
    if not isinstance(acks, dict) or any(not isinstance(v, dict) or any(not isinstance(t, str) or not isinstance(h, str)
                                                                         for t, h in v.items()) for v in acks.values()):
        raise ValueError("local_acks malformed")


class State:
    """state.json under an exclusive lock, with durable writes and a
    last-known-good copy. `recovered` is set when the load fell back to
    state.json.prev so the run can announce it."""

    def __init__(self, state_dir):
        self.dir = os.path.expanduser(state_dir)
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        self.path = os.path.join(self.dir, "state.json")
        self.prev_path = self.path + ".prev"
        self.lock_path = os.path.join(self.dir, "state.lock")
        self.lock_fd = None
        self.data = None
        self.recovered = None

    @staticmethod
    def _load(path):
        with open(path) as f:
            data = json.load(f)
        validate_state(data)
        return data

    def __enter__(self):
        self.lock_fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(self.lock_fd)
            self.lock_fd = None
            raise WatchError("another release_watch run holds %s" % self.lock_path)
        try:
            if os.path.exists(self.path):
                try:
                    self.data = self._load(self.path)
                except Exception as exc:  # noqa: BLE001 — recover, do not crash silently
                    primary = "%s: %s" % (type(exc).__name__, exc)
                    if not os.path.exists(self.prev_path):
                        raise StateUnreadable("state.json is unusable (%s) and no state.json.prev exists" % primary)
                    try:
                        self.data = self._load(self.prev_path)
                    except Exception as exc2:  # noqa: BLE001
                        raise StateUnreadable("state.json is unusable (%s) and so is state.json.prev (%s: %s)"
                                              % (primary, type(exc2).__name__, exc2))
                    aside = "%s.corrupt-%d" % (self.path, int(now_ts()))
                    os.replace(self.path, aside)
                    _fsync_dir(self.dir)
                    self.recovered = ("state.json was unusable (%s); recovered from the last-known-good copy state.json.prev; "
                                      "the damaged file is kept as %s" % (primary, os.path.basename(aside)))
            elif os.path.exists(self.prev_path):
                # a crash between the two renames in save() leaves only .prev
                try:
                    self.data = self._load(self.prev_path)
                except Exception as exc:  # noqa: BLE001
                    raise StateUnreadable("state.json is missing and state.json.prev is unusable (%s: %s)" % (type(exc).__name__, exc))
                self.recovered = "state.json was missing; recovered from the last-known-good copy state.json.prev"
            else:
                self.data = {}
        except BaseException:
            fcntl.flock(self.lock_fd, fcntl.LOCK_UN)
            os.close(self.lock_fd)
            self.lock_fd = None
            raise
        self.data.setdefault("version", WATCH_VERSION)
        self.data.setdefault("recorded", {})
        self.data.setdefault("full_hash_at", {})
        self.data.setdefault("active", {})       # finding key → {"first": ts, "last_sent": ts, "text": ...}
        self.data.setdefault("queued", [])       # undelivered messages
        self.data.setdefault("announced", {})    # channel → last announced sequence
        return self

    def save(self):
        """Durable: the new file is fsynced before it is renamed into place,
        the previous good file survives as state.json.prev, and the
        directory is fsynced so the renames themselves reach the disk."""
        validate_state(self.data)
        tmp = self.path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(self.data, f, indent=2, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        if os.path.exists(self.path):
            # hard-link, then rename over .prev: state.json stays present throughout
            prev_tmp = self.prev_path + ".tmp"
            if os.path.exists(prev_tmp):
                os.unlink(prev_tmp)
            os.link(self.path, prev_tmp)
            os.replace(prev_tmp, self.prev_path)
            _fsync_dir(self.dir)
        os.replace(tmp, self.path)
        _fsync_dir(self.dir)

    def write_beacon(self, now, findings, queued, oldest_queued):
        """The completion beacon read by release_heartbeat.py — written only
        after the state itself has been saved. Atomic, fsynced."""
        path = os.path.join(self.dir, "check.beacon.json")
        tmp = path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"version": WATCH_VERSION, "completed": now, "findings": findings,
                       "queued": queued, "oldest_queued": oldest_queued}, f, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        _fsync_dir(self.dir)

    def __exit__(self, *exc):
        if self.lock_fd is not None:
            fcntl.flock(self.lock_fd, fcntl.LOCK_UN)
            os.close(self.lock_fd)


# --------------------------------------------------------------- telegram

def telegram_credentials(cfg):
    path = os.path.expanduser(cfg["telegram_env_file"])
    token = chat = None
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line.startswith("TELEGRAM_BOT_TOKEN="):
                token = line.split("=", 1)[1].strip().strip('"').strip("'")
            elif line.startswith("OWNER_CHAT_ID="):
                chat = line.split("=", 1)[1].strip().strip('"').strip("'")
    if not token or not chat:
        raise WatchError("telegram env file %s lacks TELEGRAM_BOT_TOKEN / OWNER_CHAT_ID" % path)
    return token, chat


def send_telegram(cfg, text):
    """True when Telegram confirmed delivery. Never raises."""
    try:
        token, chat = telegram_credentials(cfg)
        body = json.dumps({"chat_id": chat, "text": text[:4000],
                           "disable_web_page_preview": True}).encode()
        status, _, resp = _post(cfg["telegram_api"] + "/bot" + token + "/sendMessage", body)
        return status == 200 and json.loads(resp.decode("utf-8", "replace")).get("ok") is True
    except Exception as exc:  # noqa: BLE001 — delivery problems are reported, not fatal
        print("  ! telegram delivery failed: %s" % _scrub(str(exc), cfg), file=sys.stderr)
        return False


def _post(url, body):
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"User-Agent": USER_AGENT, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, dict(resp.headers), resp.read(MAX_SMALL_FETCH)
    except urllib.error.HTTPError as exc:
        return exc.code, {}, exc.read(MAX_SMALL_FETCH) if exc.fp else b""


def _scrub(text, cfg):
    """Never let a bot token reach logs/state through an error string."""
    try:
        token, _ = telegram_credentials(cfg)
        return text.replace(token, "[TOKEN]")
    except Exception:  # noqa: BLE001
        return text


# ------------------------------------------------------------ findings

class Run:
    """Collects findings for one `check` run and turns them into messages."""

    def __init__(self, cfg, state):
        self.cfg = cfg
        self.state = state
        self.findings = {}   # key → text (ALERT level)
        self.transient = set()  # keys whose finding is network-class only
        self.infos = []      # one-off informational messages

    def alert(self, key, text, transient=False):
        print("  ✖ %s: %s%s" % (key, text, " (network)" if transient else ""))
        self.findings[key] = text
        if transient:
            self.transient.add(key)
        else:
            self.transient.discard(key)

    def info(self, text):
        print("  ℹ %s" % text)
        self.infos.append(text)

    def ok(self, text):
        print("  ✔ %s" % text)

    def flush(self, now):
        """Decide what to send, send it, update bookkeeping. Returns the
        list of messages actually composed (sent or queued)."""
        cfg, st = self.cfg, self.state.data
        realert = float(cfg["realert_hours"]) * 3600
        grace = max(1, int(cfg.get("transient_grace_checks", 3)))
        messages = []
        active = st["active"]
        for key, text in self.findings.items():
            prev = active.get(key)
            if key in self.transient:
                if prev is None:
                    prev = active[key] = {"first": now, "last_sent": now, "text": text,
                                          "count": 0, "notified": False}
                prev["count"] = int(prev.get("count", 0)) + 1
                if not prev.get("notified", True):
                    prev["text"] = text
                    if prev["count"] >= grace:
                        prev["notified"] = True
                        prev["last_sent"] = now
                        messages.append("🚨 briglia release watch — %s (failing for %d consecutive checks since %s)\n%s"
                                        % (key, prev["count"], iso(prev["first"]), text))
                elif now - prev["last_sent"] >= realert:
                    # the exact network error varies run to run; only time re-alerts
                    prev["last_sent"] = now
                    prev["text"] = text
                    messages.append("🚨 briglia release watch — STILL FAILING since %s — %s\n%s"
                                    % (iso(prev["first"]), key, text))
                continue
            if prev is not None and not prev.get("notified", True):
                prev = None   # a quiet network-class entry became a real finding: announce now
            if prev is None:
                active[key] = {"first": now, "last_sent": now, "text": text}
                messages.append("🚨 briglia release watch — %s\n%s" % (key, text))
            elif now - prev["last_sent"] >= realert or prev.get("text") != text:
                prev["last_sent"] = now
                prev["text"] = text
                messages.append("🚨 briglia release watch — STILL FAILING since %s — %s\n%s"
                                % (iso(prev["first"]), key, text))
        for key in list(active):
            if key not in self.findings:
                gone = active.pop(key)
                if not gone.get("notified", True):
                    continue   # never announced, so no recovery message
                first = gone["first"]
                messages.append("✅ briglia release watch — recovered: %s (failing since %s)" % (key, iso(first)))
        for text in self.infos:
            messages.append("ℹ️ briglia release watch — %s" % text)
        # deliver queued first (oldest), then new; keep whatever fails
        pending = list(st["queued"]) + messages
        st["queued"] = []
        for m in pending:
            if not send_telegram(cfg, m):
                st["queued"].append(m)
        if st["queued"]:
            st.setdefault("queued_since", now)   # reported through the beacon to the heartbeat
        else:
            st.pop("queued_since", None)
        return messages


# ---------------------------------------------------------- channel check

CHANNEL_KINDS = {"cli": lambda: rv.CLI_POLICY, "app": lambda: rv.APP_POLICY}


def channel_kind(cfg, channel):
    """The configured kind of a channel; WatchError when it is missing or unknown."""
    kind = cfg["channels"][channel].get("kind")
    if kind not in CHANNEL_KINDS:
        raise WatchError("channel %r: config declares no valid kind (cli|app) — refusing to guess which "
                         "policy and corroboration apply" % channel)
    return kind


def policy_for(cfg, channel):
    chan = cfg["channels"][channel]
    kind = channel_kind(cfg, channel)
    base = CHANNEL_KINDS[kind]()
    if base.channel != channel:
        raise WatchError("channel %r is configured as kind %r, but the pinned %s policy in py/release_verify.py "
                         "is for channel %r — the watcher config and the verifier disagree; fix the config "
                         "(DEFAULT_CONFIG / config.json) before trusting any result" % (channel, kind, kind, base.channel))
    # Test/staging overrides only through the config file — never the environment.
    if chan.get("envelope_url") or chan.get("artifact_url_prefix"):
        return rv.ReleasePolicy(base.channel, {k: v.hex() for k, v in base.keys.items()},
                                chan.get("envelope_url", base.envelope_url),
                                chan.get("artifact_url_prefix", base.artifact_url_prefix),
                                base.min_sequence)
    return base


def manifest_record(manifest, envelope_raw, tag_commit):
    return {
        "tag": "v" + manifest["version"],
        "version": manifest["version"],
        "sequence": manifest["sequence"],
        "expires": iso(manifest["expires"]),      # the verifier hands back epoch floats
        "published": iso(manifest["published"]),
        "envelope_sha256": hashlib.sha256(envelope_raw).hexdigest(),
        "assets": {k: {"url": v["url"], "sha256": v["sha256"], "size": v["size"]}
                   for k, v in manifest["platforms"].items()},
        "commit": tag_commit,
    }


def resolve_tag(cfg, repo, tag):
    """Commit a tag names, following annotated tags; None if the tag is absent."""
    try:
        ref = gh_json(cfg, "/repos/%s/git/ref/tags/%s" % (repo, tag))
    except WatchError as exc:
        if "HTTP 404" in str(exc):
            return None
        raise
    if ref.get("ref") != "refs/tags/" + tag:
        raise WatchError("ref lookup answered %r for %s" % (ref.get("ref"), tag))
    obj = ref.get("object") or {}
    for _ in range(6):
        sha, typ = str(obj.get("sha", "")), obj.get("type")
        if not _SHA_RE.match(sha):
            raise WatchError("malformed ref object for %s" % tag)
        if typ == "commit":
            return sha
        if typ != "tag":
            raise WatchError("unexpected ref object type %r for %s" % (typ, tag))
        obj = (gh_json(cfg, "/repos/%s/git/tags/%s" % (repo, sha)).get("object")) or {}
    raise WatchError("annotated tag chain too deep for %s" % tag)


def probe_asset_checked(url, size):
    """probe_asset, but a 5xx/429 answer raises (retryable) instead of
    being reported as a size problem."""
    err = probe_asset(url, size)
    m = re.match(r"^HTTP (\d+)$", err or "")
    if m and (int(m.group(1)) >= 500 or int(m.group(1)) == 429):
        raise WatchError("%s → %s" % (url, err), transient=True)
    return err


def probe_asset(url, size):
    """Range probe: the immutable URL must answer with exactly `size` total bytes."""
    status, headers, body = fetch(url, max_bytes=2, headers={"Range": "bytes=0-0"})
    if status == 206:
        cr = headers.get("Content-Range") or headers.get("content-range") or ""
        m = re.search(r"/(\d+)$", cr)
        if not m:
            return "no Content-Range in 206 response"
        if int(m.group(1)) != size:
            return "server reports %s bytes, signed size is %d" % (m.group(1), size)
        return None
    if status == 200:
        cl = headers.get("Content-Length") or headers.get("content-length")
        if cl is not None and int(cl) != size:
            return "server reports %s bytes, signed size is %d" % (cl, size)
        return None
    return "HTTP %s" % status


def full_hash(url, size, sha256):
    with tempfile.NamedTemporaryFile(prefix="briglia-watch-", delete=True) as tmp:
        err = rv.download_to_file(url, tmp.name, size, sha256, timeout=600)
    return err


def _paged(cfg, path, key, params=None, max_pages=10):
    """Every item of a paginated list endpoint; an endpoint that never ends
    within max_pages × 100 items is an error, never a silent truncation."""
    items = []
    for page in range(1, max_pages + 1):
        p = dict(params or {}, per_page=100, page=page)
        data = gh_json(cfg, path, p, max_bytes=MAX_PAGE_FETCH)
        chunk = data.get(key) if isinstance(data, dict) else None
        if not isinstance(chunk, list):
            raise WatchError("GitHub API %s: no %r list in the answer" % (path, key))
        items += chunk
        if len(chunk) < 100:
            return items
    raise WatchError("GitHub API %s: more than %d pages — refusing to judge a truncated list" % (path, max_pages))


def _int(value):
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def corroborate_signed_run(cfg, chan, run, record, require_approval):
    """The release-signed workflow run for this exact tag commit (plan
    §3.3): identity by repository + workflow path + workflow id, every
    required job successful, and — above the cutoff — approval evidence
    bound to the run's single signing execution. Returns None when
    corroborated (and annotates `record`), else the reason."""
    repo, tag, commit = chan["repo"], record["tag"], record["commit"]
    path = chan.get("workflow_path") or ""
    required = chan.get("required_jobs")
    if not path or not isinstance(required, list) or not required:
        return "config lacks workflow_path/required_jobs for this channel"
    wf = gh_json(cfg, "/repos/%s/actions/workflows/%s" % (repo, os.path.basename(path)))
    wf_id = _int(wf.get("id"))
    if wf.get("path") != path or wf_id is None:
        return "workflow %s not found by path (answered path %r)" % (path, wf.get("path"))
    runs = _paged(cfg, "/repos/%s/actions/workflows/%d/runs" % (repo, wf_id), "workflow_runs",
                  {"event": "push", "branch": tag})
    for_tag = [r for r in runs if r.get("head_branch") == tag and r.get("event") == "push"]
    if len(for_tag) > 1:
        return "%d '%s' runs exist for %s (%s) — expected exactly one" % (
            len(for_tag), path, tag, ", ".join(str(r.get("id")) for r in for_tag))
    if not for_tag:
        return "no %s push run found for %s" % (path, tag)
    r = for_tag[0]
    rid = _int(r.get("id"))
    problems = []
    if r.get("head_sha") != commit:
        problems.append("head_sha %s ≠ recorded commit %s" % (str(r.get("head_sha"))[:12], commit[:12]))
    if r.get("path") != path:
        problems.append("run path %r ≠ %s" % (r.get("path"), path))
    if _int(r.get("workflow_id")) != wf_id:
        problems.append("workflow_id %r ≠ %d" % (r.get("workflow_id"), wf_id))
    if (r.get("repository") or {}).get("full_name") != repo:
        problems.append("repository %r ≠ %s" % ((r.get("repository") or {}).get("full_name"), repo))
    if rid is None:
        problems.append("run has no id")
    if problems:
        return "the %s run for %s does not match: %s" % (path, tag, "; ".join(problems))
    if r.get("status") != "completed" or r.get("conclusion") != "success":
        return "workflow run %s for %s is %s/%s" % (rid, tag, r.get("status"), r.get("conclusion"))
    jobs = _paged(cfg, "/repos/%s/actions/runs/%d/jobs" % (repo, rid), "jobs", {"filter": "all"})
    bad = []
    for name in required:
        recs = [j for j in jobs if j.get("name") == name]
        if not recs:
            bad.append("%s: missing" % name)
            continue
        latest = max(recs, key=lambda j: (_int(j.get("run_attempt")) or 0, _int(j.get("id")) or 0))
        if latest.get("conclusion") != "success":
            bad.append("%s: %s" % (name, latest.get("conclusion")))
    if bad:
        return "workflow run %s: required job(s) not successful: %s" % (rid, "; ".join(bad))
    record["workflow_run"] = rid
    if not require_approval:
        return None

    # --- approval bound to the single signing execution
    sign_name = chan.get("signing_job") or ""
    signs = {}
    for j in jobs:
        if j.get("name") == sign_name:
            signs[_int(j.get("id"))] = j
    if None in signs or len(signs) != 1:
        return ("approval unverified: %d signing execution(s) of '%s' in run %s — one approval cannot be bound "
                "to more than one signing attempt" % (len(signs), sign_name, rid))
    sign = next(iter(signs.values()))
    if _int(sign.get("run_attempt")) != 1 or sign.get("conclusion") != "success":
        return ("approval unverified: the signing job ran in attempt %r (%s) — only a successful attempt-1 "
                "signing is bound to the run's approval" % (sign.get("run_attempt"), sign.get("conclusion")))
    env_name = chan.get("signing_environment") or ""
    env = gh_json(cfg, "/repos/%s/environments/%s" % (repo, env_name))
    env_id = _int(env.get("id"))
    if env.get("name") != env_name or env_id is None:
        return "approval unverified: environment %r answered name %r id %r" % (env_name, env.get("name"), env.get("id"))
    approvals = gh_json(cfg, "/repos/%s/actions/runs/%d/approvals" % (repo, rid))
    if not isinstance(approvals, list):
        return "not approved: the review history is not a list (unexpected API shape)"
    mine = []
    for a in approvals:
        if not isinstance(a, dict) or not isinstance(a.get("environments"), list) \
                or not isinstance(a.get("user"), dict) or not isinstance(a.get("state"), str):
            return "not approved: a review-history entry has an unexpected shape"
        ids = [_int((e or {}).get("id")) if isinstance(e, dict) else None for e in a["environments"]]
        if None in ids:
            return "not approved: a review-history environment has no id"
        if env_id in ids:
            mine.append(a)
    if any(a["state"] != "approved" for a in mine):
        return "not approved: the review history holds a %s entry for %s" % (
            "/".join(sorted({a["state"] for a in mine if a["state"] != "approved"})), env_name)
    if not mine:
        return "not approved: no approval for environment %s (id %d) in run %s" % (env_name, env_id, rid)
    if len(mine) > 1:
        return "approval unverified: %d approval entries for %s in run %s" % (len(mine), env_name, rid)
    user = mine[0]["user"]
    want = _int(chan.get("approver_user_id"))
    if want is None or _int(user.get("id")) != want:
        return "not approved: the approval is by user id %r (%s), not the configured reviewer id %r" % (
            user.get("id"), user.get("login"), chan.get("approver_user_id"))
    record["approval"] = {"user_id": want, "login": user.get("login"), "environment_id": env_id,
                          "sign_job_id": _int(sign.get("id")), "run_attempt": 1}
    return None


def corroborate_app(cfg, chan, run, record):
    """The local publisher recorded exactly this release (publish_click.sh
    writes the log only after its own public re-verification)."""
    path = os.path.expanduser(chan.get("publication_log") or "")
    if not path or not os.path.exists(path):
        return "no local publication log at %s — cannot corroborate a new app release" % (path or "<unset>")
    entries = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    hits = [e for e in entries if e.get("tag") == record["tag"]]
    if not hits:
        return "publication log has no entry for %s" % record["tag"]
    e = hits[-1]
    problems = []
    if e.get("sequence") != record["sequence"]:
        problems.append("sequence %s≠%s" % (e.get("sequence"), record["sequence"]))
    if e.get("envelopeSha256") != record["envelope_sha256"]:
        problems.append("envelope sha256 differs")
    if e.get("commit") != record["commit"]:
        problems.append("commit %s≠%s" % (str(e.get("commit"))[:12], record["commit"][:12]))
    click = record["assets"].get("click") or {}
    if e.get("clickSha256") != click.get("sha256"):
        problems.append("click sha256 differs")
    return ("publication log disagrees with the live release: " + ", ".join(problems)) if problems else None


def check_website_installers(run, channel, chan, released):
    """Every website install URL is probed independently: a failure on one
    host never skips another host, nor discards a mismatch already found on
    another. All problems go into ONE `website-installer` finding, which is
    network-class (grace period) only when EVERY problem is a network
    failure — a confirmed wrong answer from any host alerts at once."""
    try:
        site_urls = url_list(chan.get("website_install_url"))
    except WatchError as exc:
        run.alert(channel + "/config-invalid", str(exc))
        return
    site_bad, site_net = [], True
    for site_url in site_urls:
        try:
            s3, _, via_site = fetch(site_url)
        except Exception as exc:  # noqa: BLE001 — record, then check the next host
            site_bad.append("%s: fetch failed: %s" % (site_url, exc))
            site_net = site_net and is_network_error(exc)
            continue
        if s3 != 200 or via_site != released:
            site_bad.append("%s does not resolve to the released installer (HTTP %s)" % (site_url, s3))
            site_net = False
        else:
            run.ok("website install URL %s resolves to the released installer" % site_url)
    if site_bad:
        run.alert(channel + "/website-installer", "; ".join(site_bad), transient=site_net)


def check_channel(cfg, channel, run, now):
    chan = cfg["channels"][channel]
    repo = chan["repo"]
    st = run.state.data
    print("— %s (%s) —" % (channel, repo))
    try:
        policy = policy_for(cfg, channel)
        kind = channel_kind(cfg, channel)
    except WatchError as exc:
        run.alert(channel + "/config-invalid", str(exc))
        return

    # 1. authenticate the live envelope
    try:
        raw = with_retries(lambda: rv.bounded_fetch(policy.envelope_url, rv.MAX_ENVELOPE_BYTES))
    except Exception as exc:  # noqa: BLE001
        run.alert(channel + "/envelope-unreachable", "cannot fetch %s: %s" % (policy.envelope_url, exc),
                  transient=is_network_error(exc))
        return
    try:
        manifest = rv.verify_envelope(raw, policy, now)
    except rv.ReleaseVerifyError as exc:
        run.alert(channel + "/envelope-invalid", "live envelope REJECTED (%s): %s" % (exc.kind, exc))
        return
    run.ok("live envelope authenticates: v%s sequence %d" % (manifest["version"], manifest["sequence"]))
    tag = "v" + manifest["version"]
    rec = st["recorded"].get(channel)
    # Rollback is judged BEFORE anything GitHub-dependent: a replayed older
    # envelope must trip this even when the API is unreachable or confused.
    if rec is not None and rec["sequence"] > manifest["sequence"]:
        run.alert(channel + "/rollback",
                  "latest serves %s (sequence %d) but %s (sequence %d) was recorded — rollback, replay or deleted release"
                  % (tag, manifest["sequence"], rec["tag"], rec["sequence"]))

    # 3a. GitHub: latest release + tag → commit
    try:
        latest = gh_json(cfg, "/repos/%s/releases/latest" % repo)
        tag_commit = resolve_tag(cfg, repo, tag)
    except WatchError as exc:
        run.alert(channel + "/github-unreachable", "cannot query GitHub: %s" % exc,
                  transient=is_network_error(exc))
        return
    if latest.get("tag_name") != tag or latest.get("draft") is not False:
        run.alert(channel + "/latest-mismatch",
                  "GitHub 'latest' is %s (draft=%s) but the envelope served as latest is %s"
                  % (latest.get("tag_name"), latest.get("draft"), tag))
    if latest.get("immutable") is not True:
        run.alert(channel + "/not-immutable", "release %s is not immutable" % tag)
    if not tag_commit:
        run.alert(channel + "/tag-missing", "refs/tags/%s does not exist" % tag)
        return
    live = manifest_record(manifest, raw, tag_commit)

    # 2. compare with the recorded authorized release
    if rec is None or rec["sequence"] < live["sequence"]:
        cutoff = chan.get("approval_required_above_sequence")
        if _int(cutoff) is None:
            run.alert(channel + "/config-invalid", "approval_required_above_sequence is missing or not an integer")
            return
        above = live["sequence"] > cutoff
        local_ack = None
        if kind == "app" and not above:
            why = corroborate_app(cfg, chan, run, live)          # pre-CI local provenance
            live["provenance"] = "local (pre-CI)"
        else:
            try:
                why = corroborate_signed_run(cfg, chan, run, live, require_approval=above)
            except WatchError as exc:
                # An API error or missing field is never approval.
                why = "cannot verify the signed run%s: %s" % (" or its approval" if above else "", exc)
            live["provenance"] = "ci, phone-approved" if above else "ci (pre-approval-gate)"
            if why and kind == "app":
                # Break-glass local publication: never CI-approved. Alert,
                # unless the owner acknowledged exactly this envelope.
                local_why = corroborate_app(cfg, chan, run, live)
                acks = st.setdefault("local_acks", {}).get(channel, {})
                if local_why is None and acks.get(live["tag"]) == live["envelope_sha256"]:
                    local_ack = True
                    live["provenance"] = "local provenance, not phone-approved CI (owner-acknowledged)"
                    why = None
                elif local_why is None:
                    run.alert(channel + "/local-provenance",
                              "%s (sequence %d) matches the local publication log but has no corroborated "
                              "phone-approved CI run (%s) — LOCAL PROVENANCE, NOT PHONE-APPROVED CI; if this was "
                              "the owner's break-glass release run `release_watch.py acknowledge-local %s %s %s`"
                              % (tag, live["sequence"], why, channel, live["tag"], live["envelope_sha256"]))
                    why = "local provenance, not phone-approved CI (unacknowledged)"
        if why:
            run.alert(channel + "/uncorroborated-release",
                      "%s (sequence %d) is live but NOT corroborated: %s — not recorded"
                      % (tag, live["sequence"], why))
            # keep checking the bytes of what is live anyway
        else:
            st["recorded"][channel] = live
            st["full_hash_at"].pop(channel, None)   # force a full hash below
            appr = live.get("approval")
            run.info("%s: %s (sequence %d, commit %s) corroborated and RECORDED as the authorized release — %s%s"
                     % (channel, tag, live["sequence"], tag_commit[:12], live["provenance"],
                        (", approved by user id %d" % appr["user_id"]) if appr else ""))
            rec = live
    elif rec["sequence"] > live["sequence"]:
        pass   # already reported above
    else:
        diffs = [k for k in ("tag", "version", "expires", "published", "envelope_sha256", "assets", "commit")
                 if rec.get(k) != live.get(k)]
        if diffs:
            run.alert(channel + "/record-mismatch",
                      "live %s differs from the recorded release with the same sequence %d: %s"
                      % (tag, live["sequence"], ", ".join(diffs)))
        else:
            run.ok("matches the recorded authorized release (%s, commit %s)" % (rec["tag"], rec["commit"][:12]))

    # 3b. latest pointer confusion: no non-draft release may out-version latest
    try:
        # The full release list grows ~22 KB per release (three platforms of
        # assets each); it passed 512 KiB at 29 releases. Allow the page cap.
        releases = gh_json(cfg, "/repos/%s/releases" % repo, {"per_page": RELEASE_PAGE_SIZE},
                           max_bytes=MAX_PAGE_FETCH)
    except WatchError as exc:
        run.alert(channel + "/github-unreachable", "cannot list releases: %s" % exc,
                  transient=is_network_error(exc))
        releases = []
    newer = [r["tag_name"] for r in releases
             if not r.get("draft") and semver_tuple(r.get("tag_name"))
             and semver_tuple(r["tag_name"]) > semver_tuple(tag)]
    if newer:
        run.alert(channel + "/latest-frozen",
                  "non-draft release(s) newer than latest %s exist: %s" % (tag, ", ".join(sorted(newer))))
    drafts = [r["tag_name"] for r in releases if r.get("draft")]
    if drafts:
        run.info("%s: draft release(s) present: %s" % (channel, ", ".join(drafts)))
    # Every published (non-draft) release — not just latest — must carry a
    # pipeline-shaped v<semver> tag and be immutable. Drafts are never
    # immutable and are reported above.
    published = [r for r in releases if not r.get("draft")]
    bad_tags = [str(r.get("tag_name")) for r in published
                if not isinstance(r.get("tag_name"), str) or not _RELEASE_TAG_RE.match(r["tag_name"])]
    if bad_tags:
        run.alert(channel + "/release-bad-tag",
                  "published release(s) whose tag is not v<major>.<minor>.<patch> — not made by the release "
                  "pipeline: %s" % ", ".join(sorted(bad_tags)))
    mutable = [str(r.get("tag_name")) for r in published if r.get("immutable") is not True]
    if mutable:
        run.alert(channel + "/release-not-immutable",
                  "published release(s) that are NOT immutable: %s" % ", ".join(sorted(mutable)))
    if len(releases) >= RELEASE_PAGE_SIZE:
        # Only the first page is read: say so instead of claiming "all".
        run.alert(channel + "/release-list-incomplete",
                  "the release list filled one page (%d); releases beyond it are NOT checked for tag shape, "
                  "immutability or out-versioning latest — add pagination" % len(releases))
    elif releases and not bad_tags and not mutable:
        run.ok("all %d published release(s) are immutable with v<semver> tags" % len(published))

    # 4. assets: probe hourly, full hash daily / after change
    problems = []
    network_only = True
    for name, a in live["assets"].items():
        err = None
        try:
            err = with_retries(lambda: probe_asset_checked(a["url"], a["size"]))
        except Exception as exc:  # noqa: BLE001
            err = str(exc)
            network_only = network_only and is_network_error(exc)
        else:
            if err:
                network_only = False
        if err:
            problems.append("%s: %s" % (name, err))
    if problems:
        run.alert(channel + "/asset-unreachable", "; ".join(problems), transient=network_only)
    else:
        run.ok("%d asset(s) reachable with the signed sizes" % len(live["assets"]))
    last_full = st["full_hash_at"].get(channel, 0)
    if not problems and (now - last_full >= FULL_HASH_INTERVAL):
        bad = []
        for name, a in live["assets"].items():
            try:
                err = full_hash(a["url"], a["size"], a["sha256"])
            except Exception as exc:  # noqa: BLE001
                err = str(exc)
            if err:
                bad.append("%s: %s" % (name, err))
        if bad:
            run.alert(channel + "/asset-hash", "full download does not match the signed hash/size: " + "; ".join(bad))
        else:
            st["full_hash_at"][channel] = now
            run.ok("full download of every asset matches the signed sha256 + size")

    # 5. installer byte-compare (CLI)
    if chan.get("installer_asset"):
        rel_url = policy.artifact_url_prefix.format(version=manifest["version"]) + chan["installer_asset"]
        src_url = "%s/%s/%s/%s" % (cfg["raw_base"], repo, tag, chan["installer_source"])
        try:
            s1, _, released = fetch(rel_url)
            s2, _, source = fetch(src_url)
            if s1 != 200 or s2 != 200:
                run.alert(channel + "/installer", "installer fetch: release HTTP %s, source HTTP %s" % (s1, s2))
            elif released != source:
                run.alert(channel + "/installer",
                          "released %s differs from %s at %s" % (chan["installer_asset"], chan["installer_source"], tag))
            else:
                run.ok("released installer is byte-identical to %s@%s" % (chan["installer_source"], tag))
                check_website_installers(run, channel, chan, released)
        except Exception as exc:  # noqa: BLE001
            run.alert(channel + "/installer", "installer check failed: %s" % exc,
                      transient=is_network_error(exc))

    # 6. website page must link the exact asset (app). One finding key for
    # all page URLs, so the known ISR lag right after an app release (the
    # page is revalidated on a visit, ~300 s) still produces ONE alert, as
    # before, rather than one per hostname.
    try:
        page_urls = url_list(chan.get("website_page_url"))
    except WatchError as exc:
        run.alert(channel + "/config-invalid", str(exc))
        page_urls = []
    page_bad, page_net = [], True
    for page_url in page_urls:
        try:
            s, _, page = fetch(page_url, max_bytes=MAX_PAGE_FETCH)
            urls = [a["url"] for a in live["assets"].values()]
            if s != 200:
                page_bad.append("%s → HTTP %s" % (page_url, s))
                page_net = False
            elif not all(u.encode() in page for u in urls):
                page_bad.append("%s does not link the released asset(s) %s" % (page_url, ", ".join(urls)))
                page_net = False
            else:
                run.ok("website page %s links the released asset" % page_url)
        except Exception as exc:  # noqa: BLE001
            page_bad.append("%s: page check failed: %s" % (page_url, exc))
            page_net = page_net and is_network_error(exc)
    if page_bad:
        run.alert(channel + "/website-page", "; ".join(page_bad), transient=page_net)

    # 7. transition: a legacy manifest still in service must agree
    if chan.get("legacy_blob_manifest"):
        try:
            s, _, body = fetch(chan["legacy_blob_manifest"])
            legacy = json.loads(body.decode("utf-8")) if s == 200 else None
            click = live["assets"].get("click") or next(iter(live["assets"].values()))
            if not legacy or legacy.get("version") != manifest["version"] or legacy.get("sha256") != click["sha256"]:
                run.alert(channel + "/legacy-blob",
                          "legacy manifest %s (HTTP %s, version %s) disagrees with the authoritative %s"
                          % (chan["legacy_blob_manifest"], s, (legacy or {}).get("version"), tag))
            else:
                run.ok("legacy transition manifest agrees with the authoritative release")
        except Exception as exc:  # noqa: BLE001
            run.alert(channel + "/legacy-blob", "legacy manifest check failed: %s" % exc,
                      transient=is_network_error(exc))

    # 8. expiry
    days_left = (manifest["expires"] - now) / 86400
    if days_left < float(cfg["expiry_warning_days"]):
        run.alert(channel + "/expiry", "metadata for %s expires in %.1f days (%s) — publish a new release before clients refuse it"
                  % (tag, days_left, iso(manifest["expires"])))
    else:
        run.ok("metadata valid for another %.0f days" % days_left)


# ------------------------------------------------------------- commands

def load_config(path):
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    if path:
        with open(os.path.expanduser(path)) as f:
            user = json.load(f)
        for k, v in user.items():
            if k == "channels":
                for ch, chv in v.items():
                    cfg["channels"].setdefault(ch, {}).update(chv)
            else:
                cfg[k] = v
    return cfg


def cmd_check(cfg):
    now = now_ts()
    try:
        state = State(cfg["state_dir"]).__enter__()
    except StateUnreadable as exc:
        # No memory to run with: an empty state would silently discard the
        # rollback floor. Say so directly (no state needed to send) and stop;
        # the beacon goes stale, so the heartbeat repeats the alarm too.
        text = ("🚨 briglia release watch — REFUSING TO RUN: %s. The recorded rollback floor and queued alerts "
                "are not available; restore state.json from a backup or re-seed only after verifying the live "
                "releases by hand (runbook §8)." % exc)
        print("✖ %s" % exc)
        send_telegram(cfg, text)
        return 1
    try:
        run = Run(cfg, state)
        if state.recovered:
            floor = ", ".join("%s seq %d" % (c, r["sequence"]) for c, r in sorted(state.data["recorded"].items())) or "none"
            run.info("⚠️ %s — recorded floor kept: %s" % (state.recovered, floor))
        for channel in cfg["channels"]:
            try:
                check_channel(cfg, channel, run, now)
            except Exception as exc:  # noqa: BLE001 — a crash in one channel must still alert
                run.alert(channel + "/watcher-error", "watcher raised %s: %s" % (type(exc).__name__, exc))
        messages = run.flush(now)
        state.data["last_run"] = now
        state.data["last_completed"] = now
        if not run.findings:
            state.data["last_clean"] = now
        state.save()
        state.write_beacon(now, len(run.findings), len(state.data["queued"]), state.data.get("queued_since"))
    finally:
        state.__exit__(None, None, None)
    print("check complete: %d finding(s), %d message(s), %d queued"
          % (len(run.findings), len(messages), len(state.data["queued"])))
    return 2 if run.findings else 0


def cmd_acknowledge_local(cfg, channel, tag, envelope_sha256):
    """Owner act: accept ONE break-glass local release (exact tag + exact
    envelope hash) as local provenance. It is recorded on the next check as
    'local provenance, not phone-approved CI', never as CI-approved."""
    if channel not in cfg["channels"] or not _RELEASE_TAG_RE.match(tag) \
            or not re.fullmatch(r"[0-9a-f]{64}", envelope_sha256 or ""):
        print("✖ usage: acknowledge-local <channel> <vX.Y.Z> <64-hex envelope sha256>")
        return 2
    with State(cfg["state_dir"]) as state:
        state.data.setdefault("local_acks", {}).setdefault(channel, {})[tag] = envelope_sha256
        state.save()
    print("✔ %s %s (envelope %s…) acknowledged as LOCAL provenance — recorded as such on the next check"
          % (channel, tag, envelope_sha256[:12]))
    return 0


def cmd_status(cfg):
    with State(cfg["state_dir"]) as state:
        print(json.dumps(state.data, indent=2, sort_keys=True))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("command", choices=["check", "status", "acknowledge-local"])
    ap.add_argument("args", nargs="*")
    ap.add_argument("--config", help="JSON config overriding DEFAULT_CONFIG")
    args = ap.parse_args(argv)
    cfg = load_config(args.config)
    print("briglia release watch v%s — %s — %s" % (WATCH_VERSION, args.command, iso(now_ts())))
    try:
        if args.command == "acknowledge-local":
            if len(args.args) != 3:
                print("✖ usage: acknowledge-local <channel> <vX.Y.Z> <envelope sha256>")
                return 2
            return cmd_acknowledge_local(cfg, *args.args)
        if args.args:
            print("✖ %s takes no arguments" % args.command)
            return 2
        return {"check": cmd_check, "status": cmd_status}[args.command](cfg)
    except WatchError as exc:
        print("✖ %s" % exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
