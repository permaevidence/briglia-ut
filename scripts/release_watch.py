#!/usr/bin/env python3
"""Deterministic release-channel watcher (briglia-cli RELEASE_SIGNING_PLAN.md §10;
off-Mac watcher plan "Sentinel").

Re-verifies the two signed channels — Briglia CLI and this app — the way a
client would, then cross-checks what GitHub says about them, and alerts a
human over Telegram on ANY mismatch or inability to verify. No LLM is
involved: every judgement here is a byte, hash, number or string comparison
against pinned keys, pinned ids and a locally recorded history.

    release_watch.py check      [--config PATH]   # hourly
    release_watch.py status     [--config PATH]   # print the recorded state
    release_watch.py acknowledge-local CHANNEL TAG ENVELOPE_SHA256 [--config PATH]
        # owner-only: accept ONE break-glass local release as local provenance
    release_watch.py acknowledge-finding KEY [--config PATH]
        # owner-only: close one event-feed finding (a deleted tag, a feed gap)
        # that no later check can ever clear by itself

Two deployments run this same file:

  * the Mac mini (mode "local", the default): authenticated with the
    owner's gh token when GH_TOKEN is set, alerts through the Mac mini's
    Telegram bot, corroborates pre-CI app releases with the local
    publication log;
  * Sentinel on Mac 2 (mode "remote"): NO credentials at all — no
    Authorization header is ever sent, even if GH_TOKEN is set; an audit
    hook refuses to start any process; Telegram credentials come only from
    Sentinel's own 0600 telegram.env; it also writes the website cache for
    the 5-minute site job (scripts/sentinel_site.py) and sends a positive
    ✅ confirmation for every fully verified release.

The watcher watching itself is a SEPARATE program, scripts/release_heartbeat.py
(stdlib only, its own state and lock): it reads nothing from this module and
nothing from state.json — only the completion beacon `check.beacon.json`.

Per channel, in priority order (a request budget guard stops low-priority
work first when the unauthenticated GitHub allowance runs low):
  1. environment rules of `release-sign` (watch_audit.check_env_rules);
  2. the live envelope, authenticated with the PINNED key set
     (py/release_verify.py), rollback floor, GitHub `latest` + tag → commit,
     and corroboration of a new release: the pinned release workflow's run
     with every required job successful and — above the channel's approval
     cutoff — exactly one attempt-1 signing execution approved by the
     pinned reviewer id for the pinned environment id;
  3. the signing audit over EVERY run of the pinned workflow (watch_audit);
  4. the complete release list (paginated): nothing newer than latest,
     every published release immutable on a v<semver> tag; asset range
     probes hourly and a full hash daily; the CLI installer equals
     scripts/get-briglia.sh at the tag; optional website checks; expiry;
  5. release-sign deployments as discovery pointers (count check);
  6. the repository event feed (supplemental);
  7. every 6 h: release-publish rules and rulesets;
  8. a deletion re-check rotation.

Coverage: every finding key belongs to a check; a finding is cleared — and
"recovered" announced — ONLY when its check actually ran and passed in this
run. A check that is due but did not run keeps every finding exactly as it
was, and once it has had no real result for longer than its own limit a
`<channel>/coverage/<check>` warning opens.

Alert policy: a finding is sent when it opens and once when it truly
clears. The Mac mini additionally re-sends a persisting finding every
`realert_hours` (Sentinel sets 0: never repeats). Network-class findings
are announced only after `transient_grace_checks` consecutive failing
checks. Findings of the signing-execution audit (signing, deployments,
events) are REPORT-ONLY while `signing_audit_alerts` is false: they go to
a local log and to the daily status as a count, never to Telegram.

State: <state_dir>/state.json under an exclusive lock, written durably with
a last-known-good copy (state.json.prev); if both are unusable the check
refuses to run with an empty memory. Stdlib only.
"""

import argparse
import datetime
import fcntl
import hashlib
import http.client
import json
import os
import re
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
# Checkout layout: scripts/ next to py/. Installed layout: py/ inside the
# watcher's own directory. -I (isolated mode) does not put the script's
# directory on sys.path, so it is added explicitly — and only it.
for _cand in (os.path.join(HERE, "py"), os.path.join(os.path.dirname(HERE), "py")):
    if os.path.isfile(os.path.join(_cand, "release_verify.py")):
        sys.path.insert(0, _cand)
        break
if HERE not in sys.path:
    sys.path.insert(0, HERE)
import release_verify as rv  # noqa: E402
import watch_audit as audit  # noqa: E402

WATCH_VERSION = "2"
USER_AGENT = "briglia-release-watch/" + WATCH_VERSION
MAX_SMALL_FETCH = 512 * 1024          # envelopes, installers, API JSON, pages
MAX_PAGE_FETCH = 4 * 1024 * 1024
FULL_HASH_INTERVAL = 24 * 3600
ENV_PUBLISH_INTERVAL = 6 * 3600
BUDGET_RESERVE = 5
MAX_QUEUED = 200
LOG_MAX_BYTES = 1024 * 1024
LOG_KEEP = 2

# Every channel entry carries an explicit `kind` (cli | app). The kind — not
# the channel NAME — selects the verification policy and the corroboration
# path, and the pinned policy's channel must equal the config key.
DEFAULT_CONFIG = {
    "mode": "local",
    "state_dir": "~/.config/briglia-release-watch",
    "github_api": "https://api.github.com",
    "raw_base": "https://raw.githubusercontent.com",
    "telegram_env_file": "~/.claude/channels/telegram/.env",   # TELEGRAM_BOT_TOKEN, OWNER_CHAT_ID
    "telegram_api": "https://api.telegram.org",
    "realert_hours": 6,
    "realert_on_change": True,
    # Network-class findings (GitHub/CDN timeouts, 5xx, DNS blips) are only
    # announced once they have persisted for this many consecutive checks;
    # integrity findings are always announced on the first check.
    "transient_grace_checks": 3,
    "heartbeat_max_age_hours": 3,
    "expiry_warning_days": 30,
    # Coverage: a due check with no real result for longer than its limit
    # opens <channel>/coverage/<check>.
    "coverage_max_age_hours": 4,
    "coverage_limits_hours": {"env-publish": 8.25, "asset-hash": 26, "deletion": 26},
    # The signing-execution audit (signing, deployments, events) alerts on
    # the Mac mini; Sentinel's installer starts it in report-only mode.
    "signing_audit_alerts": True,
    "audit_report_since": None,
    "unverified_hold_hours": 0,
    "audits": True,
    "checker_website": True,
    "confirmations": False,
    "log_file": None,
    "check_minute": 23,
    "channels": {
        "briglia-cli": {
            "kind": "cli",
            "repo": "permaevidence/briglia-cli",
            "workflow_path": ".github/workflows/release-signed.yml",
            "workflow_id": 346353613,
            # exact job names in briglia-cli's release-signed.yml; all must succeed
            "required_jobs": ["Authorize (credential-free)", "Build macOS arm64", "Build Linux x64",
                              "Build Linux arm64 (native)", "Assemble manifest", "Sign metadata",
                              "Verify candidate (macos)", "Verify candidate (linux)",
                              "Verify candidate (linux-arm64)", "Publish immutable release",
                              "Verify public channel (macos)", "Verify public channel (linux)",
                              "Verify public channel (linux-arm64)"],
            "signing_job": "Sign metadata",
            "signing_environment": "release-sign",
            "environment_ids": {"release-sign": 20888059977, "release-publish": 20888060344},
            "approver_user_id": 338251426,          # matteoiannius-beep — stable id, never the login
            # v0.2.49 (sequence 109) was published before the approval gate
            # and stays recorded without an invented approval.
            "approval_required_above_sequence": 109,
            # Signing audit, pre-gate history: executions that STARTED before
            # this time (creation of gate deployment 6848519034), plus the
            # pinned v0.2.49 execution, which started 3 s after it and had
            # no approval (no gate yet). Exclusive deployment boundary.
            "signing_cutoff": "2026-10-04T23:56:06Z",
            "legacy_pinned_executions": [{
                "run_id": 37244536754, "ref": "v0.2.49", "sha": "7dadfc5a7cc368a90a14b190daeafbde76560501",
                "started_at": "2026-10-04T23:56:09Z", "completed_at": "2026-10-04T23:56:15Z",
                "runner_name": "GitHub Actions 1000002358"}],
            "deployment_boundary": {"id": 6848519034, "inclusive": False},
            "rulesets_expected": ["protect-main", "protect-release-tags"],
            "installer_asset": "install.sh",
            "installer_source": "scripts/get-briglia.sh",
            "website_install_url": ["https://briglia.vercel.app/install.sh",
                                    "https://briglia.dev/install.sh"],
            "website_redirect": "https://github.com/permaevidence/briglia-cli/releases/latest/download/install.sh",
            "legacy_blob_manifest": None,
        },
        "briglia-ut": {
            "kind": "app",
            "repo": "permaevidence/briglia-ut",
            "workflow_path": ".github/workflows/release-signed.yml",
            "workflow_id": 376207556,
            "required_jobs": ["Authorize (credential-free)", "Build click (Linux)",
                              "Build click (macOS, reproducibility)", "Assemble manifest", "Sign metadata",
                              "Verify candidate", "Publish immutable release", "Verify public channel"],
            "signing_job": "Sign metadata",
            "signing_environment": "release-sign",
            "environment_ids": {"release-sign": 23565890221, "release-publish": 23565891678},
            "approver_user_id": 338251426,
            # v0.8.5 (sequence 7) and earlier were signed locally and keep
            # their local provenance; above it the publication log is never
            # accepted.
            "approval_required_above_sequence": 7,
            # The app's gate deployment 6880207211 (v0.8.6) is itself the
            # first phone-approved signing: inclusive boundary, empty baseline.
            "signing_cutoff": "2026-10-06T09:16:12Z",
            "legacy_pinned_executions": [],
            "deployment_boundary": {"id": 6880207211, "inclusive": True},
            "rulesets_expected": ["protect-main", "protect-release-tags"],
            "publication_log": "~/.briglia-release-keys/briglia-ut-publications.jsonl",
            "website_page_url": ["https://briglia.vercel.app/ubuntu-touch",
                                 "https://briglia.dev/ubuntu-touch"],
            "legacy_blob_manifest": None,
        },
    },
}

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_RELEASE_TAG_RE = re.compile(r"^v\d+\.\d+\.\d+$")
# Finding keys of the signing-execution audit (report-only while
# signing_audit_alerts is false). The core checks — environment rules,
# phone approval of every published release, envelope/sequence/
# immutability, website installers — always alert.
# "Unverified" (ambiguous, not proven bad) audit states: folded into the
# daily status unless they persist beyond `unverified_hold_hours` (owner
# anti-noise rule); definite findings alert at once.
_HOLD_KEY_RE = re.compile(r"^[^/]+/(signing/|deploy-group-unverified/)")
_AUDIT_KEY_RE = re.compile(r"^[^/]+/(signing(?:/|-audit-)|run-deleted/|deploy|baseline-|event|deletion-|"
                           r"coverage/(?:signing-audit|deployments|events|deletion)$)")


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


def local_hm(ts):
    return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")


def remote(cfg):
    return cfg.get("mode") == "remote"


class WatchError(Exception):
    def __init__(self, message, transient=False):
        super().__init__(message)
        self.transient = transient


class ShapeError(WatchError, ValueError):
    """GitHub answered, but not in the documented shape."""


class BudgetExhausted(WatchError, audit.BudgetStop):
    """The GitHub request budget would drop below the reserve for this priority."""


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


# ------------------------------------------------------- budget + GitHub API

class Budget:
    """Unauthenticated GitHub allows 60 requests/hour per IP, shared with
    whatever else uses that IP. Before every request the last seen
    X-RateLimit-Remaining decides: priorities 1–2 (environment rules,
    envelope/latest/tag) may use the whole allowance, everything else stops
    at the reserve. Whatever is not reached is 'not checked', never 'clean'."""

    def __init__(self):
        self.remaining = self.reset = self.limit = self.min_seen = None
        self.requests = 0

    def observe(self, headers):
        h = {str(k).lower(): v for k, v in (headers or {}).items()}
        try:
            rem = int(h["x-ratelimit-remaining"])
        except (KeyError, ValueError, TypeError):
            return
        self.remaining = rem
        self.min_seen = rem if self.min_seen is None else min(self.min_seen, rem)
        for attr, name in (("reset", "x-ratelimit-reset"), ("limit", "x-ratelimit-limit")):
            try:
                setattr(self, attr, int(h[name]))
            except (KeyError, ValueError, TypeError):
                pass

    def check(self, priority, reserve=BUDGET_RESERVE):
        if self.remaining is None:
            return
        if self.reset is not None and now_ts() >= self.reset:
            self.remaining = None      # a new window: the next answer tells
            return
        floor = 0 if priority <= 2 else reserve
        if self.remaining <= floor:
            raise BudgetExhausted("GitHub rate limit exhausted for this IP (%s of %s left, reserve %d for the core "
                                  "checks; resets %s)" % (self.remaining, self.limit, floor,
                                                          iso(self.reset) if self.reset else "?"))


BUDGET = Budget()
_TOKEN_WARNED = []


def gh_json(cfg, path, params=None, max_bytes=MAX_SMALL_FETCH, priority=2, allow_404=False):
    url = cfg["github_api"] + path + ("?" + urllib.parse.urlencode(params) if params else "")
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if remote(cfg):
        # Remote mode is credential-free by construction: never an
        # Authorization header, whatever the environment holds.
        if token and not _TOKEN_WARNED:
            _TOKEN_WARNED.append(1)
            print("  ! GH_TOKEN/GITHUB_TOKEN is set but IGNORED: remote mode never sends credentials", file=sys.stderr)
    elif token:
        headers["Authorization"] = "Bearer " + token

    def once():
        BUDGET.check(priority)
        try:
            st, h, b = fetch(url, max_bytes=max_bytes, headers=headers)
        except WatchError:
            raise
        except Exception as exc:  # noqa: BLE001
            if is_network_error(exc):
                raise WatchError("GitHub API %s → %s" % (path, exc), transient=True)
            raise
        BUDGET.requests += 1
        BUDGET.observe(h)
        if st in (403, 429) and BUDGET.remaining == 0:
            raise BudgetExhausted("GitHub rate limit exhausted for this IP (resets %s)"
                                  % (iso(BUDGET.reset) if BUDGET.reset else "?"))
        if st >= 500 or st == 429:
            raise WatchError("GitHub API %s → HTTP %s" % (path, st), transient=True)
        return st, b
    status, body = with_retries(once)
    if status == 404 and allow_404:
        return None
    if status != 200:
        raise WatchError("GitHub API %s → HTTP %s" % (path, status))
    try:
        return json.loads(body.decode("utf-8"))
    except ValueError:
        raise ShapeError("GitHub API %s → invalid JSON" % path)


def _paged(cfg, path, key, params=None, max_pages=10, priority=2, stop=None):
    """Every item of a paginated list endpoint (`key` names the list inside
    an object answer; None = the answer is the list). An endpoint that never
    ends within max_pages × 100 items is an error, never a silent truncation.
    `stop(page_items)` may end the walk early (a known boundary reached)."""
    items = []
    for page in range(1, max_pages + 1):
        p = dict(params or {}, per_page=100, page=page)
        data = gh_json(cfg, path, p, max_bytes=MAX_PAGE_FETCH, priority=priority)
        chunk = data if key is None else (data.get(key) if isinstance(data, dict) else None)
        if not isinstance(chunk, list):
            raise ShapeError("GitHub API %s → unexpected response shape (no %s list in the answer)"
                             % (path, repr(key) if key else "top-level"))
        items += chunk
        if len(chunk) < 100 or (stop and stop(chunk)):
            return items
    raise ShapeError("GitHub API %s: more than %d pages — refusing to judge a truncated list" % (path, max_pages))


def resolve_tag(cfg, repo, tag, priority=2):
    """Commit a tag names, following annotated tags; None if the tag is absent."""
    ref = gh_json(cfg, "/repos/%s/git/ref/tags/%s" % (repo, tag), priority=priority, allow_404=True)
    if ref is None:
        return None
    gh_shape(ref, dict, "ref " + tag)
    if ref.get("ref") != "refs/tags/" + tag:
        raise ShapeError("ref lookup answered %r for %s" % (ref.get("ref"), tag))
    obj = ref.get("object") or {}
    for _ in range(6):
        gh_shape(obj, dict, "ref object " + tag)
        sha, typ = str(obj.get("sha", "")), obj.get("type")
        if not _SHA_RE.match(sha):
            raise ShapeError("malformed ref object for %s" % tag)
        if typ == "commit":
            return sha
        if typ != "tag":
            raise ShapeError("unexpected ref object type %r for %s" % (typ, tag))
        obj = (gh_shape(gh_json(cfg, "/repos/%s/git/tags/%s" % (repo, sha), priority=priority), dict, "tag " + sha)
               .get("object")) or {}
    raise ShapeError("annotated tag chain too deep for %s" % tag)


class Api:
    """What watch_audit.py may call — nothing else."""

    def __init__(self, cfg):
        self.cfg = cfg

    def get(self, path, params=None, priority=3, allow_404=False):
        return gh_json(self.cfg, path, params, max_bytes=MAX_PAGE_FETCH, priority=priority, allow_404=allow_404)

    def paged(self, path, key, params=None, priority=3, stop=None):
        return _paged(self.cfg, path, key, params, priority=priority, stop=stop)

    def tag_commit(self, repo, tag, priority=3):
        return resolve_tag(self.cfg, repo, tag, priority)


def gh_shape(value, kind, path):
    """A GitHub answer of the wrong JSON shape is a failed check (an error
    finding, never a pass): validate before anything interprets it."""
    if not isinstance(value, kind):
        raise ShapeError("GitHub API %s → unexpected response shape (%s, expected %s)"
                         % (path, type(value).__name__, kind.__name__))
    return value


def semver_tuple(version):
    if not isinstance(version, str):
        return None
    m = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", version)
    return tuple(int(x) for x in m.groups()) if m else None


# --------------------------------------------------- isolation (remote mode)

_BLOCKED_EVENTS = ("subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.spawn", "os.fork",
                   "os.forkpty", "pty.spawn", "os.startfile")


def install_no_exec_hook(program):
    """Refuse every attempt to start a process for the rest of this
    interpreter's life (sys.addaudithook cannot be removed)."""
    def hook(event, args):
        if event in _BLOCKED_EVENTS:
            raise PermissionError("%s never starts processes (blocked %s)" % (program, event))
    sys.addaudithook(hook)


class RotatingStream:
    """stdout/stderr replacement: appends to `path`, and once the file
    passes LOG_MAX_BYTES it is rotated (path → path.1 → path.2, the oldest
    dropped). Logs therefore stay below about 3 MB in total."""

    def __init__(self, path, max_bytes=LOG_MAX_BYTES, keep=LOG_KEEP):
        self.path, self.max_bytes, self.keep = path, max_bytes, keep
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)

    def _rotate(self):
        try:
            if os.path.getsize(self.path) < self.max_bytes:
                return
        except OSError:
            return
        for i in range(self.keep, 0, -1):
            src = self.path if i == 1 else "%s.%d" % (self.path, i - 1)
            if os.path.exists(src):
                os.replace(src, "%s.%d" % (self.path, i))

    def write(self, text):
        self._rotate()
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8", errors="replace") as f:
            f.write(text)
        return len(text)

    def flush(self):
        pass


def rotating_append(path, line):
    RotatingStream(path).write(line if line.endswith("\n") else line + "\n")


def setup_logging(cfg):
    if cfg.get("log_file"):
        stream = RotatingStream(os.path.expanduser(cfg["log_file"]))
        sys.stdout = sys.stderr = stream


# ------------------------------------------------------------------ state

class StateUnreadable(WatchError):
    """Neither state.json nor state.json.prev is usable."""


def _fsync_dir(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_json(path, data, indent=None):
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=indent, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    _fsync_dir(os.path.dirname(path))


def validate_state(data):
    """Raise ValueError unless `data` has the shape the watcher relies on.
    Valid JSON of the wrong shape is as dangerous as garbage: a string
    sequence would silently disable the rollback comparison."""
    if not isinstance(data, dict):
        raise ValueError("top level is not an object")
    for key, typ in (("recorded", dict), ("full_hash_at", dict), ("active", dict),
                     ("queued", list), ("announced", dict), ("audit", dict), ("coverage", dict)):
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
    outbox = data.get("confirm_outbox", [])
    if not isinstance(outbox, list) or any(not isinstance(o, dict) or not isinstance(o.get("text"), str)
                                           or not isinstance(o.get("composed"), (int, float)) for o in outbox):
        raise ValueError("confirm_outbox malformed")
    for key, a in data.get("active", {}).items():
        if not isinstance(a, dict) or not isinstance(a.get("first"), (int, float)) or not isinstance(a.get("last_sent"), (int, float)):
            raise ValueError("active[%s] malformed" % key)
    acks = data.get("local_acks", {})
    if not isinstance(acks, dict) or any(not isinstance(v, dict) or any(not isinstance(t, str) or not isinstance(h, str)
                                                                         for t, h in v.items()) for v in acks.values()):
        raise ValueError("local_acks malformed")
    for channel, aud in data.get("audit", {}).items():
        if not isinstance(aud, dict) or not isinstance(aud.get("runs", {}), dict):
            raise ValueError("audit[%s] malformed" % channel)
        b = aud.get("baseline")
        if b is not None and (not isinstance(b, dict) or not isinstance(b.get("executions"), list)
                              or not isinstance(b.get("complete"), bool)):
            raise ValueError("audit[%s].baseline malformed" % channel)


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
        self.data.setdefault("coverage", {})     # "<channel>/<check>" → last real result
        # pre-v2 per-channel coverage entries ("briglia-cli": ts) are dropped
        for k in [k for k in self.data["coverage"] if "/" not in k]:
            self.data["coverage"].pop(k)
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
            prev_tmp = self.prev_path + ".tmp"
            if os.path.exists(prev_tmp):
                os.unlink(prev_tmp)
            os.link(self.path, prev_tmp)
            os.replace(prev_tmp, self.prev_path)
            _fsync_dir(self.dir)
        os.replace(tmp, self.path)
        _fsync_dir(self.dir)

    def write_beacon(self, beacon):
        """The completion beacon read by release_heartbeat.py — written only
        after the state itself has been saved. Atomic, fsynced."""
        atomic_json(os.path.join(self.dir, "check.beacon.json"), beacon)

    def __exit__(self, *exc):
        if self.lock_fd is not None:
            fcntl.flock(self.lock_fd, fcntl.LOCK_UN)
            os.close(self.lock_fd)
            self.lock_fd = None


def prune_state(st):
    """Keep the state file bounded. Run and deployment records mirror what
    GitHub lists (the run listing is itself capped at 10 pages, the
    deployment listing pages back only to the pinned boundary), so they are
    never dropped — a dropped record that GitHub still lists would be
    re-validated every hour. What does not mirror GitHub is capped: job-record
    caches are kept only for open runs, confirmed tags at 500, queues at
    MAX_QUEUED (in flush)."""
    for aud in (st.get("audit") or {}).values():
        for rs in (aud.get("runs") or {}).values():
            if rs.get("validated_fp") and rs.get("sig_cache"):
                rs.pop("sig_cache", None)
    for tags in (st.get("confirmed_tags") or {}).values():
        del tags[:-500]


# --------------------------------------------------------------- telegram

def check_remote_telegram_env(path):
    """Remote mode: Sentinel's own 0600 file, owned by this user, never the
    Mac mini's Claude Code bot credentials."""
    real = os.path.realpath(path)
    if "/.claude/" in real + "/" or real.endswith("/.claude"):
        raise WatchError("remote mode refuses the Claude Code Telegram credentials (%s) — Sentinel uses its own bot" % path)
    st = os.stat(real)
    if st.st_mode & 0o077:
        raise WatchError("telegram env file %s is readable by others (mode %o) — refusing; it must be 0600" % (path, st.st_mode & 0o777))
    if st.st_uid != os.geteuid():
        raise WatchError("telegram env file %s is not owned by this user — refusing" % path)


def telegram_credentials(cfg):
    path = os.path.expanduser(cfg["telegram_env_file"])
    if remote(cfg):
        check_remote_telegram_env(path)
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

def audit_report_only(cfg):
    return cfg.get("signing_audit_alerts") is False


class Run:
    """Collects findings for one `check` run and turns them into messages."""

    def __init__(self, cfg, state):
        self.cfg = cfg
        self.state = state
        self.findings = {}   # key → text (ALERT level)
        self.transient = set()  # keys whose finding is network-class only
        self.infos = []      # one-off informational messages
        self.extra_messages = []   # composed elsewhere (confirmations), sent with the rest
        # Coverage: a finding is cleared — and "recovered" announced — ONLY
        # when the check that owns its key actually ran in this run and
        # passed. `checked` holds every key judged this run (pass or fail).
        self.checked = set()
        self.partial = {}    # channel → [reason, ...]  (due work not performed)
        self.due = {}        # channel → {check, ...}
        self.done = {}       # channel → {check, ...}
        self.report_log = []

    def judged(self, *keys):
        """The checks owning these finding keys ran to a verdict in this run."""
        self.checked.update(keys)

    def make_due(self, channel, *checks):
        self.due.setdefault(channel, set()).update(checks)

    def performed(self, channel, *checks):
        self.done.setdefault(channel, set()).update(checks)

    def skipped(self, channel, reason, *checks):
        """Due work for `channel` was not performed in this run."""
        print("  ⋯ not checked (%s): %s" % (channel, reason))
        self.partial.setdefault(channel, []).append(reason)
        self.reasons = getattr(self, "reasons", {})
        for c in checks:
            self.reasons.setdefault((channel, c), []).append(reason)

    def missing(self, channel):
        return sorted(self.due.get(channel, set()) - self.done.get(channel, set()))

    def preserved(self):
        """Active, announced findings that this run neither re-found nor
        judged — still unresolved."""
        return [k for k, v in self.state.data["active"].items()
                if k not in self.findings and k not in self.checked and v.get("notified", True)]

    def alert(self, key, text, transient=False):
        print("  ✖ %s: %s%s" % (key, text, " (network)" if transient else ""))
        self.findings[key] = text
        self.checked.add(key)
        if transient:
            self.transient.add(key)
        else:
            self.transient.discard(key)

    def info(self, text):
        print("  ℹ %s" % text)
        self.infos.append(text)

    def positive(self, channel, tag, text):
        """A positive release message (✅ / ☑️ / 'recorded'). It goes to the
        durable outbox, NOT to flush(): cmd_check saves the state — the
        recorded release, observed approval, rollback floor and the cleared
        pending confirmation — BEFORE delivering it, and keeps an undelivered
        one for the next run. A delivered message may repeat until its
        acknowledgment is saved (a crash or failed save after delivery); it
        is never sent without its saved evidence. Its text carries the
        original verification time, which identifies a repeat."""
        print("  ✔ %s" % text)
        self.state.data.setdefault("confirm_outbox", []).append(
            {"channel": channel, "tag": tag, "text": text, "composed": now_ts()})

    def ok(self, text):
        print("  ✔ %s" % text)

    def is_report_only(self, key):
        return audit_report_only(self.cfg) and bool(_AUDIT_KEY_RE.match(key))

    def flush(self, now):
        """Decide what to send, send it, update bookkeeping. Returns the
        list of messages actually composed (sent or queued)."""
        cfg, st = self.cfg, self.state.data
        realert = float(cfg.get("realert_hours") or 0) * 3600
        on_change = cfg.get("realert_on_change", True) is not False
        grace = max(1, int(cfg.get("transient_grace_checks", 3)))
        messages = []
        active = st["active"]
        for key, text in self.findings.items():
            prev = active.get(key)
            if self.is_report_only(key):
                if prev is None:
                    active[key] = {"first": now, "last_sent": now, "text": text, "notified": False, "report_only": True}
                    self.report_log.append("OPEN  %s — %s" % (key, text))
                elif prev.get("text") != text:
                    prev["text"] = text
                    self.report_log.append("STILL %s — %s" % (key, text))
                continue
            hold = float(cfg.get("unverified_hold_hours") or 0) * 3600
            if hold and _HOLD_KEY_RE.match(key) and (prev is None or not prev.get("notified", True)):
                if prev is None:
                    prev = active[key] = {"first": now, "last_sent": now, "text": text, "notified": False, "held": True}
                prev["text"] = text
                if now - prev["first"] >= hold:
                    prev["notified"] = True
                    prev.pop("held", None)
                    prev.pop("report_only", None)
                    prev["last_sent"] = now
                    messages.append("🚨 briglia release watch — %s (unverified for more than %.2f h, since %s)\n%s"
                                    % (key, hold / 3600, iso(prev["first"]), text))
                continue
            if key in self.transient:
                if prev is None:
                    prev = active[key] = {"first": now, "last_sent": now, "text": text,
                                          "count": 0, "notified": False}
                prev["count"] = int(prev.get("count", 0)) + 1
                if not prev.get("notified", True):
                    prev["text"] = text
                    if prev["count"] >= grace:
                        prev["notified"] = True
                        prev.pop("report_only", None)
                        prev["last_sent"] = now
                        messages.append("🚨 briglia release watch — %s (failing for %d consecutive checks since %s)\n%s"
                                        % (key, prev["count"], iso(prev["first"]), text))
                elif realert and now - prev["last_sent"] >= realert:
                    prev["last_sent"] = now
                    prev["text"] = text
                    messages.append("🚨 briglia release watch — STILL FAILING since %s — %s\n%s"
                                    % (iso(prev["first"]), key, text))
                continue
            if prev is not None and not prev.get("notified", True):
                prev = None   # a quiet (network-class or report-only) entry became an alerting finding: announce now
            if prev is None:
                active[key] = {"first": now, "last_sent": now, "text": text}
                messages.append("🚨 briglia release watch — %s\n%s" % (key, text))
            elif (realert and now - prev["last_sent"] >= realert) or (on_change and prev.get("text") != text):
                prev["last_sent"] = now
                prev["text"] = text
                messages.append("🚨 briglia release watch — STILL FAILING since %s — %s\n%s"
                                % (iso(prev["first"]), key, text))
            else:
                prev["text"] = text
        for key in list(active):
            if key not in self.findings:
                if key not in self.checked:
                    # Not judged this run (skipped, early return, upstream
                    # network failure, not due): keep it exactly as it is —
                    # never a recovery, never a reset.
                    continue
                gone = active.pop(key)
                if gone.get("report_only"):
                    self.report_log.append("CLEAR %s (open since %s)" % (key, iso(gone["first"])))
                if not gone.get("notified", True):
                    continue   # never announced, so no recovery message
                first = gone["first"]
                messages.append("✅ briglia release watch — recovered: %s (failing since %s)" % (key, iso(first)))
        for text in self.infos:
            messages.append("ℹ️ briglia release watch — %s" % text)
        messages += self.extra_messages
        if self.report_log:
            path = os.path.join(self.state.dir, "audit-report.log")
            for line in self.report_log:
                rotating_append(path, "%s %s" % (iso(now), line))
        # deliver queued first (oldest), then new; keep whatever fails
        pending = list(st["queued"]) + messages
        st["queued"] = []
        for m in pending:
            if not send_telegram(cfg, m):
                st["queued"].append(m)
        if len(st["queued"]) > MAX_QUEUED:
            dropped = len(st["queued"]) - MAX_QUEUED
            st["queued"] = ["⚠️ briglia release watch — %d older undelivered message(s) were dropped to keep the "
                            "queue bounded" % dropped] + st["queued"][-(MAX_QUEUED - 1):]
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
    # delete-on-close: the download never outlives this call
    with tempfile.NamedTemporaryFile(prefix="briglia-watch-", delete=True) as tmp:
        err = rv.download_to_file(url, tmp.name, size, sha256, timeout=600)
    return err


def _int(value):
    return value if isinstance(value, int) and not isinstance(value, bool) else None


API = None


def corroborate_signed_run(cfg, chan, run, record, require_approval, channel=None, now=None):
    """The release-signed workflow run for this exact tag commit (plan
    §3.3): identity by repository + workflow path + workflow id, every
    required job successful, and — above the cutoff — the signing audit's
    validation of that run must say 'approved' (one attempt-1 signing
    execution, one approval by the pinned reviewer id for the pinned
    environment id, observed in attempt 1's review history). Returns None
    when corroborated (and annotates `record`), else the reason."""
    repo, tag, commit = chan["repo"], record["tag"], record["commit"]
    path = chan.get("workflow_path") or ""
    required = chan.get("required_jobs")
    if not path or not isinstance(required, list) or not required:
        return "config lacks workflow_path/required_jobs for this channel"
    wf = gh_shape(gh_json(cfg, "/repos/%s/actions/workflows/%s" % (repo, os.path.basename(path))), dict, "workflow")
    wf_id = _int(wf.get("id"))
    if wf.get("path") != path or wf_id is None:
        return "workflow %s not found by path (answered path %r)" % (path, wf.get("path"))
    if _int(chan.get("workflow_id")) is not None and wf_id != chan["workflow_id"]:
        return "workflow %s has id %d, pinned %d (recreated workflow)" % (path, wf_id, chan["workflow_id"])
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
    # --- approval: the signing audit's own validation of this run
    aud = audit.channel_audit(run.state.data, channel)
    chan_v = dict(chan, workflow_id=wf_id)
    res = audit.validate_run(Api(cfg), cfg, chan_v, r, aud, now if now is not None else now_ts())
    if res["verdict"] == "reopen":
        return "approval unverified: %s" % res["reason"]
    audit.store_result(aud, r, res, now if now is not None else now_ts())
    if res["verdict"] != "approved":
        return "approval unverified: %s" % res["reason"]
    record["approval"] = res["approval"]
    return None


def corroborate_app(cfg, chan, run, record):
    """The local publisher recorded exactly this release (publish_click.sh
    writes the log only after its own public re-verification). Remote mode
    has no publication log by design."""
    if remote(cfg):
        return "remote mode has no local publication log"
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
        run.skipped(channel, "website installers (config invalid)", "website")
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
    run.judged(channel + "/website-installer")
    if site_bad:
        run.alert(channel + "/website-installer", "; ".join(site_bad), transient=site_net)


def check_core(cfg, channel, run, now):
    """Envelope, rollback, GitHub latest + tag, record comparison and
    corroboration (priority 2). Returns the context the later checks need,
    or None after an early return (everything after it is not checked)."""
    chan = cfg["channels"][channel]
    repo = chan["repo"]
    st = run.state.data
    print("— %s (%s) —" % (channel, repo))
    try:
        policy = policy_for(cfg, channel)
        kind = channel_kind(cfg, channel)
    except WatchError as exc:
        run.alert(channel + "/config-invalid", str(exc))
        run.skipped(channel, "every check (config invalid)", "core")
        return None

    # 1. authenticate the live envelope
    try:
        raw = with_retries(lambda: rv.bounded_fetch(policy.envelope_url, rv.MAX_ENVELOPE_BYTES))
    except Exception as exc:  # noqa: BLE001
        run.alert(channel + "/envelope-unreachable", "cannot fetch %s: %s" % (policy.envelope_url, exc),
                  transient=is_network_error(exc))
        run.skipped(channel, "every check after the envelope fetch (envelope unreachable)", "core")
        return None
    run.judged(channel + "/envelope-unreachable")
    try:
        manifest = rv.verify_envelope(raw, policy, now)
    except rv.ReleaseVerifyError as exc:
        run.alert(channel + "/envelope-invalid", "live envelope REJECTED (%s): %s" % (exc.kind, exc))
        run.skipped(channel, "every check after envelope verification (envelope rejected)", "core")
        return None
    run.judged(channel + "/envelope-invalid")
    run.ok("live envelope authenticates: v%s sequence %d" % (manifest["version"], manifest["sequence"]))
    tag = "v" + manifest["version"]
    rec = st["recorded"].get(channel)
    # Rollback is judged BEFORE anything GitHub-dependent: a replayed older
    # envelope must trip this even when the API is unreachable or confused.
    if rec is not None and rec["sequence"] > manifest["sequence"]:
        run.alert(channel + "/rollback",
                  "latest serves %s (sequence %d) but %s (sequence %d) was recorded — rollback, replay or deleted release"
                  % (tag, manifest["sequence"], rec["tag"], rec["sequence"]))
    run.judged(channel + "/rollback")

    # GitHub: latest release + tag → commit
    try:
        latest = gh_shape(gh_json(cfg, "/repos/%s/releases/latest" % repo), dict, "releases/latest")
        tag_commit = resolve_tag(cfg, repo, tag)
    except BudgetExhausted as exc:
        run.skipped(channel, "every GitHub-dependent check (%s)" % exc, "core")
        return None
    except WatchError as exc:
        run.alert(channel + "/github-unreachable", "cannot query GitHub: %s" % exc,
                  transient=is_network_error(exc))
        run.skipped(channel, "every GitHub-dependent check (GitHub unreachable)", "core")
        return None
    if latest.get("tag_name") != tag or latest.get("draft") is not False:
        run.alert(channel + "/latest-mismatch",
                  "GitHub 'latest' is %s (draft=%s) but the envelope served as latest is %s"
                  % (latest.get("tag_name"), latest.get("draft"), tag))
    if latest.get("immutable") is not True:
        run.alert(channel + "/not-immutable", "release %s is not immutable" % tag)
    # judged only once both verdicts exist
    run.judged(channel + "/latest-mismatch", channel + "/not-immutable")
    if not tag_commit:
        run.alert(channel + "/tag-missing", "refs/tags/%s does not exist" % tag)
        run.skipped(channel, "release record, list, assets, installer, website (tag missing)", "core")
        return None
    run.judged(channel + "/tag-missing")
    live = manifest_record(manifest, raw, tag_commit)

    # compare with the recorded authorized release
    core_complete = True
    if rec is None or rec["sequence"] < live["sequence"]:
        cutoff = chan.get("approval_required_above_sequence")
        if _int(cutoff) is None:
            run.alert(channel + "/config-invalid", "approval_required_above_sequence is missing or not an integer")
            run.skipped(channel, "release record and later checks (config invalid)", "core")
            return None
        above = live["sequence"] > cutoff
        if kind == "app" and not above:
            why = corroborate_app(cfg, chan, run, live)          # pre-CI local provenance
            live["provenance"] = "local (pre-CI)"
        else:
            try:
                why = corroborate_signed_run(cfg, chan, run, live, require_approval=above, channel=channel, now=now)
            except BudgetExhausted as exc:
                run.skipped(channel, "corroboration of %s (%s)" % (tag, exc), "core")
                return None
            except WatchError as exc:
                # An API error or missing field is never approval.
                why = "cannot verify the signed run%s: %s" % (" or its approval" if above else "", exc)
            live["provenance"] = "ci, phone-approved" if above else "ci (pre-approval-gate)"
            if why and kind == "app":
                # Break-glass local publication: never CI-approved. Alert,
                # unless the owner acknowledged exactly this envelope.
                local_why = corroborate_app(cfg, chan, run, live)
                acks = st.setdefault("local_acks", {}).get(channel, {})
                acked = acks.get(live["tag"]) == live["envelope_sha256"]
                if acked and (local_why is None or remote(cfg)):
                    live["provenance"] = "local provenance, not phone-approved CI (owner-acknowledged)"
                    why = None
                elif local_why is None or remote(cfg):
                    run.alert(channel + "/local-provenance",
                              "%s (sequence %d) has no corroborated phone-approved CI run (%s) — LOCAL PROVENANCE, "
                              "NOT PHONE-APPROVED CI; if this was the owner's break-glass release run "
                              "`release_watch.py acknowledge-local %s %s %s`"
                              % (tag, live["sequence"], why, channel, live["tag"], live["envelope_sha256"]))
                    why = "local provenance, not phone-approved CI (unacknowledged)"
        if why:
            run.alert(channel + "/uncorroborated-release",
                      "%s (sequence %d) is live but NOT corroborated: %s — not recorded"
                      % (tag, live["sequence"], why))
        else:
            st["recorded"][channel] = live
            st["full_hash_at"].pop(channel, None)   # force a full hash below
            st.setdefault("installer_verified", {}).pop(channel, None)
            tags = st.setdefault("confirmed_tags", {}).setdefault(channel, [])
            if live["tag"] not in tags:
                tags.append(live["tag"])
            appr = live.get("approval")
            if cfg.get("confirmations"):
                st.setdefault("pending_confirm", {})[channel] = {
                    "tag": live["tag"], "sequence": live["sequence"], "commit": live["commit"],
                    "envelope_sha256": live["envelope_sha256"], "provenance": live["provenance"],
                    "workflow_run": live.get("workflow_run"), "approval": appr, "first_seen": now}
            else:
                run.positive(channel, live["tag"], "ℹ️ briglia release watch — %s: %s (sequence %d, commit %s) corroborated "
                             "and RECORDED as the authorized release — %s%s"
                             % (channel, tag, live["sequence"], tag_commit[:12], live["provenance"],
                                (", approved by user id %d" % appr["user_id"]) if appr else ""))
            rec = live
        run.judged(channel + "/uncorroborated-release", channel + "/local-provenance", channel + "/record-mismatch")
    elif rec["sequence"] > live["sequence"]:
        run.skipped(channel, "release record comparison (rollback)", "core")
        core_complete = False
    else:
        run.judged(channel + "/uncorroborated-release", channel + "/local-provenance", channel + "/record-mismatch")
        diffs = [k for k in ("tag", "version", "expires", "published", "envelope_sha256", "assets", "commit")
                 if rec.get(k) != live.get(k)]
        if diffs:
            run.alert(channel + "/record-mismatch",
                      "live %s differs from the recorded release with the same sequence %d: %s"
                      % (tag, live["sequence"], ", ".join(diffs)))
        else:
            run.ok("matches the recorded authorized release (%s, commit %s)" % (rec["tag"], rec["commit"][:12]))
    if core_complete:
        run.performed(channel, "core")
    return {"policy": policy, "kind": kind, "manifest": manifest, "raw": raw, "tag": tag, "live": live,
            "tag_commit": tag_commit}


def check_release_list(cfg, channel, run, ctx):
    """Priority 4: the COMPLETE release list. Its findings are judged only
    after every page was read and every entry had the documented shape —
    a failed, malformed or truncated list keeps them exactly as they were."""
    repo = cfg["channels"][channel]["repo"]
    tag = ctx["tag"]
    try:
        releases = _paged(cfg, "/repos/%s/releases" % repo, None, priority=4)
        # every element is interpreted below: validate the whole shape first
        for r in releases:
            gh_shape(r, dict, "releases[]")
            if "tag_name" not in r or not isinstance(r.get("draft"), bool):
                raise ShapeError("GitHub API releases[] → unexpected response shape (tag_name/draft missing)")
    except BudgetExhausted as exc:
        run.skipped(channel, "release list (%s)" % exc, "release-list")
        return
    except WatchError as exc:
        if "more than" in str(exc) and "pages" in str(exc):
            run.alert(channel + "/release-list-incomplete",
                      "the release list did not end within the page limit — releases beyond it are NOT checked for tag "
                      "shape, immutability or out-versioning latest")
        else:
            run.alert(channel + "/github-unreachable", "cannot list releases: %s" % exc,
                      transient=is_network_error(exc))
        run.skipped(channel, "release list: latest-frozen, tag shape, immutability (cannot list releases: %s)" % exc,
                    "release-list")
        return
    st = run.state.data
    if channel not in st.setdefault("confirmed_tags", {}):
        # first complete list: everything published so far is history the
        # event-feed audit does not re-judge
        st["confirmed_tags"][channel] = sorted(str(r.get("tag_name")) for r in releases if not r.get("draft"))
    newer = [r["tag_name"] for r in releases
             if not r.get("draft") and semver_tuple(r.get("tag_name"))
             and semver_tuple(r["tag_name"]) > semver_tuple(tag)]
    if newer:
        run.alert(channel + "/latest-frozen",
                  "non-draft release(s) newer than latest %s exist: %s" % (tag, ", ".join(sorted(newer))))
    drafts = [str(r["tag_name"]) for r in releases if r.get("draft")]
    if drafts:
        run.info("%s: draft release(s) present: %s" % (channel, ", ".join(drafts)))
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
    if releases and not bad_tags and not mutable:
        run.ok("all %d published release(s) are immutable with v<semver> tags" % len(published))
    # judged only AFTER the complete, valid list was interpreted
    run.judged(channel + "/github-unreachable", channel + "/latest-frozen", channel + "/release-bad-tag",
               channel + "/release-not-immutable", channel + "/release-list-incomplete")
    run.performed(channel, "release-list")


def check_rest(cfg, channel, run, now, ctx):
    """Assets, installer, website, legacy manifest, expiry (no API budget
    except none — downloads and raw.githubusercontent do not count)."""
    chan = cfg["channels"][channel]
    repo = chan["repo"]
    st = run.state.data
    policy, manifest, live, tag = ctx["policy"], ctx["manifest"], ctx["live"], ctx["tag"]

    # assets: probe hourly, full hash daily / after change
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
    run.judged(channel + "/asset-unreachable")
    run.performed(channel, "assets")
    if problems:
        run.alert(channel + "/asset-unreachable", "; ".join(problems), transient=network_only)
    else:
        run.ok("%d asset(s) reachable with the signed sizes" % len(live["assets"]))
    last_full = st["full_hash_at"].get(channel, 0)
    # Per-check cadence: the full hash is due daily (or after the record
    # changed). Not due = still-fresh evidence, NOT a partial run; but
    # freshness never clears an asset-hash finding — only a real full hash.
    if now - last_full >= FULL_HASH_INTERVAL:
        run.make_due(channel, "asset-hash")
    if problems and now - last_full >= FULL_HASH_INTERVAL:
        run.skipped(channel, "full asset hash due but not performed (assets unreachable)", "asset-hash")
    if not problems and (now - last_full >= FULL_HASH_INTERVAL):
        run.judged(channel + "/asset-hash")
        run.performed(channel, "asset-hash")
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

    # installer byte-compare (CLI)
    if chan.get("installer_asset"):
        rel_url = policy.artifact_url_prefix.format(version=manifest["version"]) + chan["installer_asset"]
        src_url = "%s/%s/%s/%s" % (cfg["raw_base"], repo, tag, chan["installer_source"])
        try:
            s1, _, released = fetch(rel_url)
            s2, _, source = fetch(src_url)
            if s1 != 200 or s2 != 200:
                run.alert(channel + "/installer", "installer fetch: release HTTP %s, source HTTP %s" % (s1, s2))
                run.skipped(channel, "website installers (no verified released installer to compare)", "website")
            elif released != source:
                run.alert(channel + "/installer",
                          "released %s differs from %s at %s" % (chan["installer_asset"], chan["installer_source"], tag))
                run.skipped(channel, "website installers (no verified released installer to compare)", "website")
            else:
                run.ok("released installer is byte-identical to %s@%s" % (chan["installer_source"], tag))
            run.judged(channel + "/installer")
            run.performed(channel, "installer")
            if s1 == 200 and s2 == 200 and released == source:
                rec = st["recorded"].get(channel)
                if rec and rec.get("tag") == tag:
                    st.setdefault("installer_verified", {})[channel] = {
                        "tag": tag, "sha256": hashlib.sha256(released).hexdigest(), "size": len(released)}
                if cfg.get("checker_website", True):
                    check_website_installers(run, channel, chan, released)
                    run.performed(channel, "website")
        except Exception as exc:  # noqa: BLE001
            run.alert(channel + "/installer", "installer check failed: %s" % exc,
                      transient=is_network_error(exc))
            run.skipped(channel, "website installers (installer check failed)", "website")

    # website page must link the exact asset (app). One finding key for
    # all page URLs (the known ISR lag right after an app release).
    if cfg.get("checker_website", True):
        try:
            page_urls = url_list(chan.get("website_page_url"))
        except WatchError as exc:
            run.alert(channel + "/config-invalid", str(exc))
            run.skipped(channel, "website page (config invalid)", "website")
            page_urls = None
        if page_urls is not None:
            run.judged(channel + "/website-page")
            if page_urls:
                run.performed(channel, "website")
        else:
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

    # transition: a legacy manifest still in service must agree
    if chan.get("legacy_blob_manifest"):
        run.judged(channel + "/legacy-blob")
        run.performed(channel, "legacy-blob")
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

    # expiry
    days_left = (manifest["expires"] - now) / 86400
    if days_left < float(cfg["expiry_warning_days"]):
        run.alert(channel + "/expiry", "metadata for %s expires in %.1f days (%s) — publish a new release before clients refuse it"
                  % (tag, days_left, iso(manifest["expires"])))
    else:
        run.ok("metadata valid for another %.0f days" % days_left)
    run.judged(channel + "/expiry")
    run.performed(channel, "expiry")


def check_channel(cfg, channel, run, now):
    """Backward-compatible single-channel pass (core, list, rest)."""
    ctx = check_core(cfg, channel, run, now)
    if ctx:
        check_release_list(cfg, channel, run, ctx)
        check_rest(cfg, channel, run, now, ctx)
    return ctx


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
            elif isinstance(v, dict) and isinstance(cfg.get(k), dict):
                cfg[k].update(v)
            else:
                cfg[k] = v
    return cfg


def _guard(run, channel, check, fn, crashed):
    """Run one check; budget/network failures make it 'not checked', an
    unreadable GitHub answer is a finding of its own, a crash a watcher error."""
    try:
        result = fn()
        run.judged(channel + "/" + check + "-unreadable")
        return result
    except BudgetExhausted as exc:
        run.skipped(channel, "%s (%s)" % (check, exc), check)
    except ValueError as exc:      # ShapeError included: GitHub answered, not in the documented shape
        run.alert(channel + "/" + check + "-unreadable", "%s: GitHub answered in an unexpected shape: %s" % (check, exc))
        run.skipped(channel, "%s (unreadable answer)" % check, check)
    except WatchError as exc:
        if not exc.transient and "HTTP 404" in str(exc):
            run.alert(channel + "/" + check + "-unreadable", "%s: %s" % (check, exc))
        run.skipped(channel, "%s (%s)" % (check, exc), check)
    except Exception as exc:  # noqa: BLE001 — a crash in one check must still alert
        crashed.add(channel)
        run.alert(channel + "/watcher-error", "watcher raised %s in %s: %s" % (type(exc).__name__, check, exc))
        run.skipped(channel, "%s (watcher error)" % check, check)
    return None


def coverage_limit(cfg, check):
    limits = cfg.get("coverage_limits_hours") or {}
    hours = limits.get(check, limits.get("hourly", cfg.get("coverage_max_age_hours", 4)))
    return float(hours) * 3600


def evaluate_coverage(cfg, run, now):
    cov = run.state.data["coverage"]
    for channel in cfg["channels"]:
        for check in sorted(run.due.get(channel, set()) | run.done.get(channel, set())):
            ck = "%s/%s" % (channel, check)
            key = "%s/coverage/%s" % (channel, check)
            if check in run.done.get(channel, set()):
                cov[ck] = now
                run.judged(key)
                continue
            since = cov.setdefault(ck, now)
            if now - since > coverage_limit(cfg, check):
                reasons = "; ".join((getattr(run, "reasons", {}) or {}).get((channel, check), [])) or "not performed"
                run.alert(key, "check '%s' has had no real result since %s (limit %.2f h): %s"
                          % (check, iso(since), coverage_limit(cfg, check) / 3600, reasons))


# ---------------------------------------------- site cache + confirmations

def site_cache_path(state_dir):
    return os.path.join(os.path.expanduser(state_dir), "site-cache.json")


def write_site_cache(cfg, st, now):
    """What the 5-minute site job compares against: only evidence this
    checker VERIFIED for the recorded release. A new generation is written
    (tmp + fsync + rename) only when the content changes."""
    path = site_cache_path(cfg["state_dir"])
    chans = {}
    for channel, chan in cfg["channels"].items():
        rec = st["recorded"].get(channel)
        if not rec:
            continue
        entry = {"kind": chan.get("kind"), "tag": rec["tag"], "sequence": rec["sequence"],
                 "envelope_url": chan.get("envelope_url"), "artifact_url_prefix": chan.get("artifact_url_prefix")}
        if chan.get("installer_asset"):
            iv = (st.get("installer_verified") or {}).get(channel)
            entry["installer"] = ({"sha256": iv["sha256"], "size": iv["size"]}
                                  if iv and iv.get("tag") == rec["tag"] else None)
            entry["website_install_url"] = url_list(chan.get("website_install_url"))
            entry["redirect"] = chan.get("website_redirect")
        if chan.get("website_page_url"):
            entry["click_urls"] = [a["url"] for a in rec["assets"].values()]
            entry["website_page_url"] = url_list(chan.get("website_page_url"))
        chans[channel] = entry
    content = {"channels": chans, "check_minute": int(cfg.get("check_minute", 23))}
    old = None
    try:
        with open(path) as f:
            old = json.load(f)
    except Exception:  # noqa: BLE001 — missing or corrupt: a new generation is written
        pass
    if isinstance(old, dict) and old.get("content") == content and isinstance(old.get("generation"), int):
        return old["generation"]
    gen = (old.get("generation") + 1) if isinstance(old, dict) and isinstance(old.get("generation"), int) else 1
    atomic_json(path, {"version": 1, "generation": gen, "written": now, "content": content})
    return gen


def confirm_releases(cfg, run, now, site_gen):
    """§7: a ✅ only when every relevant check of that channel passed in
    THIS run — the fixed core set plus EVERY check that was due this run
    (deployments, events, env-publish, deletion, …), with nothing skipped —
    the checker's own website fetch matches, and the site job's current
    state is clean and fresh. Otherwise nothing (incomplete states are folded
    into the daily status) until the release has been pending longer than
    the hourly freshness limit — then one ⚠️. A ✅ goes to the durable
    outbox (Run.positive) and is sent only after the state is saved."""
    import sentinel_site   # noqa: PLC0415 — site probe helpers (no state, no lock)
    st = run.state.data
    pend = st.get("pending_confirm") or {}
    hourly_limit = coverage_limit(cfg, "hourly")
    for channel, pc in list(pend.items()):
        chan = cfg["channels"].get(channel) or {}
        rec = st["recorded"].get(channel)
        if not rec or rec["tag"] != pc["tag"]:
            pend.pop(channel)
            continue
        reasons = []
        needed = {"core", "release-list", "assets", "expiry"}
        if st["full_hash_at"].get(channel, 0) < pc["first_seen"] and "asset-hash" not in run.done.get(channel, set()):
            reasons.append("the full asset hash of this release has not passed yet")
        if cfg.get("audits", True):
            needed |= {"env-rules", "signing-audit"}
        if chan.get("installer_asset"):
            needed.add("installer")
        # Every check that was DUE this run counts, not only a fixed list:
        # due-and-skipped work (budget, network, crash) is never "complete".
        # Work that was not due (fresh) need not run again.
        missing = sorted((needed | run.due.get(channel, set())) - run.done.get(channel, set()))
        if missing:
            reasons.append("not checked in this run: " + ", ".join(missing))
        if run.partial.get(channel):
            reasons.append("partial run: " + "; ".join(run.partial[channel]))
        open_keys = sorted(k for k in set(st["active"]) | set(run.findings)
                           if k.startswith(channel + "/") and not run.is_report_only(k))
        if open_keys:
            reasons.append("open finding(s): " + ", ".join(open_keys))
        site_ok, site_why = sentinel_site.confirmation_evidence(cfg, channel, rec, st, now, site_gen)
        if not site_ok:
            reasons.append(site_why)
        if not reasons:
            appr = pc.get("approval")
            n_ro = sum(1 for k, v in st["active"].items() if k.startswith(channel + "/") and v.get("report_only"))
            msg = ("✅ Verified %s %s, sequence %d, commit %s, envelope sha256 %s…%s. %s. Installers/pages on %s match. "
                   "Verified at %s (Mac 2)."
                   % (channel, rec["tag"], rec["sequence"], rec["commit"][:12], rec["envelope_sha256"][:4],
                      rec["envelope_sha256"][-4:],
                      ("Signed in run %s, one approval by your phone account (%d) in the run's review history, first "
                       "observed by Sentinel at %s" % (pc.get("workflow_run"), appr["user_id"], local_hm(pc["first_seen"])))
                      if appr else ("Provenance: %s" % pc.get("provenance")),
                      " and ".join(sorted({urllib.parse.urlparse(u).hostname for u in
                                           url_list(chan.get("website_install_url")) + url_list(chan.get("website_page_url"))})) or "—",
                      local_hm(now)))
            if "local provenance" in str(pc.get("provenance")):
                msg = "☑️ Local provenance, NOT phone-approved CI: " + msg[2:]
            if n_ro and audit_report_only(cfg):
                msg += " (signing audit in report-only mode: %d open item(s), see the daily status)" % n_ro
            run.positive(channel, rec["tag"], msg)
            pend.pop(channel)
            continue
        if now - pc["first_seen"] > hourly_limit and not pc.get("warned"):
            pc["warned"] = now
            run.extra_messages.append("⚠️ Release %s %s seq %d seen but NOT fully verified: %s. Do not upgrade to it "
                                      "until a ✅ names it." % (channel, rec["tag"], rec["sequence"], "; ".join(reasons)))


# ------------------------------------------------------------- check run

def deliver_outbox(cfg, state):
    """Send the durable positive messages (already saved), oldest first, and
    drop each one only after Telegram confirmed it. The trimmed outbox is
    saved again; if that save fails, the delivered ones stay in the saved
    outbox, so delivery may repeat until its acknowledgment is saved — a
    duplicate (identified by its original verification time), never a
    message without saved evidence and never a lost one."""
    st = state.data
    outbox = list(st.get("confirm_outbox") or [])
    if not outbox:
        return []
    sent, keep = [], []
    for item in outbox:
        if send_telegram(cfg, item["text"]):
            sent.append(item["text"])
        else:
            keep.append(item)
    del keep[:-MAX_QUEUED]
    st["confirm_outbox"] = keep
    if sent:
        try:
            state.save()
        except Exception as exc:  # noqa: BLE001 — delivered already; a repeat next run is the accepted cost
            print("  ! state save after delivering %d positive message(s) failed (%s) — delivery may repeat until the acknowledgment is saved"
                  % (len(sent), exc), file=sys.stderr)
    if keep:
        print("  ⋯ %d positive message(s) kept in the outbox for the next run (Telegram did not confirm)" % len(keep))
    return sent


def cmd_check(cfg):
    global API
    now = now_ts()
    API = Api(cfg)
    try:
        state = State(cfg["state_dir"]).__enter__()
    except StateUnreadable as exc:
        text = ("🚨 briglia release watch — REFUSING TO RUN: %s. The recorded rollback floor and queued alerts "
                "are not available; restore state.json from a backup or re-seed only after verifying the live "
                "releases by hand (runbook §8)." % exc)
        print("✖ %s" % exc)
        send_telegram(cfg, text)
        return 1
    try:
        run = Run(cfg, state)
        st = state.data
        if state.recovered:
            floor = ", ".join("%s seq %d" % (c, r["sequence"]) for c, r in sorted(st["recorded"].items())) or "none"
            run.info("⚠️ %s — recorded floor kept: %s" % (state.recovered, floor))
        channels = list(cfg["channels"])
        crashed = set()
        audits = cfg.get("audits", True) is not False
        for ch in channels:
            run.make_due(ch, "core", "release-list", "assets", "expiry")
            chan = cfg["channels"][ch]
            if chan.get("installer_asset"):
                run.make_due(ch, "installer")
            if audits:
                run.make_due(ch, "env-rules", "signing-audit", "deployments", "events", "deletion")
                if now - st["coverage"].get(ch + "/env-publish", 0) >= ENV_PUBLISH_INTERVAL - 600:
                    run.make_due(ch, "env-publish")
        # 1. environment rules (priority 1)
        if audits:
            for ch in channels:
                if _guard(run, ch, "env-rules", lambda ch=ch: audit.check_env_rules(
                        API, cfg, ch, cfg["channels"][ch], run) or True, crashed):
                    run.performed(ch, "env-rules")
        # 2. core (priority 2)
        ctxs = {}
        for ch in channels:
            ctxs[ch] = _guard(run, ch, "core", lambda ch=ch: check_core(cfg, ch, run, now), crashed)
        # 3. signing audit (priority 3)
        if audits:
            for ch in channels:
                if _guard(run, ch, "signing-audit", lambda ch=ch: audit.signing_audit(
                        API, cfg, ch, cfg["channels"][ch], run, st, now), crashed):
                    run.performed(ch, "signing-audit")
        # 4. release list + downloads (priority 4)
        for ch in channels:
            if ctxs.get(ch):
                _guard(run, ch, "release-list", lambda ch=ch: check_release_list(cfg, ch, run, ctxs[ch]), crashed)
                _guard(run, ch, "assets", lambda ch=ch: check_rest(cfg, ch, run, now, ctxs[ch]), crashed)
            else:
                run.skipped(ch, "release list, assets, installer, website, expiry (core check did not complete)",
                            "release-list", "assets", "installer", "expiry")
        if audits:
            # 5. deployments (priority 5) — only on a complete signing audit
            for ch in channels:
                if "signing-audit" not in run.done.get(ch, set()):
                    run.skipped(ch, "deployments (signing audit incomplete this run)", "deployments")
                elif _guard(run, ch, "deployments", lambda ch=ch: audit.deployments_audit(
                        API, cfg, ch, cfg["channels"][ch], run, st, now), crashed):
                    run.performed(ch, "deployments")
            # 6. events (priority 6)
            for ch in channels:
                tags = set((st.get("confirmed_tags") or {}).get(ch, []))
                if _guard(run, ch, "events", lambda ch=ch, tags=tags: audit.events_audit(
                        API, cfg, ch, cfg["channels"][ch], run, st, now, tags), crashed):
                    run.performed(ch, "events")
            # 7. every 6 h: release-publish + rulesets
            for ch in channels:
                if "env-publish" in run.due.get(ch, set()):
                    if _guard(run, ch, "env-publish", lambda ch=ch: audit.check_env_publish(
                            API, cfg, ch, cfg["channels"][ch], run) or True, crashed):
                        run.performed(ch, "env-publish")
            # 8. deletion re-check rotation
            for ch in channels:
                if _guard(run, ch, "deletion", lambda ch=ch: audit.deletion_recheck(
                        API, cfg, ch, cfg["channels"][ch], run, st, now), crashed):
                    run.performed(ch, "deletion")
        for ch in channels:
            if ch not in crashed:
                run.judged(ch + "/watcher-error")
            if not run.missing(ch) and ch not in crashed:
                run.judged(ch + "/config-invalid")
        for ch in crashed:
            # A crashed channel run proves nothing: withdraw EVERY judgment
            # this run made for that channel, so none of its findings is
            # cleared ("recovered") by it. Findings it observed still alert.
            run.checked = {k for k in run.checked if not k.startswith(ch + "/") or k in run.findings}
            run.done.pop(ch, None)
        evaluate_coverage(cfg, run, now)
        for ch in crashed:
            run.checked = {k for k in run.checked if not k.startswith(ch + "/") or k in run.findings}
        site_gen = None
        if remote(cfg):
            site_gen = write_site_cache(cfg, st, now)
        if cfg.get("confirmations"):
            try:
                confirm_releases(cfg, run, now, site_gen)
            except Exception as exc:  # noqa: BLE001 — never lose a run over a confirmation
                print("  ! confirmation step failed: %s" % exc, file=sys.stderr)
        preserved = run.preserved()
        if preserved:
            print("  ⋯ unresolved, not re-checked this run (kept, no recovery): %s" % ", ".join(sorted(preserved)))
        messages = run.flush(now)
        partial = {ch: run.missing(ch) for ch in channels if run.missing(ch)}
        st["last_run"] = now
        st["last_completed"] = now
        st["completed_total"] = int(st.get("completed_total", 0)) + 1
        hist = st.setdefault("rate_history", [])
        if BUDGET.min_seen is not None:
            hist.append([now, BUDGET.min_seen, BUDGET.requests])
        del hist[:-60]
        alerting = sorted(k for k, v in st["active"].items() if not v.get("report_only") and not v.get("held"))
        report_open = sorted(k for k, v in st["active"].items() if v.get("report_only"))
        held = sorted(k for k, v in st["active"].items() if v.get("held"))
        if not alerting and not partial and not preserved:
            st["last_clean"] = now
        prune_state(st)
        state.save()      # the evidence of every positive message is durable BEFORE it is sent
        messages += deliver_outbox(cfg, state)
        outbox = st.get("confirm_outbox") or []
        oldest = [x for x in [st.get("queued_since")] + [o["composed"] for o in outbox] if x is not None]
        state.write_beacon({
            "version": WATCH_VERSION, "completed": now, "completed_total": st["completed_total"],
            "findings": len([k for k in run.findings if not run.is_report_only(k)]) + len(preserved),
            "open": alerting, "report_only_open": report_open, "held": held,
            "coverage_warnings": sorted(k for k in alerting if "/coverage/" in k),
            "partial": partial, "queued": len(st["queued"]) + len(outbox), "oldest_queued": min(oldest) if oldest else None,
            "recorded": {c: {"tag": r["tag"], "sequence": r["sequence"]} for c, r in st["recorded"].items()},
            "rate_history": hist[-60:], "requests": BUDGET.requests, "rate_min": BUDGET.min_seen,
            "audit_mode": "report-only" if audit_report_only(cfg) else "alert",
            "audit_report_since": cfg.get("audit_report_since"),
            "baseline": {c: {"complete": bool((a.get("baseline") or {}).get("complete")),
                             "executions": len((a.get("baseline") or {}).get("executions") or [])}
                         for c, a in (st.get("audit") or {}).items()},
            "site_generation": site_gen,
            "pending_confirm": sorted(set(st.get("pending_confirm") or {}) | {o.get("channel") for o in outbox
                                                                                  if o.get("channel")})})
    finally:
        state.__exit__(None, None, None)
    print("check complete: %d finding(s), %d unresolved kept, %d partial channel(s), %d message(s), %d queued; "
          "%d GitHub request(s), lowest remaining %s"
          % (len(run.findings), len(preserved), len(partial), len(messages),
             len(state.data["queued"]) + len(state.data.get("confirm_outbox") or []),
             BUDGET.requests, BUDGET.min_seen))
    alerting_now = [k for k in run.findings if not run.is_report_only(k)]
    return 2 if (alerting_now or preserved) else 0


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


def cmd_acknowledge_finding(cfg, key):
    """Owner act, after inspecting it: close exactly one event-feed finding
    that describes a historical incident no later check can clear (a deleted
    tag, a non-v<semver> tag, a feed gap; an unconfirmed release that was
    deleted). It never touches release approval evidence or the recorded
    rollback floor. `event-release-unconfirmed/<tag>` normally needs no
    acknowledgment: it clears by itself once that release is recorded."""
    with State(cfg["state_dir"]) as state:
        st = state.data
        channel = key.split("/", 1)[0]
        aud = (st.get("audit") or {}).get(channel) or {}
        if key not in (aud.get("event_findings") or {}):
            print("✖ %s is not an open event-feed finding (open: %s)" % (
                key, ", ".join(sorted(aud.get("event_findings") or {})) or "none"))
            return 2
        aud["event_findings"].pop(key)
        st["active"].pop(key, None)
        st.setdefault("acknowledged", []).append({"key": key, "at": now_ts()})
        del st["acknowledged"][:-100]
        state.save()
    print("✔ %s acknowledged and closed" % key)
    return 0


def cmd_status(cfg):
    with State(cfg["state_dir"]) as state:
        print(json.dumps(state.data, indent=2, sort_keys=True))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("command", choices=["check", "status", "acknowledge-local", "acknowledge-finding"])
    ap.add_argument("args", nargs="*")
    ap.add_argument("--config", help="JSON config overriding DEFAULT_CONFIG")
    args = ap.parse_args(argv)
    cfg = load_config(args.config)
    global RETRY_DELAY
    RETRY_DELAY = float(cfg.get("retry_delay_seconds", RETRY_DELAY))   # selftests shorten the in-run retry pause
    if remote(cfg):
        install_no_exec_hook("Sentinel's checker")
        rv._PROVIDER = ("python", None)      # never try the openssl subprocess
        setup_logging(cfg)
    print("briglia release watch v%s (%s mode) — %s — %s" % (WATCH_VERSION, cfg.get("mode", "local"), args.command,
                                                            iso(now_ts())))
    try:
        if args.command == "acknowledge-local":
            if len(args.args) != 3:
                print("✖ usage: acknowledge-local <channel> <vX.Y.Z> <envelope sha256>")
                return 2
            return cmd_acknowledge_local(cfg, *args.args)
        if args.command == "acknowledge-finding":
            if len(args.args) != 1:
                print("✖ usage: acknowledge-finding <channel>/<key>")
                return 2
            return cmd_acknowledge_finding(cfg, args.args[0])
        if args.args:
            print("✖ %s takes no arguments" % args.command)
            return 2
        return {"check": cmd_check, "status": cmd_status}[args.command](cfg)
    except WatchError as exc:
        print("✖ %s" % exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
