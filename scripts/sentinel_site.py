#!/usr/bin/env python3
"""Sentinel's 5-minute website check (off-Mac watcher plan §5). No GitHub API.

    sentinel_site.py [--config PATH] [--status]

Every ~5 minutes, for each website hostname (briglia.dev and the Vercel
alias), with ZERO api.github.com requests:

  * /install.sh: the first hop must be exactly the expected redirect
    (https://github.com/permaevidence/briglia-cli/releases/latest/download/install.sh);
    the bytes behind it must equal the installer the hourly checker
    VERIFIED for the recorded release (sha256 + size from site-cache.json);
  * /ubuntu-touch: the page must link the recorded click URL(s).

A wrong redirect alerts at once. A content mismatch is excused ONLY by proof
that it is exactly the content of a newer release whose envelope
authenticates with the pinned key (app page: the candidate's signed click
URL; CLI installer: never — today's CLI manifest does not sign install.sh).
A proven app transition — and an unprovable CLI installer change while a
newer signed release is live — is held until a FIXED deadline: the next
scheduled hourly check (:23 local) after it was first seen, plus 20
minutes. At or after the deadline, unless site-cache.json has a NEW
generation that verifies exactly the fetched content, this job alerts by
itself — whether the hourly check failed, ran out of budget or never ran.

Independence: this job owns site-state.json, site.lock and site.beacon.json;
it only READS site-cache.json (written by the checker, carrying a
generation number). A result computed against an older generation is
discarded, never applied to the new cache. Network failures follow the
grace rule (3 consecutive checks). Messages: one when a finding opens, one
when it truly clears (a real passing check), never repeated per run.

`confirmation_evidence()` is the helper the hourly checker uses before a ✅:
its own fetch of every installer/page plus this job's current state and a
fresh beacon. It reads; it never writes this job's files.
"""

import argparse
import datetime
import fcntl
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
for _cand in (os.path.join(HERE, "py"), os.path.join(os.path.dirname(HERE), "py")):
    if os.path.isfile(os.path.join(_cand, "release_verify.py")):
        sys.path.insert(0, _cand)
        break
import release_verify as rv  # noqa: E402

SITE_VERSION = "1"
USER_AGENT = "briglia-sentinel-site/" + SITE_VERSION
MAX_FETCH = 4 * 1024 * 1024
ALLOWANCE = 20 * 60                 # fixed allowance after the next scheduled hourly check
LOG_MAX_BYTES = 1024 * 1024
DEFAULTS = {
    "mode": "local",
    "state_dir": "~/.config/briglia-release-watch",
    "telegram_env_file": "~/.claude/channels/telegram/.env",
    "telegram_api": "https://api.telegram.org",
    "transient_grace_checks": 3,
    "check_minute": 23,
    "site_beacon_max_minutes": 20,
    "site_log_file": None,
}
_BLOCKED = ("subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.spawn", "os.fork", "os.forkpty",
            "pty.spawn", "os.startfile")


def iso(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def local_hm(ts):
    return datetime.datetime.fromtimestamp(ts).strftime("%H:%M")


def load_config(path):
    cfg = dict(DEFAULTS)
    if path:
        with open(os.path.expanduser(path)) as f:
            user = json.load(f)
        for k in DEFAULTS:
            if k in user:
                cfg[k] = user[k]
    return cfg


class RotatingStream:
    def __init__(self, path, max_bytes=LOG_MAX_BYTES, keep=2):
        self.path, self.max_bytes, self.keep = path, max_bytes, keep
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)

    def write(self, text):
        try:
            if os.path.getsize(self.path) >= self.max_bytes:
                for i in range(self.keep, 0, -1):
                    src = self.path if i == 1 else "%s.%d" % (self.path, i - 1)
                    if os.path.exists(src):
                        os.replace(src, "%s.%d" % (self.path, i))
        except OSError:
            pass
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8", errors="replace") as f:
            f.write(text)
        return len(text)

    def flush(self):
        pass


def atomic_json(path, data):
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=1, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    dfd = os.open(os.path.dirname(path), os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


# ------------------------------------------------------------------ fetching

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def first_hop(url, timeout=30):
    """(status, Location or None) without following any redirect."""
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT}, method="GET")
    try:
        with opener.open(req, timeout=timeout) as resp:
            resp.read(1)
            return resp.status, None
    except urllib.error.HTTPError as exc:
        return exc.code, (exc.headers or {}).get("Location")


def fetch(url, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read(MAX_FETCH + 1)
            status = resp.status
    except urllib.error.HTTPError as exc:
        return exc.code, b""
    if len(data) > MAX_FETCH:
        raise ValueError("response from %s exceeds %d bytes" % (url, MAX_FETCH))
    return status, data


def is_network(exc):
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code >= 500 or exc.code == 429
    return isinstance(exc, (urllib.error.URLError, OSError, ConnectionError, TimeoutError))


def probe_installer(url, redirect, want):
    """→ (problem kind, text, fetched sha256 or None). kind ∈ ok | redirect |
    content | uncached | network | network-body.

    What each kind ESTABLISHES (check_site judges only that):
      ok            redirect correct, bytes verified
      redirect      first hop wrong (or unreadable) — content NOT checked
      uncached      redirect correct, nothing cached to compare — content NOT checked
      network       first hop unreachable — neither redirect nor content checked
      network-body  redirect correct, the bytes behind it unreachable — content NOT checked
      content       redirect correct, bytes WRONG"""
    try:
        status, loc = first_hop(url)
    except Exception as exc:  # noqa: BLE001
        return ("network" if is_network(exc) else "redirect"), "%s: %s" % (url, exc), None
    if status >= 500 or status == 429:
        return "network", "%s → HTTP %s" % (url, status), None
    if status not in (301, 302, 303, 307, 308) or loc != redirect:
        return "redirect", "%s first hop is HTTP %s → %r, expected a redirect to %s" % (url, status, loc, redirect), None
    if not want:
        return "uncached", "no verified installer cached for the recorded release yet", None
    try:
        s2, body = fetch(redirect)
    except Exception as exc:  # noqa: BLE001
        return ("network-body" if is_network(exc) else "content"), "%s: %s" % (redirect, exc), None
    if s2 >= 500 or s2 == 429:
        return "network-body", "%s → HTTP %s" % (redirect, s2), None
    got = hashlib.sha256(body).hexdigest()
    if s2 != 200 or got != want["sha256"] or len(body) != want["size"]:
        return "content", ("%s serves an installer (HTTP %s, sha256 %s…, %d bytes) that is NOT the verified one "
                           "(sha256 %s…, %d bytes)" % (url, s2, got[:12], len(body), want["sha256"][:12], want["size"])), got
    return "ok", "", got


def probe_page(url, click_urls):
    try:
        s, page = fetch(url)
    except Exception as exc:  # noqa: BLE001
        return ("network" if is_network(exc) else "content"), "%s: %s" % (url, exc), None
    if s >= 500 or s == 429:
        return "network", "%s → HTTP %s" % (url, s), None
    if s != 200:
        return "content", "%s → HTTP %s" % (url, s), page
    if not click_urls or not all(u.encode() in page for u in click_urls):
        return "content", "%s does not link the verified click %s" % (url, ", ".join(click_urls or ["?"])), page
    return "ok", "", page


def candidate(entry, now):
    """A newer release whose envelope authenticates with the PINNED key
    (github.com download URL, never the API) → its manifest, else None."""
    base = rv.CLI_POLICY if entry.get("kind") == "cli" else rv.APP_POLICY
    policy = base
    if entry.get("envelope_url") or entry.get("artifact_url_prefix"):
        policy = rv.ReleasePolicy(base.channel, {k: v.hex() for k, v in base.keys.items()},
                                  entry.get("envelope_url") or base.envelope_url,
                                  entry.get("artifact_url_prefix") or base.artifact_url_prefix, base.min_sequence)
    try:
        raw = rv.bounded_fetch(policy.envelope_url, rv.MAX_ENVELOPE_BYTES)
        m = rv.verify_envelope(raw, policy, now)
    except Exception:  # noqa: BLE001 — no authenticated candidate is simply "no excuse"
        return None
    return m if m["sequence"] > entry["sequence"] else None


def next_deadline(first, minute):
    d = datetime.datetime.fromtimestamp(first)
    cand = d.replace(minute=int(minute), second=0, microsecond=0)
    if cand <= d:
        cand += datetime.timedelta(hours=1)
    return time.mktime(cand.timetuple()) + ALLOWANCE


def read_cache(state_dir):
    path = os.path.join(state_dir, "site-cache.json")
    with open(path) as f:
        c = json.load(f)
    if not isinstance(c, dict) or not isinstance(c.get("generation"), int) or not isinstance(c.get("content"), dict) \
            or not isinstance(c["content"].get("channels"), dict):
        raise ValueError("site-cache.json has an unexpected shape")
    return c


# ------------------------------------------------------------------ telegram

def telegram_credentials(cfg):
    path = os.path.expanduser(cfg["telegram_env_file"])
    if cfg.get("mode") == "remote":
        real = os.path.realpath(path)
        if "/.claude/" in real + "/":
            raise RuntimeError("remote mode refuses the Claude Code Telegram credentials")
        st = os.stat(real)
        if st.st_mode & 0o077 or st.st_uid != os.geteuid():
            raise RuntimeError("telegram env file %s must be 0600 and owned by this user" % path)
    token = chat = None
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line.startswith("TELEGRAM_BOT_TOKEN="):
                token = line.split("=", 1)[1].strip().strip('"').strip("'")
            elif line.startswith("OWNER_CHAT_ID="):
                chat = line.split("=", 1)[1].strip().strip('"').strip("'")
    if not token or not chat:
        raise RuntimeError("telegram env file lacks TELEGRAM_BOT_TOKEN / OWNER_CHAT_ID")
    return token, chat


def send_telegram(cfg, text):
    token = None
    try:
        token, chat = telegram_credentials(cfg)
        body = json.dumps({"chat_id": chat, "text": text[:4000], "disable_web_page_preview": True}).encode()
        req = urllib.request.Request(cfg["telegram_api"] + "/bot" + token + "/sendMessage", data=body, method="POST",
                                     headers={"User-Agent": USER_AGENT, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                status, raw = resp.status, resp.read(65536)
        except urllib.error.HTTPError as exc:
            status, raw = exc.code, (exc.read(65536) if exc.fp else b"")
        return status == 200 and json.loads(raw.decode("utf-8", "replace")).get("ok") is True
    except Exception as exc:  # noqa: BLE001
        msg = str(exc)
        if token:
            msg = msg.replace(token, "[TOKEN]")
        print("  ! telegram delivery failed: %s" % msg, file=sys.stderr)
        return False


# ----------------------------------------------------------------------- run

# What a probe kind establishes about the redirect / the content (see probe_installer).
_REDIRECT_KNOWN = {"ok", "redirect", "uncached", "network-body", "content"}
_CONTENT_KNOWN = {"ok", "content"}


def check_site(cfg, cache, st, now):
    """→ (findings {key: (text, network?)}, judged keys).

    A key is judged — and so may be cleared with a "recovered" message —
    only when THIS run established every predicate its finding is about, for
    every URL of the channel: site-redirect needs every first hop answered;
    site-content needs every installer's bytes / every page actually fetched
    and compared. A valid redirect never proves the content; an unreachable
    first hop proves neither. Adverse findings found are always reported. A
    held transition closes only when the content was verified on every URL."""
    findings, judged = {}, set()
    trans = st.setdefault("transitions", {})
    content = cache["content"]
    minute = content.get("check_minute", cfg["check_minute"])
    for channel, entry in sorted(content["channels"].items()):
        problems = []          # (kind, text, fetched digest[, page bytes])
        redirect_known = content_known = True
        if entry.get("website_install_url"):
            for url in entry["website_install_url"]:
                kind, text, got = probe_installer(url, entry.get("redirect"), entry.get("installer"))
                redirect_known = redirect_known and kind in _REDIRECT_KNOWN
                content_known = content_known and kind in _CONTENT_KNOWN
                if kind != "ok":
                    problems.append(("network" if kind == "network-body" else kind, text, got))
                else:
                    print("  ✔ %s serves the verified installer" % url)
        if entry.get("website_page_url"):
            for url in entry["website_page_url"]:
                kind, text, page = probe_page(url, entry.get("click_urls"))
                content_known = content_known and kind in _CONTENT_KNOWN
                if kind != "ok":
                    problems.append((kind, text, hashlib.sha256(page).hexdigest() if page else None, page))
                else:
                    print("  ✔ %s links the verified click" % url)
        rkey, ckey, nkey, ukey = (channel + "/site-redirect", channel + "/site-content", channel + "/site-unreachable",
                                  channel + "/site-uncached")
        redirect = [p for p in problems if p[0] == "redirect"]
        contentp = [p for p in problems if p[0] == "content"]
        network = [p for p in problems if p[0] == "network"]
        uncached = [p for p in problems if p[0] == "uncached"]
        judged.add(nkey)                   # every host answered ⇔ no network finding
        if redirect_known:
            judged.add(rkey)
        if content_known:
            judged.add(ckey)
        if entry.get("installer") or not entry.get("website_install_url"):
            judged.add(ukey)               # a cached installer disproves 'uncached' by itself
        if redirect:                       # always checked independently, never excused
            findings[rkey] = ("; ".join(p[1] for p in redirect), False)
        if network:
            findings[nkey] = ("; ".join(p[1] for p in network), True)
        if uncached:
            findings[ukey] = (uncached[0][1], True)
        if not contentp:
            if content_known:
                trans.pop(channel, None)   # content verified on EVERY URL: any transition closes, quietly
            continue                       # otherwise a held transition keeps its fixed deadline
        cand = candidate(entry, now)
        excusable = False
        if cand is not None and entry.get("kind") == "app":
            signed = [a["url"] for a in cand["platforms"].values()]
            excusable = all(len(p) > 3 and p[3] is not None and all(u.encode() in p[3] for u in signed)
                            for p in contentp)
        held = cand is not None and (excusable or entry.get("kind") == "cli")
        t = trans.get(channel)
        if held:
            if t is None:
                t = trans[channel] = {"first": now, "deadline": next_deadline(now, minute),
                                      "candidate_sequence": cand["sequence"], "generation": cache["generation"],
                                      "kind": "proven" if excusable else "unverified"}
            t["candidate_sequence"] = max(t["candidate_sequence"], cand["sequence"])   # never extends the deadline
            if now < t["deadline"]:
                judged.discard(ckey)       # deferred: neither raised nor cleared until the deadline
                print("  ⋯ %s: website differs while newer signed release seq %d is live — held until %s (%s)"
                      % (channel, cand["sequence"], local_hm(t["deadline"]),
                         "content proven" if excusable else "installer NOT provable: CLI manifest does not sign install.sh"))
                continue
            findings[ckey] = ("%s — still not verified by the hourly check at the fixed deadline %s (first seen %s; newer "
                              "signed release seq %d is live%s)" % ("; ".join(p[1] for p in contentp), local_hm(t["deadline"]),
                                                                    local_hm(t["first"]), t["candidate_sequence"],
                                                                    "" if excusable else ", but its installer is not signed"),
                              False)
        else:
            findings[ckey] = ("; ".join(p[1] for p in contentp), False)
    return findings, judged


def apply(cfg, st, findings, judged, now):
    grace = max(1, int(cfg.get("transient_grace_checks", 3)))
    active = st.setdefault("active", {})
    msgs = []
    for key, (text, net) in findings.items():
        prev = active.get(key)
        if prev is None:
            prev = active[key] = {"first": now, "text": text, "count": 0, "notified": False}
        prev["count"] = int(prev.get("count", 0)) + 1
        prev["text"] = text
        if not prev.get("notified") and (not net or prev["count"] >= grace):
            prev["notified"] = True
            msgs.append("🚨 Sentinel website check — %s\n%s" % (key, text))
    for key in list(active):
        if key not in findings and key in judged:
            gone = active.pop(key)
            if gone.get("notified"):
                msgs.append("✅ Sentinel website check — recovered: %s (since %s)" % (key, iso(gone["first"])))
    return msgs


def run(cfg, now=None):
    now = time.time() if now is None else now
    sd = os.path.expanduser(cfg["state_dir"])
    os.makedirs(sd, mode=0o700, exist_ok=True)
    lock = os.open(os.path.join(sd, "site.lock"), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(lock)
        print("✖ another site run holds site.lock")
        return 1
    try:
        sp = os.path.join(sd, "site-state.json")
        try:
            with open(sp) as f:
                st = json.load(f)
            if not isinstance(st, dict) or not isinstance(st.get("active", {}), dict):
                raise ValueError("shape")
        except FileNotFoundError:
            st = {}
        except Exception:  # noqa: BLE001
            st = {"note": "site-state.json was unreadable at %s; rebuilt" % iso(now)}
        st.setdefault("active", {})
        st.setdefault("queued", [])
        try:
            cache = read_cache(sd)
        except Exception as exc:  # noqa: BLE001 — not checked; alerts after the grace period
            findings = {"site/cache-unavailable": ("site-cache.json missing or unreadable (%s) — website NOT checked"
                                                   % type(exc).__name__, True)}
            msgs = apply(cfg, st, findings, set(), now)
            gen = None
        else:
            gen = cache["generation"]
            findings, judged = check_site(cfg, cache, st, now)
            judged.add("site/cache-unavailable")
            try:
                gen_now = read_cache(sd)["generation"]
            except Exception:  # noqa: BLE001
                gen_now = None
            if gen_now != gen:
                print("  ⋯ site-cache.json changed during this run (generation %s → %s) — results discarded" % (gen, gen_now))
                return 0
            msgs = apply(cfg, st, findings, judged, now)
        pending = list(st["queued"]) + msgs
        st["queued"] = []
        for m in pending:
            if not send_telegram(cfg, m):
                st["queued"].append(m)
        del st["queued"][:-100]
        st["completed_total"] = int(st.get("completed_total", 0)) + 1
        st["last_completed"] = now
        atomic_json(sp, st)
        atomic_json(os.path.join(sd, "site.beacon.json"), {
            "version": SITE_VERSION, "completed": now, "generation": gen, "completed_total": st["completed_total"],
            "open": sorted(k for k, v in st["active"].items() if v.get("notified")),
            "pending": sorted(k for k, v in st["active"].items() if not v.get("notified")),
            "transitions": {c: {"candidate_sequence": t["candidate_sequence"], "deadline": t["deadline"]}
                            for c, t in st.get("transitions", {}).items()},
            "queued": len(st["queued"])})
        print("site check complete: generation %s, %d finding(s), %d message(s)" % (gen, len(findings), len(msgs)))
        return 2 if any(v.get("notified") for v in st["active"].values()) else 0
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN)
        os.close(lock)


# --------------------------------------------------- helper for the checker's ✅

def confirmation_evidence(cfg, channel, rec, st, now, site_gen):
    """(ok, why). Called by release_watch.py before a ✅: its own fetch of
    every installer and page of `channel` matches the release it confirms,
    the site job has no open finding or foreign transition for `channel`,
    and its beacon is fresh and readable."""
    sd = os.path.expanduser(cfg["state_dir"])
    max_age = float(cfg.get("site_beacon_max_minutes", 20)) * 60
    try:
        with open(os.path.join(sd, "site.beacon.json")) as f:
            b = json.load(f)
        completed = float(b["completed"])
    except Exception:  # noqa: BLE001
        return False, "the website job's beacon is missing or unreadable"
    if now - completed > max_age or completed > now + 600:
        return False, "the website job's beacon is stale (last %s)" % iso(completed)
    try:
        with open(os.path.join(sd, "site-state.json")) as f:
            ss = json.load(f)
    except Exception:  # noqa: BLE001
        return False, "the website job's state is unreadable"
    open_site = [k for k, v in (ss.get("active") or {}).items() if k.startswith(channel + "/") or k.startswith("site/")]
    if open_site:
        return False, "open website finding(s): %s" % ", ".join(sorted(open_site))
    t = (ss.get("transitions") or {}).get(channel)
    if t and t.get("candidate_sequence") != rec["sequence"]:
        return False, "an unrelated website transition is open (candidate seq %s)" % t.get("candidate_sequence")
    chan = cfg["channels"][channel]

    def urls(v):
        return [v] if isinstance(v, str) else list(v or [])
    if chan.get("installer_asset"):
        iv = (st.get("installer_verified") or {}).get(channel)
        if not iv or iv.get("tag") != rec["tag"]:
            return False, "no verified installer for %s" % rec["tag"]
        for url in urls(chan.get("website_install_url")):
            kind, text, _ = probe_installer(url, chan.get("website_redirect"), iv)
            if kind != "ok":
                return False, "own website fetch: " + text
    for url in urls(chan.get("website_page_url")):
        kind, text, _ = probe_page(url, [a["url"] for a in rec["assets"].values()])
        if kind != "ok":
            return False, "own website fetch: " + text
    return True, ""


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--config")
    ap.add_argument("--status", action="store_true")
    a = ap.parse_args(argv)
    cfg = load_config(a.config)
    if cfg.get("mode") == "remote":
        def hook(event, args):
            if event in _BLOCKED:
                raise PermissionError("Sentinel's site job never starts processes (blocked %s)" % event)
        sys.addaudithook(hook)
        rv._PROVIDER = ("python", None)
        if cfg.get("site_log_file"):
            sys.stdout = sys.stderr = RotatingStream(os.path.expanduser(cfg["site_log_file"]))
    print("sentinel site v%s — %s" % (SITE_VERSION, iso(time.time())))
    if a.status:
        sd = os.path.expanduser(cfg["state_dir"])
        for n in ("site.beacon.json", "site-state.json", "site-cache.json"):
            try:
                print("— %s —\n%s" % (n, open(os.path.join(sd, n)).read().rstrip()))
            except Exception as exc:  # noqa: BLE001
                print("— %s — (unreadable: %s)" % (n, exc))
        return 0
    return run(cfg)


if __name__ == "__main__":
    sys.exit(main())
