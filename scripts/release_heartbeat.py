#!/usr/bin/env python3
"""Independent heartbeat and daily status for the release-channel watcher
(RELEASE_SIGNING_PLAN.md §10; off-Mac watcher plan §4.4 and §8).

Alerts a human over Telegram when `release_watch.py check` has stopped
completing — and, on Sentinel, when the 5-minute website job
(sentinel_site.py) has stopped. It is deliberately DISJOINT from both jobs
so that whatever breaks them cannot also silence the report about it:

  * standard library only — it never imports release_watch.py,
    sentinel_site.py or py/release_verify.py;
  * it reads only the jobs' completion beacons (`check.beacon.json`,
    `site.beacon.json`), never their state files or locks;
  * it keeps its own bookkeeping in `heartbeat-state.json` under its own
    lock, and writes its own beacon `heartbeat.beacon.json` (read by the
    daily status). If its own state is unreadable it still alerts — with an
    empty memory and a note — rather than exit;
  * the config file is optional and tolerated: a missing or corrupt config
    falls back to the built-in defaults and is mentioned in the alert.

The one thing it shares with the checker is the Telegram bot credential
file; a missing credential file is reported on stderr and by the exit code.

    release_heartbeat.py [--config PATH] [--status]
    release_heartbeat.py --daily [--config PATH]      # Sentinel, 09:00

Alert conditions: no beacon, unreadable or implausible beacon, beacon older
than its limit (`heartbeat_max_age_hours` for the hourly check,
`site_beacon_max_minutes` for the site job when configured), or the checker
reporting undelivered alerts queued for longer than the window. One message
when a condition opens, one when it clears; a condition is re-sent only
when its KIND changes or, if `realert_hours` > 0, after that long.

`--daily` reads the three beacons and sends one status: "✅ All checks
complete", "⚠️ Incomplete" or "🚨 Findings", with honest counts (hourly
checks completed vs scheduled, site checks completed, recorded releases,
open findings and coverage warnings, the report-only signing-audit count,
the lowest GitHub budget seen). A stale, missing or unreadable beacon is
never clean. A MISSING daily status means Sentinel or Mac 2 is down.

Optional dead-man URL (`deadman_url`, e.g. a healthchecks.io check, off
until configured): every heartbeat pings it when healthy and pings
`<url>/fail` when alerting. It catches outages, not dishonesty.
Exit 0 = healthy, 2 = alerting, 1 = the heartbeat itself could not run.
"""

import argparse
import datetime
import fcntl
import json
import os
import sys
import time
import urllib.error
import urllib.request

HEARTBEAT_VERSION = "2"
USER_AGENT = "briglia-release-heartbeat/" + HEARTBEAT_VERSION
BEACON_NAME = "check.beacon.json"
SITE_BEACON_NAME = "site.beacon.json"
OWN_BEACON_NAME = "heartbeat.beacon.json"
STATE_NAME = "heartbeat-state.json"
DAILY_STATE_NAME = "daily-state.json"
LOCK_NAME = "heartbeat.lock"
DAILY_LOCK_NAME = "daily.lock"
FUTURE_SLACK = 600          # a beacon "completed" more than 10 min in the future is corrupt
REPORT_ONLY_DAYS = 14
LOG_MAX_BYTES = 1024 * 1024
_BLOCKED = ("subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.spawn", "os.fork", "os.forkpty",
            "pty.spawn", "os.startfile")

DEFAULTS = {
    "mode": "local",
    "state_dir": "~/.config/briglia-release-watch",
    "telegram_env_file": "~/.claude/channels/telegram/.env",
    "telegram_api": "https://api.telegram.org",
    "heartbeat_max_age_hours": 3,
    "realert_hours": 6,
    "site_beacon_max_minutes": None,      # Sentinel: 20
    "heartbeat_beacon_max_minutes": 15,
    "check_minute": None,                 # Sentinel: 23 (counts scheduled hourly checks)
    "deadman_url": None,
    "heartbeat_log_file": None,
    "daily_log_file": None,
    "signing_audit_alerts": True,
    "audit_report_since": None,
    "installer_hint": "sudo /usr/bin/python3 -I install_sentinel.py --audit-alerts on",
}


def iso(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def local_hm(ts):
    return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")


# ------------------------------------------------------------------ config

def load_config(path):
    """Defaults overlaid with the file; returns (cfg, problem_or_None).
    Never raises: the heartbeat must run with a broken config."""
    cfg = dict(DEFAULTS)
    if not path:
        return cfg, None
    try:
        with open(os.path.expanduser(path)) as f:
            user = json.load(f)
        if not isinstance(user, dict):
            raise ValueError("top level is not an object")
    except Exception as exc:  # noqa: BLE001
        return cfg, "config %s unreadable (%s: %s) — using built-in defaults" % (path, type(exc).__name__, exc)
    for k in DEFAULTS:
        if k in user:
            cfg[k] = user[k]
    try:
        float(cfg["heartbeat_max_age_hours"]); float(cfg["realert_hours"] or 0)
        str(cfg["state_dir"]); str(cfg["telegram_env_file"]); str(cfg["telegram_api"])
        if cfg["site_beacon_max_minutes"] is not None:
            float(cfg["site_beacon_max_minutes"])
    except Exception as exc:  # noqa: BLE001
        return dict(DEFAULTS), "config %s has invalid values (%s) — using built-in defaults" % (path, exc)
    return cfg, None


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


def rotate_stray_logs(state_dir, max_bytes=LOG_MAX_BYTES, keep=2):
    """launchd's own stdout/stderr files (interpreter-level crashes only)
    are rotated here, so no Sentinel file grows without bound."""
    logs = os.path.join(state_dir, "logs")
    try:
        names = os.listdir(logs)
    except OSError:
        return
    for n in names:
        p = os.path.join(logs, n)
        if n.startswith("launchd-") and n.endswith(".log"):
            try:
                if os.path.getsize(p) >= max_bytes:
                    for i in range(keep, 0, -1):
                        src = p if i == 1 else "%s.%d" % (p, i - 1)
                        if os.path.exists(src):
                            os.replace(src, "%s.%d" % (p, i))
            except OSError:
                pass


# ---------------------------------------------------------------- telegram

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
        raise RuntimeError("telegram env file %s lacks TELEGRAM_BOT_TOKEN / OWNER_CHAT_ID" % path)
    return token, chat


def send_telegram(cfg, text):
    """True when Telegram confirmed delivery. Never raises; never logs the token."""
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


def ping_deadman(cfg, healthy):
    url = cfg.get("deadman_url")
    if not url:
        return
    if not str(url).startswith("https://") and "127.0.0.1" not in str(url):
        print("  ! deadman_url must be https:// — not pinged", file=sys.stderr)
        return
    try:
        req = urllib.request.Request(url.rstrip("/") + ("" if healthy else "/fail"), headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=15) as resp:
            resp.read(1024)
    except Exception as exc:  # noqa: BLE001 — the dead-man service notices the missing ping itself
        print("  ! dead-man ping failed: %s" % exc, file=sys.stderr)


# ------------------------------------------------------------------- state

def atomic_write_json(path, data):
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    dfd = os.open(os.path.dirname(path) or ".", os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def load_own_state(path):
    """(state, problem_or_None). Unreadable own state → empty memory + note."""
    empty = {"version": HEARTBEAT_VERSION, "active": None, "active_site": None, "queued": []}
    if not os.path.exists(path):
        return empty, None
    try:
        with open(path) as f:
            st = json.load(f)
        if not isinstance(st, dict) or not isinstance(st.get("queued", []), list):
            raise ValueError("unexpected shape")
        for k in ("active", "active_site"):
            if st.get(k) is not None and not isinstance(st[k], dict):
                raise ValueError("unexpected shape")
            st.setdefault(k, None)
        st.setdefault("queued", [])
        st["queued"] = [m for m in st["queued"] if isinstance(m, str)]
        return st, None
    except Exception as exc:  # noqa: BLE001
        return empty, "own state %s unreadable (%s) — continuing with empty memory" % (path, type(exc).__name__)


# ------------------------------------------------------------------ beacon

def read_json(path):
    with open(path) as f:
        return json.load(f)


def read_beacon(state_dir, now, max_age):
    """(problem_or_None, kind, beacon_or_None) for the hourly checker."""
    path = os.path.join(state_dir, BEACON_NAME)
    if not os.path.exists(path):
        return "the hourly check has NEVER completed (no %s in %s)" % (BEACON_NAME, state_dir), "never", None
    try:
        b = read_json(path)
        completed = float(b["completed"])
    except Exception as exc:  # noqa: BLE001
        return ("the check's completion beacon %s is unreadable (%s) — the checker may be crashing mid-run"
                % (path, type(exc).__name__)), "unreadable", None
    if completed > now + FUTURE_SLACK:
        return "the completion beacon claims a time in the future (%s) — clock or corruption problem" % iso(completed), "future", b
    age = now - completed
    if age > max_age:
        return ("the hourly check has not completed since %s (%.1f h ago, limit %.2f h). "
                "The watcher itself may be broken or the Mac may be offline." % (iso(completed), age / 3600, max_age / 3600)), "stale", b
    queued = b.get("queued") or 0
    oldest = b.get("oldest_queued")
    if isinstance(queued, int) and queued > 0 and isinstance(oldest, (int, float)) and now - oldest > max_age:
        return ("the check completes but has %d undelivered alert(s) queued since %s — the checker cannot reach Telegram; "
                "read its log" % (queued, iso(oldest))), "undelivered", b
    return None, None, b


def read_site_beacon(state_dir, now, max_age):
    path = os.path.join(state_dir, SITE_BEACON_NAME)
    if not os.path.exists(path):
        return "the 5-minute website check has NEVER completed (no %s)" % SITE_BEACON_NAME, "never", None
    try:
        b = read_json(path)
        completed = float(b["completed"])
    except Exception as exc:  # noqa: BLE001
        return "the website check's beacon is unreadable (%s)" % type(exc).__name__, "unreadable", None
    if completed > now + FUTURE_SLACK:
        return "the website check's beacon claims a future time (%s)" % iso(completed), "future", b
    if now - completed > max_age:
        return ("the 5-minute website check has not completed since %s (%.0f min ago, limit %.0f min)"
                % (iso(completed), (now - completed) / 60, max_age / 60)), "stale", b
    return None, None, b


# ---------------------------------------------------------------------- run

def _transition(st, slot, problem, kind, now, realert, label, notes):
    """One message when a condition opens, one when it clears; again only
    when its kind changes or after realert (0 = never)."""
    msgs = []
    prev = st.get(slot)
    if problem:
        text = problem + "".join("\n(note: %s)" % n for n in notes)
        if prev is None:
            st[slot] = {"first": now, "last_sent": now, "text": problem, "kind": kind}
            msgs.append("🚨 %s — %s" % (label, text))
        elif prev.get("kind") != kind or (realert and now - float(prev.get("last_sent", 0)) >= realert):
            prev.update(last_sent=now, text=problem, kind=kind)
            msgs.append("🚨 %s — STILL FAILING since %s — %s" % (label, iso(float(prev.get("first", now))), text))
        else:
            prev["text"] = problem
        print("  ✖ %s" % problem)
    elif prev:
        st[slot] = None
        msgs.append("✅ %s — completing again (failing since %s)" % (label, iso(float(prev.get("first", now)))))
    return msgs


def run(cfg, cfg_problem, now=None):
    now = time.time() if now is None else now
    state_dir = os.path.expanduser(cfg["state_dir"])
    os.makedirs(state_dir, mode=0o700, exist_ok=True)
    lock_fd = os.open(os.path.join(state_dir, LOCK_NAME), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(lock_fd)
        print("✖ another heartbeat run holds %s" % os.path.join(state_dir, LOCK_NAME))
        return 1
    try:
        rotate_stray_logs(state_dir)
        state_path = os.path.join(state_dir, STATE_NAME)
        st, state_problem = load_own_state(state_path)
        max_age = float(cfg["heartbeat_max_age_hours"]) * 3600
        realert = float(cfg["realert_hours"] or 0) * 3600
        notes = [n for n in (cfg_problem, state_problem) if n]
        problem, kind, beacon = read_beacon(state_dir, now, max_age)
        messages = _transition(st, "active", problem, kind, now, realert, "briglia release heartbeat", notes)
        if not problem:
            print("  ✔ last check completed %s (%s finding(s), %s queued)"
                  % (iso(float(beacon["completed"])), beacon.get("findings"), beacon.get("queued")))
        site_problem = None
        if cfg.get("site_beacon_max_minutes") is not None:
            site_problem, skind, sb = read_site_beacon(state_dir, now, float(cfg["site_beacon_max_minutes"]) * 60)
            messages += _transition(st, "active_site", site_problem, skind, now, realert,
                                    "briglia release heartbeat (website job)", notes)
            if not site_problem:
                print("  ✔ last website check completed %s" % iso(float(sb["completed"])))
        for n in notes:
            print("  ! %s" % n, file=sys.stderr)
        pending = list(st["queued"]) + messages
        st["queued"] = []
        for m in pending:
            if not send_telegram(cfg, m):
                st["queued"].append(m)
        del st["queued"][:-100]
        st["last_run"] = now
        st["completed_total"] = int(st.get("completed_total", 0)) + 1
        st["version"] = HEARTBEAT_VERSION
        alerting = bool(problem or site_problem)
        try:
            atomic_write_json(state_path, st)
            atomic_write_json(os.path.join(state_dir, OWN_BEACON_NAME),
                              {"version": HEARTBEAT_VERSION, "completed": now, "completed_total": st["completed_total"],
                               "alerting": alerting, "queued": len(st["queued"])})
        except Exception as exc:  # noqa: BLE001 — the alert (if any) was already attempted; say so and go on
            print("  ! could not persist heartbeat state: %s" % exc, file=sys.stderr)
        ping_deadman(cfg, not alerting)
        print("heartbeat: %s — %d message(s) sent, %d queued" % ("ALERT" if alerting else "ok",
                                                                len(pending) - len(st["queued"]), len(st["queued"])))
        return 2 if alerting else 0
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


# -------------------------------------------------------------------- daily

def scheduled_between(start, end, minute):
    """How many :MM local-time boundaries fall in (start, end]."""
    if minute is None or end <= start:
        return None
    d = datetime.datetime.fromtimestamp(start).replace(minute=int(minute), second=0, microsecond=0)
    if time.mktime(d.timetuple()) <= start:
        d += datetime.timedelta(hours=1)
    n = 0
    while time.mktime(d.timetuple()) <= end and n < 10000:
        n += 1
        d += datetime.timedelta(hours=1)
    return n


def daily(cfg, cfg_problem, now=None):
    now = time.time() if now is None else now
    sd = os.path.expanduser(cfg["state_dir"])
    os.makedirs(sd, mode=0o700, exist_ok=True)
    lock_fd = os.open(os.path.join(sd, DAILY_LOCK_NAME), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(lock_fd)
        print("✖ another daily run holds the lock")
        return 1
    try:
        dpath = os.path.join(sd, DAILY_STATE_NAME)
        try:
            ds = read_json(dpath)
            if not isinstance(ds, dict):
                raise ValueError
        except Exception:  # noqa: BLE001
            ds = {}
        since = float(ds.get("last") or now - 86400)
        level = 0          # 0 clean, 1 incomplete, 2 findings
        lines = []
        # hourly checker
        max_age = float(cfg["heartbeat_max_age_hours"]) * 3600
        problem, _, b = read_beacon(sd, now, max_age)
        if problem:
            level = max(level, 1)
            lines.append("Hourly check: " + problem)
        b = b or {}
        total = b.get("completed_total") if isinstance(b.get("completed_total"), int) else None
        done = (total - int(ds["check_total"])) if total is not None and isinstance(ds.get("check_total"), int) else None
        eligible = scheduled_between(since, now, cfg.get("check_minute"))
        lines.insert(0, "Hourly checks completed: %s of %s scheduled since %s" % (
            "?" if done is None else done, "?" if eligible is None else eligible, local_hm(since)))
        if done is None or (eligible is not None and done < eligible):
            level = max(level, 1)
        # website job
        site_total = None
        if cfg.get("site_beacon_max_minutes") is not None:
            sp, _, sb = read_site_beacon(sd, now, float(cfg["site_beacon_max_minutes"]) * 60)
            sb = sb or {}
            site_total = sb.get("completed_total") if isinstance(sb.get("completed_total"), int) else None
            sdone = (site_total - int(ds["site_total"])) if site_total is not None and isinstance(ds.get("site_total"), int) else None
            lines.append("Website checks completed: %s" % ("?" if sdone is None else sdone))
            if sp:
                level = max(level, 1)
                lines.append("Website job: " + sp)
            if sb.get("open"):
                level = 2
                lines.append("Open website finding(s): " + ", ".join(sb["open"]))
            if sb.get("pending") or sb.get("transitions"):
                level = max(level, 1)
                lines.append("Website, pending (not yet alerts): %s" % ", ".join(
                    list(sb.get("pending") or []) + ["%s release transition" % c for c in (sb.get("transitions") or {})]))
        # heartbeat itself
        try:
            hb = read_json(os.path.join(sd, OWN_BEACON_NAME))
            if now - float(hb["completed"]) > float(cfg.get("heartbeat_beacon_max_minutes") or 15) * 60:
                level = max(level, 1)
                lines.append("Heartbeat: last run %s — stale" % iso(float(hb["completed"])))
            elif hb.get("alerting"):
                level = 2
                lines.append("Heartbeat is alerting (see earlier messages)")
        except Exception:  # noqa: BLE001
            level = max(level, 1)
            lines.append("Heartbeat beacon missing or unreadable")
        # releases, findings, coverage, budget
        rec = b.get("recorded") or {}
        if rec:
            lines.append("Recorded: " + "; ".join("%s %s seq %s" % (c, r.get("tag"), r.get("sequence"))
                                                  for c, r in sorted(rec.items())))
        if b.get("open"):
            level = 2
            lines.append("Open finding(s): " + ", ".join(b["open"]))
        if b.get("coverage_warnings"):
            level = max(level, 1)
        if b.get("partial"):
            level = max(level, 1)
            lines.append("Last run not complete for: " + "; ".join("%s (%s)" % (c, ", ".join(v))
                                                                   for c, v in sorted(b["partial"].items())))
        for c, bl in sorted((b.get("baseline") or {}).items()):
            if not bl.get("complete"):
                level = max(level, 1)
                lines.append("%s: legacy signing baseline still being recorded" % c)
        if b.get("pending_confirm"):
            lines.append("Release(s) seen, ✅ not yet sent: " + ", ".join(b["pending_confirm"]))
        ro = b.get("report_only_open") or []
        # the config is authoritative for the mode and its start date (the
        # beacon only carries what the last check saw)
        report_only = cfg.get("signing_audit_alerts") is False or (
            cfg.get("signing_audit_alerts") is None and b.get("audit_mode") == "report-only")
        if report_only:
            start = cfg.get("audit_report_since") or b.get("audit_report_since")
            lines.append("Signing audit (report-only%s): %d open item(s)%s" % (
                " since " + start if start else "", len(ro), " — see audit-report.log" if ro else ""))
            try:
                started = datetime.datetime.strptime(start, "%Y-%m-%d").timestamp() if start else None
            except ValueError:
                started = None
            if started is not None and now - started >= REPORT_ONLY_DAYS * 86400:
                lines.append("The %d-day report-only period is over. Switching the signing audit to alerts is explicit, "
                             "never automatic: %s" % (REPORT_ONLY_DAYS, cfg.get("installer_hint")))
        hist = [h for h in (b.get("rate_history") or []) if isinstance(h, list) and len(h) >= 2 and h[0] > since]
        if hist:
            lines.append("Lowest GitHub budget seen: %s of 60" % min(h[1] for h in hist))
        if cfg_problem:
            lines.append("Note: " + cfg_problem)
        head = ["✅ All checks complete", "⚠️ Incomplete", "🚨 Findings"][level]
        msg = "%s — Sentinel daily status %s\n%s" % (head, local_hm(now), "\n".join("• " + l for l in lines))
        print(msg)
        pending = list(ds.get("queued") or []) + [msg]
        queued = [m for m in pending if not send_telegram(cfg, m)]
        ds = {"last": now, "check_total": total, "site_total": site_total, "queued": queued[-10:], "level": level}
        atomic_write_json(dpath, ds)
        return 0 if level == 0 else 2
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--config", help="watcher config JSON (optional; tolerated when unreadable)")
    ap.add_argument("--status", action="store_true", help="print the beacons and the heartbeat's own state")
    ap.add_argument("--daily", action="store_true", help="send the daily status")
    args = ap.parse_args(argv)
    cfg, cfg_problem = load_config(args.config)
    if cfg.get("mode") == "remote":
        def hook(event, a):
            if event in _BLOCKED:
                raise PermissionError("Sentinel's heartbeat never starts processes (blocked %s)" % event)
        sys.addaudithook(hook)
        logf = cfg.get("daily_log_file" if args.daily else "heartbeat_log_file")
        if logf:
            sys.stdout = sys.stderr = RotatingStream(os.path.expanduser(logf))
    print("briglia release heartbeat v%s — %s" % (HEARTBEAT_VERSION, iso(time.time())))
    if args.status:
        state_dir = os.path.expanduser(cfg["state_dir"])
        for name in (BEACON_NAME, SITE_BEACON_NAME, OWN_BEACON_NAME, STATE_NAME):
            p = os.path.join(state_dir, name)
            print("— %s —" % p)
            try:
                print(open(p).read().rstrip())
            except Exception as exc:  # noqa: BLE001
                print("(unreadable: %s)" % exc)
        if cfg_problem:
            print("! " + cfg_problem)
        return 0
    if args.daily:
        return daily(cfg, cfg_problem)
    return run(cfg, cfg_problem)


if __name__ == "__main__":
    sys.exit(main())
