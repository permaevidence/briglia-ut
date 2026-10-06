#!/usr/bin/env python3
"""Install, update or remove Sentinel — Briglia's independent, credential-free
release watcher — on this Mac (off-Mac watcher plan §3 and §11).

Run it exactly like this, typed, after checking this file's sha256 against
the digest GitHub shows next to it on the release page:

    sudo /usr/bin/python3 -I ~/Downloads/install_sentinel.py

Other commands (same file, same sudo):
    … install_sentinel.py --status
    … install_sentinel.py --audit-alerts on     # end the report-only period (explicit, never automatic)
    … install_sentinel.py --deadman-url URL     # optional outside dead-man ping (e.g. healthchecks.io); "off" removes it
    … install_sentinel.py --uninstall [--remove-state] [--remove-user]
    … install_sentinel.py --bundle-file PATH    # use a local copy of the bundle (still checked
                                                # against the sha256 embedded below)

What it does:
  * downloads the bundle briglia-sentinel-<version>.pyz from the SAME
    immutable GitHub release this file belongs to (the URL is built from
    the version embedded below, never from any input) and refuses it unless
    its sha256 is the one embedded below;
  * refuses a downgrade; keeps state, bot and settings on reinstall;
  * creates (once) the standard user `brigliawatch` — not an admin, no
    password (login disabled), no login shell, hidden — or refuses to reuse
    an existing user of that name that is not exactly what it created;
  * puts the code under /Library/Application Support/briglia-sentinel
    (root-owned) and the state under brigliawatch's home (0700);
  * asks for the Sentinel bot token at a hidden prompt, checks it with
    Telegram, and proves the chat with a 6-digit code you type back;
  * runs the first check, the website check and the heartbeat in the
    foreground as brigliawatch, prints the recorded floor and the legacy
    signing baseline for you to compare, and only after you type "yes"
  * loads four system launch jobs (hourly check at :23, website every 5
    minutes, heartbeat every 5 minutes, daily status at 09:00), each running
    as brigliawatch; any failure rolls back with no job loaded.

The signing-execution audit starts in REPORT-ONLY mode (owner decision):
for 14 days its findings go to a local log and to the daily status as a
count; switching it to alerts afterwards is this file's `--audit-alerts on`.

This file never updates itself and nothing in Sentinel ever asks you to
update. Root on this Mac defeats any watcher; the separate user only keeps
ordinary processes away from Sentinel's state and bot token.
"""

import argparse
import datetime
import getpass
import hashlib
import io
import json
import os
import plistlib
import re
import secrets
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zipfile

VERSION = "@SENTINEL_VERSION@"
BUNDLE_SHA256 = "@BUNDLE_SHA256@"
BUNDLE_NAME = "briglia-sentinel-%s.pyz" % VERSION
RELEASE_BASE = "https://github.com/permaevidence/briglia-ut/releases/download/v%s/" % VERSION
USER = "brigliawatch"
UID_RANGE = range(450, 500)          # hidden service-account range
LABEL = "dev.briglia.sentinel"
JOBS = ("check", "heartbeat", "site", "daily")
MAX_BUNDLE = 8 * 1024 * 1024
PROGRAMS = {"check": ["release_watch.py", "check"], "heartbeat": ["release_heartbeat.py"],
            "site": ["sentinel_site.py"], "daily": ["release_heartbeat.py", "--daily"]}


class Refuse(Exception):
    pass


def say(msg=""):
    print(msg, flush=True)


# ------------------------------------------------------------------ host

class Host:
    """Every path and command the installer touches. Production values are
    fixed; the selftest redirects them (only when NOT running as root)."""

    def __init__(self, test_root=None, test_bin=None, test_bundle=None, telegram_api=None, test_config=None):
        self.test = test_root is not None
        if self.test and os.geteuid() == 0:
            raise Refuse("test options are refused when running as root")
        r = test_root or ""
        self.code_root = r + "/Library/Application Support/briglia-sentinel" if self.test else \
            "/Library/Application Support/briglia-sentinel"
        self.daemons = (r + "/Library/LaunchDaemons") if self.test else "/Library/LaunchDaemons"
        self.home = (r + "/Users/" + USER) if self.test else "/Users/" + USER
        self.users_root = (r + "/Users") if self.test else "/Users"
        self.state_dir = self.home + "/Library/Application Support/briglia-sentinel"
        self.python = sys.executable if self.test else "/usr/bin/python3"
        self.bin = test_bin
        self.bundle_file = test_bundle
        self.telegram_api = telegram_api or "https://api.telegram.org"
        self.test_config = test_config or {}
        self.owner_log = (r + "/ownership.json") if self.test else None

    def cmd(self, name):
        real = {"dscl": "/usr/bin/dscl", "dseditgroup": "/usr/sbin/dseditgroup", "launchctl": "/bin/launchctl",
                "sudo": "/usr/bin/sudo", "pmset": "/usr/bin/pmset", "systemsetup": "/usr/sbin/systemsetup"}[name]
        return os.path.join(self.bin, name) if self.test else real

    def run(self, name, *args, check=False):
        p = subprocess.run([self.cmd(name)] + list(args), capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if check and p.returncode != 0:
            raise Refuse("%s %s failed (%d): %s" % (name, " ".join(args), p.returncode, (p.stderr or p.stdout).strip()))
        return p

    def as_user(self, argv):
        """Run a Sentinel program as brigliawatch (foreground)."""
        if self.test:
            return subprocess.run(argv, capture_output=True, text=True, stdin=subprocess.DEVNULL)
        return subprocess.run([self.cmd("sudo"), "-u", USER, "-H"] + argv, capture_output=True, text=True,
                              stdin=subprocess.DEVNULL, cwd="/")

    def own(self, path, owner, mode):
        os.chmod(path, mode)
        if self.test:
            log = {}
            if os.path.exists(self.owner_log):
                log = json.load(open(self.owner_log))
            log[re.sub(r"\.(new|tmp)$", "", path)] = [owner, oct(mode)]   # staged files are renamed into place
            json.dump(log, open(self.owner_log, "w"), indent=1, sort_keys=True)
            return
        if owner == "root":
            os.chown(path, 0, 0)
        else:
            uid = int(self.user_attr("UniqueID"))
            os.chown(path, uid, 20)

    def user_attr(self, attr):
        p = self.run("dscl", ".", "-read", "/Users/" + USER, attr)
        if p.returncode != 0:
            return None
        m = re.search(r"^%s:\s*(.*)$" % re.escape(attr), p.stdout, re.M)
        if m and m.group(1).strip():
            return m.group(1).strip()
        lines = p.stdout.splitlines()
        return lines[1].strip() if len(lines) > 1 and lines[0].strip() == attr + ":" else None

    def ask(self, prompt, secret=False):
        if secret and not self.test:
            return getpass.getpass(prompt)
        sys.stdout.write(prompt)
        sys.stdout.flush()
        line = sys.stdin.readline()
        if not line:
            raise Refuse("no answer given")
        return line.strip()


# ------------------------------------------------------------- helpers

def vtuple(v):
    m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", v or "")
    return tuple(int(x) for x in m.groups()) if m else None


def fetch_bundle(host):
    if host.bundle_file:
        with open(host.bundle_file, "rb") as f:
            data = f.read(MAX_BUNDLE + 1)
    else:
        url = RELEASE_BASE + BUNDLE_NAME
        req = urllib.request.Request(url, headers={"User-Agent": "briglia-sentinel-installer/" + VERSION})
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = resp.read(MAX_BUNDLE + 1)
    if len(data) > MAX_BUNDLE:
        raise Refuse("the bundle is larger than %d bytes — refusing" % MAX_BUNDLE)
    got = hashlib.sha256(data).hexdigest()
    if got != BUNDLE_SHA256:
        raise Refuse("the downloaded bundle's sha256 is %s, but this installer embeds %s — refusing (nothing installed)"
                     % (got, BUNDLE_SHA256))
    return data


def telegram(host, token, method, payload=None):
    body = json.dumps(payload or {}).encode()
    req = urllib.request.Request("%s/bot%s/%s" % (host.telegram_api, token, method), data=body, method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            out = json.loads(resp.read(1 << 20).decode())
    except urllib.error.HTTPError as exc:
        out = json.loads((exc.read(1 << 20) or b"{}").decode() or "{}")
    if not out.get("ok"):
        raise Refuse("Telegram %s failed: %s" % (method, out.get("description", "no answer")))
    return out["result"]


def write_json(host, path, data, owner, mode):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    host.own(tmp, owner, mode)
    os.replace(tmp, path)


def mkdir(host, path, owner, mode):
    os.makedirs(path, exist_ok=True)
    host.own(path, owner, mode)


# ------------------------------------------------------------- the user

def check_or_create_user(host):
    exists = host.run("dscl", ".", "-read", "/Users/" + USER).returncode == 0
    if exists:
        problems = []
        uid = host.user_attr("UniqueID")
        if not uid or not uid.isdigit() or int(uid) not in UID_RANGE:
            problems.append("UniqueID %r is not in the range this installer uses" % uid)
        if host.user_attr("UserShell") != "/usr/bin/false":
            problems.append("it has a login shell (%s)" % host.user_attr("UserShell"))
        if host.user_attr("NFSHomeDirectory") != "/Users/" + USER:
            problems.append("its home is %s" % host.user_attr("NFSHomeDirectory"))
        if host.user_attr("RealName") != "Briglia Sentinel":
            problems.append("its name is %r" % host.user_attr("RealName"))
        if host.user_attr("AuthenticationHint"):
            problems.append("it has a password hint")
        if not os.path.exists(os.path.join(host.home, ".briglia-sentinel-user")):
            problems.append("its home lacks the marker this installer writes")
        admin = host.run("dseditgroup", "-o", "checkmember", "-m", USER, "admin")
        if admin.returncode == 0 or admin.stdout.startswith("yes"):
            problems.append("it is a member of the admin group")
        if problems:
            raise Refuse("a user named %s already exists and is not exactly what this installer creates (%s) — "
                         "refusing to reuse it" % (USER, "; ".join(problems)))
        say("✔ user %s exists as this installer created it (standard user, uid %s)" % (USER, uid))
        return False
    if os.path.exists(host.home):
        raise Refuse("%s exists but no user %s does — refusing" % (host.home, USER))
    used = set()
    for line in host.run("dscl", ".", "-list", "/Users", "UniqueID", check=True).stdout.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].lstrip("-").isdigit():
            used.add(int(parts[1]))
    free = [u for u in UID_RANGE if u not in used]
    if not free:
        raise Refuse("no free user id in %d–%d" % (UID_RANGE[0], UID_RANGE[-1]))
    uid = free[0]
    path = "/Users/" + USER
    for attr, val in (("UniqueID", str(uid)), ("PrimaryGroupID", "20"), ("UserShell", "/usr/bin/false"),
                      ("RealName", "Briglia Sentinel"), ("NFSHomeDirectory", path), ("Password", "*"),
                      ("IsHidden", "1")):
        if attr == "UniqueID":
            host.run("dscl", ".", "-create", path, check=True)
        host.run("dscl", ".", "-create", path, attr, val, check=True)
    admin = host.run("dseditgroup", "-o", "checkmember", "-m", USER, "admin")
    if admin.returncode == 0 or admin.stdout.startswith("yes"):
        raise Refuse("the new user %s turned out to be an admin — refusing" % USER)
    mkdir(host, host.home, USER, 0o700)
    marker = os.path.join(host.home, ".briglia-sentinel-user")
    open(marker, "w").write("created by install_sentinel.py %s at %s\n" % (VERSION, time.strftime("%Y-%m-%dT%H:%M:%S")))
    host.own(marker, "root", 0o444)
    say("✔ created the standard user %s (uid %d, no password, no login shell, hidden, not an admin)" % (USER, uid))
    return True


# ------------------------------------------------------------ host checks

def host_checks(host):
    warn = []
    p = host.run("pmset", "-g")
    m = re.search(r"^\s*sleep\s+(\d+)", p.stdout, re.M)
    if m and m.group(1) != "0":
        warn.append("the Mac sleeps after %s min (pmset sleep); Sentinel only runs while awake" % m.group(1))
    m = re.search(r"^\s*autorestart\s+(\d+)", p.stdout, re.M)
    if m and m.group(1) == "0":
        warn.append("'start up automatically after a power failure' is off")
    if "On" in host.run("systemsetup", "-getremotelogin").stdout:
        warn.append("Remote Login (SSH) is ON")
    if host.run("launchctl", "print", "system/com.apple.screensharing").returncode == 0:
        warn.append("Screen Sharing is ON")
    if host.run("launchctl", "print", "system/com.apple.RemoteDesktop.agent").returncode == 0:
        warn.append("Remote Management is ON")
    root = host.users_root
    for u in (sorted(os.listdir(root)) if os.path.isdir(root) else []):
        ak = os.path.join(root, u, ".ssh", "authorized_keys")
        try:
            if os.path.exists(ak) and os.path.getsize(ak):
                warn.append("%s has SSH authorized_keys" % ak)
        except OSError:
            pass
    for w in warn:
        say("  ⚠️ %s" % w)
    if not warn:
        say("✔ host: no sleep, restarts after power failure, no remote access found")


# ---------------------------------------------------------------- config

def make_config(host, old):
    sd = host.state_dir
    cfg = {
        "mode": "remote",
        "state_dir": sd,
        "telegram_env_file": sd + "/telegram.env",
        "log_file": sd + "/logs/check.log",
        "site_log_file": sd + "/logs/site.log",
        "heartbeat_log_file": sd + "/logs/heartbeat.log",
        "daily_log_file": sd + "/logs/daily.log",
        "confirmations": True,
        "checker_website": False,
        "realert_hours": 0,
        "realert_on_change": False,
        "unverified_hold_hours": 2.25,
        "heartbeat_max_age_hours": 2.25,
        "coverage_limits_hours": {"hourly": 2.25, "env-publish": 8.25, "asset-hash": 26, "deletion": 26},
        "site_beacon_max_minutes": 20,
        "heartbeat_beacon_max_minutes": 15,
        "check_minute": 23,
        "signing_audit_alerts": False,
        "audit_report_since": datetime.date.today().isoformat(),
        "deadman_url": None,
        "installer_hint": "sudo /usr/bin/python3 -I install_sentinel.py --audit-alerts on",
        "sentinel_version": VERSION,
        "channels": {},
    }
    for keep in ("signing_audit_alerts", "audit_report_since", "deadman_url"):
        if isinstance(old, dict) and keep in old:
            cfg[keep] = old[keep]
    for k, v in host.test_config.items():
        cfg[k] = v
    return cfg


def plist_for(host, job, cfg_path):
    prog = PROGRAMS[job]
    args = [host.python, "-I", "-S", os.path.join(host.code_root, "current", prog[0])] + prog[1:] + ["--config", cfg_path]
    d = {"Label": "%s.%s" % (LABEL, job), "ProgramArguments": args, "UserName": USER, "GroupName": "staff",
         "EnvironmentVariables": {"HOME": host.home, "PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8"},
         "WorkingDirectory": host.state_dir, "RunAtLoad": False, "ProcessType": "Background", "LowPriorityIO": True,
         "Umask": 0o077,
         # interpreter-level crashes only; the programs rotate their own logs
         "StandardOutPath": host.state_dir + "/logs/launchd-%s.log" % job,
         "StandardErrorPath": host.state_dir + "/logs/launchd-%s.log" % job}
    if job == "check":
        d["StartCalendarInterval"] = {"Minute": 23}
    elif job == "daily":
        d["StartCalendarInterval"] = {"Hour": 9, "Minute": 0}
    else:
        d["StartInterval"] = 300
    return plistlib.dumps(d, sort_keys=True)


def unload_all(host):
    for job in JOBS:
        host.run("launchctl", "bootout", "system/%s.%s" % (LABEL, job))


# ---------------------------------------------------------------- install

def install(host):
    say("Sentinel %s installer" % VERSION)
    if not host.test:
        if os.geteuid() != 0:
            raise Refuse("run it with sudo: sudo /usr/bin/python3 -I %s" % os.path.abspath(sys.argv[0]))
        if sys.platform != "darwin":
            raise Refuse("macOS only")
    if sys.version_info < (3, 9):
        raise Refuse("needs /usr/bin/python3 3.9 or newer (install the Command Line Tools)")
    if not re.fullmatch(r"[0-9a-f]{64}", BUNDLE_SHA256) or not vtuple(VERSION):
        raise Refuse("this is an unbuilt installer template")
    installed = None
    vf = os.path.join(host.code_root, "VERSION")
    if os.path.exists(vf):
        installed = open(vf).read().strip()
        if vtuple(installed) and vtuple(installed) > vtuple(VERSION):
            raise Refuse("Sentinel %s is installed; refusing to downgrade to %s" % (installed, VERSION))
    bundle = fetch_bundle(host)
    say("✔ bundle %s matches the embedded sha256 %s…%s" % (BUNDLE_NAME, BUNDLE_SHA256[:8], BUNDLE_SHA256[-8:]))
    host_checks(host)
    check_or_create_user(host)

    # code (root-owned), staged then switched
    mkdir(host, host.code_root, "root", 0o755)
    vdir = os.path.join(host.code_root, VERSION)
    stage = vdir + ".new"
    shutil.rmtree(stage, ignore_errors=True)
    os.makedirs(stage)
    with zipfile.ZipFile(io.BytesIO(bundle)) as z:
        for name in z.namelist():
            if name.startswith("/") or ".." in name.split("/"):
                raise Refuse("unsafe path in bundle: %s" % name)
            dest = os.path.join(stage, name)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "wb") as f:
                f.write(z.read(name))
    if os.path.exists(vdir):
        shutil.rmtree(vdir)
    os.replace(stage, vdir)
    for dp, dn, fn in os.walk(vdir):
        host.own(dp, "root", 0o755)
        for n in fn:
            host.own(os.path.join(dp, n), "root", 0o644)

    # state (brigliawatch-owned)
    for d in (host.home + "/Library", host.home + "/Library/Application Support"):
        if not os.path.isdir(d):
            mkdir(host, d, USER, 0o700)
    mkdir(host, host.state_dir, USER, 0o700)
    mkdir(host, host.state_dir + "/logs", USER, 0o700)
    cfg_path = os.path.join(host.code_root, "config.json")
    old_cfg = None
    if os.path.exists(cfg_path):
        try:
            old_cfg = json.load(open(cfg_path))
        except ValueError:
            old_cfg = None
    cfg = make_config(host, old_cfg)

    # Telegram (kept on reinstall)
    tg = cfg["telegram_env_file"]
    if os.path.exists(tg) and host.ask("A Sentinel bot is already configured. Keep it? [Y/n] ").lower() not in ("n", "no"):
        say("✔ keeping the configured Sentinel bot")
    else:
        setup_telegram(host, tg)

    prev_current = os.path.realpath(os.path.join(host.code_root, "current")) \
        if os.path.islink(os.path.join(host.code_root, "current")) else None
    old_plists = {}
    for job in JOBS:
        p = os.path.join(host.daemons, "%s.%s.plist" % (LABEL, job))
        if os.path.exists(p):
            old_plists[job] = open(p, "rb").read()
    unload_all(host)
    try:
        write_json(host, cfg_path, cfg, "root", 0o644)
        link = os.path.join(host.code_root, "current")
        tmp_link = link + ".new"
        if os.path.lexists(tmp_link):
            os.unlink(tmp_link)
        os.symlink(VERSION, tmp_link)
        os.replace(tmp_link, link)

        # first runs, in the foreground, as brigliawatch
        code = os.path.join(host.code_root, "current")
        say("… first check (as %s; the first one also records the legacy signing baseline and may stop early when "
            "the unauthenticated GitHub budget runs out — it then resumes hourly)" % USER)
        p = host.as_user([host.python, "-I", "-S", os.path.join(code, "release_watch.py"), "check", "--config", cfg_path])
        if p.returncode not in (0, 2):
            raise Refuse("the first check could not run (exit %d): %s" % (p.returncode, (p.stdout + p.stderr)[-1500:]))
        for prog in (["sentinel_site.py"], ["release_heartbeat.py"]):
            q = host.as_user([host.python, "-I", "-S", os.path.join(code, prog[0])] + prog[1:] + ["--config", cfg_path])
            if q.returncode not in (0, 2):
                raise Refuse("%s could not run (exit %d): %s" % (prog[0], q.returncode, (q.stdout + q.stderr)[-1500:]))
        show_floor(host)
        if host.ask("Does this match the releases you approved? Type yes to activate Sentinel: ").strip().lower() != "yes":
            raise Refuse("not confirmed — nothing activated")

        # launch jobs
        mkdir(host, host.daemons, "root", 0o755)
        for job in JOBS:
            p = os.path.join(host.daemons, "%s.%s.plist" % (LABEL, job))
            with open(p + ".new", "wb") as f:
                f.write(plist_for(host, job, cfg_path))
            host.own(p + ".new", "root", 0o644)
            os.replace(p + ".new", p)
        for job in JOBS:
            host.run("launchctl", "bootstrap", "system", os.path.join(host.daemons, "%s.%s.plist" % (LABEL, job)), check=True)
            host.run("launchctl", "print", "system/%s.%s" % (LABEL, job), check=True)
    except Exception as exc:
        say("✖ %s — rolling back: no Sentinel job stays loaded" % exc)
        unload_all(host)
        for job in JOBS:
            p = os.path.join(host.daemons, "%s.%s.plist" % (LABEL, job))
            if job in old_plists:
                with open(p, "wb") as f:
                    f.write(old_plists[job])
            elif os.path.exists(p):
                os.unlink(p)
        link = os.path.join(host.code_root, "current")
        if prev_current and os.path.basename(prev_current) != VERSION:
            os.unlink(link)
            os.symlink(os.path.basename(prev_current), link)
        if old_cfg is not None:
            write_json(host, cfg_path, old_cfg, "root", 0o644)
        if old_plists and installed:
            for job in JOBS:
                if job in old_plists:
                    host.run("launchctl", "bootstrap", "system", os.path.join(host.daemons, "%s.%s.plist" % (LABEL, job)))
            say("  the previous Sentinel %s is active again" % installed)
        raise Refuse(str(exc))
    with open(os.path.join(host.code_root, "VERSION.new"), "w") as f:
        f.write(VERSION + "\n")
    host.own(os.path.join(host.code_root, "VERSION.new"), "root", 0o644)
    os.replace(os.path.join(host.code_root, "VERSION.new"), vf)
    say("✔ Sentinel %s is active: check at :23 every hour, website + heartbeat every 5 minutes, daily status at 09:00"
        % VERSION)
    say("  signing audit: %s" % ("ALERTS" if cfg["signing_audit_alerts"] else
                                 "report-only since %s (switch with --audit-alerts on after 14 days)" % cfg["audit_report_since"]))
    say("  Rule: upgrade Briglia only after Sentinel's ✅ names that exact version and sequence.")
    return 0


def setup_telegram(host, tg_path):
    say("Create the Sentinel bot with @BotFather on your phone, send it /start, then paste its token here.")
    token = host.ask("Sentinel bot token (hidden): ", secret=True).strip()
    if not re.fullmatch(r"\d+:[A-Za-z0-9_-]{30,}", token):
        raise Refuse("that does not look like a bot token")
    me = telegram(host, token, "getMe")
    say("✔ token works: @%s" % me.get("username"))
    host.ask("Send /start to @%s from your phone now, then press Enter. " % me.get("username"))
    ups = telegram(host, token, "getUpdates", {"timeout": 0})
    chats = {}
    for u in ups:
        m = u.get("message") or {}
        c = m.get("chat") or {}
        if c.get("type") == "private" and isinstance(c.get("id"), int):
            chats[c["id"]] = (m.get("from") or {}).get("username") or c.get("first_name")
    if len(chats) != 1:
        raise Refuse("expected exactly one private chat with the bot, found %d — send /start once, from your account only"
                     % len(chats))
    chat_id, who = next(iter(chats.items()))
    code = "%06d" % secrets.randbelow(10 ** 6)
    telegram(host, token, "sendMessage", {"chat_id": chat_id, "text": "Sentinel setup code: %s" % code})
    if host.ask("Type the 6-digit code Sentinel just sent to %s: " % who).strip() != code:
        raise Refuse("wrong code — nothing activated")
    with open(tg_path + ".new", "w") as f:
        f.write("TELEGRAM_BOT_TOKEN=%s\nOWNER_CHAT_ID=%d\n" % (token, chat_id))
    host.own(tg_path + ".new", USER, 0o600)
    os.replace(tg_path + ".new", tg_path)
    say("✔ chat verified; the token is stored only in %s (0600, %s)" % (tg_path, USER))


def show_floor(host):
    try:
        st = json.load(open(os.path.join(host.state_dir, "state.json")))
    except Exception as exc:  # noqa: BLE001
        raise Refuse("cannot read the first check's state: %s" % exc)
    say("\nRecorded releases (the rollback floor):")
    for ch, r in sorted((st.get("recorded") or {}).items()):
        say("  %s  %s  sequence %s  commit %s  (%s)" % (ch, r.get("tag"), r.get("sequence"), str(r.get("commit"))[:12],
                                                      r.get("provenance")))
    if not st.get("recorded"):
        say("  (none yet — the budget may have run out; the next hourly check continues)")
    say("Legacy signing baseline (executions before the approval gate, labelled 'not phone-approved'):")
    for ch, a in sorted((st.get("audit") or {}).items()):
        b = a.get("baseline") or {}
        ex = b.get("executions") or []
        newest = max(ex, key=lambda x: x[1]) if ex else None
        say("  %s  cutoff %s  %s  %d execution(s)%s" % (
            ch, b.get("cutoff"), "complete" if b.get("complete") else "STILL BEING RECORDED (resumes hourly)", len(ex),
            ", newest run %s started %s" % (newest[0], newest[1]) if newest else ""))
    say("")


# ----------------------------------------------------------- other modes

def set_config(host, key, value):
    cfg_path = os.path.join(host.code_root, "config.json")
    if not os.path.exists(cfg_path):
        raise Refuse("Sentinel is not installed")
    cfg = json.load(open(cfg_path))
    cfg[key] = value
    write_json(host, cfg_path, cfg, "root", 0o644)


def status(host):
    vf = os.path.join(host.code_root, "VERSION")
    say("installed: %s" % (open(vf).read().strip() if os.path.exists(vf) else "no"))
    for job in JOBS:
        p = host.run("launchctl", "print", "system/%s.%s" % (LABEL, job))
        say("  %s: %s" % (job, "loaded" if p.returncode == 0 else "not loaded"))
    cfg_path = os.path.join(host.code_root, "config.json")
    if os.path.exists(cfg_path):
        cfg = json.load(open(cfg_path))
        say("  signing audit: %s; dead-man: %s" % ("alerts" if cfg.get("signing_audit_alerts") else
                                                   "report-only since %s" % cfg.get("audit_report_since"),
                                                   cfg.get("deadman_url") or "off"))
    return 0


def uninstall(host, remove_state, remove_user):
    unload_all(host)
    for job in JOBS:
        p = os.path.join(host.daemons, "%s.%s.plist" % (LABEL, job))
        if os.path.exists(p):
            os.unlink(p)
    shutil.rmtree(host.code_root, ignore_errors=True)
    say("✔ Sentinel jobs and code removed")
    if remove_state or remove_user:
        shutil.rmtree(host.state_dir, ignore_errors=True)
        say("✔ state removed (bot token included)")
    if remove_user:
        host.run("dscl", ".", "-delete", "/Users/" + USER, check=True)
        shutil.rmtree(host.home, ignore_errors=True)
        say("✔ user %s removed" % USER)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--uninstall", action="store_true")
    ap.add_argument("--remove-state", action="store_true")
    ap.add_argument("--remove-user", action="store_true")
    ap.add_argument("--audit-alerts", choices=["on", "off"])
    ap.add_argument("--deadman-url")
    ap.add_argument("--bundle-file", help="local copy of the bundle; verified against the embedded sha256 like a download")
    # selftest only (refused as root)
    ap.add_argument("--test-root", help=argparse.SUPPRESS)
    ap.add_argument("--test-bin", help=argparse.SUPPRESS)
    ap.add_argument("--test-bundle", help=argparse.SUPPRESS)
    ap.add_argument("--test-telegram-api", help=argparse.SUPPRESS)
    ap.add_argument("--test-config", help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    try:
        host = Host(a.test_root, a.test_bin, a.test_bundle or a.bundle_file, a.test_telegram_api,
                    json.loads(a.test_config) if a.test_config else None)
        if not host.test and os.geteuid() != 0:
            raise Refuse("run it with sudo: sudo /usr/bin/python3 -I %s" % os.path.abspath(sys.argv[0]))
        if a.uninstall:
            return uninstall(host, a.remove_state, a.remove_user)
        if a.status:
            return status(host)
        if a.audit_alerts:
            set_config(host, "signing_audit_alerts", a.audit_alerts == "on")
            say("✔ signing audit: %s" % ("ALERTS from the next hourly check" if a.audit_alerts == "on" else "report-only"))
            return 0
        if a.deadman_url:
            url = None if a.deadman_url == "off" else a.deadman_url
            if url and not url.startswith("https://"):
                raise Refuse("the dead-man URL must start with https://")
            set_config(host, "deadman_url", url)
            say("✔ dead-man ping: %s" % (url or "off"))
            return 0
        return install(host)
    except Refuse as exc:
        say("✖ %s" % exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
