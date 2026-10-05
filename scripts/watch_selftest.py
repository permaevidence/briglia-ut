#!/usr/bin/env python3
"""Battery for scripts/release_watch.py against an in-process fake of
everything it talks to — GitHub Releases/refs/Actions API, the release
download host (with Range), raw.githubusercontent, the website, a legacy
Blob manifest and the Telegram Bot API — with fault injection. Runs the
REAL watcher on a throwaway copy of this repository whose pinned keys are
generated test keys, so every alert path is exercised end to end.

    python3 scripts/watch_selftest.py
"""

import hashlib
import http.server
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from signing_fixture import TestKey, raw_envelope  # noqa: E402

PASSED = FAILED = 0


def check(label, ok, detail=""):
    global PASSED, FAILED
    print("  %s %s%s" % ("✔" if ok else "✖", label, "" if ok or not detail else " — " + str(detail)[-500:]))
    if ok:
        PASSED += 1
    else:
        FAILED += 1


class Fake:
    """One server: envelopes, downloads, GitHub API, raw source, website,
    legacy manifest, Telegram. All state is plain dicts the test mutates."""

    def __init__(self):
        self.envelopes = {}        # channel -> bytes served as latest
        self.assets = {}           # (channel, version, name) -> bytes
        self.releases = {}         # repo -> [ {tag_name, draft, immutable, id} ]
        self.tags = {}             # repo -> {tag: sha}
        self.runs = {}             # repo -> [ {id, name, head_sha, head_branch, status, conclusion, jobs:[...]}, ]
        self.raw = {}              # (repo, tag, path) -> bytes
        self.site_installer = None  # bytes served by /site/cli/install.sh (None → redirect to release asset)
        self.site_installer_redirect = None
        self.site_page = b""
        self.domain_installer = None   # bytes served by /domain/cli/install.sh (None → same as the site)
        self.domain_page = None        # bytes served by /domain/app (None → same as the site)
        self.legacy_manifest = None
        self.telegram = []         # captured message texts
        self.hits = []             # every GET path, in order
        self.faults = {}           # range_total: int | None; asset_404: name; asset_sub: {name: bytes};
        #                          api_status: int; tg_status: int; ref_status: int
        fake = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, status, body=b"", ctype="application/octet-stream", headers=None):
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                if body and self.command != "HEAD":
                    self.wfile.write(body)

            def _json(self, status, obj):
                self._send(status, json.dumps(obj).encode(), "application/json")

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n) if n else b""
                m = re.match(r"^/tg/bot([^/]+)/sendMessage$", self.path)
                if m:
                    if fake.faults.get("tg_status"):
                        return self._json(fake.faults["tg_status"], {"ok": False})
                    if m.group(1) != "tok":
                        return self._json(401, {"ok": False})
                    fake.telegram.append(json.loads(body)["text"])
                    return self._json(200, {"ok": True, "result": {}})
                self._send(404)

            def do_GET(self):
                u = urllib.parse.urlparse(self.path)
                p, q = u.path, urllib.parse.parse_qs(u.query)
                fake.hits.append(p)
                if p == fake.faults.get("disconnect_path"):   # connection dropped without an answer
                    self.connection.shutdown(2)
                    self.connection.close()
                    return
                m = re.match(r"^/latest/([^/]+)/manifest\.sig\.json$", p)
                if m:
                    env = fake.envelopes.get(m.group(1))
                    return self._send(200, env, "application/json") if env else self._send(404)
                m = re.match(r"^/download/([^/]+)/v([^/]+)/([^/]+)$", p)
                if m:
                    chan, ver, name = m.groups()
                    if fake.faults.get("asset_404") == name:
                        return self._send(404)
                    data = fake.assets.get((chan, ver, name))
                    if data is None:
                        return self._send(404)
                    data = fake.faults.get("asset_sub", {}).get(name, data)
                    rng = self.headers.get("Range")
                    if rng:
                        total = fake.faults.get("range_total") or len(data)
                        return self._send(206, data[:1], headers={"Content-Range": "bytes 0-0/%d" % total})
                    return self._send(200, data)
                m = re.match(r"^/raw/([^/]+/[^/]+)/([^/]+)/(.+)$", p)
                if m:
                    data = fake.raw.get((m.group(1), m.group(2), m.group(3)))
                    return self._send(200, data) if data is not None else self._send(404)
                if p == "/site/cli/install.sh":
                    if fake.site_installer is not None:
                        return self._send(200, fake.site_installer)
                    if fake.site_installer_redirect:
                        return self._send(308, headers={"Location": fake.site_installer_redirect})
                    return self._send(404)
                if p == "/site/app":
                    return self._send(200, fake.site_page, "text/html")
                # the "real domain" (briglia.dev) — same deployment as the
                # alias unless a test hijacks it independently
                if p == "/domain/cli/install.sh":
                    if fake.domain_installer is not None:
                        return self._send(200, fake.domain_installer)
                    self.path = "/site/cli/install.sh"
                    return self.do_GET()
                if p == "/domain/app":
                    page = fake.site_page if fake.domain_page is None else fake.domain_page
                    return self._send(200, page, "text/html")
                if p == "/legacy/manifest.json":
                    if fake.legacy_manifest is None:
                        return self._send(404)
                    return self._send(200, json.dumps(fake.legacy_manifest).encode(), "application/json")
                if p.startswith("/api/"):
                    if fake.faults.get("api_status"):
                        return self._json(fake.faults["api_status"], {"message": "injected"})
                    m = re.match(r"^/api/repos/([^/]+/[^/]+)/releases/latest$", p)
                    if m:
                        rels = [r for r in fake.releases.get(m.group(1), []) if not r["draft"]]
                        return self._json(200, rels[-1]) if rels else self._json(404, {})
                    m = re.match(r"^/api/repos/([^/]+/[^/]+)/releases$", p)
                    if m:
                        return self._json(200, list(reversed(fake.releases.get(m.group(1), []))))
                    m = re.match(r"^/api/repos/([^/]+/[^/]+)/git/ref/tags/([^/]+)$", p)
                    if m:
                        if fake.faults.get("ref_status"):
                            return self._json(fake.faults["ref_status"], {})
                        sha = fake.tags.get(m.group(1), {}).get(m.group(2))
                        if not sha:
                            return self._json(404, {"message": "Not Found"})
                        if isinstance(sha, dict):   # annotated: {"tag_sha":..., "commit":...}
                            return self._json(200, {"ref": "refs/tags/" + m.group(2),
                                                    "object": {"type": "tag", "sha": sha["tag_sha"]}})
                        return self._json(200, {"ref": "refs/tags/" + m.group(2), "object": {"type": "commit", "sha": sha}})
                    m = re.match(r"^/api/repos/([^/]+/[^/]+)/git/tags/([0-9a-f]{40})$", p)
                    if m:
                        for t in fake.tags.get(m.group(1), {}).values():
                            if isinstance(t, dict) and t["tag_sha"] == m.group(2):
                                return self._json(200, {"object": {"type": "commit", "sha": t["commit"]}})
                        return self._json(404, {})
                    m = re.match(r"^/api/repos/([^/]+/[^/]+)/actions/runs$", p)
                    if m:
                        branch = q.get("branch", [None])[0]
                        runs = [dict(r, jobs=None) for r in fake.runs.get(m.group(1), []) if r["head_branch"] == branch]
                        return self._json(200, {"workflow_runs": runs})
                    m = re.match(r"^/api/repos/([^/]+/[^/]+)/actions/runs/(\d+)/jobs$", p)
                    if m:
                        r = next((r for r in fake.runs.get(m.group(1), []) if r["id"] == int(m.group(2))), None)
                        return self._json(200, {"jobs": r["jobs"]}) if r else self._json(404, {})
                self._send(404)

            do_HEAD = do_GET

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = "http://127.0.0.1:%d" % self.server.server_address[1]

    def close(self):
        self.server.shutdown()
        self.server.server_close()


JOBS_OK = [{"name": n, "conclusion": "success"} for n in
           ("Authorize (credential-free)", "Build macOS arm64", "Sign metadata", "Publish immutable release",
            "Verify public channel (linux)", "Verify public channel (macos)", "Verify public channel (linux-arm64)")]


def main():
    root = tempfile.mkdtemp(prefix="briglia-watch-selftest-")
    repo_src = os.path.dirname(HERE)
    repo = os.path.join(root, "repo")
    os.makedirs(repo)
    for item in ("py", "scripts"):
        shutil.copytree(os.path.join(repo_src, item), os.path.join(repo, item),
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    cli_key, app_key = TestKey("briglia-cli"), TestKey("briglia-ut")
    rv_path = os.path.join(repo, "py", "release_verify.py")
    s = open(rv_path).read()
    s = re.sub(r"# STAMP-CLI-KEY-BEGIN.*?# STAMP-CLI-KEY-END",
               '# STAMP-CLI-KEY-BEGIN\nCLI_KEYS = {\n    "%s":\n        "%s",\n}\n# STAMP-CLI-KEY-END' % (cli_key.key_id, cli_key.pub_hex), s, flags=re.S)
    s = re.sub(r"# STAMP-APP-KEY-BEGIN.*?# STAMP-APP-KEY-END",
               '# STAMP-APP-KEY-BEGIN\nAPP_KEYS = {\n    "%s":\n        "%s",\n}\n# STAMP-APP-KEY-END' % (app_key.key_id, app_key.pub_hex), s, flags=re.S)
    s = re.sub(r"^MIN_CLI_SEQUENCE = \d+$", "MIN_CLI_SEQUENCE = 1", s, flags=re.M)
    s = re.sub(r"^MIN_APP_SEQUENCE = \d+$", "MIN_APP_SEQUENCE = 1", s, flags=re.M)
    open(rv_path, "w").write(s)

    fake = Fake()
    B = fake.base
    tg_env = os.path.join(root, "tg.env")
    open(tg_env, "w").write("TELEGRAM_BOT_TOKEN=tok\nOWNER_CHAT_ID=1\n")
    pub_log = os.path.join(root, "briglia-ut-publications.jsonl")
    state_dir = os.path.join(root, "state")
    cfg_path = os.path.join(root, "cfg.json")
    cfg = {
        "state_dir": state_dir, "github_api": B + "/api", "raw_base": B + "/raw",
        "telegram_env_file": tg_env, "telegram_api": B + "/tg",
        "realert_hours": 6, "heartbeat_max_age_hours": 3, "expiry_warning_days": 30,
        "channels": {
            "briglia-cli": {"kind": "cli", "repo": "test/briglia-cli", "workflow_name": "Release (signed)",
                        "installer_asset": "install.sh", "installer_source": "scripts/get-briglia.sh",
                        "website_install_url": [B + "/site/cli/install.sh", B + "/domain/cli/install.sh"],
                        "envelope_url": B + "/latest/briglia-cli/manifest.sig.json",
                        "artifact_url_prefix": B + "/download/briglia-cli/v{version}/",
                        "legacy_blob_manifest": None},
            "briglia-ut": {"kind": "app", "repo": "test/briglia-ut", "publication_log": pub_log,
                       "website_page_url": [B + "/site/app", B + "/domain/app"],
                       "envelope_url": B + "/latest/briglia-ut/manifest.sig.json",
                       "artifact_url_prefix": B + "/download/briglia-ut/v{version}/",
                       "legacy_blob_manifest": B + "/legacy/manifest.json"},
        },
    }
    json.dump(cfg, open(cfg_path, "w"))
    watcher = os.path.join(repo, "scripts", "release_watch.py")

    def run(cmd="check"):
        p = subprocess.run([sys.executable, watcher, cmd, "--config", cfg_path], capture_output=True, text=True)
        return p.returncode, p.stdout + p.stderr

    def state():
        return json.load(open(os.path.join(state_dir, "state.json")))

    def set_state(mut):
        st = state()
        mut(st)
        json.dump(st, open(os.path.join(state_dir, "state.json"), "w"))

    def sha(b):
        return hashlib.sha256(b).hexdigest()

    def envelope(key, chan, version, seq, assets, expires_days=180, published=None):
        payload = {"channel": chan, "expires": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + expires_days * 86400)),
                   "platforms": {n: {"sha256": sha(b), "size": len(b), "url": "%s/download/%s/v%s/%s" % (B, chan, version, n)}
                                 for n, b in assets.items()},
                   "published": published or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 60)),
                   "schema": 1, "sequence": seq, "version": version}
        return key.sign(json.dumps(payload, sort_keys=True, indent=2).encode())

    def publish(chan, version, seq, assets, commit, expires_days=180, workflow="success", log=True, immutable=True):
        key = cli_key if chan == "briglia-cli" else app_key
        repo_name = "test/" + chan
        for n, b in assets.items():
            fake.assets[(chan, version, n)] = b
        env = envelope(key, chan, version, seq, assets, expires_days)
        fake.envelopes[chan] = env
        rid = 1000 + len(fake.releases.get(repo_name, []))
        fake.releases.setdefault(repo_name, []).append({"id": rid, "tag_name": "v" + version, "draft": False, "immutable": immutable})
        fake.tags.setdefault(repo_name, {})["v" + version] = commit
        if chan == "briglia-cli":
            fake.assets[(chan, version, "install.sh")] = assets.get("install.sh", b"")
            fake.raw[(repo_name, "v" + version, "scripts/get-briglia.sh")] = assets.get("install.sh", b"")
            fake.site_installer_redirect = "%s/download/briglia-cli/v%s/install.sh" % (B, version)
            if workflow:
                fake.runs.setdefault(repo_name, []).append({
                    "id": 500 + seq, "name": "Release (signed)", "head_sha": commit, "head_branch": "v" + version,
                    "run_number": seq, "status": "completed", "conclusion": workflow,
                    "jobs": JOBS_OK if workflow == "success" else [{"name": "Sign metadata", "conclusion": "failure"}]})
        else:
            click = assets["click"]
            fake.site_page = ("<a href=\"%s/download/briglia-ut/v%s/click\">download</a>" % (B, version)).encode()
            fake.legacy_manifest = {"version": version, "sha256": sha(click), "size": len(click)}
            if log:
                with open(pub_log, "a") as f:
                    f.write(json.dumps({"tag": "v" + version, "version": version, "sequence": seq, "clickSha256": sha(click),
                                        "envelopeSha256": sha(env), "releaseId": rid, "keyId": app_key.key_id,
                                        "commit": commit, "recorded": "2026-01-01T00:00:00Z"}) + "\n")
        return env

    C1, C2, C3 = "a" * 40, "b" * 40, "c" * 40
    try:
        print("— first run: both channels seeded and announced —")
        publish("briglia-cli", "0.1.58", 58, {"briglia-macos-arm64.tar.gz": b"mac58" * 1000, "briglia-linux-x64.tar.gz": b"lin58" * 1000,
                                          "install.sh": b"#!/bin/bash\necho installer 58\n"}, C1)
        publish("briglia-ut", "0.7.4", 1, {"click": b"click74" * 500}, C2)
        rc, out = run()
        st = state()
        check("first check exits 0, records both channels", rc == 0 and st["recorded"]["briglia-cli"]["sequence"] == 58
              and st["recorded"]["briglia-ut"]["sequence"] == 1 and st["recorded"]["briglia-cli"]["commit"] == C1, out)
        check("recording is announced (two ℹ️ messages), no alerts",
              len(fake.telegram) == 2 and all(m.startswith("ℹ️") and "RECORDED" in m for m in fake.telegram), fake.telegram)
        check("full hash performed on first record", set(st["full_hash_at"]) == {"briglia-cli", "briglia-ut"}
              and "full download of every asset matches" in out, out)
        check("installer identity + website resolution + page link + legacy manifest all verified",
              all(x in out for x in ("byte-identical", "legacy transition manifest agrees",
                                     "website install URL %s/site/cli/install.sh resolves" % B,
                                     "website install URL %s/domain/cli/install.sh resolves" % B,
                                     "website page %s/site/app links" % B, "website page %s/domain/app links" % B)), out)
        check("every published release checked: immutable + v<semver> tags (clean)",
              "published release(s) are immutable with v<semver> tags" in out, out)
        fake.telegram.clear()
        rc, out = run()
        check("second identical run is SILENT (no messages) and skips the daily full hash",
              rc == 0 and not fake.telegram and "full download" not in out and "matches the recorded authorized release" in out, out)

        print("— envelope integrity —")
        good = fake.envelopes["briglia-cli"]
        t = json.loads(good); t["signature"] = ("A" if t["signature"][0] != "A" else "B") + t["signature"][1:]
        fake.envelopes["briglia-cli"] = json.dumps(t).encode()
        rc, out = run()
        check("tampered live envelope → alert (briglia-cli/envelope-invalid), exit 2",
              rc == 2 and any("envelope-invalid" in m for m in fake.telegram), fake.telegram)
        n = len(fake.telegram)
        rc, out = run()
        check("same failure within the re-alert window is NOT re-sent", len(fake.telegram) == n, fake.telegram[n:])
        set_state(lambda st: st["active"]["briglia-cli/envelope-invalid"].__setitem__("last_sent", time.time() - 7 * 3600))
        rc, out = run()
        check("after realert_hours the failure is re-sent as STILL FAILING",
              len(fake.telegram) == n + 1 and "STILL FAILING" in fake.telegram[-1], fake.telegram[n:])
        fake.envelopes["briglia-cli"] = good
        fake.telegram.clear()
        rc, out = run()
        check("recovery message when the envelope is good again", rc == 0 and len(fake.telegram) == 1
              and fake.telegram[0].startswith("✅") and "envelope-invalid" in fake.telegram[0], fake.telegram)
        fake.telegram.clear()
        fake.envelopes["briglia-cli"] = envelope(TestKey("briglia-cli"), "briglia-cli", "0.1.58", 58,
                                             {"briglia-macos-arm64.tar.gz": b"mac58" * 1000, "briglia-linux-x64.tar.gz": b"lin58" * 1000, "install.sh": b"x"})
        rc, out = run()
        check("envelope signed by a DIFFERENT key → rejected", rc == 2 and any("envelope-invalid" in m for m in fake.telegram), fake.telegram)
        fake.envelopes["briglia-cli"] = good
        run(); fake.telegram.clear()

        print("— rollback / sibling / new release —")
        older = envelope(cli_key, "briglia-cli", "0.1.57", 57, {"briglia-macos-arm64.tar.gz": b"mac57" * 1000})
        fake.assets[("briglia-cli", "0.1.57", "briglia-macos-arm64.tar.gz")] = b"mac57" * 1000
        fake.envelopes["briglia-cli"] = older
        rc, out = run()
        check("latest URL replaying an OLDER valid envelope (GitHub still says 0.1.58) → rollback alert + latest-mismatch",
              rc == 2 and any("/rollback" in m and "sequence 57" in m for m in fake.telegram)
              and any("latest-mismatch" in m for m in fake.telegram), fake.telegram)
        fake.telegram.clear()
        fake.faults["api_status"] = 503
        rc, out = run()
        check("…rollback is still judged when the GitHub API is down", rc == 2 and "/rollback" in out, out)
        del fake.faults["api_status"]
        # deleted-release variant: 0.1.58 vanishes from GitHub, 0.1.57 is latest again
        saved_rel, saved_tag = fake.releases["test/briglia-cli"].pop(), fake.tags["test/briglia-cli"].pop("v0.1.58")
        fake.releases["test/briglia-cli"].append({"id": 900, "tag_name": "v0.1.57", "draft": False, "immutable": True})
        fake.tags["test/briglia-cli"]["v0.1.57"] = "9" * 40
        rc, out = run()
        check("release deleted wholesale (0.1.57 latest again) → rollback alert, record keeps 58",
              rc == 2 and "/rollback" in out and state()["recorded"]["briglia-cli"]["sequence"] == 58, out)
        fake.releases["test/briglia-cli"].pop(); fake.tags["test/briglia-cli"].pop("v0.1.57")
        fake.releases["test/briglia-cli"].append(saved_rel); fake.tags["test/briglia-cli"]["v0.1.58"] = saved_tag
        fake.envelopes["briglia-cli"] = good; run(); fake.telegram.clear()
        sibling = envelope(cli_key, "briglia-cli", "0.1.58", 58, {"briglia-macos-arm64.tar.gz": b"EVIL" * 1000, "briglia-linux-x64.tar.gz": b"lin58" * 1000, "install.sh": b"#!/bin/bash\necho installer 58\n"})
        fake.envelopes["briglia-cli"] = sibling
        rc, out = run()
        check("validly signed envelope with the SAME sequence but different assets → record-mismatch alert",
              rc == 2 and any("record-mismatch" in m and "assets" in m for m in fake.telegram), fake.telegram)
        fake.envelopes["briglia-cli"] = good; run(); fake.telegram.clear()
        publish("briglia-cli", "0.1.59", 59, {"briglia-macos-arm64.tar.gz": b"mac59" * 1000, "briglia-linux-x64.tar.gz": b"lin59" * 1000,
                                          "install.sh": b"#!/bin/bash\necho installer 59\n"}, C3, workflow="failure")
        rc, out = run()
        st = state()
        check("new release whose workflow FAILED → uncorroborated alert, NOT recorded (record stays 58)",
              rc == 2 and st["recorded"]["briglia-cli"]["sequence"] == 58 and any("uncorroborated" in m for m in fake.telegram), fake.telegram)
        fake.telegram.clear()
        fake.runs["test/briglia-cli"][-1].update({"conclusion": "success", "jobs": JOBS_OK})
        rc, out = run()
        st = state()
        check("same release once the workflow is green → recorded + announced + recovery for the previous alert",
              rc == 0 and st["recorded"]["briglia-cli"]["sequence"] == 59 and st["recorded"]["briglia-cli"]["commit"] == C3
              and any("RECORDED" in m and "v0.1.59" in m for m in fake.telegram)
              and any(m.startswith("✅") and "uncorroborated" in m for m in fake.telegram), fake.telegram)
        fake.telegram.clear()
        fake.tags["test/briglia-cli"]["v0.1.59"] = "d" * 40
        rc, out = run()
        check("tag moved to another commit after recording → record-mismatch (commit)",
              rc == 2 and any("record-mismatch" in m and "commit" in m for m in fake.telegram), fake.telegram)
        fake.tags["test/briglia-cli"]["v0.1.59"] = {"tag_sha": "e" * 40, "commit": C3}
        fake.telegram.clear()
        rc, out = run()
        check("annotated tag resolving to the recorded commit → clean (recovery only)",
              rc == 0 and len(fake.telegram) == 1 and fake.telegram[0].startswith("✅"), fake.telegram)
        fake.telegram.clear()

        print("— GitHub state —")
        fake.releases["test/briglia-cli"].append({"id": 1099, "tag_name": "v0.1.60", "draft": False, "immutable": True})
        rc, out = run()
        check("a newer non-draft release while latest stays 0.1.59 → latest-mismatch/frozen alert",
              rc == 2 and any("latest" in m for m in fake.telegram), fake.telegram)
        fake.releases["test/briglia-cli"].pop(); run(); fake.telegram.clear()
        fake.releases["test/briglia-cli"][-1]["immutable"] = False
        rc, out = run()
        check("latest release not immutable → alert", rc == 2 and any("not-immutable" in m for m in fake.telegram), fake.telegram)
        fake.releases["test/briglia-cli"][-1]["immutable"] = True; run(); fake.telegram.clear()
        # R4.3: rogue releases outside the v* pipeline, and any mutable release
        fake.releases["test/briglia-cli"].insert(0, {"id": 1, "tag_name": "x", "draft": False, "immutable": True})
        rc, out = run()
        check("an OLDER published release on a non-v<semver> tag ('x') → release-bad-tag alert, exit 2",
              rc == 2 and any("release-bad-tag" in m and ": x" in m for m in fake.telegram)
              and not any("latest-mismatch" in m for m in fake.telegram), fake.telegram)
        fake.releases["test/briglia-cli"].pop(0); fake.telegram.clear(); rc, out = run()
        check("…recovery once the rogue release is gone", rc == 0 and len(fake.telegram) == 1
              and "recovered: briglia-cli/release-bad-tag" in fake.telegram[0], fake.telegram)
        fake.telegram.clear()
        fake.releases["test/briglia-cli"].append({"id": 1098, "tag_name": "v0.1.59-hotfix", "draft": False, "immutable": True})
        rc, out = run()
        check("a rogue release on a v-prefixed but non-semver tag MARKED LATEST → release-bad-tag AND latest-mismatch",
              rc == 2 and any("release-bad-tag" in m and "v0.1.59-hotfix" in m for m in fake.telegram)
              and any("latest-mismatch" in m for m in fake.telegram), fake.telegram)
        fake.releases["test/briglia-cli"].pop(); run(); fake.telegram.clear()
        fake.releases["test/briglia-cli"][0]["immutable"] = False
        rc, out = run()
        check("an OLDER (non-latest) published release that is not immutable → release-not-immutable alert naming it",
              rc == 2 and any("release-not-immutable" in m and "v0.1.58" in m for m in fake.telegram)
              and not any("/not-immutable" in m for m in fake.telegram), fake.telegram)
        fake.releases["test/briglia-cli"][0]["immutable"] = True; run(); fake.telegram.clear()
        fake.releases["test/briglia-cli"].insert(0, {"id": 2, "tag_name": "scratch", "draft": True, "immutable": False})
        rc, out = run()
        check("a DRAFT on an odd tag (never immutable) → informational only, no tag/immutability alert",
              rc == 0 and not any("release-bad-tag" in m or "release-not-immutable" in m for m in fake.telegram)
              and any("draft release(s) present: scratch" in m for m in fake.telegram), fake.telegram)
        fake.releases["test/briglia-cli"].pop(0); run(); fake.telegram.clear()
        filler = [{"id": 10 + i, "tag_name": "v0.0.%d" % i, "draft": False, "immutable": True}
                  for i in range(100 - len(fake.releases["test/briglia-cli"]))]
        fake.releases["test/briglia-cli"][0:0] = filler
        rc, out = run()
        check("a FULL first page of releases → release-list-incomplete alert, never 'all … releases' claimed",
              rc == 2 and any("release-list-incomplete" in m for m in fake.telegram)
              and "published release(s) are immutable" not in out.split("— briglia-ut")[0], fake.telegram)
        del fake.releases["test/briglia-cli"][0:len(filler)]; run(); fake.telegram.clear()
        fake.faults["api_status"] = 503
        # network-class: retried in-run and announced only after
        # transient_grace_checks (default 3) consecutive failing checks
        run(); run()
        quiet = not any("github-unreachable" in m for m in fake.telegram)
        rc, out = run()
        check("GitHub API unreachable → silent for the first 2 checks, alert on the 3rd (never silent for long)",
              quiet and rc == 2 and any("github-unreachable" in m for m in fake.telegram), fake.telegram)
        del fake.faults["api_status"]; run(); fake.telegram.clear()

        print("— assets —")
        fake.faults["asset_404"] = "briglia-linux-x64.tar.gz"
        rc, out = run()
        check("asset missing at its immutable URL → asset-unreachable alert",
              rc == 2 and any("asset-unreachable" in m and "briglia-linux-x64.tar.gz" in m for m in fake.telegram), fake.telegram)
        del fake.faults["asset_404"]; run(); fake.telegram.clear()
        fake.faults["range_total"] = 12345
        rc, out = run()
        check("server reporting a different total size → alert (Range probe)",
              rc == 2 and any("signed size" in m for m in fake.telegram), fake.telegram)
        del fake.faults["range_total"]; run(); fake.telegram.clear()
        fake.faults["asset_sub"] = {"briglia-macos-arm64.tar.gz": b"mac59" * 999 + b"XXXXX"}
        rc, out = run()
        check("substituted bytes with the right size pass the hourly probe (documented limit)", rc == 0 and not fake.telegram, out)
        set_state(lambda st: st["full_hash_at"].__setitem__("briglia-cli", 0))
        rc, out = run()
        check("…and are caught by the daily full download (asset-hash alert)",
              rc == 2 and any("asset-hash" in m for m in fake.telegram), fake.telegram)
        del fake.faults["asset_sub"]; run(); fake.telegram.clear()

        print("— installer + website —")
        fake.raw[("test/briglia-cli", "v0.1.59", "scripts/get-briglia.sh")] = b"#!/bin/bash\necho DIFFERENT\n"
        rc, out = run()
        check("released install.sh ≠ scripts/get-briglia.sh@tag → installer alert",
              rc == 2 and any("/installer" in m and "differs" in m for m in fake.telegram), fake.telegram)
        fake.raw[("test/briglia-cli", "v0.1.59", "scripts/get-briglia.sh")] = b"#!/bin/bash\necho installer 59\n"; run(); fake.telegram.clear()
        fake.site_installer = b"#!/bin/bash\necho stale website copy\n"
        rc, out = run()
        check("website install URL serving different bytes → website-installer alert",
              rc == 2 and any("website-installer" in m for m in fake.telegram), fake.telegram)
        fake.site_installer = None; run(); fake.telegram.clear()
        fake.site_page = b"<html>no link here</html>"
        rc, out = run()
        check("app page not linking the released click → website-page alert",
              rc == 2 and any("website-page" in m for m in fake.telegram), fake.telegram)
        fake.site_page = ("<a href=\"%s/download/briglia-ut/v0.7.4/click\">x</a>" % B).encode(); run(); fake.telegram.clear()
        # R6: the real domain is probed too, so a domain-only hijack shows
        fake.domain_installer = b"#!/bin/bash\necho hijacked domain\n"
        rc, out = run()
        check("real domain serving different installer bytes while the Vercel alias is fine → website-installer alert naming the domain",
              rc == 2 and any("website-installer" in m and "/domain/cli/install.sh" in m and "/site/cli/install.sh" not in m
                              for m in fake.telegram), fake.telegram)
        fake.domain_installer = None; run(); fake.telegram.clear()
        fake.domain_page = b"<html>hijacked</html>"
        rc, out = run()
        check("real domain page not linking the released click while the alias does → website-page alert naming the domain",
              rc == 2 and any("website-page" in m and "/domain/app" in m and "/site/app " not in m for m in fake.telegram), fake.telegram)
        fake.domain_page = None; run(); fake.telegram.clear()
        good_page = fake.site_page
        fake.site_page = b"<html>stale ISR copy</html>"
        rc, out = run()
        check("both hostnames stale at once (the ISR-lag case) → ONE website-page message, not one per hostname",
              rc == 2 and sum("website-page" in m for m in fake.telegram) == 1, fake.telegram)
        fake.site_page = good_page; run(); fake.telegram.clear()
        # Codex round 1: one host's connection failure must neither skip the
        # other host nor discard a mismatch already found on it.
        alias, domain = "/site/cli/install.sh", "/domain/cli/install.sh"
        fake.faults["disconnect_path"] = alias
        fake.domain_installer = b"#!/bin/bash\necho malicious real domain\n"
        fake.hits.clear(); rc, out = run()
        check("alias connection dropped + real-domain bytes wrong → BOTH hosts fetched, website-installer alert on the FIRST check",
              rc == 2 and alias in fake.hits and domain in fake.hits
              and any("website-installer" in m and domain + " does not resolve" in m for m in fake.telegram), fake.telegram)
        del fake.faults["disconnect_path"]; fake.domain_installer = None; run(); fake.telegram.clear()
        fake.site_installer = b"#!/bin/bash\necho malicious alias\n"
        fake.faults["disconnect_path"] = domain
        fake.hits.clear(); rc, out = run()
        check("alias bytes wrong + real-domain connection dropped → BOTH hosts fetched, mismatch kept, alert on the FIRST check",
              rc == 2 and alias in fake.hits and domain in fake.hits
              and any("website-installer" in m and alias + " does not resolve" in m for m in fake.telegram), fake.telegram)
        del fake.faults["disconnect_path"]; fake.site_installer = None; run(); fake.telegram.clear()
        fake.site_installer = b"#!/bin/bash\necho malicious alias\n"
        rc, out = run()
        n = len(fake.telegram)
        fake.site_installer = None
        fake.faults["disconnect_path"] = alias       # recovery NOT established: the alias cannot be read
        rc, out = run()
        check("a known website-installer mismatch whose host then stops answering → NO false recovery message",
              n >= 1 and rc == 2 and not any("recovered" in m and "website-installer" in m for m in fake.telegram[n:]), fake.telegram)
        del fake.faults["disconnect_path"]; run(); fake.telegram.clear()
        fake.legacy_manifest = {"version": "0.7.3", "sha256": "00" * 32}
        rc, out = run()
        check("legacy Blob manifest disagreeing with the authoritative release → legacy-blob alert",
              rc == 2 and any("legacy-blob" in m for m in fake.telegram), fake.telegram)
        fake.legacy_manifest = {"version": "0.7.4", "sha256": sha(b"click74" * 500), "size": len(b"click74" * 500)}; run(); fake.telegram.clear()

        print("— app corroboration —")
        env75 = publish("briglia-ut", "0.7.5", 2, {"click": b"click75" * 500}, "f" * 40, log=False)
        rc, out = run()
        st = state()
        check("new app release absent from the local publication log → uncorroborated, not recorded",
              rc == 2 and st["recorded"]["briglia-ut"]["sequence"] == 1 and any("uncorroborated" in m and "publication log" in m for m in fake.telegram), fake.telegram)
        fake.telegram.clear()
        with open(pub_log, "a") as f:
            f.write(json.dumps({"tag": "v0.7.5", "version": "0.7.5", "sequence": 2, "clickSha256": "11" * 32,
                                "envelopeSha256": sha(fake.envelopes["briglia-ut"]), "commit": "f" * 40}) + "\n")
        rc, out = run()
        check("publication log entry with a different click hash → still uncorroborated",
              rc == 2 and state()["recorded"]["briglia-ut"]["sequence"] == 1, out)
        fake.telegram.clear()
        with open(pub_log, "a") as f:
            f.write(json.dumps({"tag": "v0.7.5", "version": "0.7.5", "sequence": 2, "clickSha256": sha(b"click75" * 500),
                                "envelopeSha256": sha(fake.envelopes["briglia-ut"]), "commit": "f" * 40}) + "\n")
        rc, out = run()
        check("matching publication log entry → recorded + announced",
              rc == 0 and state()["recorded"]["briglia-ut"]["sequence"] == 2 and any("RECORDED" in m and "v0.7.5" in m for m in fake.telegram), fake.telegram)
        fake.telegram.clear()

        print("— expiry —")
        fake.envelopes["briglia-ut"] = envelope(app_key, "briglia-ut", "0.7.5", 2, {"click": b"click75" * 500}, expires_days=10,
                                            published=state()["recorded"]["briglia-ut"]["published"])
        rc, out = run()
        check("metadata expiring within the warning window → expiry alert (plus record mismatch on the changed expiry)",
              rc == 2 and any("/expiry" in m and "10.0 days" in m or "/expiry" in m and "9.9 days" in m for m in fake.telegram), fake.telegram)
        fake.telegram.clear()

        print("— delivery, locking, heartbeat —")
        fake.envelopes["briglia-ut"] = env75      # back to the recorded envelope: expiry + mismatch recover
        run(); fake.telegram.clear()
        fake.faults["tg_status"] = 500
        fake.faults["asset_404"] = "click"
        rc, out = run()
        st = state()
        check("Telegram down while a NEW finding appears → message QUEUED in state, run still completes",
              rc == 2 and any("asset-unreachable" in m for m in st["queued"]) and st.get("last_completed"), out)
        del fake.faults["tg_status"]
        rc, out = run()
        check("queued message delivered on the next run", any("asset-unreachable" in m for m in fake.telegram) and not state()["queued"], fake.telegram)
        del fake.faults["asset_404"]; run(); fake.telegram.clear()
        import fcntl
        fd = os.open(os.path.join(state_dir, "state.lock"), os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        rc, out = run()
        check("a concurrent run is refused while the lock is held", rc == 1 and "holds" in out, out)
        fcntl.flock(fd, fcntl.LOCK_UN); os.close(fd)
        fake.telegram.clear()

        # ---------------------------------------------------------- heartbeat
        print("— independent heartbeat (release_heartbeat.py) —")
        heartbeat = os.path.join(repo, "scripts", "release_heartbeat.py")
        beacon_path = os.path.join(state_dir, "check.beacon.json")
        hb_state_path = os.path.join(state_dir, "heartbeat-state.json")

        def hb(*extra, env=None, config=cfg_path):
            p = subprocess.run([sys.executable, heartbeat, "--config", config, *extra],
                               capture_output=True, text=True, env=env)
            return p.returncode, p.stdout + p.stderr

        def beacon():
            return json.load(open(beacon_path))

        def set_beacon(mut):
            b = beacon(); mut(b); json.dump(b, open(beacon_path, "w"))

        src = open(heartbeat).read()
        imports = set()
        for line in src.splitlines():
            m = re.match(r"^(?:import|from)\s+([A-Za-z_][\w.]*)", line)
            if m:
                imports.add(m.group(1).split(".")[0])
        check("heartbeat imports the standard library only", imports and imports <= set(sys.stdlib_module_names), sorted(imports))
        check("heartbeat never imports the checker or the verifier module, nor extends sys.path",
              not imports & {"release_watch", "release_verify"} and "sys.path" not in src and "__import__" not in src)
        b = beacon()
        check("check writes the completion beacon (completed ≈ now, 0 findings, 0 queued)",
              abs(time.time() - b["completed"]) < 120 and b["findings"] == 0 and b["queued"] == 0 and b["oldest_queued"] is None, b)
        rc, out = hb()
        check("heartbeat with a fresh beacon → silent, exit 0", rc == 0 and not fake.telegram, out)
        check("heartbeat keeps its own state file, separate from state.json", os.path.exists(hb_state_path), out)
        fd = os.open(os.path.join(state_dir, "state.lock"), os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        rc, out = hb()
        check("heartbeat runs while the CHECKER's lock is held (does not share it)", rc == 0 and "holds" not in out, out)
        fcntl.flock(fd, fcntl.LOCK_UN); os.close(fd)
        # the verifier module disappears: the checker cannot import, the heartbeat must not care
        py_dir = os.path.join(repo, "py")
        os.rename(py_dir, py_dir + ".gone")
        rc, out = run()
        check("checker without py/release_verify.py fails to start (exit ≠ 0) and leaves the beacon untouched",
              rc != 0 and beacon() == b, out[-300:])
        rc, out = hb()
        check("heartbeat still runs with the verifier module missing (fresh beacon → healthy)", rc == 0 and not fake.telegram, out)
        set_beacon(lambda x: x.__setitem__("completed", time.time() - 4 * 3600))
        rc, out = hb()
        check("…and alerts once the beacon is older than the limit → exit 2", rc == 2 and len(fake.telegram) == 1 and "has not completed" in fake.telegram[0], fake.telegram)
        rc, out = hb()
        check("stale alert is not re-sent within the window", len(fake.telegram) == 1, fake.telegram)
        os.rename(py_dir + ".gone", py_dir)
        run(); fake.telegram.clear()
        rc, out = hb()
        check("recovery message once checks complete again", rc == 0 and len(fake.telegram) == 1 and fake.telegram[0].startswith("✅"), fake.telegram)
        fake.telegram.clear()
        os.unlink(beacon_path)
        rc, out = hb()
        check("no beacon at all → 'NEVER completed' alert", rc == 2 and any("NEVER" in m for m in fake.telegram), fake.telegram)
        fake.telegram.clear()
        open(beacon_path, "w").write("{not json")
        rc, out = hb()
        check("unreadable beacon → alert (different text, sent immediately)", rc == 2 and any("unreadable" in m for m in fake.telegram), fake.telegram)
        fake.telegram.clear()
        run(); hb(); fake.telegram.clear()
        set_beacon(lambda x: (x.__setitem__("queued", 2), x.__setitem__("oldest_queued", time.time() - 4 * 3600)))
        rc, out = hb()
        check("checker reporting alerts undelivered for longer than the limit → heartbeat alerts", rc == 2 and any("undelivered" in m for m in fake.telegram), fake.telegram)
        fake.telegram.clear()
        run(); hb(); fake.telegram.clear()
        set_beacon(lambda x: x.__setitem__("completed", time.time() - 4 * 3600))
        open(hb_state_path, "w").write("garbage")
        rc, out = hb()
        check("heartbeat's OWN state corrupt → still alerts (with a note) and rebuilds its state",
              rc == 2 and any("has not completed" in m and "own state" in m for m in fake.telegram) and json.load(open(hb_state_path))["active"], fake.telegram)
        fake.telegram.clear()
        run(); hb(); fake.telegram.clear()
        fake_home = os.path.join(root, "fakehome"); os.makedirs(fake_home)
        env = dict(os.environ, HOME=fake_home)
        rc, out = hb(config=os.path.join(root, "missing-config.json"), env=env)
        hb_default_state = os.path.join(fake_home, ".config", "briglia-release-watch", "heartbeat-state.json")
        check("missing config → built-in defaults, still tries to alert (no beacon there), never touches the real state dir",
              rc == 2 and "built-in defaults" in out and os.path.exists(hb_default_state) and beacon()["findings"] == 0, out)
        open(os.path.join(root, "bad-config.json"), "w").write("{oops")
        rc, out = hb(config=os.path.join(root, "bad-config.json"), env=env)
        check("corrupt config → same fallback", rc == 2 and "built-in defaults" in out, out)
        set_beacon(lambda x: x.__setitem__("completed", time.time() - 4 * 3600))
        fake.faults["tg_status"] = 500
        rc, out = hb()
        check("Telegram down at heartbeat time → alert queued in the heartbeat's own state", rc == 2 and json.load(open(hb_state_path))["queued"], out)
        del fake.faults["tg_status"]
        rc, out = hb()
        check("queued heartbeat alert delivered on the next run", any("has not completed" in m for m in fake.telegram) and not json.load(open(hb_state_path))["queued"], fake.telegram)
        run(); hb(); fake.telegram.clear()
        rc, out = hb("--status")
        check("heartbeat --status prints the beacon and its state", rc == 0 and '"completed"' in out and '"queued"' in out, out[-300:])

        # ------------------------------------------------- state durability
        print("— state durability and recovery —")
        state_path = os.path.join(state_dir, "state.json")
        prev_path = state_path + ".prev"
        seq_now = state()["recorded"]["briglia-cli"]["sequence"]   # 59 at this point in the battery
        check("state.json.prev exists after saves and is a valid previous state", os.path.exists(prev_path) and json.load(open(prev_path))["recorded"]["briglia-cli"]["sequence"] == seq_now)
        check("state files are private (0600)", (os.stat(state_path).st_mode & 0o777) == 0o600 and (os.stat(prev_path).st_mode & 0o777) == 0o600)
        good = open(state_path).read()
        open(state_path, "w").write("{garbage")
        rc, out = run()
        st = state()
        aside = [f for f in os.listdir(state_dir) if f.startswith("state.json.corrupt-")]
        check("corrupt state.json → recovered from .prev, floor kept, damaged file kept aside, recovery ANNOUNCED",
              rc == 0 and st["recorded"]["briglia-cli"]["sequence"] == seq_now and aside
              and any("recovered from the last-known-good" in m and "seq %d" % seq_now in m for m in fake.telegram), (out[-300:], fake.telegram))
        fake.telegram.clear()
        rc, out = run()
        check("next run is silent again", rc == 0 and not fake.telegram, fake.telegram)
        bad = json.loads(good); bad["recorded"]["briglia-cli"]["sequence"] = "58"
        json.dump(bad, open(state_path, "w"))
        rc, out = run()
        check("VALID JSON of the wrong shape (string sequence) is treated as corrupt → recovered, announced",
              rc == 0 and isinstance(state()["recorded"]["briglia-cli"]["sequence"], int) and any("recovered" in m for m in fake.telegram), fake.telegram)
        fake.telegram.clear()
        os.unlink(state_path)
        rc, out = run()
        check("state.json missing but .prev present (crash between renames) → recovered, announced",
              rc == 0 and state()["recorded"]["briglia-cli"]["sequence"] == seq_now and any("was missing" in m for m in fake.telegram), fake.telegram)
        fake.telegram.clear()
        b_before = beacon()
        open(state_path, "w").write("{garbage"); open(prev_path, "w").write("{garbage")
        rc, out = run()
        check("BOTH state.json and .prev unusable → refuses to run (exit 1), direct 🚨 alert, files untouched, beacon untouched",
              rc == 1 and any("REFUSING TO RUN" in m for m in fake.telegram) and open(state_path).read() == "{garbage"
              and open(prev_path).read() == "{garbage" and beacon() == b_before, (out[-300:], fake.telegram))
        fake.telegram.clear()
        open(state_path, "w").write(good); os.unlink(prev_path)
        run(); fake.telegram.clear()
        rc, out = run("status")
        check("status prints the state", rc == 0 and '"recorded"' in out, out[-200:])
        check("bot token never appears in output or state", "tok" not in out.replace("token", "") and "tok" not in json.dumps(state()).replace("token", ""))

        # ------------------------------- config-driven kind + retired-channel replay
        print("— config-driven channel kind (rename plan §6) and pre-rename envelope replay —")
        st_before = json.dumps(state()["recorded"], sort_keys=True)

        def run_with(cfg_variant, tag):
            path = os.path.join(root, "cfg-%s.json" % tag)
            variant = json.loads(json.dumps(cfg_variant))
            variant["state_dir"] = os.path.join(root, "state-" + tag)
            json.dump(variant, open(path, "w"))
            p = subprocess.run([sys.executable, watcher, "check", "--config", path], capture_output=True, text=True)
            rec = json.load(open(os.path.join(variant["state_dir"], "state.json")))["recorded"]
            return p.returncode, p.stdout + p.stderr, rec

        # load_config merges a config file OVER DEFAULT_CONFIG per channel, so the
        # two production channels always carry their built-in kind; a channel the
        # defaults do not know must declare its own.
        nokind = json.loads(json.dumps(cfg))
        nokind["channels"]["briglia-cli-staging"] = {k: v for k, v in nokind["channels"]["briglia-cli"].items() if k != "kind"}
        rc, out, rec = run_with(nokind, "nokind")
        check("a channel the defaults don't know, declared without `kind` → config-invalid alert, exit 2, nothing recorded "
              "for it, the known channels still checked",
              rc == 2 and "briglia-cli-staging/config-invalid" in out and "no valid kind" in out
              and "briglia-cli-staging" not in rec and rec.get("briglia-cli", {}).get("sequence") is not None
              and rec.get("briglia-ut", {}).get("sequence") is not None
              and any("config-invalid" in m and "no valid kind" in m for m in fake.telegram), (out[-400:], rec))
        fake.telegram.clear()
        badkind = json.loads(json.dumps(cfg)); badkind["channels"]["briglia-cli"]["kind"] = "phone"
        rc, out, rec = run_with(badkind, "badkind")
        check("unknown kind → config-invalid, nothing recorded",
              rc == 2 and "briglia-cli/config-invalid" in out and "briglia-cli" not in rec, out[-300:])
        fake.telegram.clear()
        stale = json.loads(json.dumps(cfg))
        stale["channels"]["ada-cli"] = stale["channels"].pop("briglia-cli")   # the pre-rename name, correct kind
        rc, out, rec = run_with(stale, "stale")
        check("config still keyed by the retired channel name (kind correct) → config-invalid naming the disagreement, "
              "no fetch, nothing recorded",
              rc == 2 and "ada-cli/config-invalid" in out and "disagree" in out and "pinned cli policy" in out
              and "ada-cli" not in rec and "briglia-cli" not in rec, out[-400:])
        fake.telegram.clear()
        swapped = json.loads(json.dumps(cfg)); swapped["channels"]["briglia-cli"]["kind"] = "app"
        rc, out, rec = run_with(swapped, "swapped")
        check("right name, wrong kind (app policy for the cli channel) → config-invalid, nothing recorded",
              rc == 2 and "briglia-cli/config-invalid" in out and "briglia-cli" not in rec, out[-300:])
        fake.telegram.clear()
        # A pre-rename envelope — the SAME key material under its retired keyId,
        # channel `ada-cli` — served as latest on the renamed channel: exactly what
        # the redirect serves between the repo rename and the first Briglia release.
        good = fake.envelopes["briglia-cli"]
        legacy_payload = json.dumps({"channel": "ada-cli", "expires": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 90 * 86400)),
                                     "platforms": {"ada-macos-arm64.tar.gz": {"sha256": sha(b"x"), "size": 1, "url": B + "/download/ada-cli/v0.1.58/ada-macos-arm64.tar.gz"}},
                                     "published": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 60)),
                                     "schema": 1, "sequence": 999, "version": "0.1.58"}, sort_keys=True, indent=2).encode()
        fake.envelopes["briglia-cli"] = raw_envelope(cli_key.priv, legacy_payload, "ada-cli", "ada-cli-release-v1-" + cli_key.fingerprint)
        rc, out = run()
        check("pre-rename `ada-cli` envelope (same key, retired keyId, higher sequence) served as latest → envelope-invalid, "
              "floor untouched, never recorded",
              rc == 2 and "briglia-cli/envelope-invalid" in out
              and json.dumps(state()["recorded"], sort_keys=True) == st_before
              and any("envelope-invalid" in m for m in fake.telegram), (out[-300:], fake.telegram))
        fake.envelopes["briglia-cli"] = good
        run(); fake.telegram.clear()
        check("state untouched by the config-variant runs (separate state dirs)",
              json.dumps(state()["recorded"], sort_keys=True) == st_before)

        # ------------------------------------------------- installer (macOS)
        if sys.platform == "darwin":
            print("— atomic, verified deployment (install_release_watch.sh with a launchctl shim) —")
            ihome = os.path.join(root, "ihome")
            iroot = os.path.join(ihome, ".config", "briglia-release-watch")
            os.makedirs(iroot, mode=0o700)
            icfg = dict(cfg, state_dir=os.path.join(iroot, "state"))
            json.dump(icfg, open(os.path.join(iroot, "config.json"), "w"))
            shim_dir = os.path.join(root, "shim"); os.makedirs(shim_dir)
            shim_log = os.path.join(root, "shim.log")
            ibin = os.path.join(iroot, "bin")
            fail_file = os.path.join(root, "shim.fail")   # regex; the shim fails ONCE when a call matches, then deletes it
            open(os.path.join(shim_dir, "launchctl"), "w").write(
                "#!/bin/bash\n"
                "new=absent; [ -e '%s.new' ] && new=present\n"
                "echo \"$1 $2 ${3:-} bin.new=$new\" >> '%s'\n"
                "if [ -f '%s' ] && echo \"$1 $2 ${3:-}\" | grep -Eq \"$(cat '%s')\"; then rm -f '%s'; echo 'injected launchctl failure' >&2; exit 1; fi\n"
                "exit 0\n" % (ibin, shim_log, fail_file, fail_file, fail_file))
            os.chmod(os.path.join(shim_dir, "launchctl"), 0o755)
            ienv = dict(os.environ, PATH=shim_dir + os.pathsep + os.environ["PATH"], BRIGLIA_WATCH_HOME=ihome)
            installer = os.path.join(repo, "scripts", "install_release_watch.sh")

            def install():
                p = subprocess.run(["bash", installer], capture_output=True, text=True, env=ienv)
                return p.returncode, p.stdout + p.stderr

            def shim_calls():
                return [l.strip() for l in open(shim_log)] if os.path.exists(shim_log) else []

            rc, out = install()
            calls = shim_calls()
            check("fresh install succeeds; snapshot has checker, heartbeat and verifier; no bin.new/bin.old left",
                  rc == 0 and all(os.path.exists(os.path.join(ibin, f)) for f in ("release_watch.py", "release_heartbeat.py", "py/release_verify.py", "SNAPSHOT_COMMIT"))
                  and not os.path.exists(ibin + ".new") and not os.path.exists(ibin + ".old"), out[-400:])
            ops = []
            for c in calls:
                parts = c.split()
                kind = re.search(r"\.(check|heartbeat)\.plist", parts[2]) if parts[0] == "bootstrap" else None
                ops.append(parts[0] + (" " + kind.group(1) if kind else ""))
            check("agents are unloaded first, then bootstrapped checker → heartbeat, sequentially",
                  ops == ["bootout", "bootout", "bootstrap check", "print", "bootstrap heartbeat", "print"], calls)
            check("every bootstrap happens after the snapshot swap (bin.new absent)", all("bin.new=absent" in c for c in calls if c.startswith("bootstrap")), calls)
            check("both jobs were verified in the foreground before loading (beacon + heartbeat state present)",
                  os.path.exists(os.path.join(icfg["state_dir"], "check.beacon.json")) and os.path.exists(os.path.join(icfg["state_dir"], "heartbeat-state.json")))
            plists = {k: open(os.path.join(ihome, "Library", "LaunchAgents", "com.permaevidence.briglia-release-watch.%s.plist" % k)).read() for k in ("check", "heartbeat")}
            check("plists: no RunAtLoad, checker runs release_watch.py check, heartbeat runs release_heartbeat.py",
                  all("<key>RunAtLoad</key><false/>" in p for p in plists.values())
                  and "<string>%s/release_watch.py</string><string>check</string>" % ibin in plists["check"]
                  and "<string>%s/release_heartbeat.py</string>" % ibin in plists["heartbeat"] and "release_watch" not in plists["heartbeat"], plists)
            # refresh: the snapshot is replaced atomically, the old one goes away only on success
            open(os.path.join(ibin, "MARKER"), "w").write("old snapshot")
            os.unlink(shim_log)
            rc, out = install()
            check("refresh succeeds and drops the old snapshot", rc == 0 and not os.path.exists(os.path.join(ibin, "MARKER")) and not os.path.exists(ibin + ".old"), out[-300:])
            # failure: make the checker unable to run (both state files corrupt) → rollback
            open(os.path.join(ibin, "MARKER"), "w").write("old snapshot")
            sp = os.path.join(icfg["state_dir"], "state.json")
            good_i = open(sp).read()
            open(sp, "w").write("{garbage"); open(sp + ".prev", "w").write("{garbage")
            os.unlink(shim_log)
            rc, out = install()
            calls = shim_calls()
            check("checker failing from the new snapshot → install exits 1, previous snapshot restored, failed one kept",
                  rc == 1 and os.path.exists(os.path.join(ibin, "MARKER")) and os.path.exists(ibin + ".failed") and not os.path.exists(ibin + ".old"), out[-400:])
            check("…and the previous agents are reloaded after the rollback (rollback boots out again first — idempotent)",
                  [c.split()[0] for c in calls] == ["bootout", "bootout", "bootout", "bootout", "bootstrap", "print", "bootstrap", "print"], calls)
            open(sp, "w").write(good_i); os.unlink(sp + ".prev")
            # activation failures (plist swap + launchctl) are part of the transaction too
            agents_dir = os.path.join(ihome, "Library", "LaunchAgents")
            check_plist = os.path.join(agents_dir, "com.permaevidence.briglia-release-watch.check.plist")
            hb_plist = os.path.join(agents_dir, "com.permaevidence.briglia-release-watch.heartbeat.plist")

            def leftovers():
                return [f for f in os.listdir(agents_dir) if f.endswith((".plist.new", ".plist.old"))]

            for label, pattern, loaded_kind in (
                    ("checker bootstrap", r"^bootstrap .*\.check\.plist", None),
                    ("heartbeat bootstrap", r"^bootstrap .*\.heartbeat\.plist", "check"),
                    ("launchctl print after the heartbeat bootstrap", r"^print gui/[0-9]+/.*\.heartbeat", "heartbeat")):
                marker_text = "<!-- OLDPLIST %s -->" % label
                open(check_plist, "a").write("\n" + marker_text + "\n")
                open(os.path.join(ibin, "MARKER"), "w").write("old snapshot")
                open(fail_file, "w").write(pattern)
                if os.path.exists(shim_log):
                    os.unlink(shim_log)
                rc, out = install()
                calls = shim_calls()
                ops_seq = [c.split()[0] for c in calls]
                failed_at = next((i for i, c in enumerate(calls) if re.match(pattern, c)), None)
                after = ops_seq[failed_at + 1:] if failed_at is not None else []
                check("%s fails → exit 1, previous plists restored, no .new/.old plist left, previous snapshot restored" % label,
                      rc == 1 and marker_text in open(check_plist).read() and not leftovers()
                      and os.path.exists(os.path.join(ibin, "MARKER")) and os.path.exists(ibin + ".failed") and not os.path.exists(ibin + ".old")
                      and "release_heartbeat.py" in open(hb_plist).read(), (out[-500:], leftovers()))
                check("…partially loaded agents are booted out and the previous ones reloaded (checker → heartbeat)",
                      failed_at is not None and after == ["bootout", "bootout", "bootstrap", "print", "bootstrap", "print"]
                      and all("bin.new=absent" in c for c in calls), calls)
                if loaded_kind:
                    check("…the %s agent that had already loaded was among those booted out" % loaded_kind,
                          any(c.startswith("bootout") and ".%s" % loaded_kind in c for c in calls[failed_at + 1:]), calls)
                check("…the fail-once injection was consumed (the rollback's launchctl calls succeeded)", not os.path.exists(fail_file))
            rc, out = install()
            check("a clean install afterwards succeeds and replaces the old plists (marker gone, no leftovers)",
                  rc == 0 and "OLDPLIST" not in open(check_plist).read() and not leftovers() and not os.path.exists(os.path.join(ibin, "MARKER")), out[-300:])
            fake.telegram.clear()
        else:
            print("— installer checks skipped (macOS only) —")
    finally:
        fake.close()
        shutil.rmtree(root, ignore_errors=True)

    print("\nwatch selftest: %d passed, %d failed" % (PASSED, FAILED))
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
