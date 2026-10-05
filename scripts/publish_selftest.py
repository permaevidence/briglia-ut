#!/usr/bin/env python3
"""Battery for scripts/publish_click.sh + scripts/release/publish-github-release.sh
against an in-process fake GitHub Releases API and download host, with fault
injection. Runs the REAL scripts on a throwaway copy of this
repository whose app key is a generated test key.

    python3 scripts/publish_selftest.py
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
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "py"))
from signing_fixture import TestKey, manifest_bytes, raw_envelope  # noqa: E402
import release_verify as rv  # noqa: E402

PASSED = FAILED = 0


def check(label, ok, detail=""):
    global PASSED, FAILED
    print("  %s %s%s" % ("✔" if ok else "✖", label,
                          "" if ok or not detail else " — " + str(detail)[-400:]))
    if ok:
        PASSED += 1
    else:
        FAILED += 1


class FakeGitHub:
    """Releases API + uploads + public download host + git refs, one server."""

    def __init__(self):
        self.releases = {}
        self.next_id = 100
        self.hits = []
        self.faults = {}   # upload_fail: asset name; patch: "ambiguous"|"fail";
        #                   download_substitute: name -> bytes; latest_override: bytes;
        #                   latest_queue: [bytes, ...] served in order (race simulation);
        #                   ref_status: HTTP status forced on the tag-ref lookup;
        #                   ref_prefix_match: answer the lookup with a DIFFERENT ref name;
        #                   tag_on_publish: sha the tag gets at publish time regardless
        #                     of target_commitish (a tag pushed in the race window);
        #                   ref_flip_after: after that many truthful ref lookups,
        #                     answer with a different sha (post-publication drift)
        self.created = []  # create-release request bodies (target_commitish pinning)
        # Git refs: tag name -> {"type": "commit"|"tag", "sha"}; annotated tag
        # objects: sha -> {"object": {...}}. Like GitHub, a release's tag is
        # created when the release is PUBLISHED, and only if it does not exist.
        self.tags = {}
        self.tag_objects = {}
        self.ref_lookups = 0
        self.asset_gets = []      # asset ids downloaded through the API (pre-go-live gate)
        self.token_leaked = False  # Authorization reached the storage host
        self._asset_seq = 5000
        gh = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, status, body=b"", ctype="application/json"):
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if body:
                    self.wfile.write(body)

            def _json(self, status, obj):
                self._send(status, json.dumps(obj).encode())

            def _body(self):
                n = int(self.headers.get("Content-Length") or 0)
                return self.rfile.read(n) if n else b""

            def _auth(self):
                return self.headers.get("Authorization") == "Bearer t0k"

            def _assets_json(self, r):
                out = []
                for n in r["order"] if r.get("order") else r["assets"]:
                    if n not in r["assets"]:
                        continue
                    body = r["assets"][n]
                    a = {"id": r.setdefault("asset_ids", {}).setdefault(n, gh.next_asset_id()), "name": n,
                         "size": len(body), "state": "uploaded"}
                    if gh.faults.get("asset_digest", True):
                        a["digest"] = "sha256:" + hashlib.sha256(body).hexdigest()
                    if gh.faults.get("asset_size_lie") == n:
                        a["size"] = len(body) + 1
                    out.append(a)
                return out

            def _rel_json(self, r):
                return {"id": r["id"], "tag_name": r["tag_name"], "draft": r["draft"],
                        "name": r["name"], "immutable": r["immutable"],
                        "target_commitish": r.get("target_commitish"),
                        "assets": self._assets_json(r)}

            def do_GET(self):
                gh.hits.append(("GET", self.path))
                parsed = urllib.parse.urlparse(self.path)
                path = parsed.path
                m = re.match(r"^/api/repos/([^/]+/[^/]+)/releases/tags/([^/]+)$", path)
                if m:
                    if not self._auth():
                        return self._json(401, {"message": "bad token"})
                    for r in gh.releases.values():
                        if r["tag_name"] == m.group(2) and not r["draft"]:
                            return self._json(200, self._rel_json(r))
                    return self._json(404, {"message": "Not Found"})
                m = re.match(r"^/api/repos/([^/]+/[^/]+)/releases/(\d+)$", path)
                if m:
                    r = gh.releases.get(int(m.group(2)))
                    return self._json(200, self._rel_json(r)) if r else self._json(404, {})
                m = re.match(r"^/api/repos/([^/]+/[^/]+)/releases/(\d+)/assets$", path)
                if m:
                    if not self._auth():
                        return self._json(401, {"message": "bad token"})
                    r = gh.releases.get(int(m.group(2)))
                    if r is None:
                        return self._json(404, {})
                    page = int(urllib.parse.parse_qs(parsed.query).get("page", ["1"])[0])
                    items = self._assets_json(r) if page == 1 else []
                    if gh.faults.get("asset_list_extra") and page == 1:
                        items.append({"id": 99999, "name": gh.faults["asset_list_extra"], "size": 1, "state": "uploaded"})
                    return self._json(200, items)
                m = re.match(r"^/api/repos/([^/]+/[^/]+)/releases/assets/(\d+)$", path)
                if m:
                    # Like GitHub: the API answers a redirect to a storage host,
                    # which must NOT receive the token.
                    if not self._auth() or self.headers.get("Accept") != "application/octet-stream":
                        return self._json(401 if not self._auth() else 415, {"message": "bad request"})
                    gh.asset_gets.append(int(m.group(2)))
                    self.send_response(302)
                    # another HOST name for the same server: curl must drop the token
                    self.send_header("Location", "http://localhost:%d/blob/%s" % (gh.server.server_address[1], m.group(2)))
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                m = re.match(r"^/blob/(\d+)$", path)
                if m:
                    if self.headers.get("Authorization"):
                        gh.token_leaked = True
                    for r in gh.releases.values():
                        for n, aid in r.get("asset_ids", {}).items():
                            if aid == int(m.group(1)) and n in r["assets"]:
                                body = r["assets"][n]
                                sub = gh.faults.get("blob_substitute", {})
                                return self._send(200, sub.get(n, body), "application/octet-stream")
                    return self._send(404, b"")
                m = re.match(r"^/api/repos/([^/]+/[^/]+)/git/ref/tags/([^/]+)$", path)
                if m:
                    if not self._auth():
                        return self._json(401, {"message": "bad token"})
                    if gh.faults.get("ref_status"):
                        return self._json(int(gh.faults["ref_status"]), {"message": "injected"})
                    tag = m.group(2)
                    if gh.faults.get("ref_prefix_match"):
                        return self._json(200, {"ref": "refs/tags/%s-rc1" % tag,
                                                "object": {"type": "commit", "sha": "f" * 40}})
                    t = gh.tags.get(tag)
                    if t is None:
                        return self._json(404, {"message": "Not Found"})
                    gh.ref_lookups += 1
                    flip = gh.faults.get("ref_flip_after")
                    if flip is not None and gh.ref_lookups > flip:
                        t = {"type": "commit", "sha": "e" * 40}
                    return self._json(200, {"ref": "refs/tags/" + tag, "object": dict(t)})
                m = re.match(r"^/api/repos/([^/]+/[^/]+)/git/tags/([0-9a-f]{40})$", path)
                if m:
                    if not self._auth():
                        return self._json(401, {"message": "bad token"})
                    obj = gh.tag_objects.get(m.group(2))
                    return self._json(200, obj) if obj else self._json(404, {"message": "Not Found"})
                m = re.match(r"^/api/repos/([^/]+/[^/]+)/releases$", path)
                if m:
                    page = int(urllib.parse.parse_qs(parsed.query).get("page", ["1"])[0])
                    items = [self._rel_json(r) for r in gh.releases.values()] if page == 1 else []
                    return self._json(200, items)
                if path == "/latest/manifest.sig.json":
                    if gh.faults.get("latest_queue"):
                        return self._send(200, gh.faults["latest_queue"].pop(0))
                    if "latest_override" in gh.faults:
                        return self._send(200, gh.faults["latest_override"])
                    latest = gh.latest()
                    if latest and "manifest.sig.json" in latest["assets"]:
                        return self._send(200, latest["assets"]["manifest.sig.json"])
                    return self._send(404, b"")
                m = re.match(r"^/download/(v[^/]+)/([^/]+)$", path)
                if m:
                    for r in gh.releases.values():
                        if r["tag_name"] == m.group(1) and not r["draft"] and m.group(2) in r["assets"]:
                            sub = gh.faults.get("download_substitute", {})
                            return self._send(200, sub.get(m.group(2), r["assets"][m.group(2)]))
                    return self._send(404, b"")
                self._send(404, b"")

            def do_POST(self):
                gh.hits.append(("POST", self.path))
                body = self._body()
                parsed = urllib.parse.urlparse(self.path)
                if not self._auth():
                    return self._json(401, {"message": "bad token"})
                m = re.match(r"^/api/repos/([^/]+/[^/]+)/releases$", parsed.path)
                if m:
                    req = json.loads(body)
                    gh.created.append(req)
                    rid = gh.next_id
                    gh.next_id += 1
                    gh.releases[rid] = {"id": rid, "tag_name": req["tag_name"], "draft": bool(req.get("draft")),
                                        "name": req.get("name", ""), "immutable": False, "assets": {},
                                        "order": [], "target_commitish": req.get("target_commitish")}
                    return self._json(201, self._rel_json(gh.releases[rid]))
                m = re.match(r"^/api/repos/([^/]+/[^/]+)/releases/(\d+)/assets$", parsed.path)
                if m:
                    name = urllib.parse.parse_qs(parsed.query)["name"][0]
                    r = gh.releases.get(int(m.group(2)))
                    if r is None or not r["draft"]:
                        return self._json(422, {"message": "not a draft"})
                    if gh.faults.get("upload_fail") == name:
                        return self._json(500, {"message": "injected upload failure"})
                    if gh.faults.get("upload_corrupt") == name:
                        body = bytes([body[0] ^ 1]) + body[1:]   # storage-side damage / wrong artifact
                    r["assets"][name] = body
                    r["order"].append(name)
                    return self._json(201, {"name": name})
                self._json(404, {})

            def do_PATCH(self):
                gh.hits.append(("PATCH", self.path))
                body = json.loads(self._body())
                m = re.match(r"^/api/repos/([^/]+/[^/]+)/releases/(\d+)$", self.path)
                r = gh.releases.get(int(m.group(2))) if m else None
                if r is None:
                    return self._json(404, {})
                mode = gh.faults.get("patch")
                if mode == "fail":
                    return self._json(502, {"message": "injected: not applied"})
                if body.get("draft") is False:
                    r["draft"] = False
                    r["immutable"] = gh.faults.get("immutable", True)
                    # GitHub creates the tag now — at target_commitish only if the
                    # tag does not exist yet (an existing tag is kept untouched).
                    if gh.faults.get("tag_on_publish"):
                        gh.tags[r["tag_name"]] = {"type": "commit", "sha": gh.faults["tag_on_publish"]}
                    elif r["tag_name"] not in gh.tags:
                        gh.tags[r["tag_name"]] = {"type": "commit",
                                                  "sha": r.get("target_commitish") or "0" * 40}
                if mode == "ambiguous":
                    return self._json(502, {"message": "injected: applied but timed out"})
                self._json(200, self._rel_json(r))

            def do_DELETE(self):
                gh.hits.append(("DELETE", self.path))
                m = re.match(r"^/api/repos/([^/]+/[^/]+)/releases/(\d+)$", self.path)
                r = gh.releases.pop(int(m.group(2)), None) if m else None
                self._send(204 if r else 404, b"")

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = "http://127.0.0.1:%d" % self.server.server_address[1]

    def next_asset_id(self):
        self._asset_seq += 1
        return self._asset_seq

    def latest(self):
        published = [r for r in self.releases.values() if not r["draft"]]
        return published[-1] if published else None

    def seed_published(self, tag, assets, sha="1" * 40):
        """A release that already exists and is live — e.g. the previous
        identity's last release, which this publisher never created."""
        rid = self.next_id
        self.next_id += 1
        self.releases[rid] = {"id": rid, "tag_name": tag, "draft": False, "name": tag,
                              "immutable": True, "assets": dict(assets),
                              "order": list(assets), "target_commitish": sha}
        self.tags[tag] = {"type": "commit", "sha": sha}
        return self.releases[rid]

    def by_tag(self, tag):
        return next((r for r in self.releases.values() if r["tag_name"] == tag), None)

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def main():
    root = tempfile.mkdtemp(prefix="briglia-ut-publish-selftest-")
    repo_src = os.path.dirname(HERE)
    repo = os.path.join(root, "repo")
    os.makedirs(repo)
    for item in ("manifest.json", "LICENSE", ".gitignore", "py", "qml", "click", "assets", "scripts", "clickable.yaml"):
        src = os.path.join(repo_src, item)
        if os.path.isdir(src):
            shutil.copytree(src, os.path.join(repo, item),
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        elif os.path.exists(src):
            shutil.copy2(src, os.path.join(repo, item))
    key = TestKey("briglia-ut")
    other = TestKey("briglia-ut")
    os.makedirs(os.path.join(repo, ".release-keys"))
    shutil.copy2(key.pub, os.path.join(repo, ".release-keys", "briglia-ut-release.pub.pem"))
    rv_path = os.path.join(repo, "py", "release_verify.py")

    def stamp(sequence, version, key_id=key.key_id, pub_hex=key.pub_hex, push=True):
        s = open(rv_path).read()
        s = re.sub(r"# STAMP-APP-KEY-BEGIN.*?# STAMP-APP-KEY-END",
                   '# STAMP-APP-KEY-BEGIN\nAPP_KEYS = {\n    "%s":\n        "%s",\n}\n# STAMP-APP-KEY-END'
                   % (key_id, pub_hex), s, flags=re.S)
        s = re.sub(r"^APP_RELEASE_SEQUENCE = \d+$", "APP_RELEASE_SEQUENCE = %d" % sequence, s, flags=re.M)
        open(rv_path, "w").write(s)
        m = json.load(open(os.path.join(repo, "manifest.json")))
        m["version"] = version
        json.dump(m, open(os.path.join(repo, "manifest.json"), "w"), indent=2)
        subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)
        subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "stamp", "--allow-empty"],
                       cwd=repo, check=True, capture_output=True)
        if push:
            subprocess.run(["git", "push", "-q", "origin", "HEAD:main"], cwd=repo, check=True, capture_output=True)

    def head():
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True).stdout.strip()
    origin = os.path.join(root, "origin.git")
    subprocess.run(["git", "init", "-q", "--bare", "-b", "main", origin], check=True)
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo, check=True)
    subprocess.run(["git", "remote", "add", "origin", origin], cwd=repo, check=True)
    stamp(1, "0.7.4")

    gh = FakeGitHub()
    log = os.path.join(root, "publications.jsonl")
    base_env = {
        "REPO_ROOT": repo, "REPO": "test/briglia-ut", "GH_TOKEN": "t0k",
        "GH_API_URL": gh.base + "/api", "GH_UPLOADS_URL": gh.base + "/api",
        "PUBLIC_DOWNLOAD_BASE": gh.base + "/download",
        "LIVE_ENVELOPE_URL": gh.base + "/latest/manifest.sig.json",
        "SIGNING_KEY": key.priv, "PUBLICATION_LOG": log, "PUBLIC_RETRY_SLEEP": "0.05",
        "HOME": root, "PUBLISH_LOCK": os.path.join(root, "publish.lock"),
    }

    def run(*args, **env):
        e = dict(os.environ)
        e.update(base_env)
        e.update(env)
        p = subprocess.run([os.path.join(repo_src, "scripts", "publish_click.sh"), *args],
                           capture_output=True, text=True, env=e)
        return p.returncode, p.stdout + p.stderr

    def posts():
        return [h for h in gh.hits if h[0] == "POST"]

    def log_lines():
        return open(log).read().splitlines() if os.path.exists(log) else []

    def verify_public(seq, version):
        policy = rv.ReleasePolicy("briglia-ut", key.keys(), gh.base + "/latest/manifest.sig.json",
                                  gh.base + "/download/v{version}/", 1)
        rv.TRUST_FILE = os.path.join(root, "trust.json")
        try:
            m = rv.resolve_release(policy)
        except rv.ReleaseVerifyError as exc:
            return False, exc
        return m["sequence"] == seq and m["version"] == version, m

    # The channel's existing live state: a briglia-ut sequence-1 release.
    live1_click = b"live-1-click-bytes"

    def live1_manifest(**over):
        fields = dict(channel="briglia-ut", version="0.7.4", sequence=1,
                      url=gh.base + "/download/v0.7.4/briglia.permaevidence_0.7.4_all.click",
                      platforms=None, schema=1)
        fields.update(over)
        platforms = fields["platforms"]
        if platforms is None:
            platforms = {"click": {"url": fields["url"], "size": len(live1_click),
                                   "sha256": hashlib.sha256(live1_click).hexdigest()}}
        return manifest_bytes(fields["channel"], fields["version"], fields["sequence"],
                              platforms, schema=fields["schema"])

    def live1_envelope(payload=None):
        return raw_envelope(key.priv, payload or live1_manifest(), "briglia-ut", key.key_id)

    try:
        print("— gates —")
        rc, out = run()
        check("no live release → refused (bootstrap retired), nothing posted",
              rc != 0 and "bootstrap retired" in out and not posts(), out)
        rc, out = run("--bootstrap")
        check("--bootstrap is gone: unknown option, nothing posted",
              rc == 2 and "unknown option" in out and not posts(), out)

        # From here on the live state is the sequence-1 release and the
        # source is stamped as sequence 2.
        gh.seed_published("v0.7.4", {"briglia.permaevidence_0.7.4_all.click": live1_click,
                                     "manifest.json": live1_manifest(),
                                     "manifest.sig.json": live1_envelope()})
        stamp(2, "0.7.5")
        rc, out = run("--dry-run")
        check("--dry-run signs + verifies, publishes nothing",
              rc == 0 and "dry run" in out and "the app's verifier" in out and not posts(), out)
        open(os.path.join(repo, "stray.txt"), "w").write("x")
        rc, out = run()
        check("dirty tree refused", rc != 0 and "not clean" in out and not posts(), out)
        rc, out = run("--dry-run", "--allow-dirty")
        check("--allow-dirty lets a dry run through", rc == 0, out)
        os.unlink(os.path.join(repo, "stray.txt"))
        rc, out = run("0.9.9")
        check("version argument != manifest.json refused", rc != 0 and "!= manifest.json" in out, out)
        rc, out = run(EXPECTED_PUB=other.pub, SIGNING_KEY=other.priv)
        check("committed key not pinned in release_verify.py → refused",
              rc != 0 and "does not pin" in out and not posts(), out)
        os.chmod(key.priv, 0o644)
        rc, out = run()
        check("signing key with loose permissions refused", rc != 0 and "0600" in out, out)
        os.chmod(key.priv, 0o600)

        print("— first publish over the live sequence 1 —")
        stamp(2, "0.7.5")
        # Two supersession reads see the live floor; after publication the
        # latest pointer still serves the previous envelope twice (GitHub's
        # propagation lag, measured live in the Stage-7 rehearsal), then
        # catches up.
        gh.faults["latest_queue"] = [live1_envelope()] * 4
        rc, out = run()
        rel = gh.by_tag("v0.7.5")
        check("sequence 2 over the authenticated live sequence 1 publishes",
              rc == 0 and rel is not None and rel["draft"] is False, out)
        check("latest still serving the previous envelope after publication is waited out (twice), not treated as a mismatch",
              out.count("latest still serves the previous release") == 2 and "public state verified" in out, out)
        check("assets uploaded in order, envelope last",
              rel and rel["order"] == ["briglia.permaevidence_0.7.5_all.click", "manifest.json", "manifest.sig.json"],
              rel and rel["order"])
        ok, m = verify_public(2, "0.7.5")
        check("public envelope verifies with the app's verifier (seq 2, channel briglia-ut)",
              ok and m["channel"] == "briglia-ut", str(m)[:200])
        click_built = open(os.path.join(repo, "build", "briglia.permaevidence_0.7.5_all.click"), "rb").read()
        check("published click == built click, and matches the signed sha256",
              rel["assets"]["briglia.permaevidence_0.7.5_all.click"] == click_built
              and m["platforms"]["click"]["sha256"] == hashlib.sha256(click_built).hexdigest())
        check("publication recorded after verification",
              len(log_lines()) == 1 and json.loads(log_lines()[0])["sequence"] == 2)
        check("release PATCHed with explicit make_latest",
              any(h[0] == "PATCH" for h in gh.hits))
        check("the tag is pinned to the exact reviewed HEAD commit",
              gh.created and gh.created[-1].get("target_commitish") == head(), gh.created[-1:])
        print("— supersession —")
        stamp(2, "0.7.5")
        rc, out = run()
        check("same sequence again → superseded", rc != 0 and "superseded" in out, out)
        stamp(3, "0.7.5")
        rc, out = run()
        check("higher sequence but same tag → immutability refuses republish",
              rc != 0 and "already exists" in out, out)
        ok, m = verify_public(2, "0.7.5")
        check("latest is now v0.7.5 seq 2", ok)
        rv.TRUST_FILE = os.path.join(root, "trust.json")
        rv.record_accepted(rv.ReleasePolicy("briglia-ut", key.keys(), "", gh.base + "/download/v{version}/", 1), m)

        print("— concurrency —")
        stamp(3, "0.7.6", push=False)
        rc, out = run()
        check("HEAD not on origin/main → refused before any build/network",
              rc != 0 and "not on origin/main" in out and not gh.by_tag("v0.7.6"), out)
        subprocess.run(["git", "push", "-q", "origin", "HEAD:main"], cwd=repo, check=True, capture_output=True)
        import fcntl
        lock_fd = os.open(base_env["PUBLISH_LOCK"], os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        rc, out = run()
        check("a second publisher is refused while the lock is held",
              rc != 0 and "publisher lock" in out and not gh.by_tag("v0.7.6"), out)
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)
        live_now = gh.latest()["assets"]["manifest.sig.json"]
        # Race: the channel advances to sequence 9 between our first check
        # (sees 2) and the pre-publish re-check (sees 9) → we must stop.
        raced = key.sign(json.dumps({"channel": "briglia-ut", "expires": "2099-01-01T00:00:00Z",
                                     "platforms": {"click": {"sha256": "ab" * 32, "size": 1,
                                                             "url": gh.base + "/download/v0.9.0/x.click"}},
                                     "published": "2026-01-01T00:00:00Z", "schema": 1,
                                     "sequence": 9, "version": "0.9.0"}, sort_keys=True, indent=2).encode())
        gh.faults["latest_queue"] = [live_now, raced]
        posts_before = len(posts())
        rc, out = run()
        check("channel advanced between the two checks → refused at 'before publish', nothing created",
              rc != 0 and "superseded (before publish)" in out and len(posts()) == posts_before
              and not gh.by_tag("v0.7.6"), out)
        gh.faults.pop("latest_queue", None)

        print("— fault injection —")
        stale_id = gh.next_id
        gh.releases[stale_id] = {"id": stale_id, "tag_name": "v0.7.6", "draft": True, "name": "stale",
                                 "immutable": False, "assets": {}, "order": []}
        gh.next_id += 1
        rc, out = run()
        check("stale draft for the tag is deleted, then v0.7.6 publishes",
              rc == 0 and stale_id not in gh.releases and ("DELETE", "/api/repos/test/briglia-ut/releases/%d" % stale_id) in gh.hits
              and gh.by_tag("v0.7.6") and not gh.by_tag("v0.7.6")["draft"], out)
        stamp(4, "0.7.7")
        gh.faults["upload_fail"] = "manifest.sig.json"
        before = len(log_lines())
        rc, out = run()
        drafts = [r for r in gh.releases.values() if r["tag_name"] == "v0.7.7"]
        check("envelope upload failure → exit 1, draft left, old release stays latest, nothing recorded",
              rc != 0 and "uploading manifest.sig.json failed" in out and drafts and drafts[0]["draft"]
              and gh.latest()["tag_name"] == "v0.7.6" and len(log_lines()) == before, out)
        del gh.faults["upload_fail"]
        rc, out = run()
        check("retry cleans the stale draft and publishes v0.7.7",
              rc == 0 and len([r for r in gh.releases.values() if r["tag_name"] == "v0.7.7"]) == 1
              and gh.latest()["tag_name"] == "v0.7.7", out)
        stamp(5, "0.7.8")
        gh.faults["patch"] = "ambiguous"
        rc, out = run()
        check("ambiguous publish PATCH (applied, 502) → confirmed by re-read, success with warning",
              rc == 0 and "confirmed by re-read" in out and gh.latest()["tag_name"] == "v0.7.8", out)
        del gh.faults["patch"]
        stamp(6, "0.7.9")
        gh.faults["patch"] = "fail"
        before = len(log_lines())
        rc, out = run()
        check("publish PATCH failure (not applied) → exit 1, still a draft, nothing recorded",
              rc != 0 and "remains a draft" in out and gh.by_tag("v0.7.9")["draft"] and len(log_lines()) == before, out)
        del gh.faults["patch"]
        rc, out = run()
        check("retry after PATCH failure publishes v0.7.9", rc == 0 and gh.latest()["tag_name"] == "v0.7.9", out)
        stamp(7, "0.7.10")
        good_latest = gh.latest()["assets"]["manifest.sig.json"]
        tampered = json.loads(good_latest)
        tampered["signature"] = ("B" if tampered["signature"][0] != "B" else "C") + tampered["signature"][1:]
        gh.faults["latest_override"] = json.dumps(tampered).encode()
        rc, out = run()
        check("tampered LIVE envelope → hard stop (never unlocks bootstrap), nothing posted",
              rc != 0 and "hard stop" in out and not gh.by_tag("v0.7.10"), out)
        rc, out = run("--bootstrap")
        check("…and --bootstrap no longer exists to bypass it", rc == 2 and "unknown option" in out
              and not gh.by_tag("v0.7.10"), out)
        del gh.faults["latest_override"]
        gh.faults["download_substitute"] = {"briglia.permaevidence_0.7.10_all.click": b"not the click"}
        before = len(log_lines())
        rc, out = run()
        check("public click differs from the built one → exit 1, NOT recorded",
              rc != 0 and "public click differs" in out and len(log_lines()) == before, out)
        del gh.faults["download_substitute"]
        stamp(8, "0.7.11")
        gh.faults["immutable"] = False
        before = len(log_lines())
        rc, out = run()
        check("release not immutable → exit 1, NOT recorded",
              rc != 0 and "NOT immutable" in out and len(log_lines()) == before, out)
        del gh.faults["immutable"]

        print("— pre-go-live gate: the draft is read back before the PATCH (plan §3.2) —")
        click12 = "briglia.permaevidence_0.7.12_all.click"

        def patched(tag):
            r = gh.by_tag(tag)
            return r is not None and ("PATCH", "/api/repos/test/briglia-ut/releases/%d" % r["id"]) in gh.hits

        def refused_before_patch(rc, out, tag, before):
            r = gh.by_tag(tag)
            return (rc != 0 and "pre-publication verification of draft" in out and r is not None and r["draft"]
                    and not patched(tag) and gh.latest()["tag_name"] == "v0.7.11" and len(log_lines()) == before)
        stamp(9, "0.7.12")
        before = len(log_lines())
        gh.faults["upload_corrupt"] = click12
        rc, out = run()
        check("uploaded click differs by one byte from the verified one → gate refuses, NO PATCH, draft stays, old latest, nothing recorded",
              refused_before_patch(rc, out, "v0.7.12", before) and "API digest" in out, out)
        gh.faults["asset_digest"] = False
        rc, out = run()
        check("…and with no API digest the downloaded BYTES still catch it (digest is never a substitute)",
              refused_before_patch(rc, out, "v0.7.12", before) and "uploaded bytes differ" in out, out)
        del gh.faults["asset_digest"]
        del gh.faults["upload_corrupt"]
        gh.faults["asset_list_extra"] = "evil.sh"
        rc, out = run()
        check("draft holds an EXTRA asset → refused before the PATCH", refused_before_patch(rc, out, "v0.7.12", before)
              and "not exactly the staged set" in out, out)
        del gh.faults["asset_list_extra"]
        swapped = key.sign(json.dumps({"channel": "briglia-ut", "expires": "2099-01-01T00:00:00Z",
                                       "platforms": {"click": {"sha256": "ab" * 32, "size": 1,
                                                               "url": gh.base + "/download/v0.7.12/" + click12}},
                                       "published": "2026-01-01T00:00:00Z", "schema": 1,
                                       "sequence": 99, "version": "0.7.12"}, sort_keys=True, indent=2).encode())
        gh.faults["blob_substitute"] = {"manifest.sig.json": swapped}
        rc, out = run()
        check("draft envelope swapped for ANOTHER authenticated envelope (sequence 99) → refused before the PATCH",
              refused_before_patch(rc, out, "v0.7.12", before), out)
        del gh.faults["blob_substitute"]
        gh.faults["asset_size_lie"] = "manifest.json"
        rc, out = run()
        check("API reports a size different from the staged file → refused before the PATCH",
              refused_before_patch(rc, out, "v0.7.12", before) and "API size" in out, out)
        del gh.faults["asset_size_lie"]
        gh.faults["asset_digest"] = False
        gh.asset_gets.clear()
        rc, out = run()
        rel12 = gh.by_tag("v0.7.12")
        patch_at = gh.hits.index(("PATCH", "/api/repos/test/briglia-ut/releases/%d" % rel12["id"])) if rel12 else -1
        gets_at = [i for i, h in enumerate(gh.hits) if h[0] == "GET" and re.match(r"^/api/repos/test/briglia-ut/releases/assets/\d+$", h[1])]
        check("no API digest (optional field) but bytes verified → publishes; stale draft from the refusals cleaned first",
              rc == 0 and rel12 and rel12["draft"] is False and len([r for r in gh.releases.values() if r["tag_name"] == "v0.7.12"]) == 1, out)
        check("the gate downloaded all 3 draft assets BEFORE the go-live PATCH",
              len(gh.asset_gets) == 3 and gets_at and max(gets_at) < patch_at, (gets_at, patch_at))
        check("the token never reached the asset storage host", gh.token_leaked is False)
        del gh.faults["asset_digest"]
        p = subprocess.run([os.path.join(repo_src, "scripts", "release", "publish-github-release.sh")], capture_output=True, text=True,
                           env={**os.environ, "GH_TOKEN": "t0k", "REPO": "test/briglia-ut", "REF_NAME": "v9.9.8", "VERSION": "9.9.8",
                                "TITLE": "t", "ASSETS": os.path.join(repo, "manifest.json"), "GH_API_URL": gh.base + "/api",
                                "TARGET_COMMITISH": "a" * 40})
        check("publish-github-release.sh without PREPUBLISH_VERIFY refuses before any API call",
              p.returncode != 0 and "PREPUBLISH_VERIFY is required" in p.stdout + p.stderr, p.stdout + p.stderr)

        print("— tag binding (refs API, not target_commitish) —")
        by_tag_log = {json.loads(l)["tag"]: json.loads(l)["commit"] for l in log_lines()}
        check("every tag created so far names the commit recorded for its publication",
              by_tag_log and all(gh.tags.get(t, {}).get("sha") == c for t, c in by_tag_log.items()),
              {t: (gh.tags.get(t, {}).get("sha"), c) for t, c in by_tag_log.items()})
        stamp(13, "0.7.16")
        gh.tags["v0.7.16"] = {"type": "commit", "sha": "a" * 40}
        before = len(log_lines())
        rc, out = run()
        check("pre-existing tag naming ANOTHER commit → refused before the draft, nothing created/recorded",
              rc != 0 and "not the reviewed HEAD" in out and "(before draft)" in out
              and not gh.by_tag("v0.7.16") and len(log_lines()) == before, out)
        gh.tags["v0.7.16"] = {"type": "commit", "sha": head()}
        rc, out = run()
        check("pre-existing lightweight tag naming the reviewed HEAD → publishes, tag untouched",
              rc == 0 and gh.by_tag("v0.7.16") and not gh.by_tag("v0.7.16")["draft"]
              and gh.tags["v0.7.16"]["sha"] == head() and json.loads(log_lines()[-1])["commit"] == head(), out)
        stamp(14, "0.7.17")
        gh.tags["v0.7.17"] = {"type": "tag", "sha": "b" * 40}
        gh.tag_objects["b" * 40] = {"object": {"type": "tag", "sha": "c" * 40}}
        gh.tag_objects["c" * 40] = {"object": {"type": "commit", "sha": head()}}
        rc, out = run()
        check("pre-existing ANNOTATED tag (nested) resolving to the reviewed HEAD → publishes",
              rc == 0 and gh.by_tag("v0.7.17") and not gh.by_tag("v0.7.17")["draft"], out)
        stamp(15, "0.7.18")
        gh.tags["v0.7.18"] = {"type": "tag", "sha": "b" * 40}
        gh.tag_objects["c" * 40] = {"object": {"type": "commit", "sha": "a" * 40}}
        rc, out = run()
        check("pre-existing annotated tag resolving to ANOTHER commit → refused, nothing created",
              rc != 0 and "not the reviewed HEAD" in out and not gh.by_tag("v0.7.18"), out)
        del gh.tags["v0.7.18"]
        gh.faults["ref_status"] = 500
        posts_before = len(posts())
        rc, out = run()
        check("tag lookup error (HTTP 500) → refused, never treated as absent, nothing created",
              rc != 0 and "cannot resolve refs/tags/v0.7.18" in out and len(posts()) == posts_before, out)
        del gh.faults["ref_status"]
        gh.faults["ref_prefix_match"] = True
        rc, out = run()
        check("tag lookup answering a different ref name (prefix match) → refused, nothing created",
              rc != 0 and "cannot resolve refs/tags/v0.7.18" in out and len(posts()) == posts_before, out)
        del gh.faults["ref_prefix_match"]
        gh.faults["tag_on_publish"] = "d" * 40
        before = len(log_lines())
        rc, out = run()
        check("tag created at ANOTHER commit in the publish window → post-publication check fails, NOT recorded",
              rc != 0 and "(after publish)" in out and "not the reviewed HEAD" in out
              and gh.by_tag("v0.7.18") and not gh.by_tag("v0.7.18")["draft"]
              and len(log_lines()) == before and "public state verified" not in out, out)
        del gh.faults["tag_on_publish"]
        stamp(16, "0.7.19")
        gh.ref_lookups = 0
        gh.faults["ref_flip_after"] = 1   # pre-publish lookups are 404s (uncounted); the inner post-publish lookup is truthful, the outer re-check sees drift
        before = len(log_lines())
        rc, out = run()
        check("tag drift seen only by publish_click.sh's own post-publication re-check → NOT recorded",
              rc != 0 and "bound to the wrong commit" in out and len(log_lines()) == before
              and gh.by_tag("v0.7.19") and not gh.by_tag("v0.7.19")["draft"], out)
        del gh.faults["ref_flip_after"]
        inner = os.path.join(repo_src, "scripts", "release", "publish-github-release.sh")
        inner_env = {"GH_TOKEN": "t0k", "REPO": "test/briglia-ut", "REF_NAME": "v9.9.9", "VERSION": "9.9.9",
                     "TITLE": "t", "ASSETS": os.path.join(repo, "manifest.json"), "GH_API_URL": gh.base + "/api"}
        posts_before = len(posts())
        p = subprocess.run([inner], capture_output=True, text=True, env={**os.environ, **inner_env})
        check("publish-github-release.sh without TARGET_COMMITISH refuses",
              p.returncode != 0 and "TARGET_COMMITISH is required" in p.stdout + p.stderr, p.stdout + p.stderr)
        p = subprocess.run([inner], capture_output=True, text=True, env={**os.environ, **inner_env, "TARGET_COMMITISH": "main"})
        check("publish-github-release.sh with a branch name instead of a commit SHA refuses",
              p.returncode != 0 and "full 40-hex commit SHA" in p.stdout + p.stderr and len(posts()) == posts_before,
              p.stdout + p.stderr)
        print("— public propagation window (step 6) —")
        live_env = gh.latest()["assets"]["manifest.sig.json"]
        stamp(17, "0.7.20")
        gh.faults["latest_queue"] = [live_env] * 4   # 2 supersession reads + 2 stale step-6 reads, then the real latest
        before = len(log_lines())
        rc, out = run()
        check("latest pointer lag: the authenticated previous release seen twice after publish → waited out, then recorded",
              rc == 0 and out.count("latest still serves the previous release") == 2 and len(log_lines()) == before + 1
              and json.loads(log_lines()[-1])["sequence"] == 17, out)
        foreign_env = raw_envelope(other.priv, live1_manifest(), "briglia-ut", other.key_id)
        stamp(18, "0.7.21")
        gh.faults["latest_queue"] = [gh.by_tag("v0.7.20")["assets"]["manifest.sig.json"]] * 2 + [foreign_env]
        before = len(log_lines())
        rc, out = run()
        check("step 6 sees an envelope that is neither ours nor an authenticated previous state → hard stop, release live but NOT recorded",
              rc != 0 and "neither this release nor an authenticated previous state" in out and "NOT recorded" in out
              and len(log_lines()) == before and gh.by_tag("v0.7.21") and not gh.by_tag("v0.7.21")["draft"], out)
        stamp(19, "0.7.22")
        gh.faults["latest_queue"] = [gh.by_tag("v0.7.20")["assets"]["manifest.sig.json"]] * 8
        before = len(log_lines())
        rc, out = run(PUBLIC_PROPAGATION_ATTEMPTS="3")
        check("latest never catches up within the bounded window → hard stop naming the live release, NOT recorded",
              rc != 0 and "still serves the previous release" in out and "live and immutable but NOT recorded" in out
              and len(log_lines()) == before and gh.by_tag("v0.7.22") and not gh.by_tag("v0.7.22")["draft"], out)
        gh.faults.pop("latest_queue", None)
        stamp(20, "0.7.23")
        newer = raw_envelope(key.priv, json.dumps({"channel": "briglia-ut", "schema": 1, "sequence": 99, "version": "9.9.9",
                              "published": "2026-09-01T00:00:00Z", "expires": "2027-09-01T00:00:00Z",
                              "platforms": {"click": {"url": gh.base + "/download/v9.9.9/x.click", "size": 1, "sha256": "ab" * 32}}},
                             sort_keys=True, indent=2).encode(), "briglia-ut", key.key_id)
        gh.faults["latest_queue"] = [gh.by_tag("v0.7.20")["assets"]["manifest.sig.json"]] * 2 + [newer]
        before = len(log_lines())
        rc, out = run()
        check("step 6 sees an authenticated NEWER sibling → hard stop (never waited out), NOT recorded",
              rc != 0 and "a sibling publication got ahead" in out and len(log_lines()) == before, out)
        gh.faults.pop("latest_queue", None)
        check("every publication in the log is monotonic",
              [json.loads(l)["sequence"] for l in log_lines()] == sorted({json.loads(l)["sequence"] for l in log_lines()}),
              log_lines())
        check("--legacy-blob flags are gone (retired transition)", run("--legacy-blob")[0] == 2 and run("--legacy-blob-only")[0] == 2)
        check("the token never appears in output", "t0k" not in out)
    finally:
        gh.close()
        shutil.rmtree(root, ignore_errors=True)

    print("\npublish selftest: %d passed, %d failed" % (PASSED, FAILED))
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
