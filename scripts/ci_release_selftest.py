#!/usr/bin/env python3
"""Offline battery for the app's signed-release CI pieces (UT
signing-in-CI plan §8.1): the extracted manifest generator, supersession
check, candidate verifier, pre-publication staging gate, and a static
check of .github/workflows/release-signed.yml. Throwaway keys, an
in-process download host, a throwaway git repository — no network, no
production key.

    python3 scripts/ci_release_selftest.py
"""

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from signing_fixture import TestKey, FakeHost, stamp_app_policy, raw_envelope  # noqa: E402

REL = os.path.join(HERE, "release")
PASSED = FAILED = 0


def check(label, ok, detail=""):
    global PASSED, FAILED
    print("  %s %s%s" % ("✔" if ok else "✖", label, "" if ok or not detail else " — " + str(detail)[-500:]))
    if ok:
        PASSED += 1
    else:
        FAILED += 1


def sh(cmd, cwd=None, env=None):
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, env=dict(os.environ, **(env or {})))
    return p.returncode, p.stdout + p.stderr


def sha(b):
    return hashlib.sha256(b).hexdigest()


# ------------------------------------------------------------ static checks

def workflow_jobs(text):
    """Split a workflow into {job_id: block text} by indentation (no YAML
    dependency: the file's shape is ours)."""
    jobs, cur, buf, in_jobs = {}, None, [], False
    for line in text.splitlines():
        if line.startswith("jobs:"):
            in_jobs = True
            continue
        if not in_jobs:
            continue
        m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if m:
            if cur:
                jobs[cur] = "\n".join(buf)
            cur, buf = m.group(1), []
        elif cur:
            buf.append(line)
    if cur:
        jobs[cur] = "\n".join(buf)
    return jobs


def run_blocks(text):
    """Every `run:` script body (block scalars and one-liners)."""
    out, lines, i = [], text.splitlines(), 0
    while i < len(lines):
        m = re.match(r"^(\s*)(?:- )?run:\s*(\|)?\s*(.*)$", lines[i])
        if m:
            if m.group(2):
                ind = len(m.group(1))
                body = []
                i += 1
                while i < len(lines) and (not lines[i].strip() or len(lines[i]) - len(lines[i].lstrip()) > ind):
                    body.append(lines[i])
                    i += 1
                out.append("\n".join(body))
                continue
            out.append(m.group(3))
        i += 1
    return out


def static_workflow_checks(path):
    text = open(path).read()
    jobs = workflow_jobs(text)
    problems = []
    for u in re.findall(r"uses:\s*(\S+)", text):
        if not re.search(r"@[0-9a-f]{40}$", u):
            problems.append("action not SHA-pinned: " + u)
    on = text.split("\non:", 1)[1].split("\n\n", 1)[0] if "\non:" in text else ""
    if "workflow_dispatch" in text or "pull_request" in on or "schedule" in on or not re.search(r"push:\s*\n\s*tags:", on):
        problems.append("trigger is not tag-push only")
    if "branches" in on:
        problems.append("trigger lists branches")
    for jid, block in jobs.items():
        if "secrets." in block and jid != "sign":
            problems.append("job %s references a secret" % jid)
        if "environment: release-sign" in block and jid != "sign":
            problems.append("job %s uses release-sign" % jid)
        if "contents: write" in block and jid != "publish":
            problems.append("job %s has contents: write" % jid)
    if "secrets." in text.split("jobs:", 1)[0]:
        problems.append("a secret outside the jobs")
    if not re.search(r"^permissions:\s*\n\s+contents: read", text, re.M):
        problems.append("top-level permissions are not contents: read")
    for body in run_blocks(text):
        if "${{" in body:
            problems.append("context expression inside run: %s" % body.strip()[:60])
    sign = jobs.get("sign", "")
    if "environment: release-sign" not in sign or "BRIGLIA_UT_SIGNING_KEY" not in sign:
        problems.append("sign job lacks the release-sign environment or its secret")
    first_step = sign.split("steps:", 1)[1] if "steps:" in sign else ""
    if not re.search(r'RUN_ATTEMPT: \$\{\{ github\.run_attempt \}\}', first_step) \
            or '[ "$RUN_ATTEMPT" = "1" ]' not in first_step \
            or first_step.find("RUN_ATTEMPT") > first_step.find("SIGNING_KEY_B64"):
        problems.append("sign job does not refuse run_attempt != 1 before touching the key")
    if not re.search(r'cmp -s "linux/\$FILENAME" "macos/\$FILENAME" \|\|', jobs.get("assemble", "")):
        problems.append("assemble lacks the hard reproducibility gate")
    if "needs: [authorize, build, build-repro]" not in jobs.get("assemble", ""):
        problems.append("assemble does not need both builds")
    pub = jobs.get("publish", "")
    if "check-supersession.sh" not in pub or "prepublish-verify.py stage" not in pub \
            or "PREPUBLISH_VERIFY=scripts/release/prepublish-verify.py" not in pub:
        problems.append("publish lacks the supersession re-check or the pre-go-live gate")
    if "environment: release-publish" not in pub:
        problems.append("publish does not use release-publish")
    for jid in ("verify-candidate", "verify-production", "build", "build-repro", "assemble", "authorize"):
        if "environment:" in jobs.get(jid, "") or "secrets." in jobs.get(jid, ""):
            problems.append("%s holds an environment or secret" % jid)
    if "vars.RELEASE_CHANNEL_ENABLED == 'true'" not in jobs.get("authorize", ""):
        problems.append("authorize is not gated by RELEASE_CHANNEL_ENABLED")
    if "cancel-in-progress: false" not in text:
        problems.append("concurrency may cancel a publication")
    return problems, jobs


def quiesce_tests(root):
    """breakglass-quiesce.py against a fake Actions/Releases API."""
    import http.server
    import threading
    import urllib.parse
    st = {"var": "false", "runs": {}, "jobs": {}, "releases": [], "cancels": [], "deletes": [], "lie_total": False}

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _j(self, code, obj):
            b = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            u = urllib.parse.urlparse(self.path)
            q = urllib.parse.parse_qs(u.query)
            page = int(q.get("page", ["1"])[0])
            if u.path.endswith("/actions/variables/RELEASE_CHANNEL_ENABLED"):
                return self._j(200, {"name": "RELEASE_CHANNEL_ENABLED", "value": st["var"]})
            if u.path.endswith("/actions/workflows/release-signed.yml"):
                return self._j(200, {"id": 9, "path": ".github/workflows/release-signed.yml"})
            m = re.search(r"/actions/workflows/9/runs$", u.path)
            if m:
                want = q.get("status", [None])[0]
                runs = [r for r in st["runs"].values() if r["status"] == want]
                chunk = runs[(page - 1) * 100:page * 100]
                return self._j(200, {"total_count": len(runs) + (1 if st["lie_total"] and runs else 0), "workflow_runs": chunk})
            m = re.search(r"/actions/runs/(\d+)/jobs$", u.path)
            if m:
                jobs = st["jobs"].get(int(m.group(1)), [])
                return self._j(200, {"total_count": len(jobs), "jobs": jobs if page == 1 else []})
            m = re.search(r"/actions/runs/(\d+)$", u.path)
            if m:
                return self._j(200, st["runs"][int(m.group(1))])
            if u.path.endswith("/releases"):
                return self._j(200, st["releases"] if page == 1 else [])
            self._j(404, {})

        def do_POST(self):
            m = re.search(r"/actions/runs/(\d+)/cancel$", self.path)
            if m:
                st["cancels"].append(int(m.group(1)))
                r = st["runs"][int(m.group(1))]
                r["status"], r["conclusion"] = "completed", "cancelled"   # the request "lands" later in reality
                return self._j(202, {})
            self._j(404, {})

        def do_DELETE(self):
            m = re.search(r"/releases/(\d+)$", self.path)
            if m:
                st["deletes"].append(int(m.group(1)))
                st["releases"] = [r for r in st["releases"] if r["id"] != int(m.group(1))]
                self.send_response(204)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self._j(404, {})

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    api = "http://127.0.0.1:%d" % srv.server_address[1]
    tool = os.path.join(REL, "breakglass-quiesce.py")

    def q(*args):
        return sh([sys.executable, tool, "--repo", "o/r", "--poll-seconds", "0.05", *args],
                  env={"GH_TOKEN": "t", "GH_API_URL": api})
    try:
        print("— break-glass quiesce (plan §10 steps 2–5) —")
        st["var"] = "true"
        rc, out = q()
        check("admission still open (RELEASE_CHANNEL_ENABLED=true) → refuses, publish nothing", rc != 0 and "admission is not closed" in out, out)
        st["var"] = "false"
        st["runs"] = {11: {"id": 11, "head_branch": "v0.8.7", "status": "waiting", "html_url": "u11"},
                      12: {"id": 12, "head_branch": "v0.8.8", "status": "in_progress", "html_url": "u12"}}
        st["jobs"] = {11: [{"status": "waiting"}], 12: [{"status": "in_progress"}]}
        st["releases"] = [{"id": 501, "tag_name": "v0.8.8", "draft": True}]
        rc, out = q()
        check("outstanding runs without --wait → refuses and lists both", rc != 0 and "run 11" in out and "run 12" in out
              and "still not terminal" in out, out)
        rc, out = q("--cancel")
        check("--cancel: the in-progress run gets a cancel REQUEST; the run waiting for approval is left to the owner's phone",
              st["cancels"] == [12] and "must REJECT it on the phone" in out and rc != 0, out)
        st["jobs"][12] = [{"status": "in_progress"}]
        rc, out = q()
        check("a cancelled run whose job is still in progress is NOT terminal → refuses (a request is not proof)",
              rc != 0 and "still not terminal" in out, out)
        st["jobs"][12] = [{"status": "completed"}]
        st["runs"][11].update(status="completed", conclusion="failure")   # the owner rejected it
        st["jobs"][11] = [{"status": "completed"}]
        rc, out = q()
        check("both terminal but a draft remains for a touched tag → refuses", rc != 0 and "draft release(s) remain" in out, out)
        rc, out = q("--delete-drafts")
        check("--delete-drafts reconciles the draft → CI quiet, exit 0", rc == 0 and st["deletes"] == [501] and "CI is quiet" in out, out)
        st["runs"][13] = {"id": 13, "head_branch": "v0.8.9", "status": "queued", "html_url": "u13"}
        st["lie_total"] = True
        rc, out = q()
        check("a run list whose length disagrees with total_count → refused as possibly truncated",
              rc != 0 and "truncated" in out, out)
        st["lie_total"] = False
        st["runs"][13].update(status="completed", conclusion="success")
        st["jobs"][13] = [{"status": "completed"}]
        st["releases"] = [{"id": 601, "tag_name": "v0.8.9", "draft": False}]
        rc, out = q()
        check("no run outstanding; a touched tag already PUBLISHED is reported as the live release", rc == 0, out)
    finally:
        srv.shutdown()
        srv.server_close()


def restore_check_tests(root):
    """restore-check.sh with throwaway keys: MATCH only for the right
    passphrase AND the right expected key; nothing written; no echo."""
    print("— owner restore check (plan §5 step 4) —")
    d = os.path.join(root, "usb")
    os.makedirs(d)
    keys = {"cli": TestKey("briglia-cli"), "ut": TestKey("briglia-ut")}
    openssl = subprocess.run(["bash", "-c", '. "%s/openssl-resolve.sh" && resolve_openssl >/dev/null && printf %%s "$OPENSSL"' % REL],
                             capture_output=True, text=True).stdout
    for k, pw in (("cli", "correct horse cli"), ("ut", "correct horse ut")):
        subprocess.run([openssl, "enc", "-aes-256-cbc", "-pbkdf2", "-iter", "600000", "-pass", "env:PASS", "-in",
                        keys[k].priv, "-out", os.path.join(d, keys[k].key_id.replace("briglia-", "ada-") + ".priv.pem.enc")],
                       env=dict(os.environ, PASS=pw), check=True, capture_output=True)
    before = sorted(os.listdir(d))
    env = {"EXPECTED_CLI_PUB": keys["cli"].pub, "EXPECTED_UT_PUB": keys["ut"].pub,
           "CLI_SUFFIX": keys["cli"].fingerprint, "UT_SUFFIX": keys["ut"].fingerprint}

    def rc_run(stdin, **over):
        p = subprocess.run([os.path.join(REL, "restore-check.sh"), d], input=stdin, capture_output=True, text=True,
                           env=dict(os.environ, **dict(env, **over)))
        return p.returncode, p.stdout, p.stderr
    rc, out, err = rc_run("correct horse cli\ncorrect horse ut\n")
    check("right passphrases → both MATCH, exit 0", rc == 0 and "CLI key: MATCH" in out and "UT key: MATCH" in out, out + err)
    check("the passphrases never appear in any output", "correct horse" not in out + err, out + err)
    rc, out, err = rc_run("wrong\ncorrect horse ut\n")
    check("wrong CLI passphrase → CLI NO MATCH, exit ≠ 0, 'do NOT delete'", rc != 0 and "CLI key: NO MATCH" in out
          and "UT key: MATCH" in out and "do NOT delete" in out, out)
    rc, out, err = rc_run("correct horse cli\ncorrect horse ut\n", EXPECTED_UT_PUB=keys["cli"].pub)
    check("right passphrase but a different expected key → NO MATCH", rc != 0 and "UT key: NO MATCH" in out, out)
    rc, out, err = rc_run("correct horse cli\ncorrect horse ut\n", UT_SUFFIX="0000000000000000")
    check("backup missing on the stick → NO MATCH", rc != 0 and "UT key: NO MATCH" in out, out)
    check("nothing was written next to the backups", sorted(os.listdir(d)) == before, os.listdir(d))


def main():
    root = tempfile.mkdtemp(prefix="briglia-ut-ci-release-")
    host = FakeHost()
    try:
        print("— static workflow checks —")
        problems, jobs = static_workflow_checks(os.path.join(SRC, ".github", "workflows", "release-signed.yml"))
        check("release-signed.yml: SHA-pinned actions, tag-push only, secret + release-sign only in sign, contents:write only "
              "in publish, no ${{ }} in run:, attempt-1 guard first, reproducibility gate, publish gates",
              not problems, problems)
        check("the eight jobs the watcher requires exist with their names",
              all(n in "\n".join(jobs.values()) for n in (
                  "name: Authorize (credential-free)", "name: Build click (Linux)", "name: Build click (macOS, reproducibility)",
                  "name: Assemble manifest", "name: Sign metadata", "name: Verify candidate",
                  "name: Publish immutable release", "name: Verify public channel")), sorted(jobs))

        print("— manifest generator and the real v0.8.5 release —")
        fx = os.path.join(HERE, "fixtures", "release-0.8.5")
        recorded = open(os.path.join(fx, "manifest.json"), "rb").read()
        m = json.loads(recorded)
        rc, out = sh([sys.executable, os.path.join(REL, "build-manifest.py"), m["version"], str(m["sequence"]),
                      m["platforms"]["click"]["url"], m["platforms"]["click"]["sha256"], str(m["platforms"]["click"]["size"]),
                      m["published"], "180"])
        check("build-manifest.py reproduces the published v0.8.5 manifest byte for byte", rc == 0 and out.encode() == recorded,
              out[:300])
        rc, out = sh([os.path.join(REL, "verify-envelope.sh"), os.path.join(fx, "manifest.sig.json"),
                      os.path.join(SRC, ".release-keys", "briglia-ut-release.pub.pem"), "briglia-ut", os.path.join(root, "p")])
        check("the real public v0.8.5 envelope authenticates with the committed key through the extracted scripts",
              rc == 0 and open(os.path.join(root, "p"), "rb").read() == recorded, out)
        fixture = open(os.path.join(HERE, "fixtures", "release_verify_0.8.5.py"), "rb").read()
        pinned = open(os.path.join(HERE, "fixtures", "release_verify_0.8.5.py.sha256")).read().strip()
        check("the pinned v0.8.5 verifier fixture matches its committed sha256 and is production-stamped (APP_RELEASE_SEQUENCE 7)",
              sha(fixture) == pinned and b"APP_RELEASE_SEQUENCE = 7\n" in fixture
              and b"7bb0163ac16c5cb3" in fixture, (sha(fixture), pinned))

        print("— a throwaway channel: live 0.8.5/seq 7 and candidate 0.8.6/seq 8 —")
        key, other = TestKey("briglia-ut"), TestKey("briglia-ut")
        repo = os.path.join(root, "repo")
        os.makedirs(repo)
        for item in ("manifest.json", "LICENSE", "py", "qml", "click", "assets", "scripts"):
            s = os.path.join(SRC, item)
            (shutil.copytree if os.path.isdir(s) else shutil.copy2)(
                s, os.path.join(repo, item), **({"ignore": shutil.ignore_patterns("__pycache__", "*.pyc")} if os.path.isdir(s) else {}))
        os.makedirs(os.path.join(repo, ".release-keys"))
        pub = os.path.join(repo, ".release-keys", "briglia-ut-release.pub.pem")
        shutil.copy2(key.pub, pub)
        base = host.base + "/releases"
        rv_path = os.path.join(repo, "py", "release_verify.py")
        prod_rv = open(rv_path).read()

        def set_version(version, seq, **manifest_over):
            open(rv_path, "w").write(stamp_app_policy(prod_rv, key.key_id, key.pub_hex, base, seq))
            mf = json.load(open(os.path.join(SRC, "manifest.json")))
            mf["version"] = version
            mf.update(manifest_over)
            json.dump(mf, open(os.path.join(repo, "manifest.json"), "w"), indent=2)

        def build(outdir):
            rc, out = sh([sys.executable, os.path.join(repo, "scripts", "build_click.py"), outdir], env={"SOURCE_DATE_EPOCH": "0"})
            assert rc == 0, out
            name = next(f for f in os.listdir(outdir) if f.endswith(".click"))
            return os.path.join(outdir, name)

        def git(*args):
            return subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True, check=True).stdout.strip()

        def sign_manifest(version, seq, click, outdir, signer=key, url=None, published="2026-10-01T00:00:00Z"):
            data = open(click, "rb").read()
            url = url or "%s/download/v%s/%s" % (base, version, os.path.basename(click))
            rc, out = sh([sys.executable, os.path.join(REL, "build-manifest.py"), version, str(seq), url, sha(data),
                          str(len(data)), published, "180"])
            mpath = os.path.join(outdir, "manifest.json")
            open(mpath, "w").write(out)
            env = signer.sign(out.encode())
            open(os.path.join(outdir, "manifest.sig.json"), "wb").write(env)
            return mpath, os.path.join(outdir, "manifest.sig.json"), env

        git("init", "-q", "-b", "main")
        set_version("0.8.5", 7)
        git("add", "-A")
        git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "live 0.8.5")
        live_commit = git("rev-parse", "HEAD")
        live_dir = os.path.join(root, "live")
        os.makedirs(live_dir)
        live_click = build(live_dir)
        _, _, live_env = sign_manifest("0.8.5", 7, live_click, live_dir)
        host.put("/releases/latest/download/manifest.sig.json", live_env)
        host.put("/releases/download/v0.8.5/" + os.path.basename(live_click), open(live_click, "rb").read())

        set_version("0.8.6", 8)
        git("add", "-A")
        git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "candidate 0.8.6")
        cand_commit = git("rev-parse", "HEAD")
        fx_text = stamp_app_policy(fixture.decode(), key.key_id, key.pub_hex, base)
        fx_path = os.path.join(root, "fixture_rv.py")
        open(fx_path, "w").write(fx_text)
        fx_sha = sha(fx_text.encode())

        def candidate(cname, version="0.8.6", seq=8, signer=key, url=None, mutate_click=None, **manifest_over):
            d = os.path.join(root, "c-" + cname)
            os.makedirs(d)
            set_version(version, seq, **manifest_over)
            click = build(d)
            if mutate_click:
                mutate_click(click)
            mpath, epath, _ = sign_manifest(version, seq, click, d, signer=signer, url=url)
            set_version("0.8.6", 8)
            return d, click, mpath, epath

        def vc(d, click, mpath, epath, version="0.8.6", seq=8, commit=None, fxsha=None, pubkey=pub):
            return sh([sys.executable, os.path.join(REL, "verify-candidate.py"), "--click", click, "--manifest", mpath,
                       "--envelope", epath, "--pub", pubkey, "--version", version, "--sequence", str(seq),
                       "--live-commit", commit or live_commit, "--repo-root", repo,
                       "--live-envelope-url", host.base + "/releases/latest/download/manifest.sig.json",
                       "--fixture", fx_path, "--fixture-sha256", fxsha or fx_sha])

        print("— verify-candidate.py (§3.2 a–f) —")
        good = candidate("good")
        rc, out = vc(*good)
        check("a good candidate passes (a)–(f): committed key, own verifier, live shipped verifier, pinned fixture, identity, hashes",
              rc == 0 and all(x in out for x in ("✔ (a)", "✔ (b)", "✔ (c)", "✔ (d)", "✔ (e)", "✔ (f)")), out)
        rc, out = vc(*good, commit=cand_commit)
        check("live click's verifier ≠ source at the pinned commit → refused (c)",
              rc != 0 and "(c)" in out and "differs from py/release_verify.py" in out, out)
        bad = candidate("otherkey", signer=other)
        rc, out = vc(*bad)
        check("candidate signed by another key → refused at (a)", rc != 0 and "(a)" in out, out)
        rc, out = vc(*bad, pubkey=other.pub)
        check("…even when checked against that key: keyId not pinned in the click's verifier → refused (b)",
              rc != 0 and "(b)" in out and "REJECTS" in out, out)
        eq = candidate("equalseq", seq=7)
        rc, out = vc(*eq, seq=7)
        check("sequence equal to the live floor (7) → refused by the live verifier (c)",
              rc != 0 and "(c)" in out and "not above its floor 7" in out, out)
        url_bad = candidate("url", url="%s/download/v0.8.5/%s" % (base, "briglia.permaevidence_0.8.6_all.click"))
        rc, out = vc(*url_bad)
        check("signed click URL outside …/download/v0.8.6/ → refused", rc != 0 and ("(f)" in out or "(b)" in out), out)
        d, click, mpath, epath = candidate("hash")
        with open(click, "ab") as f:
            f.write(b"\0")
        rc, out = vc(d, click, mpath, epath)
        check("click differing from the signed sha256/size → refused (f)", rc != 0 and "(f)" in out, out)
        rc, out = vc(*good, version="0.8.7")
        check("version ≠ tag → refused", rc != 0, out)
        for label, over in (("package name", {"name": "evil.permaevidence"}), ("architecture", {"architecture": "arm64"}),
                            ("framework", {"framework": "ubuntu-sdk-20.04"}),
                            ("hooks", {"hooks": {"briglia": {"apparmor": "click/briglia.apparmor", "desktop": "click/other.desktop"}}})):
            if label == "hooks":
                shutil.copy2(os.path.join(repo, "click", "briglia.desktop"), os.path.join(repo, "click", "other.desktop"))
            c = candidate("id-" + label.replace(" ", ""), **over)
            if label == "hooks":
                os.unlink(os.path.join(repo, "click", "other.desktop"))
            rc, out = vc(*c)
            check("changed app identity (%s) → refused at (e)" % label, rc != 0 and "(e)" in out, out)
        aa = os.path.join(repo, "click", "briglia.apparmor")
        saved = open(aa).read()
        open(aa, "w").write(saved.replace('"policy_groups": [', '"policy_groups": [\n        "location",', 1)
                            if '"policy_groups": [' in saved else saved + "\n")
        c = candidate("apparmor")
        open(aa, "w").write(saved)
        rc, out = vc(*c)
        check("changed apparmor profile → refused (e)", rc != 0 and "(e)" in out, out)
        rc, out = vc(*good, fxsha="0" * 64)
        check("pinned fixture whose sha256 does not match → refused (d)", rc != 0 and "(d)" in out, out)

        print("— check-supersession.sh —")

        def supersede(seq, live=None):
            if live is not None:
                host.put("/releases/latest/download/manifest.sig.json", live)
            return sh([os.path.join(REL, "check-supersession.sh")],
                      env={"SEQUENCE": str(seq), "EXPECTED_PUB": pub, "LIVE_URL": host.base + "/releases/latest/download/manifest.sig.json"})
        rc, out = supersede(8, live_env)
        check("candidate 8 over authenticated live 7 → passes", rc == 0 and "live (check): v0.8.5 sequence 7" in out, out)
        rc, out = supersede(7)
        check("equal sequence → superseded", rc != 0 and "superseded" in out, out)
        rc, out = supersede(6)
        check("lower sequence → superseded", rc != 0 and "superseded" in out, out)
        foreign = raw_envelope(other.priv, json.loads(live_env)["payload"].encode(), "briglia-ut", other.key_id)
        rc, out = supersede(8, foreign)
        check("live envelope signed by a foreign key → hard stop, never 'absent'", rc != 0 and "hard stop" in out, out)
        host.routes.pop("/releases/latest/download/manifest.sig.json")
        rc, out = supersede(8)
        check("no live release (404) → refused, no bootstrap", rc != 0 and "bootstrap retired" in out, out)
        host.put("/releases/latest/download/manifest.sig.json", live_env)

        print("— prepublish-verify.py stage (publish job's own inputs) —")
        prefix = base + "/download/v{version}/"

        def stage(d, name, **over):
            args = {"version": "0.8.6", "sequence": "8", "url_prefix": prefix,
                    "expect_file": os.path.basename(good[1])}
            args.update(over)
            out_dir = os.path.join(root, "staging-" + name)
            cmd = [sys.executable, os.path.join(REL, "prepublish-verify.py"), "stage", "--dist", d, "--pub", pub,
                   "--version", args["version"], "--sequence", args["sequence"], "--url-prefix", args["url_prefix"],
                   "--out", out_dir, "--expect-file", args["expect_file"]]
            rc, out = sh(cmd)
            return rc, out, out_dir
        rc, out, sdir = stage(good[0], "good")
        listed = [l for l in out.splitlines() if l.startswith(sdir)]
        check("good inputs → staged read-only copies, envelope last",
              rc == 0 and [os.path.basename(p) for p in listed][-2:] == ["manifest.json", "manifest.sig.json"]
              and not (os.stat(sdir).st_mode & stat.S_IWUSR)
              and all(not (os.stat(p).st_mode & 0o222) for p in listed), out)
        tampered = os.path.join(root, "tamper-dist")
        shutil.copytree(good[0], tampered)
        tc = os.path.join(tampered, os.path.basename(good[1]))
        data = bytearray(open(tc, "rb").read())
        data[len(data) // 2] ^= 1
        open(tc, "wb").write(bytes(data))
        rc, out, _ = stage(tampered, "tampered")
        check("click altered after artifact download (E7) → stage refuses, nothing staged", rc != 0 and "signed sha256/size" in out, out)
        rc, out, _ = stage(good[0], "wrongver", version="0.8.7")
        check("authorized version ≠ signed version → refused", rc != 0 and "authorized version" in out, out)
        rc, out, _ = stage(good[0], "wrongseq", sequence="9")
        check("authorized sequence ≠ signed sequence → refused", rc != 0 and "authorized sequence" in out, out)
        rc, out, _ = stage(good[0], "wrongprefix", url_prefix=host.base + "/elsewhere/v{version}/")
        check("signed URL outside the authorized release location → refused", rc != 0 and "outside" in out, out)
        swapped = os.path.join(root, "swap-dist")
        shutil.copytree(good[0], swapped)
        shutil.copy2(bad[3], os.path.join(swapped, "manifest.sig.json"))
        rc, out, _ = stage(swapped, "swapped")
        check("envelope swapped for one signed by another key → refused", rc != 0 and "does not authenticate" in out, out)
        quiesce_tests(root)
        restore_check_tests(root)
        for p in [os.path.join(root, x) for x in os.listdir(root) if x.startswith("staging-")]:
            for dp, dn, fn in os.walk(p):
                os.chmod(dp, 0o755)
    finally:
        host.close()
        for dp, dn, fn in os.walk(root):
            try:
                os.chmod(dp, 0o755)
            except OSError:
                pass
        shutil.rmtree(root, ignore_errors=True)
    print("\nci release selftest: %d passed, %d failed" % (PASSED, FAILED))
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
