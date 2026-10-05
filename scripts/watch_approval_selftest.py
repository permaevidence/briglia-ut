#!/usr/bin/env python3
"""Battery for the watcher's signed-run corroboration and approval
evidence (UT signing-in-CI plan §3.3), both channels, against the fake
GitHub of watch_selftest.py. Runs the REAL watcher on a throwaway copy of
this repository with generated test keys.

    python3 scripts/watch_approval_selftest.py
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from signing_fixture import TestKey  # noqa: E402
from watch_selftest import Fake, signed_run, jobs_ok, CLI_JOB_NAMES, APP_JOB_NAMES  # noqa: E402

PASSED = FAILED = 0
REVIEWER = 4242001
ENV_ID = 5150


def check(label, ok, detail=""):
    global PASSED, FAILED
    print("  %s %s%s" % ("✔" if ok else "✖", label, "" if ok or not detail else " — " + str(detail)[-600:]))
    if ok:
        PASSED += 1
    else:
        FAILED += 1


def approval(user_id=REVIEWER, login="matteoiannius-beep", env_id=ENV_ID, state="approved"):
    return {"state": state, "comment": "", "environments": [{"id": env_id, "name": "release-sign"}],
            "user": {"login": login, "id": user_id}}


def main():
    root = tempfile.mkdtemp(prefix="briglia-watch-approval-")
    repo = os.path.join(root, "repo")
    os.makedirs(repo)
    src = os.path.dirname(HERE)
    for item in ("py", "scripts"):
        shutil.copytree(os.path.join(src, item), os.path.join(repo, item),
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    keys = {"briglia-cli": TestKey("briglia-cli"), "briglia-ut": TestKey("briglia-ut")}
    rv_path = os.path.join(repo, "py", "release_verify.py")
    s = open(rv_path).read()
    for tag, var, chan in (("CLI", "CLI_KEYS", "briglia-cli"), ("APP", "APP_KEYS", "briglia-ut")):
        k = keys[chan]
        s = re.sub(r"# STAMP-%s-KEY-BEGIN.*?# STAMP-%s-KEY-END" % (tag, tag),
                   '# STAMP-%s-KEY-BEGIN\n%s = {\n    "%s":\n        "%s",\n}\n# STAMP-%s-KEY-END'
                   % (tag, var, k.key_id, k.pub_hex, tag), s, flags=re.S)
    s = re.sub(r"^MIN_CLI_SEQUENCE = \d+$", "MIN_CLI_SEQUENCE = 1", s, flags=re.M)
    s = re.sub(r"^MIN_APP_SEQUENCE = \d+$", "MIN_APP_SEQUENCE = 1", s, flags=re.M)
    open(rv_path, "w").write(s)

    fake = Fake()
    B = fake.base
    for r in ("test/briglia-cli", "test/briglia-ut"):
        fake.environments[r] = {"release-sign": {"id": ENV_ID, "name": "release-sign"}}
    tg_env = os.path.join(root, "tg.env")
    open(tg_env, "w").write("TELEGRAM_BOT_TOKEN=tok\nOWNER_CHAT_ID=1\n")
    pub_log = os.path.join(root, "publications.jsonl")
    state_dir = os.path.join(root, "state")
    cfg_path = os.path.join(root, "cfg.json")
    json.dump({
        "state_dir": state_dir, "github_api": B + "/api", "raw_base": B + "/raw",
        "telegram_env_file": tg_env, "telegram_api": B + "/tg", "transient_grace_checks": 1,
        "channels": {
            "briglia-cli": {"kind": "cli", "repo": "test/briglia-cli", "installer_asset": None,
                            "website_install_url": [], "legacy_blob_manifest": None,
                            "approval_required_above_sequence": 60, "approver_user_id": REVIEWER,
                            "envelope_url": B + "/latest/briglia-cli/manifest.sig.json",
                            "artifact_url_prefix": B + "/download/briglia-cli/v{version}/"},
            "briglia-ut": {"kind": "app", "repo": "test/briglia-ut", "publication_log": pub_log,
                           "website_page_url": [], "legacy_blob_manifest": None,
                           "approval_required_above_sequence": 7, "approver_user_id": REVIEWER,
                           "envelope_url": B + "/latest/briglia-ut/manifest.sig.json",
                           "artifact_url_prefix": B + "/download/briglia-ut/v{version}/"},
        }}, open(cfg_path, "w"))
    watcher = os.path.join(repo, "scripts", "release_watch.py")

    def run(*cmd):
        p = subprocess.run([sys.executable, watcher, *(cmd or ("check",)), "--config", cfg_path],
                           capture_output=True, text=True)
        return p.returncode, p.stdout + p.stderr

    def state():
        return json.load(open(os.path.join(state_dir, "state.json")))

    def recorded(chan):
        return state()["recorded"].get(chan, {})

    def sha(b):
        return hashlib.sha256(b).hexdigest()

    def release(chan, version, seq, commit, run=None, log=False):
        """Make `version` live on the fake channel; optionally attach a
        signed workflow run and/or a local publication-log entry."""
        name = "click" if chan == "briglia-ut" else "briglia-linux-x64.tar.gz"
        body = ("%s-%s" % (chan, version)).encode() * 300
        fake.assets[(chan, version, name)] = body
        payload = {"channel": chan, "schema": 1, "sequence": seq, "version": version,
                   "published": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 60)),
                   "expires": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 180 * 86400)),
                   "platforms": {name: {"url": "%s/download/%s/v%s/%s" % (B, chan, version, name),
                                        "size": len(body), "sha256": sha(body)}}}
        env = keys[chan].sign(json.dumps(payload, sort_keys=True, indent=2).encode())
        fake.envelopes[chan] = env
        r = "test/" + chan
        fake.releases.setdefault(r, []).append({"id": 1000 + seq, "tag_name": "v" + version, "draft": False,
                                                "immutable": True})
        fake.tags.setdefault(r, {})["v" + version] = commit
        if run is not None:
            fake.runs.setdefault(r, []).append(run)
        if log:
            with open(pub_log, "a") as f:
                f.write(json.dumps({"tag": "v" + version, "version": version, "sequence": seq,
                                    "clickSha256": sha(body), "envelopeSha256": sha(env), "commit": commit}) + "\n")
        return env

    def cli_run(rid, version, seq, commit, approvals=None, jobs=None, **over):
        r = signed_run("test/briglia-cli", rid, "v" + version, commit, seq,
                       jobs if jobs is not None else jobs_ok(CLI_JOB_NAMES, rid * 100), approvals=approvals)
        r.update(over)
        return r

    def app_run(rid, version, seq, commit, approvals=None, jobs=None, **over):
        r = signed_run("test/briglia-ut", rid, "v" + version, commit, seq,
                       jobs if jobs is not None else jobs_ok(APP_JOB_NAMES, rid * 100), approvals=approvals)
        r.update(over)
        return r

    def last_run(chan):
        return fake.runs["test/" + chan][-1]

    def retry(chan, label, mutate, expect_text, ok_after=False):
        """Mutate the latest run's evidence, check the release stays
        unrecorded with `expect_text` in the alert, then restore."""
        fake.telegram.clear()
        before = recorded(chan).get("sequence")
        saved = json.loads(json.dumps(last_run(chan)))
        mutate(last_run(chan))
        rc, out = run()
        check(label, rc == 2 and recorded(chan).get("sequence") == before
              and any("uncorroborated" in m and expect_text in m for m in fake.telegram), (out[-800:], fake.telegram))
        fake.runs["test/" + chan][-1] = saved

    C = ["%040x" % (0xc0ffee + i) for i in range(40)]
    try:
        print("— CLI: migration boundary —")
        release("briglia-cli", "0.2.48", 60, C[0], run=cli_run(601, "0.2.48", 60, C[0]))
        release("briglia-ut", "0.8.4", 6, C[1], log=True)
        rc, out = run()
        check("at the cutoff (CLI seq 60, app seq 6): recorded without any approval record, labelled pre-gate / pre-CI",
              rc == 0 and recorded("briglia-cli").get("sequence") == 60 and recorded("briglia-ut").get("sequence") == 6
              and recorded("briglia-cli").get("provenance") == "ci (pre-approval-gate)"
              and recorded("briglia-ut").get("provenance") == "local (pre-CI)", out[-800:])

        print("— CLI: approval bound to the single signing execution —")
        release("briglia-cli", "0.2.49", 61, C[2], run=cli_run(611, "0.2.49", 61, C[2], approvals=[approval()]))
        retry("briglia-cli", "above the cutoff with NO approval → not approved, not recorded",
              lambda r: r.update(approvals=[]), "no approval for environment release-sign")
        retry("briglia-cli", "approval by ANOTHER user id with the SAME login → refused (stable id, never the login)",
              lambda r: r.update(approvals=[approval(user_id=999)]), "not the configured reviewer id")
        retry("briglia-cli", "approval for a DIFFERENT environment id → refused",
              lambda r: r.update(approvals=[approval(env_id=ENV_ID + 1)]), "no approval for environment")
        retry("briglia-cli", "a REJECTED entry for the signing environment next to an approval → not approved",
              lambda r: r.update(approvals=[approval(state="rejected"), approval()]), "rejected")
        retry("briglia-cli", "two approval entries for the signing environment → approval unverified",
              lambda r: r.update(approvals=[approval(), approval()]), "approval unverified: 2 approval entries")
        retry("briglia-cli", "signing job ran in attempt 2 (re-run all jobs) → approval unverified",
              lambda r: [j.update(run_attempt=2) for j in r["jobs"] if j["name"] == "Sign metadata"],
              "approval unverified: the signing job ran in attempt 2")
        retry("briglia-cli", "two signing executions in one run → approval unverified",
              lambda r: r["jobs"].append({"id": 7, "name": "Sign metadata", "conclusion": "success", "run_attempt": 2}),
              "approval unverified: 2 signing execution")
        retry("briglia-cli", "review history with an unexpected shape → not approved",
              lambda r: r.update(approvals=[{"state": "approved", "environments": "release-sign", "user": {"id": REVIEWER}}]),
              "unexpected shape")
        fake.faults["approvals_status"] = 500
        fake.telegram.clear()
        rc, out = run()
        check("review-history API error → not approved (never success), not recorded",
              rc == 2 and recorded("briglia-cli").get("sequence") == 60
              and any("uncorroborated" in m and "cannot verify" in m for m in fake.telegram), (out[-600:], fake.telegram))
        del fake.faults["approvals_status"]
        fake.environments["test/briglia-cli"]["release-sign"] = {"id": ENV_ID, "name": "release-sign-OLD"}
        fake.telegram.clear()
        rc, out = run()
        check("signing environment answering another name → approval unverified",
              rc == 2 and recorded("briglia-cli").get("sequence") == 60 and any("approval unverified" in m for m in fake.telegram),
              fake.telegram)
        fake.environments["test/briglia-cli"]["release-sign"] = {"id": ENV_ID, "name": "release-sign"}

        print("— CLI: run identity and required jobs —")
        retry("briglia-cli", "same-named workflow at ANOTHER path → refused (never matched by display name)",
              lambda r: r.update(path=".github/workflows/evil.yml"), "run path")
        fake.faults["runs_unfiltered"] = True   # an API answer that includes another workflow's run
        retry("briglia-cli", "run of a different workflow id → refused",
              lambda r: r.update(workflow_id=78), "workflow_id")
        del fake.faults["runs_unfiltered"]
        retry("briglia-cli", "run at another commit → refused",
              lambda r: r.update(head_sha="f" * 40), "head_sha")
        retry("briglia-cli", "a SKIPPED required job fails corroboration",
              lambda r: [j.update(conclusion="skipped") for j in r["jobs"] if j["name"] == "Verify candidate (linux)"],
              "Verify candidate (linux): skipped")
        retry("briglia-cli", "only two of the three public verification jobs → refused (no weakening)",
              lambda r: r.update(jobs=[j for j in r["jobs"] if j["name"] != "Verify public channel (linux-arm64)"]),
              "Verify public channel (linux-arm64): missing")
        fake.workflows["test/briglia-cli"] = {"id": 77, "path": ".github/workflows/other.yml", "name": "Release (signed)"}
        fake.faults["wf_any_name"] = True
        fake.telegram.clear()
        rc, out = run()
        check("workflow lookup answering another path → refused",
              rc == 2 and any("not found by path" in m for m in fake.telegram), fake.telegram)
        del fake.workflows["test/briglia-cli"]
        del fake.faults["wf_any_name"]
        fake.runs["test/briglia-cli"].append(cli_run(612, "0.2.49", 61, C[2], approvals=[approval()]))
        fake.telegram.clear()
        rc, out = run()
        check("two runs for the same tag → alert, not recorded",
              rc == 2 and recorded("briglia-cli").get("sequence") == 60 and any("2 '" in m and "runs exist" in m for m in fake.telegram),
              fake.telegram)
        fake.runs["test/briglia-cli"].pop()
        fake.telegram.clear()
        rc, out = run()
        rec = recorded("briglia-cli")
        check("the correct evidence → recorded, announced as phone-approved with the reviewer id",
              rc == 0 and rec.get("sequence") == 61 and rec.get("approval", {}).get("user_id") == REVIEWER
              and rec.get("approval", {}).get("environment_id") == ENV_ID and rec.get("provenance") == "ci, phone-approved"
              and any("RECORDED" in m and "approved by user id %d" % REVIEWER in m for m in fake.telegram),
              (out[-600:], fake.telegram))
        jobs = jobs_ok(CLI_JOB_NAMES, 6200)
        for j in jobs:
            if j["name"] == "Publish immutable release":
                j["conclusion"] = "failure"
        jobs.append({"id": 6299, "name": "Publish immutable release", "conclusion": "success", "run_attempt": 2})
        release("briglia-cli", "0.2.50", 62, C[3], run=cli_run(621, "0.2.50", 62, C[3], approvals=[approval()], jobs=jobs,
                                                              run_attempt=2))
        fake.telegram.clear()
        rc, out = run()
        check("publish failed in attempt 1, re-run of the FAILED job only (attempt 2), one attempt-1 signing + one approval → recorded",
              rc == 0 and recorded("briglia-cli").get("sequence") == 62, (out[-600:], fake.telegram))

        print("— app: local provenance boundary and CI approval —")
        release("briglia-ut", "0.8.5", 7, C[4], log=True)
        rc, out = run()
        check("app sequence 7 (the cutoff) is recorded from the local publication log, labelled local pre-CI",
              rc == 0 and recorded("briglia-ut").get("sequence") == 7 and recorded("briglia-ut").get("provenance") == "local (pre-CI)",
              out[-600:])
        env8 = release("briglia-ut", "0.8.6", 8, C[5], log=True)
        fake.telegram.clear()
        rc, out = run()
        check("above the cutoff a matching publication-log entry is NEVER accepted → 'local provenance, not phone-approved CI' alert",
              rc == 2 and recorded("briglia-ut").get("sequence") == 7
              and any("local-provenance" in m and "LOCAL PROVENANCE, NOT PHONE-APPROVED CI" in m for m in fake.telegram),
              (out[-600:], fake.telegram))
        rc, out = run("acknowledge-local", "briglia-ut", "v0.8.6", "0" * 64)
        rc, out = run()
        check("an acknowledgement for a DIFFERENT envelope hash does not record it",
              rc == 2 and recorded("briglia-ut").get("sequence") == 7, out[-400:])
        rc, out = run("acknowledge-local", "briglia-ut", "v0.8.6", sha(env8))
        fake.telegram.clear()
        rc2, out2 = run()
        rec = recorded("briglia-ut")
        check("owner acknowledgement of exactly that envelope → recorded as LOCAL provenance (never CI-approved), no approval field",
              rc == 0 and rc2 == 0 and rec.get("sequence") == 8 and "not phone-approved CI" in rec.get("provenance", "")
              and "approval" not in rec and any("RECORDED" in m and "not phone-approved CI" in m for m in fake.telegram),
              (out2[-600:], fake.telegram))
        release("briglia-ut", "0.8.7", 9, C[6], run=app_run(901, "0.8.7", 9, C[6], approvals=[]))
        retry("briglia-ut", "app CI release without an approval → not approved (no publication-log fallback)",
              lambda r: None, "no approval")
        retry("briglia-ut", "app CI release with the macOS reproducibility build SKIPPED → refused",
              lambda r: [j.update(conclusion="skipped") for j in r["jobs"] if j["name"] == "Build click (macOS, reproducibility)"]
              or r.update(approvals=[approval()]), "Build click (macOS, reproducibility): skipped")
        last_run("briglia-ut")["approvals"] = [approval()]
        fake.telegram.clear()
        rc, out = run()
        rec = recorded("briglia-ut")
        check("app CI release with one approval by the reviewer id for the signing environment → recorded as phone-approved",
              rc == 0 and rec.get("sequence") == 9 and rec.get("provenance") == "ci, phone-approved"
              and rec.get("approval", {}).get("user_id") == REVIEWER, (out[-600:], fake.telegram))
        rc, out = run("acknowledge-local", "briglia-ut", "not-a-tag", "0" * 64)
        check("acknowledge-local validates its arguments", rc == 2, out[-200:])
    finally:
        fake.close()
        shutil.rmtree(root, ignore_errors=True)
    print("\nwatch approval selftest: %d passed, %d failed" % (PASSED, FAILED))
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
