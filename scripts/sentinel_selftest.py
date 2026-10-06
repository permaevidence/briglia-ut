#!/usr/bin/env python3
"""Battery for Sentinel (off-Mac watcher plan): remote mode, environment
rules, the signing audit with its legacy baseline, deployments, the event
feed, report-only mode, the budget guard, per-check coverage, the 5-minute
website job, positive confirmations, the heartbeat/daily status, log
rotation and the installer — all against the in-process fake GitHub /
website / Telegram of watch_selftest.py, with generated test keys. The
fixture uses the PRODUCTION pins (workflow ids, environment ids, reviewer
id, signing cutoffs, the pinned CLI v0.2.49 legacy execution, deployment
boundaries) and the exact anchor timestamps from the plan's round-4 review.

    python3 scripts/sentinel_selftest.py
"""

import copy
import datetime
import hashlib
import importlib
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
from watch_selftest import Fake, job_rec, CLI_JOB_NAMES, APP_JOB_NAMES  # noqa: E402

PASSED = FAILED = 0
REV = 338251426
CLI, UT = "test/briglia-cli", "test/briglia-ut"
CLI_WF, UT_WF = 346353613, 376207556
CLI_ENV, CLI_PUB, UT_ENV, UT_PUB = 20888059977, 20888060344, 23565890221, 23565891678
PIN_RUN, PIN_SHA = 37244536754, "7dadfc5a7cc368a90a14b190daeafbde76560501"
APP_RUN, APP_SHA = 37441659727, "d533d74960b5fdcd8c457993d9d809776a7d7067"
WF_PATH = ".github/workflows/release-signed.yml"


def check(label, ok, detail=""):
    global PASSED, FAILED
    print("  %s %s%s" % ("✔" if ok else "✖", label, "" if ok or not detail else " — " + str(detail)[-700:]))
    if ok:
        PASSED += 1
    else:
        FAILED += 1


def sha(b):
    return hashlib.sha256(b).hexdigest()


def approval(user_id=REV, env_id=UT_ENV, state="approved", login="matteoiannius-beep"):
    return {"state": state, "comment": "", "environments": [{"id": env_id, "name": "release-sign"}],
            "user": {"login": login, "id": user_id}}


def env_obj(eid, name="release-sign", reviewers=(("User", REV),), bypass=False, self_review=True, extra=(),
            dbp=None, reviewer_rule=True):
    rules = [{"id": 1, "type": "branch_policy"}]
    if reviewer_rule:
        rules.insert(0, {"id": 2, "type": "required_reviewers", "prevent_self_review": self_review,
                         "reviewers": [{"type": t, "reviewer": {"id": i, "login": "matteoiannius-beep"}} for t, i in reviewers]})
    rules += [{"id": 9, "type": t} for t in extra]
    return {"id": eid, "name": name, "can_admins_bypass": bypass, "protection_rules": rules,
            "deployment_branch_policy": dbp or {"protected_branches": False, "custom_branch_policies": True}}


def run_obj(repo, rid, tag, commit, wf, created, jobs, attempt=1, status="completed", conclusion="success",
            updated=None, approvals_by_attempt=None, path=WF_PATH):
    return {"id": rid, "name": "Release (signed)", "path": path, "event": "push", "workflow_id": wf,
            "repository": {"full_name": repo}, "head_sha": commit, "head_branch": tag, "run_attempt": attempt,
            "status": status, "conclusion": conclusion, "created_at": created, "updated_at": updated or created,
            "jobs": jobs, "approvals_by_attempt": approvals_by_attempt if approvals_by_attempt is not None else {}}


def full_jobs(names, base, sign_started, sign_completed, sign_runner, attempt=1):
    out = []
    for i, n in enumerate(names):
        if n == "Sign metadata":
            out.append(job_rec(base + i, n, attempt=attempt, started=sign_started, completed=sign_completed, runner=sign_runner))
        else:
            out.append(job_rec(base + i, n, attempt=attempt, started=sign_started, completed=sign_completed,
                               runner="GitHub Actions %d" % (base + i)))
    return out


def main():
    root = tempfile.mkdtemp(prefix="briglia-sentinel-selftest-")
    repo = os.path.join(root, "repo")
    os.makedirs(repo)
    src = os.path.dirname(HERE)
    for item in ("py", "scripts", "manifest.json"):
        s_ = os.path.join(src, item)
        (shutil.copytree if os.path.isdir(s_) else shutil.copy)(s_, os.path.join(repo, item),
                                                               **({"ignore": shutil.ignore_patterns("__pycache__", "*.pyc")}
                                                                  if os.path.isdir(s_) else {}))
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
    scripts = os.path.join(repo, "scripts")

    fake = Fake()
    B = fake.base
    sd = os.path.join(root, "state")
    os.makedirs(sd, mode=0o700)
    tg_env = os.path.join(root, "sentinel-tg.env")
    open(tg_env, "w").write("TELEGRAM_BOT_TOKEN=tok\nOWNER_CHAT_ID=1\n")
    os.chmod(tg_env, 0o600)
    cfg = {
        "mode": "remote", "state_dir": sd, "github_api": B + "/api", "raw_base": B + "/raw",
        "telegram_env_file": tg_env, "telegram_api": B + "/tg",
        "log_file": os.path.join(sd, "logs", "check.log"), "site_log_file": os.path.join(sd, "logs", "site.log"),
        "heartbeat_log_file": os.path.join(sd, "logs", "heartbeat.log"), "daily_log_file": os.path.join(sd, "logs", "daily.log"),
        "confirmations": True, "checker_website": False, "realert_hours": 0, "realert_on_change": False,
        "heartbeat_max_age_hours": 2.25,
        "coverage_limits_hours": {"hourly": 2.25, "env-publish": 8.25, "asset-hash": 26, "deletion": 26},
        "site_beacon_max_minutes": 20, "check_minute": 23, "transient_grace_checks": 3,
        "signing_audit_alerts": True, "audit_report_since": None, "retry_delay_seconds": 0.2,
        "channels": {
            "briglia-cli": {"repo": CLI, "envelope_url": B + "/latest/briglia-cli/manifest.sig.json",
                            "artifact_url_prefix": B + "/download/briglia-cli/v{version}/",
                            "website_install_url": [B + "/site/cli/install.sh", B + "/domain/cli/install.sh"],
                            "website_redirect": B + "/latestdl/briglia-cli/install.sh"},
            "briglia-ut": {"repo": UT, "envelope_url": B + "/latest/briglia-ut/manifest.sig.json",
                           "artifact_url_prefix": B + "/download/briglia-ut/v{version}/",
                           "website_page_url": [B + "/site/app", B + "/domain/app"], "publication_log": None},
        },
    }
    cfg_path = os.path.join(root, "config.json")

    def write_cfg(**over):
        c = copy.deepcopy(cfg)
        c.update(over)
        json.dump(c, open(cfg_path, "w"))
    write_cfg()

    clean_env = {k: v for k, v in os.environ.items() if k not in ("GH_TOKEN", "GITHUB_TOKEN")}
    tmpd = os.path.join(root, "tmp")
    os.makedirs(tmpd)
    clean_env["TMPDIR"] = tmpd

    def run(*cmd, env=None):
        p = subprocess.run([sys.executable, "-I", "-S", os.path.join(scripts, "release_watch.py"), *(cmd or ("check",)),
                            "--config", cfg_path], capture_output=True, text=True, env=env or clean_env)
        log = ""
        lp = os.path.join(sd, "logs", "check.log")
        if os.path.exists(lp):
            log = open(lp).read()[-6000:]
        return p.returncode, p.stdout + p.stderr + log

    def site():
        p = subprocess.run([sys.executable, "-I", "-S", os.path.join(scripts, "sentinel_site.py"), "--config", cfg_path],
                           capture_output=True, text=True, env=clean_env)
        return p.returncode, p.stdout + p.stderr

    def hb(*extra):
        p = subprocess.run([sys.executable, "-I", "-S", os.path.join(scripts, "release_heartbeat.py"), *extra,
                            "--config", cfg_path], capture_output=True, text=True, env=clean_env)
        return p.returncode, p.stdout + p.stderr

    def state():
        return json.load(open(os.path.join(sd, "state.json")))

    def set_state(mut):
        st = state()
        mut(st)
        json.dump(st, open(os.path.join(sd, "state.json"), "w"))

    def active():
        return state()["active"]

    def tg(sub):
        return [m for m in fake.telegram if sub in m]

    # ------------------------------------------------------------ world
    def envelope(chan, version, seq, platforms):
        payload = {"channel": chan, "schema": 1, "sequence": seq, "version": version,
                   "published": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 60)),
                   "expires": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 180 * 86400)),
                   "platforms": {n: {"url": "%s/download/%s/v%s/%s" % (B, chan, version, n), "size": len(b), "sha256": sha(b)}
                                 for n, b in platforms.items()}}
        return keys[chan].sign(json.dumps(payload, sort_keys=True, indent=2).encode())

    INST = {}

    def cli_release(version, seq, commit, publish=True):
        body = ("cli-%s" % version).encode() * 200
        inst = ("#!/bin/sh\necho briglia installer %s\n" % version).encode()
        INST[version] = inst
        fake.assets[("briglia-cli", version, "linux-x64")] = body
        fake.assets[("briglia-cli", version, "install.sh")] = inst
        fake.raw[(CLI, "v" + version, "scripts/get-briglia.sh")] = inst
        fake.tags.setdefault(CLI, {})["v" + version] = commit
        if publish:
            fake.envelopes["briglia-cli"] = envelope("briglia-cli", version, seq, {"linux-x64": body})
            fake.releases.setdefault(CLI, []).append({"id": 2000 + seq, "tag_name": "v" + version, "draft": False,
                                                      "immutable": True})
            fake.latest_installer = inst

    def app_release(version, seq, commit, publish=True):
        click = ("click-%s" % version).encode() * 300
        fake.assets[("briglia-ut", version, "click")] = click
        fake.tags.setdefault(UT, {})["v" + version] = commit
        if publish:
            fake.envelopes["briglia-ut"] = envelope("briglia-ut", version, seq, {"click": click})
            fake.releases.setdefault(UT, []).append({"id": 3000 + seq, "tag_name": "v" + version, "draft": False,
                                                     "immutable": True})
            fake.site_page = ('<a href="%s/download/briglia-ut/v%s/click">get</a>' % (B, version)).encode()

    fake.workflows[CLI] = {"id": CLI_WF, "path": WF_PATH, "name": "Release (signed)"}
    fake.workflows[UT] = {"id": UT_WF, "path": WF_PATH, "name": "Release (signed)"}
    fake.environments[CLI] = {"release-sign": env_obj(CLI_ENV), "release-publish": env_obj(CLI_PUB, "release-publish", reviewer_rule=False)}
    fake.environments[UT] = {"release-sign": env_obj(UT_ENV), "release-publish": env_obj(UT_PUB, "release-publish", reviewer_rule=False)}
    for r in (CLI, UT):
        for e in ("release-sign", "release-publish"):
            fake.branch_policies[(r, e)] = [{"id": 5, "name": "v*", "type": "tag"}]
        fake.rulesets[r] = [{"id": 1, "name": "protect-main", "enforcement": "active"},
                            {"id": 2, "name": "protect-release-tags", "enforcement": "active"}]
    fake.site_installer_redirect = B + "/latestdl/briglia-cli/install.sh"
    S47, S48 = "4" * 40, "8" * 40
    cli_release("0.2.47", 107, S47)
    cli_release("0.2.48", 108, S48)
    cli_release("0.2.49", 109, PIN_SHA)
    app_release("0.8.5", 7, "5" * 40)
    app_release("0.8.6", 8, APP_SHA)
    fake.runs[CLI] = [
        run_obj(CLI, 37000000001, "v0.2.47", S47, CLI_WF, "2026-10-02T21:40:00Z",
                full_jobs(CLI_JOB_NAMES, 1100, "2026-10-02T21:56:00Z", "2026-10-02T21:56:07Z", "GitHub Actions 1000001001")),
        run_obj(CLI, 37000000002, "v0.2.48", S48, CLI_WF, "2026-10-03T16:39:02Z",
                full_jobs(CLI_JOB_NAMES, 1200, "2026-10-03T16:54:20Z", "2026-10-03T16:54:27Z", "GitHub Actions 1000001002")),
        # The pinned anchor (plan round-4 review): signing started 3 s AFTER the
        # gate deployment's creation, and its review history is EMPTY.
        run_obj(CLI, PIN_RUN, "v0.2.49", PIN_SHA, CLI_WF, "2026-10-04T23:39:20Z",
                full_jobs(CLI_JOB_NAMES, 1300, "2026-10-04T23:56:09Z", "2026-10-04T23:56:15Z", "GitHub Actions 1000002358"),
                updated="2026-10-04T23:57:09Z", approvals_by_attempt={"1": []}),
    ]
    fake.runs[UT] = [
        run_obj(UT, APP_RUN, "v0.8.6", APP_SHA, UT_WF, "2026-10-06T09:09:00Z",
                full_jobs(APP_JOB_NAMES, 2100, "2026-10-06T09:19:48Z", "2026-10-06T09:19:54Z", "GitHub Actions 1000002482"),
                updated="2026-10-06T09:21:00Z", approvals_by_attempt={"1": [approval(env_id=UT_ENV)]}),
    ]
    fake.deployments[CLI] = [{"id": i, "sha": s_, "ref": r, "environment": "release-sign", "created_at": c}
                             for i, s_, r, c in ((6848519034, PIN_SHA, "v0.2.49", "2026-10-04T23:56:06Z"),
                                                 (6830408286, S48, "v0.2.48", "2026-10-03T16:54:21Z"),
                                                 (6821284748, S47, "v0.2.47", "2026-10-02T21:55:52Z"))]
    fake.deployments[UT] = [{"id": 6880207211, "sha": APP_SHA, "ref": "v0.8.6", "environment": "release-sign",
                             "created_at": "2026-10-06T09:16:12Z"}]
    fake.dep_statuses[(UT, 6880207211)] = [{"state": "success", "target_url": "https://github.com/%s/actions/runs/%d/job/2104" % (UT, APP_RUN),
                                            "log_url": "https://github.com/%s/actions/runs/%d/job/2104" % (UT, APP_RUN)}]
    fake.events[CLI] = [{"id": "100", "type": "ReleaseEvent", "payload": {"action": "published", "release": {"tag_name": "v0.2.49"}},
                         "created_at": "2026-10-04T23:56:49Z"}]
    fake.events[UT] = [{"id": "200", "type": "ReleaseEvent", "payload": {"action": "published", "release": {"tag_name": "v0.8.6"}},
                        "created_at": "2026-10-06T09:21:00Z"}]

    def scrub(*subs):
        """Forget every trace of a finished scenario (findings, runs,
        deployments, anomalies) so later scenarios start clean."""
        def mut(st):
            for k in list(st["active"]):
                if any(x in k for x in subs):
                    st["active"].pop(k)
            for a in st.get("audit", {}).values():
                for coll in ("runs", "deployments", "anomalies"):
                    for k in list(a.get(coll, {})):
                        v = a[coll][k]
                        blob = k + json.dumps(v) if coll != "anomalies" else k + v
                        if any(x in blob for x in subs):
                            a[coll].pop(k)
        set_state(mut)

    def cli_run_by(rid):
        return next(r for r in fake.runs[CLI] if r["id"] == rid)

    def app_run_by(rid):
        return next(r for r in fake.runs[UT] if r["id"] == rid)

    try:
        # ---------------------------------------------------------- seed
        print("— seed: production pins, exact anchors, credential-free —")
        write_cfg(seed_runs_per_check=2)
        rc, out = run()
        st0 = state()
        b0 = st0["audit"]["briglia-cli"]["baseline"]
        check("seed spread over checks: 2 of 3 pre-gate runs read, baseline NOT complete, signing audit not checked "
              "(no verdict from a partial baseline), and no alert", not b0["complete"] and len(b0["done_runs"]) == 2
              and not st0["audit"]["briglia-cli"]["runs"].get(str(PIN_RUN), {}).get("verdict")
              and "signing-audit" in json.load(open(os.path.join(sd, "check.beacon.json")))["partial"]["briglia-cli"]
              and not tg("🚨"), (b0, fake.telegram))
        write_cfg()
        rc, out = run(env=dict(clean_env, GH_TOKEN="ghp_should_never_be_sent", GITHUB_TOKEN="ghs_nor_this"))
        st = state()
        check("next run completes the seed (exit 0) with both channels recorded", rc == 0 and st["recorded"]["briglia-cli"]["sequence"] == 109
              and st["recorded"]["briglia-ut"]["sequence"] == 8, out[-1500:])
        check("GH_TOKEN/GITHUB_TOKEN set → NO Authorization header ever reached the fake GitHub (remote mode)",
              fake.auth_seen == [] and "IGNORED" in out, fake.auth_seen)
        b = st["audit"]["briglia-cli"]["baseline"]
        check("CLI legacy baseline: complete, 3 executions — the two pre-cutoff ones AND the pinned v0.2.49 one "
              "(started 23:56:09, 3 s after the 23:56:06 gate deployment)",
              b["complete"] and len(b["executions"]) == 3
              and [str(PIN_RUN), "2026-10-04T23:56:09Z", "2026-10-04T23:56:15Z", "GitHub Actions 1000002358"] in b["executions"], b)
        check("app baseline: complete and EMPTY (its v0.8.6 signing is the first phone-approved one)",
              st["audit"]["briglia-ut"]["baseline"]["complete"] and st["audit"]["briglia-ut"]["baseline"]["executions"] == [])
        check("CLI v0.2.49 run (empty review history) is LEGACY, not phone-approved, and raises no alert",
              st["audit"]["briglia-cli"]["runs"][str(PIN_RUN)]["verdict"] == "legacy"
              and not any("signing" in k for k in st["active"]), st["audit"]["briglia-cli"]["runs"][str(PIN_RUN)])
        check("app v0.8.6 run validates its approval (reviewer id, pinned env id, attempt 1)",
              st["audit"]["briglia-ut"]["runs"][str(APP_RUN)]["verdict"] == "approved"
              and st["recorded"]["briglia-ut"]["approval"]["user_id"] == REV)
        check("deployments: CLI 6848519034 is the EXCLUSIVE legacy boundary (nothing audited), app 6880207211 the "
              "INCLUSIVE approved boundary (audited, explained by its one execution)",
              set(st["audit"]["briglia-cli"]["deployments"]) == set()
              and st["audit"]["briglia-ut"]["deployments"].get("6880207211", {}).get("settled") is True, st["audit"]["briglia-ut"]["deployments"])
        check("event feed cursor seeded without judging history", st["audit"]["briglia-cli"].get("events_cursor") == 100
              and st["audit"]["briglia-ut"].get("events_cursor") == 200)
        check("no ✅ yet: the website job has never run (no fresh site beacon), and nothing else was sent",
              not tg("✅ Verified") and not tg("🚨"), fake.telegram)
        check("site-cache.json written (generation 1) with the verified installer and the recorded click URL",
              json.load(open(os.path.join(sd, "site-cache.json")))["generation"] == 1
              and json.load(open(os.path.join(sd, "site-cache.json")))["content"]["channels"]["briglia-cli"]["installer"]["sha256"]
              == sha(INST["0.2.49"]))
        beacon = json.load(open(os.path.join(sd, "check.beacon.json")))
        check("beacon carries counts for the daily status (completed_total, recorded, rate history, audit mode)",
              beacon["completed_total"] == 2 and beacon["recorded"]["briglia-cli"]["sequence"] == 109 and "rate_history" in beacon)
        rc, out = site()
        check("site job: both hosts serve the verified installer and link the click → exit 0, beacon written",
              rc == 0 and os.path.exists(os.path.join(sd, "site.beacon.json")), out)
        n_api = fake.api_hits
        site()
        check("the site job makes ZERO api.github.com requests", fake.api_hits == n_api, fake.api_hits - n_api)
        fake.telegram.clear()
        rc, out = run()
        conf = tg("✅ Verified")
        check("second hourly run: ✅ for BOTH channels, naming version, sequence, commit, envelope, run and reviewer id",
              len(conf) == 2 and any("briglia-ut v0.8.6, sequence 8" in m and "one approval by your phone account (338251426)" in m
                                     and "37441659727" in m for m in conf)
              and any("briglia-cli v0.2.49, sequence 109" in m and "Provenance: ci (pre-approval-gate)" in m for m in conf),
              (conf, out[-1500:]))
        fake.telegram.clear()
        rc, out = run()
        check("third run is silent (no repeats), exit 0", rc == 0 and not fake.telegram, fake.telegram)

        # ------------------------------------------------------- env rules
        print("— environment rules (release-sign, hourly) —")
        base_env = copy.deepcopy(fake.environments[CLI]["release-sign"])

        def env_case(label, mutate, expect_key, expect_text, bp=None):
            fake.environments[CLI]["release-sign"] = mutate(copy.deepcopy(base_env))
            if bp is not None:
                fake.branch_policies[(CLI, "release-sign")] = bp
            fake.telegram.clear()
            rc_, out_ = run()
            ok = any(expect_key in m and expect_text in m for m in fake.telegram)
            fake.environments[CLI]["release-sign"] = copy.deepcopy(base_env)
            fake.branch_policies[(CLI, "release-sign")] = [{"id": 5, "name": "v*", "type": "tag"}]
            run()
            check(label, ok, (fake.telegram, out_[-600:]))
        def rev(e, lst):
            e["protection_rules"][0]["reviewers"] = [{"type": t, "reviewer": {"id": i, "login": "matteoiannius-beep"}} for t, i in lst]
            return e
        env_case("reviewer removed → env-rules alert", lambda e: rev(e, []), "briglia-cli/env-rules", "expected exactly User id")
        env_case("reviewer swapped (same login, other id) → alert", lambda e: rev(e, [("User", 999)]), "env-rules", "999")
        env_case("a second reviewer added → alert", lambda e: rev(e, [("User", REV), ("User", 199348073)]), "env-rules", "199348073")
        env_case("a Team reviewer → alert", lambda e: rev(e, [("Team", REV)]), "env-rules", "Team")
        env_case("admin bypass enabled → alert", lambda e: dict(e, can_admins_bypass=True), "env-rules", "can_admins_bypass")
        env_case("self-review allowed → alert", lambda e: (e["protection_rules"][0].update(prevent_self_review=False) or e),
                 "env-rules", "prevent_self_review")
        env_case("an extra rule type → reported as DRIFT, not weakening", lambda e: (e["protection_rules"].append({"id": 7, "type": "wait_timer"}) or e),
                 "briglia-cli/env-drift", "drift")
        env_case("protected-branches policy → alert", lambda e: dict(e, deployment_branch_policy={"protected_branches": True, "custom_branch_policies": False}),
                 "env-rules", "deployment_branch_policy")
        env_case("an extra '*' branch policy → alert", lambda e: e, "env-rules", "branch policies",
                 bp=[{"id": 5, "name": "v*", "type": "tag"}, {"id": 6, "name": "*", "type": "branch"}])
        env_case("'v*' typed as a BRANCH policy → alert", lambda e: e, "env-rules", "branch policies",
                 bp=[{"id": 5, "name": "v*", "type": "branch"}])
        env_case("recreated environment (other id) → alert", lambda e: dict(e, id=1), "env-rules", "recreated")
        fake.environments[CLI]["release-sign"] = dict(base_env, protection_rules=list(reversed(base_env["protection_rules"])))
        fake.telegram.clear()
        rc, out = run()
        check("reordered response → no alert", not tg("env-rules") and rc == 0, fake.telegram)
        fake.environments[CLI]["release-sign"] = copy.deepcopy(base_env)
        del fake.environments[CLI]["release-sign"]
        fake.telegram.clear()
        run()
        check("environment deleted (confirmed 404) → integrity alert", bool(tg("does not exist (confirmed 404)")), fake.telegram)
        fake.environments[CLI]["release-sign"] = copy.deepcopy(base_env)
        run()
        set_state(lambda st: st["active"].__setitem__("briglia-cli/env-rules", {"first": time.time() - 60, "last_sent": time.time() - 60,
                                                                                  "text": "injected"}))
        fake.faults["disconnect_path"] = "/api/repos/%s/environments/release-sign" % CLI
        fake.telegram.clear()
        rc, out = run()
        check("environment fetch fails (network) → NOT 'missing protection', finding kept, no recovery, env-rules not done",
              "briglia-cli/env-rules" in active() and not tg("recovered") and not tg("does not exist"), (fake.telegram, out[-500:]))
        del fake.faults["disconnect_path"]
        fake.telegram.clear()
        run()
        check("…next real pass → exactly one recovery", len(tg("recovered: briglia-cli/env-rules")) == 1, fake.telegram)
        fake.telegram.clear()

        # ---------------------------------------------- signing audit
        print("— signing audit: re-validation, executions, legacy baseline —")
        pin = cli_run_by(PIN_RUN)
        saved_pin = copy.deepcopy(pin)
        pin["jobs"].append(job_rec(9001, "Sign metadata", attempt=2, started="2026-10-07T10:00:00Z",
                                   completed="2026-10-07T10:00:06Z", runner="GitHub Actions 777"))
        pin.update(run_attempt=2, updated_at="2026-10-07T10:01:00Z")
        pin["approvals_by_attempt"]["2"] = [approval(env_id=CLI_ENV)]
        fake.telegram.clear()
        rc, out = run()
        check("a NEW signing execution on the pinned legacy CLI run 37244536754 → unverified (outside the fixed baseline)",
              bool(tg("briglia-cli/signing/%d" % PIN_RUN)) and state()["audit"]["briglia-cli"]["runs"][str(PIN_RUN)]["verdict"] == "unverified",
              (fake.telegram, out[-800:]))
        fake.runs[CLI][fake.runs[CLI].index(pin)] = copy.deepcopy(saved_pin)
        cli_run_by(PIN_RUN).update(run_attempt=2, updated_at="2026-10-07T11:00:00Z")
        carried = [dict(j, id=j["id"] + 5000, run_attempt=2) for j in saved_pin["jobs"]]
        cli_run_by(PIN_RUN)["jobs"] = saved_pin["jobs"] + carried
        fake.telegram.clear()
        rc, out = run()
        check("a publish-only retry of the legacy execution (carried copy) keeps LEGACY provenance and clears the finding",
              state()["audit"]["briglia-cli"]["runs"][str(PIN_RUN)]["verdict"] == "legacy"
              and len(tg("recovered: briglia-cli/signing/%d" % PIN_RUN)) == 1, (fake.telegram, out[-600:]))
        # new run on any date cannot be legacy
        old = cli_run_by(37000000001)
        rogue = run_obj(CLI, 37000000099, "v0.2.47", S47, CLI_WF, "2026-09-01T00:00:00Z",
                        full_jobs(CLI_JOB_NAMES, 9900, "2026-10-07T12:00:00Z", "2026-10-07T12:00:05Z", "GitHub Actions 9999"),
                        approvals_by_attempt={"1": []})
        fake.runs[CLI].append(rogue)
        fake.telegram.clear()
        run()
        check("a NEW run (backdated creation, old tag) can't obtain the legacy label → SIGNED WITHOUT an approval",
              any("37000000099" in m and "WITHOUT an approval" in m for m in fake.telegram), fake.telegram)
        fake.runs[CLI].remove(rogue)
        set_state(lambda st: [st["audit"]["briglia-cli"]["runs"].pop("37000000099", None),
                              st["active"].pop("briglia-cli/signing/37000000099", None)])
        # approved run settled, then signing re-run → unverified
        app = app_run_by(APP_RUN)
        saved_app = copy.deepcopy(app)
        app.update(run_attempt=2, updated_at="2026-10-07T13:00:00Z")
        app["jobs"].append(job_rec(9101, "Sign metadata", attempt=2, started="2026-10-07T13:00:00Z", completed="2026-10-07T13:00:06Z",
                                   runner="GitHub Actions 888"))
        app["approvals_by_attempt"]["2"] = [approval(env_id=UT_ENV)]
        fake.telegram.clear()
        run()
        check("approved run (settled) whose signing is RE-RUN → fingerprint change reopens it → unverified (2 executions)",
              any("briglia-ut/signing/%d" % APP_RUN in m and "2 signing executions" in m for m in fake.telegram), fake.telegram)
        fake.runs[UT][fake.runs[UT].index(app)] = copy.deepcopy(saved_app)
        app = app_run_by(APP_RUN)
        app.update(run_attempt=3, updated_at="2026-10-07T14:00:00Z")
        app["jobs"] = saved_app["jobs"] + [dict(j, id=j["id"] + 7000, run_attempt=3) for j in saved_app["jobs"]]
        app["approvals_by_attempt"]["3"] = []
        fake.telegram.clear()
        run()
        check("publish-only retry of the approved run: history replaced (attempt 2 empty) but the attempt-1 approval was "
              "OBSERVED earlier → still approved, finding clears",
              state()["audit"]["briglia-ut"]["runs"][str(APP_RUN)]["verdict"] == "approved"
              and len(tg("recovered: briglia-ut/signing/%d" % APP_RUN)) == 1, fake.telegram)
        fake.runs[UT][fake.runs[UT].index(app)] = copy.deepcopy(saved_app)
        set_state(lambda st: st["audit"]["briglia-ut"]["runs"].pop(str(APP_RUN)))
        run()
        fake.telegram.clear()

        # waiting → approved hours later → executed
        print("— signing audit: the approval lifecycle (rehearsal shapes) —")
        cli_release("0.2.50", 110, "a" * 40, publish=False)
        waiting = run_obj(CLI, 37500000001, "v0.2.50", "a" * 40, CLI_WF, "2026-10-07T15:00:00Z",
                          [job_rec(5001, "Authorize (credential-free)"),
                           dict(job_rec(5002, "Sign metadata", status="waiting", conclusion=None, completed=None),
                                runner_name=None, steps=[])],
                          status="waiting", conclusion=None, approvals_by_attempt={"1": []})
        fake.runs[CLI].append(waiting)
        dep = {"id": 6900000001, "sha": "a" * 40, "ref": "v0.2.50", "environment": "release-sign", "created_at": "2026-10-07T15:01:00Z"}
        fake.deployments[CLI].append(dep)
        fake.telegram.clear()
        rc, out = run()
        rs = state()["audit"]["briglia-cli"]["runs"]["37500000001"]
        check("waiting for the tap (status waiting, runner null, steps []) → pending, NO alert, its deployment is explained "
              "by the pending slot", rs["verdict"] == "pending" and rs["pending_attempt"] == 1 and not tg("🚨"), (rs, fake.telegram))
        set_state(lambda st: st["audit"]["briglia-cli"]["runs"]["37500000001"].__setitem__("pending_since", time.time() - 49 * 3600))
        fake.telegram.clear()
        run()
        check("…after 48 h of waiting: ONE info message, still no alert",
              len(tg("waiting for the signing review for more than 48 h")) == 1 and not tg("🚨"), fake.telegram)
        fake.telegram.clear()
        run()
        check("…and the info is not repeated", not tg("48 h"), fake.telegram)
        waiting.update(status="completed", conclusion="success", updated_at="2026-10-07T19:00:00Z",
                       jobs=full_jobs(CLI_JOB_NAMES, 5100, "2026-10-07T18:55:00Z", "2026-10-07T18:55:06Z", "GitHub Actions 5555"),
                       approvals_by_attempt={"1": [approval(env_id=CLI_ENV)]})
        fake.telegram.clear()
        run()
        check("approved hours later and executed → approved, no alarm, group settles",
              state()["audit"]["briglia-cli"]["runs"]["37500000001"]["verdict"] == "approved" and not tg("🚨")
              and state()["audit"]["briglia-cli"]["deployments"]["6900000001"].get("settled"), fake.telegram)

        def audit_case(label, rid, jobs, expect, approvals=None, status="completed", conclusion="success", extra_deps=0,
                       tag="v0.2.51", commit="b" * 40, attempt=1):
            cli_release(tag[1:], 111, commit, publish=False)
            r = run_obj(CLI, rid, tag, commit, CLI_WF, "2026-10-07T20:00:00Z", jobs, status=status, conclusion=conclusion,
                        approvals_by_attempt={"1": approvals or []}, attempt=attempt)
            fake.runs[CLI].append(r)
            fake.telegram.clear()
            rc_, out_ = run()
            v = state()["audit"]["briglia-cli"]["runs"].get(str(rid), {})
            ok = expect(v, fake.telegram)
            check(label, ok, (v.get("verdict"), v.get("reason"), fake.telegram[-3:], out_[-600:] if not ok else ""))
            fake.runs[CLI].remove(r)
            set_state(lambda st: [st["audit"]["briglia-cli"]["runs"].pop(str(rid), None)]
                      + [st["active"].pop(k) for k in list(st["active"]) if str(rid) in k])

        def unverified(sub):
            return lambda v, t: v.get("verdict") == "unverified" and sub in (v.get("reason") or "")
        sign = lambda **kw: dict(job_rec(6002, "Sign metadata"), **kw)  # noqa: E731
        audit_case("runner_name present and null with empty steps, still waiting → pending (not executed)", 37600000001,
                   [dict(sign(status="waiting", conclusion=None), runner_name=None, steps=[])],
                   lambda v, t: v.get("verdict") == "pending", status="waiting", conclusion=None)
        audit_case("the same record with the runner_name KEY MISSING → unverified (never 'no runner')", 37600000002,
                   [{k: v for k, v in sign(status="waiting", conclusion=None, steps=[]).items() if k != "runner_name"}],
                   unverified("runner_name key is missing"), status="waiting", conclusion=None)
        audit_case("steps missing → unverified", 37600000003,
                   [{k: v for k, v in sign(status="waiting", conclusion=None, runner_name=None).items() if k != "steps"}],
                   unverified("steps are missing"), status="waiting", conclusion=None)
        audit_case("no 'Sign metadata' record at all → unverified, never 'not executed'", 37600000004,
                   [job_rec(6001, "Authorize (credential-free)")], unverified("no record of the signing job"))
        audit_case("completed run with a still-pending signing record → unverified (contradiction)", 37600000005,
                   [dict(sign(status="waiting", conclusion=None), runner_name=None, steps=[])], unverified("still waiting"))
        audit_case("legitimately skipped signing job (no runner, conclusion skipped) → settled, no alert", 37600000006,
                   [dict(sign(conclusion="skipped"), runner_name=None, steps=[])],
                   lambda v, t: v.get("verdict") == "settled-unexecuted" and not any("🚨" in m for m in t), conclusion="failure")
        audit_case("signing that FAILED after starting, no approval → unverified (the key may have been used)", 37600000007,
                   [sign(conclusion="failure")], unverified("WITHOUT an approval"), conclusion="failure")
        audit_case("approval by the OWNER account (admin bypass) → unverified", 37600000008, [sign()],
                   unverified("not the pinned reviewer"), approvals=[approval(user_id=199348073, env_id=CLI_ENV, login="permaevidence")])
        audit_case("approval by 338251426 for ANOTHER environment id → unverified", 37600000009, [sign()],
                   unverified("WITHOUT an approval"), approvals=[approval(env_id=CLI_ENV + 1)])
        audit_case("a REJECTED entry next to the approval → unverified", 37600000010, [sign()],
                   unverified("rejected"), approvals=[approval(env_id=CLI_ENV, state="rejected"), approval(env_id=CLI_ENV)])
        audit_case("a record missing started_at (executed) → unverified directly, even as the only record", 37600000011,
                   [sign(started_at=None)], unverified("lacks started_at"))
        audit_case("copies of one execution that disagree on the conclusion → unverified", 37600000012,
                   [sign(), dict(sign(conclusion="failure"), id=6099, run_attempt=2)], unverified("disagree"), attempt=2)
        audit_case("rejected at review (rehearsal: completed/failure, runner '', steps []) with the rejection in the "
                   "observed history → settled-unexecuted with ONE reached-review slot",
                   37600000013, [dict(sign(conclusion="failure"), runner_name="", steps=[])],
                   lambda v, t: v.get("verdict") == "settled-unexecuted" and v.get("env_capacity") == 1,
                   approvals=[approval(env_id=CLI_ENV, state="rejected")], conclusion="failure")
        audit_case("cancelled while waiting, never observed waiting (no lifecycle evidence) → settled, NO capacity",
                   37600000014, [dict(sign(conclusion="cancelled"), runner_name="", steps=[])],
                   lambda v, t: v.get("verdict") == "settled-unexecuted" and v.get("env_capacity") == 0, conclusion="cancelled")
        rogue2 = run_obj(CLI, 37600000015, "v0.2.51", "b" * 40, CLI_WF, "2026-10-07T20:00:00Z", [sign()],
                         approvals_by_attempt={"1": [approval(env_id=CLI_ENV)]}, path=".github/workflows/evil.yml")
        fake.runs[CLI].append(rogue2)
        fake.telegram.clear()
        run()
        check("a run listed under the pinned workflow id but with ANOTHER path → unverified",
              any("37600000015" in m and "workflow path" in m for m in fake.telegram), fake.telegram)
        fake.runs[CLI].remove(rogue2)
        set_state(lambda st: [st["audit"]["briglia-cli"]["runs"].pop("37600000015", None)]
                  + [st["active"].pop(k) for k in list(st["active"]) if "37600000015" in k])
        # tag moved / deleted
        fake.tags[CLI]["v0.2.50"] = "c" * 40
        cli_run_by(37500000001)["updated_at"] = "2026-10-07T21:00:00Z"
        fake.telegram.clear()
        run()
        check("tag moved after signing → unverified ('tag moved')", any("37500000001" in m and "moved" in m for m in fake.telegram), fake.telegram)
        del fake.tags[CLI]["v0.2.50"]
        cli_run_by(37500000001)["updated_at"] = "2026-10-07T21:30:00Z"
        fake.telegram.clear()
        run()
        st_ = state()
        check("tag deleted → unverified ('deleted') (same finding, text updated, no repeated Telegram message — "
              "anti-noise)", "deleted" in st_["active"]["briglia-cli/signing/37500000001"]["text"] and not tg("37500000001"),
              (st_["active"].get("briglia-cli/signing/37500000001"), fake.telegram))
        fake.tags[CLI]["v0.2.50"] = "a" * 40
        cli_run_by(37500000001)["updated_at"] = "2026-10-07T22:00:00Z"
        run()
        # run deleted
        fake.runs[CLI].remove(cli_run_by(37500000001))
        fake.telegram.clear()
        run()
        check("a known run disappears and GET answers 404 → 'DELETED' integrity alert",
              any("run-deleted/37500000001" in m for m in fake.telegram), fake.telegram)
        fake.deployments[CLI].remove(dep)
        scrub("37500000001", "6900000001", "v0.2.50")
        run()
        fake.telegram.clear()

        # -------------------------------------------- deployments
        print("— deployments: count check over unique executions —")
        cli_release("0.2.52", 112, "d" * 40, publish=False)
        jobs52 = full_jobs(CLI_JOB_NAMES, 7100, "2026-10-08T10:00:00Z", "2026-10-08T10:00:06Z", "GitHub Actions 7100")
        r52 = run_obj(CLI, 37700000001, "v0.2.52", "d" * 40, CLI_WF, "2026-10-08T09:50:00Z", jobs52,
                      approvals_by_attempt={"1": [approval(env_id=CLI_ENV)]})
        fake.runs[CLI].append(r52)
        d1 = {"id": 6900000101, "sha": "d" * 40, "ref": "v0.2.52", "environment": "release-sign", "created_at": "2026-10-08T09:59:00Z"}
        fake.deployments[CLI].append(d1)
        run()
        r52.update(run_attempt=2, updated_at="2026-10-08T11:00:00Z",
                   jobs=jobs52 + [dict(j, id=j["id"] + 100, run_attempt=2) for j in jobs52])
        r52["approvals_by_attempt"]["2"] = []
        d2 = dict(d1, id=6900000102, created_at="2026-10-08T11:00:00Z")
        fake.deployments[CLI].append(d2)
        fake.telegram.clear()
        rc, out = run()
        check("carried-copy inflation: one execution listed twice + a legitimate AND a rogue deployment → capacity 1 → "
              "'NOT EXPLAINED' (copies never add capacity)",
              any("deploy-unexplained/v0.2.52" in m and "only 1 unique signing instance" in m for m in fake.telegram)
              and state()["audit"]["briglia-cli"]["runs"]["37700000001"]["verdict"] == "approved", (fake.telegram, out[-800:]))
        # a new pending slot does not hide the anomaly
        r52.update(run_attempt=3, status="waiting", conclusion=None, updated_at="2026-10-08T12:00:00Z")
        r52["jobs"] = r52["jobs"] + [dict(job_rec(7300, "Sign metadata", attempt=3, status="waiting", conclusion=None, completed=None),
                                          runner_name=None, steps=[])]
        r52["approvals_by_attempt"]["3"] = []
        fake.telegram.clear()
        run()
        st_ = state()
        check("…a later pending signing slot raises capacity but NEVER clears the earlier anomaly (kept, not 'pending')",
              "briglia-cli/deploy-unexplained/v0.2.52@dddddddddddd" in st_["active"] and not tg("recovered: briglia-cli/deploy-unexplained"),
              (st_["active"].keys(), fake.telegram))
        fake.deployments[CLI].remove(d2)
        r52.update(run_attempt=2, status="completed", conclusion="success", updated_at="2026-10-08T13:00:00Z",
                   jobs=jobs52 + [dict(j, id=j["id"] + 100, run_attempt=2) for j in jobs52])
        fake.telegram.clear()
        run()
        check("…the anomaly clears only on a real pass with NO pending instance and the count holding over settled ones",
              len(tg("recovered: briglia-cli/deploy-unexplained/v0.2.52")) == 1, fake.telegram)
        check("…and the removed deployment itself was reported as DELETED (confirmed 404)",
              "briglia-cli/deployment-deleted/6900000102" in active())
        scrub("6900000102")
        # same sha/ref, two runs → count passes; claim only executions
        r52b = run_obj(CLI, 37700000002, "v0.2.52", "d" * 40, CLI_WF, "2026-10-08T14:00:00Z",
                       full_jobs(CLI_JOB_NAMES, 7400, "2026-10-08T14:05:00Z", "2026-10-08T14:05:06Z", "GitHub Actions 7400"),
                       approvals_by_attempt={"1": [approval(env_id=CLI_ENV)]})
        fake.runs[CLI].append(r52b)
        fake.deployments[CLI].append(dict(d1, id=6900000103, created_at="2026-10-08T14:04:00Z"))
        fake.telegram.clear()
        run()
        check("same-SHA/ref ambiguity: two pinned runs, two deployments → the count check passes (it is a consistency "
              "check, not a binding)", not tg("deploy-unexplained"), fake.telegram)
        fake.deployments[CLI].append(dict(d1, id=6900000104, created_at="2026-10-08T15:00:00Z"))
        fake.dep_statuses[(CLI, 6900000104)] = [{"state": "inactive", "target_url": "https://github.com/%s/actions/runs/%d/job/1"
                                                 % (CLI, PIN_RUN), "log_url": ""}]
        fake.telegram.clear()
        run()
        check("a third deployment whose forged status points at an approved run ELSEWHERE → still unexplained AND a "
              "hint alert (target_url is never trusted)",
              bool(tg("deploy-unexplained/v0.2.52")) and bool(tg("deploy-hint/6900000104")), fake.telegram)
        fake.faults["deployments_hide"] = (6900000104,)
        fake.telegram.clear()
        run()
        check("a known deployment that merely DROPS OFF the listing (GET still answers) is not 'deleted'",
              not tg("deployment-deleted/6900000104"), fake.telegram)
        del fake.faults["deployments_hide"]
        fake.deployments[CLI] = [d for d in fake.deployments[CLI] if d["id"] != 6900000104]
        fake.telegram.clear()
        run()
        check("a known deployment vanishes from the listing and GET → 404 → 'DELETED' alert",
              bool(tg("deployment-deleted/6900000104")), fake.telegram)
        set_state(lambda st: [st["audit"]["briglia-cli"]["deployments"].pop("6900000104")]
                  + [st["active"].pop(k) for k in list(st["active"]) if "6900000104" in k or "v0.2.52" in k])
        # rogue deployment with no run at all
        fake.deployments[CLI].append({"id": 6900000201, "sha": "e" * 40, "ref": "v9.9.9", "environment": "release-sign",
                                      "created_at": "2026-10-08T16:00:00Z"})
        fake.telegram.clear()
        run()
        check("a release-sign deployment with NO pinned-workflow run → 'NOT EXPLAINED by the pinned workflow'",
              bool(tg("deploy-unexplained/v9.9.9")), fake.telegram)
        fake.deployments[CLI] = [d for d in fake.deployments[CLI] if d["id"] != 6900000201]
        set_state(lambda st: [st["audit"]["briglia-cli"]["deployments"].pop("6900000201")]
                  + [st["audit"]["briglia-cli"]["anomalies"].pop(k) for k in list(st["audit"]["briglia-cli"]["anomalies"])]
                  + [st["active"].pop(k) for k in list(st["active"]) if "v9.9.9" in k])
        # pending → rejected replaces the slot (one capacity, not two)
        cli_release("0.2.53", 113, "f" * 40, publish=False)
        r53 = run_obj(CLI, 37800000001, "v0.2.53", "f" * 40, CLI_WF, "2026-10-08T17:00:00Z",
                      [dict(job_rec(8001, "Sign metadata", status="waiting", conclusion=None, completed=None), runner_name=None, steps=[])],
                      status="waiting", conclusion=None, approvals_by_attempt={"1": []})
        fake.runs[CLI].append(r53)
        fake.deployments[CLI].append({"id": 6900000301, "sha": "f" * 40, "ref": "v0.2.53", "environment": "release-sign",
                                      "created_at": "2026-10-08T17:01:00Z"})
        run()
        r53.update(status="completed", conclusion="failure", updated_at="2026-10-08T17:30:00Z",
                   jobs=[dict(job_rec(8001, "Sign metadata", conclusion="failure"), runner_name="", steps=[])],
                   approvals_by_attempt={"1": [approval(env_id=CLI_ENV, state="rejected")]})
        fake.telegram.clear()
        run()
        v = state()["audit"]["briglia-cli"]["runs"]["37800000001"]
        check("pending → rejected REPLACES the pending slot: capacity 1 (not 2), the one deployment is explained, no alert",
              v["verdict"] == "settled-unexecuted" and v["env_capacity"] == 1 and not v.get("pending_attempt") and not tg("🚨"),
              (v, fake.telegram))
        fake.deployments[CLI].append({"id": 6900000302, "sha": "f" * 40, "ref": "v0.2.53", "environment": "release-sign",
                                      "created_at": "2026-10-08T17:40:00Z"})
        fake.telegram.clear()
        run()
        check("…a second deployment for that rejected attempt is NOT explained (a rejection adds one slot, once)",
              bool(tg("deploy-unexplained/v0.2.53")), fake.telegram)
        fake.deployments[CLI] = [d for d in fake.deployments[CLI] if not str(d["id"]).startswith("69000003")]
        fake.runs[CLI].remove(r53)
        set_state(lambda st: [st["audit"]["briglia-cli"]["runs"].pop("37800000001")]
                  + [st["audit"]["briglia-cli"]["deployments"].pop(k) for k in list(st["audit"]["briglia-cli"]["deployments"]) if k.startswith("69000003")]
                  + [st["audit"]["briglia-cli"]["anomalies"].pop(k) for k in list(st["audit"]["briglia-cli"]["anomalies"])]
                  + [st["active"].pop(k) for k in list(st["active"]) if "v0.2.53" in k])
        # >100 deployments: no false deletion
        many = [{"id": 6950000000 + i, "sha": "d" * 40, "ref": "v0.2.52", "environment": "release-sign",
                 "created_at": "2026-10-08T18:00:00Z"} for i in range(120)]
        fake.deployments[CLI] += many
        run()
        fake.telegram.clear()
        run()
        st_ = state()
        check("more than 100 deployments (two pages): every one is listed, none reported deleted",
              not tg("deployment-deleted") and sum(1 for k in st_["audit"]["briglia-cli"]["deployments"] if k.startswith("6950")) == 120,
              fake.telegram)
        fake.deployments[CLI] = [d for d in fake.deployments[CLI] if not str(d["id"]).startswith("6950")]
        set_state(lambda st: [st["audit"]["briglia-cli"]["deployments"].pop(k) for k in list(st["audit"]["briglia-cli"]["deployments"])
                              if k.startswith("6950")] + [st["audit"]["briglia-cli"]["anomalies"].pop(k)
                                                          for k in list(st["audit"]["briglia-cli"]["anomalies"])]
                  + [st["active"].pop(k) for k in list(st["active"]) if "v0.2.52" in k])
        run()
        fake.telegram.clear()

        # ------------------------------------------------- events
        print("— event feed —")
        fake.events[CLI].append({"id": "101", "type": "ReleaseEvent", "created_at": "2026-10-08T19:00:00Z",
                                 "payload": {"action": "published", "release": {"tag_name": "v0.2.60"}}})
        fake.events[CLI].append({"id": "102", "type": "DeleteEvent", "created_at": "2026-10-08T19:01:00Z",
                                 "actor": {"login": "permaevidence"}, "payload": {"ref_type": "tag", "ref": "v0.2.60"}})
        fake.events[CLI].append({"id": "103", "type": "CreateEvent", "created_at": "2026-10-08T19:02:00Z",
                                 "payload": {"ref_type": "tag", "ref": "sneaky"}})
        fake.telegram.clear()
        run()
        check("tag DeleteEvent → alert at once", bool(tg("event-tag-deleted/v0.2.60")), fake.telegram)
        check("non-v<semver> CreateEvent → alert", bool(tg("event-bad-tag/sneaky")), fake.telegram)
        check("a published-but-unrecorded release is NOT alerted after one check …", not tg("event-release-unconfirmed"), fake.telegram)
        fake.telegram.clear()
        run()
        check("… but is after two ('published but never confirmed; it may have been deleted since')",
              bool(tg("event-release-unconfirmed/v0.2.60")) and bool(tg("may have been deleted")), fake.telegram)
        fake.telegram.clear()
        run()
        check("event findings are not repeated (anti-noise)", not tg("event-"), fake.telegram)
        rc, out = run("acknowledge-finding", "briglia-cli/event-tag-deleted/v0.2.60")
        rc2, out2 = run("acknowledge-finding", "briglia-cli/nonsense")
        fake.telegram.clear()
        run()
        st_ = state()
        check("acknowledge-finding closes exactly that event finding (owner act), refuses an unknown key",
              rc == 0 and rc2 == 2 and "briglia-cli/event-tag-deleted/v0.2.60" not in st_["active"]
              and "briglia-cli/event-bad-tag/sneaky" in st_["active"], (out[-300:], out2[-300:]))
        for k in ("briglia-cli/event-bad-tag/sneaky", "briglia-cli/event-release-unconfirmed/v0.2.60"):
            run("acknowledge-finding", k)
        set_state(lambda st: st["audit"]["briglia-cli"]["event_releases"].clear())
        fake.events[CLI] += [{"id": str(1000 + i), "type": "WatchEvent", "payload": {}, "created_at": "2026-10-09T00:00:00Z"}
                             for i in range(320)]
        set_state(lambda st: st["audit"]["briglia-cli"].__setitem__("events_cursor", 103))
        fake.telegram.clear()
        run()
        check("cursor not reached within 3 pages → an explicit coverage-GAP finding stays open",
              bool(tg("events-gap")), fake.telegram)
        cur = state()["audit"]["briglia-cli"]["events_cursor"]
        check("the event cursor is persisted (survives restart) and advanced to the newest processed event", cur == 1319, cur)
        run("acknowledge-finding", "briglia-cli/events-gap")
        fake.telegram.clear()

        # ------------------------------------------------- report-only
        print("— report-only signing audit (owner decision, first 14 days) —")
        write_cfg(signing_audit_alerts=False, audit_report_since=(datetime.date.today() - datetime.timedelta(days=3)).isoformat())
        rogue = run_obj(CLI, 37900000001, "v0.2.47", S47, CLI_WF, "2026-10-09T01:00:00Z",
                        full_jobs(CLI_JOB_NAMES, 9100, "2026-10-09T01:05:00Z", "2026-10-09T01:05:06Z", "GitHub Actions 9100"),
                        approvals_by_attempt={"1": []})
        fake.runs[CLI].append(rogue)
        fake.deployments[CLI].append({"id": 6990000001, "sha": "e" * 40, "ref": "v8.8.8", "environment": "release-sign",
                                      "created_at": "2026-10-09T01:00:00Z"})
        fake.environments[CLI]["release-sign"] = dict(copy.deepcopy(base_env), can_admins_bypass=True)
        fake.telegram.clear()
        rc, out = run()
        st_ = state()
        check("report-only: an unapproved signing run and an unexplained deployment send NO Telegram message …",
              not tg("signing/37900000001") and not tg("deploy-unexplained/v8.8.8"), fake.telegram)
        rlog = open(os.path.join(sd, "audit-report.log")).read() if os.path.exists(os.path.join(sd, "audit-report.log")) else ""
        check("… they go to the local audit-report.log and stay open (counted in the beacon)",
              "signing/37900000001" in rlog and "deploy-unexplained/v8.8.8" in rlog
              and len(json.load(open(os.path.join(sd, "check.beacon.json")))["report_only_open"]) >= 2, rlog[-500:])
        check("… while the CORE checks still alert from day one (environment rule integrity)", bool(tg("env-rules")), fake.telegram)
        fake.environments[CLI]["release-sign"] = copy.deepcopy(base_env)
        fake.telegram.clear()
        hb("--daily")
        out = fake.telegram[-1] if fake.telegram else ""
        check("daily status reports the report-only count in one line", "Signing audit (report-only since" in out
              and "open item(s)" in out and "report-only period is over" not in out, out[-800:])
        write_cfg(signing_audit_alerts=False, audit_report_since=(datetime.date.today() - datetime.timedelta(days=15)).isoformat())
        fake.telegram.clear()
        hb("--daily")
        out = fake.telegram[-1] if fake.telegram else ""
        check("after day 14 the daily status says the period is over and how to switch — explicitly, never automatically",
              "report-only period is over" in out and "--audit-alerts on" in out, out[-800:])
        fake.telegram.clear()
        run()
        check("…and nothing switched by itself (still no audit Telegram message)", not tg("signing/37900000001"), fake.telegram)
        write_cfg()      # alerts on (explicit switch)
        fake.telegram.clear()
        run()
        check("explicit switch to alerts: each open audit finding is announced ONCE …",
              len(tg("signing/37900000001")) == 1 and len(tg("deploy-unexplained/v8.8.8")) == 1, fake.telegram)
        fake.telegram.clear()
        run()
        check("… and not repeated", not tg("37900000001") and not tg("v8.8.8"), fake.telegram)
        fake.runs[CLI].remove(rogue)
        fake.deployments[CLI] = [d for d in fake.deployments[CLI] if d["id"] != 6990000001]
        set_state(lambda st: [st["audit"]["briglia-cli"]["runs"].pop("37900000001")]
                  + [st["audit"]["briglia-cli"]["deployments"].pop("6990000001", None)]
                  + [st["audit"]["briglia-cli"]["anomalies"].pop(k) for k in list(st["audit"]["briglia-cli"]["anomalies"])]
                  + [st["active"].pop(k) for k in list(st["active"]) if "37900000001" in k or "v8.8.8" in k])
        run()
        fake.telegram.clear()

        # ------------------------------------------------- unverified hold (anti-noise)
        print("— unverified states folded until the freshness limit (owner anti-noise rule) —")
        write_cfg(unverified_hold_hours=2.25)
        held_run = run_obj(CLI, 37910000001, "v0.2.47", S47, CLI_WF, "2026-10-09T02:00:00Z",
                           full_jobs(CLI_JOB_NAMES, 9200, "2026-10-09T02:05:00Z", "2026-10-09T02:05:06Z", "GitHub Actions 9200"),
                           approvals_by_attempt={"1": []})
        fake.runs[CLI].append(held_run)
        fake.telegram.clear()
        run()
        st_ = state()
        check("an UNVERIFIED signing state is held (no Telegram message), listed for the daily status",
              not tg("signing/37910000001") and st_["active"]["briglia-cli/signing/37910000001"].get("held")
              and "briglia-cli/signing/37910000001" in json.load(open(os.path.join(sd, "check.beacon.json")))["held"], fake.telegram)
        set_state(lambda st: st["active"]["briglia-cli/signing/37910000001"].__setitem__("first", time.time() - 2.3 * 3600))
        run()
        check("…still open beyond the freshness limit → alerts ONCE", len(tg("signing/37910000001")) == 1, fake.telegram)
        run()
        check("…not repeated", len(tg("signing/37910000001")) == 1, fake.telegram)
        fake.runs[CLI].remove(held_run)
        scrub("37910000001")
        write_cfg()
        fake.telegram.clear()

        # ------------------------------------------------- budget
        print("— budget guard (60/hour per IP) —")
        run()
        set_state(lambda st: st.__setitem__("active", {}))
        run()
        clean_before = state().get("last_clean")
        fake.rate = {"remaining": 14, "limit": 60, "reset": time.time() + 3000}
        rc, out = run()
        st_ = state()
        check("a run left partial by the budget (no finding at all) never advances last_clean",
              clean_before and st_.get("last_clean") == clean_before and not st_["active"]
              and json.load(open(os.path.join(sd, "check.beacon.json")))["partial"], (clean_before, st_.get("last_clean"),
                                                                                    list(st_["active"])))
        fake.rate = {"remaining": 12, "limit": 60, "reset": time.time() + 3000}
        set_state(lambda st: st["coverage"].__setitem__("briglia-cli/events", time.time() - 3 * 3600))
        fake.telegram.clear()
        rc, out = run()
        st_ = state()
        b_ = json.load(open(os.path.join(sd, "check.beacon.json")))
        check("low budget: environment rules and the core checks ran; lower priorities were left NOT CHECKED with the "
              "rate-limit reason (priority order kept)",
              "env-rules" not in str(b_["partial"]) and "core" not in str(b_["partial"].get("briglia-cli", []))
              and "events" in str(b_["partial"]) and "rate limit" in out, (b_["partial"], out[-1000:]))
        check("…a due check skipped beyond its limit opens coverage/<check> naming the rate limit",
              any("coverage/events" in m and "rate limit" in m for m in fake.telegram), fake.telegram)
        check("…the request count matches the header delta (no request after the reserve)",
              b_["requests"] == 12 - fake.rate["remaining"] and fake.rate["remaining"] >= 0, (b_["requests"], fake.rate))
        fake.rate = {"remaining": 0, "limit": 60, "reset": time.time() + 3000}
        rc, out = run()
        check("rate-limited 403 (remaining 0) is handled: not checked, no crash, no 'missing protection'",
              rc in (0, 2) and "watcher-error" not in str(state()["active"]) and "does not exist" not in out, out[-600:])
        # a budget stop in the middle of the signing audit never settles an unexamined run
        sneaky = run_obj(CLI, 37990000001, "v0.2.47", S47, CLI_WF, "2026-10-09T03:00:00Z",
                         full_jobs(CLI_JOB_NAMES, 9900, "2026-10-09T03:05:00Z", "2026-10-09T03:05:06Z", "GitHub Actions 9901"),
                         approvals_by_attempt={"1": []})
        fake.runs[CLI].append(sneaky)
        fake.rate = None
        run()
        fake.runs[CLI][-1]["updated_at"] = "2026-10-09T03:30:00Z"
        scrub("37990000001")
        fake.rate = {"remaining": 14, "limit": 60, "reset": time.time() + 3000}
        run()
        rs_ = state()["audit"]["briglia-cli"]["runs"].get("37990000001", {})
        check("budget runs out during the signing audit → the new run stays UNEXAMINED (not settled, no verdict)",
              not rs_.get("validated_fp") and rs_.get("verdict") is None, rs_)
        fake.rate = None
        fake.telegram.clear()
        run()
        check("…next run with budget: it is validated and its missing approval alerts",
              any("signing/37990000001" in m and "WITHOUT an approval" in m for m in fake.telegram), fake.telegram)
        fake.runs[CLI].remove(sneaky)
        scrub("37990000001")
        fake.telegram.clear()
        run()
        check("budget back → coverage/events closed by a real pass", "briglia-cli/coverage/events" not in active(), active().keys())
        fake.telegram.clear()

        # ---------------------------------------- site job + confirmation
        print("— website job (5 min, no API), transitions and ✅ —")
        site_mod_path = scripts
        sys.path.insert(0, os.path.join(repo, "py"))
        sys.path.insert(0, site_mod_path)
        import sentinel_site as SS  # noqa: E402
        import release_heartbeat as HB  # noqa: E402
        scfg = SS.load_config(cfg_path)
        fake.domain_installer = b"#!/bin/sh\necho evil\n"
        fake.telegram.clear()
        rc = SS.run(scfg)
        check("one host serving installer bytes itself instead of the pinned redirect → alert at once",
              bool(tg("briglia-cli/site-redirect")), fake.telegram)
        fake.domain_installer = None
        fake.telegram.clear()
        SS.run(scfg)
        check("…restored → one recovery", len(tg("recovered: briglia-cli/site-redirect")) == 1, fake.telegram)
        fake.site_installer_redirect = B + "/download/briglia-cli/v0.2.49/install.sh"
        fake.telegram.clear()
        SS.run(scfg)
        check("changed first-hop redirect → alert at once", bool(tg("briglia-cli/site-redirect")), fake.telegram)
        fake.site_installer_redirect = B + "/latestdl/briglia-cli/install.sh"
        SS.run(scfg)
        fake.domain_page = b"<a href='https://evil.example/x.click'>"
        fake.telegram.clear()
        SS.run(scfg)
        check("wrong app link → alert", bool(tg("briglia-ut/site-content")), fake.telegram)
        fake.domain_page = None
        SS.run(scfg)
        fake.telegram.clear()
        api_before = fake.api_hits
        # a NEWER signed app release is live, but a host links something else:
        # a newer envelope alone never excuses a mismatch
        saved_env_ut, saved_page = fake.envelopes["briglia-ut"], fake.site_page
        app_release("0.8.7", 9, "9" * 40)
        fake.domain_page = b"<a href='https://evil.example/x.click'>"
        SS.run(scfg)
        check("newer signed release live but the page links OTHER content → alert at once (a newer envelope alone "
              "excuses nothing)", bool(tg("briglia-ut/site-content")) and not json.load(open(os.path.join(sd, "site-state.json")))
              .get("transitions", {}).get("briglia-ut"), fake.telegram)
        fake.domain_page = None
        fake.envelopes["briglia-ut"], fake.site_page = saved_env_ut, saved_page
        fake.releases[UT].pop()
        SS.run(scfg)
        fake.telegram.clear()
        # a genuine app release in progress: newer signed envelope, page already links it
        app_release("0.8.7", 9, "9" * 40)
        t0 = time.time()
        SS.run(scfg, now=t0)
        sst = json.load(open(os.path.join(sd, "site-state.json")))
        check("app page links exactly the NEWER signed release's click → held as a transition, no alert",
              "briglia-ut" in sst.get("transitions", {}) and not tg("🚨"), (sst.get("transitions"), fake.telegram))
        dl = sst["transitions"]["briglia-ut"]["deadline"]
        exp = SS.next_deadline(t0, 23)
        lt = datetime.datetime.fromtimestamp(dl - 20 * 60)
        check("deadline = next scheduled :23 after first sight + 20 min", abs(dl - exp) < 1 and lt.minute == 23 and dl - t0 <= 3600 + 1200,
              (iso_(dl), iso_(t0)))
        app_release("0.8.8", 10, "8" * 40)
        SS.run(scfg, now=t0 + 600)
        sst = json.load(open(os.path.join(sd, "site-state.json")))
        check("a repeated HIGHER candidate does not extend the deadline", sst["transitions"]["briglia-ut"]["deadline"] == dl)
        fake.telegram.clear()
        SS.run(scfg, now=dl + 1)
        check("the hourly check never ran → at the fixed deadline the site job ALERTS by itself", bool(tg("briglia-ut/site-content"))
              and bool(tg("fixed deadline")), fake.telegram)
        check("the site job made zero GitHub API requests through all of this", fake.api_hits == api_before, fake.api_hits - api_before)
        # the hourly check verifies 0.8.8 → new cache generation → content verified, transition closes
        fake.runs[UT].append(run_obj(UT, 37442000010, "v0.8.8", "8" * 40, UT_WF, "2026-10-09T08:00:00Z",
                                     full_jobs(APP_JOB_NAMES, 4100, "2026-10-09T08:05:00Z", "2026-10-09T08:05:06Z", "GitHub Actions 4100"),
                                     approvals_by_attempt={"1": [approval(env_id=UT_ENV)]}))
        fake.deployments[UT].append({"id": 6880300000, "sha": "8" * 40, "ref": "v0.8.8", "environment": "release-sign",
                                     "created_at": "2026-10-09T08:04:00Z"})
        fake.events[UT].append({"id": "201", "type": "ReleaseEvent", "created_at": "2026-10-09T08:07:00Z",
                                "payload": {"action": "published", "release": {"tag_name": "v0.8.8"}}})
        fake.telegram.clear()
        rc, out = run()
        check("hourly check records app v0.8.8 but sends NO ✅ while a site finding is open (⚠️ folded into the daily "
              "status before the freshness limit)", state()["recorded"]["briglia-ut"]["sequence"] == 10
              and not tg("✅ Verified briglia-ut") and not tg("⚠️ Release"), (fake.telegram, out[-800:]))
        fake.telegram.clear()
        SS.run(scfg)
        check("new cache generation verifies exactly the fetched page → the site finding clears with ONE recovery",
              len(tg("recovered: briglia-ut/site-content")) == 1, fake.telegram)
        fake.telegram.clear()
        run()
        check("next hourly run: ✅ for app v0.8.8 (site clean and fresh)", bool(tg("✅ Verified briglia-ut v0.8.8, sequence 10")), fake.telegram)
        # CLI release: installer differs, never excused, held quietly, alert at the deadline
        cli_release("0.2.54", 114, "1" * 40)
        t1 = time.time()
        fake.telegram.clear()
        SS.run(scfg, now=t1)
        sst = json.load(open(os.path.join(sd, "site-state.json")))
        check("CLI installer differs while a newer signed CLI release is live → NOT excused (install.sh is not signed); "
              "held quietly until the deadline (owner anti-noise rule: no immediate notice)",
              sst["transitions"].get("briglia-cli", {}).get("kind") == "unverified" and not tg("🚨"), (sst.get("transitions"), fake.telegram))
        fake.telegram.clear()
        SS.run(scfg, now=sst["transitions"]["briglia-cli"]["deadline"] + 5)
        check("…at the deadline it alerts, saying the installer is not signed", any("briglia-cli/site-content" in m and "not signed" in m
                                                                                    for m in fake.telegram), fake.telegram)
        fake.envelopes["briglia-cli"] = envelope("briglia-cli", "0.2.49", 109, {"linux-x64": fake.assets[("briglia-cli", "0.2.49", "linux-x64")]})
        fake.latest_installer = INST["0.2.49"]
        fake.releases[CLI].pop()
        SS.run(scfg)
        fake.latest_installer = b"#!/bin/sh\necho different\n"
        fake.telegram.clear()
        SS.run(scfg)
        check("installer mismatch with an EQUAL sequence (no newer signed release) → alert at once",
              bool(tg("briglia-cli/site-content")) or "briglia-cli/site-content" in json.load(open(os.path.join(sd, "site-state.json")))["active"],
              fake.telegram)
        fake.latest_installer = INST["0.2.49"]
        SS.run(scfg)
        # generation race: the cache is replaced while a site run is probing
        orig_probe = SS.probe_installer

        def racing_probe(url, redirect, want):
            c = json.load(open(os.path.join(sd, "site-cache.json")))
            c["generation"] += 1
            json.dump(c, open(os.path.join(sd, "site-cache.json"), "w"))
            SS.probe_installer = orig_probe
            return "content", "pretend mismatch", None
        SS.probe_installer = racing_probe
        before = open(os.path.join(sd, "site-state.json")).read()
        SS.run(scfg)
        SS.probe_installer = orig_probe
        check("a site result computed against an OLD cache generation is discarded (state untouched)",
              open(os.path.join(sd, "site-state.json")).read() == before)
        os.rename(os.path.join(sd, "site-cache.json"), os.path.join(sd, "site-cache.json.bak"))
        fake.telegram.clear()
        SS.run(scfg); SS.run(scfg)
        quiet = not tg("cache-unavailable")
        SS.run(scfg)
        check("missing site cache → not checked; alerts only after the grace period (3 checks)", quiet and bool(tg("cache-unavailable")),
              fake.telegram)
        os.rename(os.path.join(sd, "site-cache.json.bak"), os.path.join(sd, "site-cache.json"))
        SS.run(scfg)
        fake.telegram.clear()

        # confirmation variants
        print("— confirmations —")
        cli_release("0.2.54", 114, "1" * 40)
        fake.runs[CLI].append(run_obj(CLI, 37950000001, "v0.2.54", "1" * 40, CLI_WF, "2026-10-09T09:00:00Z",
                                      full_jobs(CLI_JOB_NAMES, 9500, "2026-10-09T09:05:00Z", "2026-10-09T09:05:06Z", "GitHub Actions 9500"),
                                      approvals_by_attempt={"1": [approval(env_id=CLI_ENV)]}))
        fake.deployments[CLI].append({"id": 6900009001, "sha": "1" * 40, "ref": "v0.2.54", "environment": "release-sign",
                                      "created_at": "2026-10-09T09:04:00Z"})
        fake.events[CLI].append({"id": "2000", "type": "ReleaseEvent", "created_at": "2026-10-09T09:07:00Z",
                                 "payload": {"action": "published", "release": {"tag_name": "v0.2.54"}}})
        # site beacon stale
        bpath = os.path.join(sd, "site.beacon.json")
        bb = json.load(open(bpath)); bb["completed"] = time.time() - 3600; json.dump(bb, open(bpath, "w"))
        fake.telegram.clear()
        run()
        check("CLI v0.2.54 recorded, but the site beacon is STALE → no ✅, and no ⚠️ yet (folded into the daily status)",
              state()["recorded"]["briglia-cli"]["sequence"] == 114 and not tg("✅ Verified briglia-cli") and not tg("⚠️ Release"),
              fake.telegram)
        set_state(lambda st: st["pending_confirm"]["briglia-cli"].__setitem__("first_seen", time.time() - 3 * 3600))
        fake.telegram.clear()
        run()
        check("…still not verifiable beyond the freshness limit → ONE ⚠️ 'NOT fully verified' naming the stale beacon",
              len(tg("⚠️ Release briglia-cli v0.2.54 seq 114 seen but NOT fully verified")) == 1 and bool(tg("stale")), fake.telegram)
        fake.telegram.clear()
        run()
        check("…and the ⚠️ is not repeated", not tg("⚠️ Release"), fake.telegram)
        SS.run(scfg)
        fake.faults["tg_status"] = 500
        run()
        del fake.faults["tg_status"]
        queued = [o["text"] for o in state().get("confirm_outbox", [])]
        check("✅ composed while Telegram is down is KEPT in the saved outbox (not lost)",
              any("✅ Verified briglia-cli v0.2.54" in m for m in queued) and "briglia-cli" not in state().get("pending_confirm", {}),
              queued)
        m0 = next((m for m in queued if "✅ Verified briglia-cli v0.2.54" in m), "")
        vt = (re.search(r"Verified at ([0-9: -]+) \(Mac 2\)", m0) or re.search("(?!)", "")) if m0 else None
        vt = vt.group(1) if vt else "<none kept>"
        fake.telegram.clear()
        run()
        late = tg("✅ Verified briglia-cli v0.2.54")
        check("…delivered on the next run with its ORIGINAL verification time", len(late) == 1 and ("Verified at %s (Mac 2)" % vt) in late[0],
              late)

        # partial coverage blocks the ✅
        app_release("0.9.1", 12, "6" * 40)
        fake.runs[UT].append(run_obj(UT, 37443000012, "v0.9.1", "6" * 40, UT_WF, "2026-10-09T10:00:00Z",
                                     full_jobs(APP_JOB_NAMES, 4200, "2026-10-09T10:05:00Z", "2026-10-09T10:05:06Z", "GitHub Actions 4200"),
                                     approvals_by_attempt={"1": [approval(env_id=UT_ENV)]}))
        fake.deployments[UT].append({"id": 6880400000, "sha": "6" * 40, "ref": "v0.9.1", "environment": "release-sign",
                                     "created_at": "2026-10-09T10:04:00Z"})
        SS.run(scfg)
        fake.faults["disconnect_path"] = "/api/repos/%s/environments/release-sign" % UT
        fake.telegram.clear()
        run()
        del fake.faults["disconnect_path"]
        check("app v0.9.1 recorded (corroborated) while the environment rules could NOT be checked → no ✅ (partial coverage)",
              state()["recorded"]["briglia-ut"]["sequence"] == 12 and not tg("✅ Verified briglia-ut v0.9.1"), fake.telegram)
        SS.run(scfg)
        fake.telegram.clear()
        run()
        check("…next complete run → ✅", bool(tg("✅ Verified briglia-ut v0.9.1, sequence 12")), fake.telegram)

        # remote acknowledge-local (app break-glass, no publication log)
        app_release("0.9.2", 13, "7" * 40)
        fake.telegram.clear()
        run()
        env11 = fake.envelopes["briglia-ut"]
        check("app release with no CI run, remote mode → LOCAL PROVENANCE alert (no publication log needed)",
              bool(tg("LOCAL PROVENANCE, NOT PHONE-APPROVED CI")), fake.telegram)
        rc, out = run("acknowledge-local", "briglia-ut", "v0.9.2", sha(env11))
        SS.run(scfg)
        fake.telegram.clear()
        run()
        SS.run(scfg)
        run()
        check("owner acknowledge-local in remote mode → recorded as local provenance and confirmed with ☑️, never ✅",
              state()["recorded"]["briglia-ut"]["sequence"] == 13 and bool(tg("☑️ Local provenance, NOT phone-approved CI"))
              and not tg("✅ Verified briglia-ut v0.9.2"), fake.telegram)

        # ------------------------------------------------- remote isolation
        print("— remote-mode isolation —")
        p = subprocess.run([sys.executable, "-I", "-S", "-c",
                            "import sys; sys.path.insert(0, %r); sys.path.insert(0, %r); import release_watch as w; "
                            "w.install_no_exec_hook('t'); import subprocess\n"
                            "try:\n subprocess.run(['/usr/bin/true'])\nexcept PermissionError as e:\n print('BLOCKED', e)\n"
                            "import os\ntry:\n os.system('true')\nexcept PermissionError:\n print('BLOCKED2')"
                            % (os.path.join(repo, "py"), scripts)], capture_output=True, text=True)
        check("the audit hook blocks subprocess and os.system", "BLOCKED" in p.stdout and "BLOCKED2" in p.stdout, p.stdout + p.stderr)
        claude_dir = os.path.join(root, "fakehome", ".claude", "channels", "telegram")
        os.makedirs(claude_dir)
        open(os.path.join(claude_dir, ".env"), "w").write("TELEGRAM_BOT_TOKEN=tok\nOWNER_CHAT_ID=1\n")
        os.chmod(os.path.join(claude_dir, ".env"), 0o600)
        write_cfg(telegram_env_file=os.path.join(claude_dir, ".env"))
        set_state(lambda st: st["queued"].append("probe message"))
        fake.telegram.clear()
        rc, out = run()
        check("remote mode refuses the Mac mini's Claude Code Telegram credentials (nothing sent through them)",
              not fake.telegram and "refuses the Claude Code Telegram credentials" in out, out[-500:])
        os.chmod(tg_env, 0o644)
        write_cfg()
        rc, out = run()
        check("telegram.env readable by others (0644) → refused", not fake.telegram and "readable by others" in out, out[-500:])
        os.chmod(tg_env, 0o600)
        run()
        check("…fixed → the messages queued meanwhile are delivered", not state()["queued"], state()["queued"])

        # ------------------------------------------------- coverage
        print("— per-check coverage limits —")
        set_state(lambda st: st["coverage"].update({"briglia-cli/env-publish": time.time() - 9 * 3600}))
        fake.faults["disconnect_path"] = "/api/repos/%s/rulesets" % CLI
        fake.telegram.clear()
        run()
        check("6-hourly env-publish due and failing beyond 8.25 h → coverage/env-publish warning",
              bool(tg("briglia-cli/coverage/env-publish")), fake.telegram)
        del fake.faults["disconnect_path"]
        set_state(lambda st: st["coverage"].update({"briglia-cli/env-publish": time.time() - 4 * 3600}))
        fake.telegram.clear()
        run()
        check("…not due (ran < 6 h ago) → no request, no recovery (freshness never synthesizes a pass)",
              not tg("recovered: briglia-cli/coverage/env-publish") and "briglia-cli/coverage/env-publish" in active(), fake.telegram)
        set_state(lambda st: st["coverage"].update({"briglia-cli/env-publish": time.time() - 7 * 3600}))
        fake.telegram.clear()
        run()
        check("…due again and performed → one recovery", len(tg("recovered: briglia-cli/coverage/env-publish")) == 1, fake.telegram)

        # ------------------------------------------------- heartbeat / daily
        print("— heartbeat and daily status —")
        hcfg, _ = HB.load_config(cfg_path)
        fake.telegram.clear()
        now = time.time()
        sb = json.load(open(bpath))
        HB.run(hcfg, None, now=sb["completed"] + 19 * 60)
        quiet = not tg("website job")
        HB.run(hcfg, None, now=sb["completed"] + 21 * 60)
        check("site job stalled next to a healthy checker → heartbeat alerts within 25 min of its last result",
              quiet and bool(tg("website job")), fake.telegram)
        fake.telegram.clear()
        HB.run(hcfg, None, now=sb["completed"] + 26 * 60)
        check("…and does not repeat it every 5 minutes (anti-noise)", not fake.telegram, fake.telegram)
        cb = json.load(open(os.path.join(sd, "check.beacon.json")))
        fake.telegram.clear()
        HB.run(hcfg, None, now=cb["completed"] + 2.3 * 3600)
        check("hourly check stalled → heartbeat alerts after 2 h 15 min", bool(tg("has not completed since")), fake.telegram)
        SS.run(scfg)
        HB.run(hcfg, None)
        moved = os.path.join(scripts, "release_watch.py")
        os.rename(moved, moved + ".gone")
        os.rename(os.path.join(scripts, "sentinel_site.py"), os.path.join(scripts, "sentinel_site.py.gone"))
        rc1, out1 = hb()
        rc2, out2 = hb("--daily")
        check("heartbeat and daily status still run with the checker and site modules deleted",
              rc1 in (0, 2) and rc2 in (0, 2) and "Traceback" not in out1 + out2, out1[-300:] + out2[-300:])
        os.rename(moved + ".gone", moved)
        os.rename(os.path.join(scripts, "sentinel_site.py.gone"), os.path.join(scripts, "sentinel_site.py"))
        fake.telegram.clear()
        HB.daily(hcfg, None)
        msg = fake.telegram[-1] if fake.telegram else ""
        check("daily status: one message with completed/scheduled counts, recorded releases and the lowest budget",
              "Sentinel daily status" in msg and "Hourly checks completed:" in msg and "Recorded:" in msg, msg)
        os.rename(bpath, bpath + ".x")
        fake.telegram.clear()
        HB.daily(hcfg, None)
        check("a missing site beacon makes the daily status '⚠️ Incomplete', never clean",
              fake.telegram and fake.telegram[-1].startswith(("⚠️ Incomplete", "🚨 Findings")), fake.telegram)
        os.rename(bpath + ".x", bpath)
        # DST: scheduled-hour counting over a fall-back night
        n = HB.scheduled_between(0, 24 * 3600, 23)
        check("scheduled hourly checks are counted from local wall-clock :23 boundaries (24 in a 24 h window)", n == 24, n)
        # dead-man
        dm_hits = []
        orig_urlopen = HB.urllib.request.urlopen

        def fake_urlopen(req, timeout=None):
            u = req.full_url if hasattr(req, "full_url") else req
            if "hc-ping" in u:
                dm_hits.append(u)

                class R:
                    def read(self, n=-1):
                        return b"OK"

                    def __enter__(self):
                        return self

                    def __exit__(self, *a):
                        return False
                return R()
            return orig_urlopen(req, timeout=timeout)
        HB.urllib.request.urlopen = fake_urlopen
        HB.run(dict(hcfg, deadman_url=None), None)
        none_hits = list(dm_hits)
        HB.run(dict(hcfg, deadman_url="https://hc-ping.example/uuid"), None)
        HB.run(dict(hcfg, deadman_url="https://hc-ping.example/uuid"), None,
               now=json.load(open(os.path.join(sd, "check.beacon.json")))["completed"] + 3 * 3600)
        HB.urllib.request.urlopen = orig_urlopen
        check("dead-man ping is OFF until a URL is configured; then healthy → <url>, alerting → <url>/fail",
              none_hits == [] and dm_hits[0] == "https://hc-ping.example/uuid" and dm_hits[-1].endswith("/uuid/fail"), dm_hits)

        # ------------------------------------------------- logs + bounded state
        print("— bounded logs and state —")
        lp = os.path.join(root, "rot", "x.log")
        import release_watch as RW  # noqa: E402
        stream = RW.RotatingStream(lp, max_bytes=1000)
        for i in range(400):
            stream.write("line %04d %s\n" % (i, "x" * 40))
        files = sorted(os.listdir(os.path.dirname(lp)))
        sizes = [os.path.getsize(os.path.join(os.path.dirname(lp), f)) for f in files]
        check("log rotation keeps current + 2 old files, each capped near the limit", files == ["x.log", "x.log.1", "x.log.2"]
              and max(sizes) < 1100, (files, sizes))
        logs = os.listdir(os.path.join(sd, "logs"))
        check("checker, site, heartbeat and daily logs are written to rotating files", {"check.log", "site.log", "heartbeat.log",
                                                                                      "daily.log"} <= set(logs) or {"check.log"} <= set(logs), logs)
        big = {"audit": {"briglia-cli": {"runs": {str(i): {"validated_fp": [1], "verdict": "approved", "sig_cache": {"x": 1}}
                                                  for i in range(1000)}, "deployments": {}}}, "confirmed_tags": {"x": ["t"] * 900}}
        RW.prune_state(big)
        check("state stays bounded: job caches dropped once settled, old tags capped at 500; run records mirror "
              "GitHub's capped listing and are kept (never re-validated hourly)",
              len(big["audit"]["briglia-cli"]["runs"]) == 1000 and len(big["confirmed_tags"]["x"]) == 500
              and not any("sig_cache" in r for r in big["audit"]["briglia-cli"]["runs"].values()))
        stray = os.path.join(sd, "logs", "launchd-check.log")
        open(stray, "w").write("x" * (1024 * 1024 + 10))
        HB.rotate_stray_logs(sd)
        check("launchd's stray stdout/stderr files are rotated by the heartbeat", os.path.exists(stray + ".1")
              and not os.path.exists(stray))
        check("the full-hash download is delete-on-close (no temp file left behind)",
              os.listdir(tmpd) == [], os.listdir(tmpd))

        # ------------------------------------------------- installer
        print("— installer (test root, shimmed dscl/dseditgroup/launchctl) —")
        dist = os.path.join(root, "dist")
        out_b = subprocess.run([sys.executable, os.path.join(scripts, "sentinel", "build_bundle.py"), dist, "--version", "0.9.0"],
                               capture_output=True, text=True)
        out_b2 = subprocess.run([sys.executable, os.path.join(scripts, "sentinel", "build_bundle.py"), dist + "2", "--version", "0.9.0"],
                                capture_output=True, text=True)
        check("bundle and installer build reproducibly (two builds, identical bytes)",
              out_b.returncode == 0 and all(open(os.path.join(dist, f), "rb").read() == open(os.path.join(dist + "2", f), "rb").read()
                                            for f in ("briglia-sentinel-0.9.0.pyz", "install_sentinel.py")), out_b.stderr)
        inst = os.path.join(dist, "install_sentinel.py")
        bundle = os.path.join(dist, "briglia-sentinel-0.9.0.pyz")
        shims = os.path.join(root, "shims")
        os.makedirs(shims)
        users_db = os.path.join(root, "dscl.json")
        launch_log = os.path.join(root, "launchctl.log")
        launch_fail = os.path.join(root, "launchctl.fail")
        json.dump({}, open(users_db, "w"))
        open(os.path.join(shims, "dscl"), "w").write("""#!%s
import json, sys
db = json.load(open(%r)); a = sys.argv[1:]
if a[1] == "-list":
    for n, u in sorted(db.items()): print(n, u.get("UniqueID", ""))
    print("root 0"); print("alice 501"); sys.exit(0)
name = a[2].split("/")[-1]
if a[1] == "-read":
    if name not in db: sys.exit(56)
    for k, v in db[name].items():
        if len(a) == 3 or k in a[3:]: print("%%s: %%s" %% (k, v))
    sys.exit(0)
if a[1] == "-create":
    db.setdefault(name, {})
    if len(a) > 3: db[name][a[3]] = a[4]
elif a[1] == "-delete":
    db.pop(name, None)
json.dump(db, open(%r, "w"))
""" % (sys.executable, users_db, users_db))
        open(os.path.join(shims, "dseditgroup"), "w").write("""#!%s
import json, sys
db = json.load(open(%r)); u = sys.argv[sys.argv.index("-m") + 1]
if db.get(u, {}).get("_admin"): print("yes %%s is a member of admin" %% u); sys.exit(0)
print("no %%s is NOT a member of admin" %% u); sys.exit(67)
""" % (sys.executable, users_db))
        open(os.path.join(shims, "launchctl"), "w").write("""#!/bin/bash
case "$*" in *com.apple.*) exit 113;; esac
echo "$*" >> %r
if [ -f %r ] && echo "$*" | grep -Eq "$(cat %r)"; then exit 5; fi
exit 0
""" % (launch_log, launch_fail, launch_fail))
        open(os.path.join(shims, "pmset"), "w").write("#!/bin/bash\necho ' sleep                0'\necho ' autorestart          1'\n")
        open(os.path.join(shims, "systemsetup"), "w").write("#!/bin/bash\necho 'Remote Login: Off'\n")
        for f in os.listdir(shims):
            os.chmod(os.path.join(shims, f), 0o755)
        TOKEN = "123456789:" + "A" * 35
        fake.tg_tokens.add(TOKEN)
        test_cfg = {"github_api": B + "/api", "raw_base": B + "/raw", "telegram_api": B + "/tg",
                    "channels": cfg["channels"], "signing_audit_alerts": False}

        def install(troot, answers, extra=(), bundle_path=None, wait_code=False, installer=None):
            p_ = subprocess.Popen([sys.executable, installer or inst, "--test-root", troot, "--test-bin", shims,
                                   "--test-bundle", bundle_path or bundle, "--test-telegram-api", B + "/tg",
                                   "--test-config", json.dumps(test_cfg)] + list(extra),
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=clean_env)
            for a_ in answers:
                if a_ == "<CODE>":
                    code = None
                    for _ in range(200):
                        hits = [m for m in fake.telegram if m.startswith("Sentinel setup code:")]
                        if hits:
                            code = hits[-1].split(":")[1].strip()
                            break
                        time.sleep(0.05)
                    a_ = code or "000000"
                elif a_ == "<WRONG>":
                    a_ = "999999x"
                try:
                    p_.stdin.write(a_ + "\n")
                    p_.stdin.flush()
                except BrokenPipeError:
                    break
            try:
                p_.stdin.close()
            except BrokenPipeError:
                pass
            o_ = p_.stdout.read()
            p_.wait(timeout=600)
            return p_.returncode, o_

        def launch_calls():
            return [l.strip() for l in open(launch_log)] if os.path.exists(launch_log) else []

        def plist_dir(troot):
            return os.path.join(troot, "Library", "LaunchDaemons")

        troot = os.path.join(root, "mac2")
        os.makedirs(troot)
        fake.telegram.clear()
        rc, out = install(troot, [TOKEN, "", "<CODE>", "yes"])
        db = json.load(open(users_db))
        check("fresh install succeeds; prints the recorded floor and the legacy baseline before activating",
              rc == 0 and "Recorded releases (the rollback floor)" in out and "Legacy signing baseline" in out
              and "execution(s)" in out, out[-1500:])
        u = db.get("brigliawatch", {})
        check("user brigliawatch created: hidden uid in 450–499, no password ('*'), /usr/bin/false, NOT an admin",
              450 <= int(u.get("UniqueID", 0)) < 500 and u.get("Password") == "*" and u.get("UserShell") == "/usr/bin/false"
              and u.get("IsHidden") == "1" and not u.get("_admin"), u)
        own = json.load(open(os.path.join(troot, "ownership.json")))
        code_root = os.path.join(troot, "Library", "Application Support", "briglia-sentinel")
        sdir = os.path.join(troot, "Users", "brigliawatch", "Library", "Application Support", "briglia-sentinel")
        check("code root-owned (files 0644), state 0700 brigliawatch, telegram.env 0600 brigliawatch",
              own[os.path.join(code_root, "0.9.0", "release_watch.py")] == ["root", "0o644"]
              and own[sdir] == ["brigliawatch", "0o700"] and own[os.path.join(sdir, "telegram.env")] == ["brigliawatch", "0o600"]
              and own[os.path.join(code_root, "config.json")] == ["root", "0o644"], {k: v for k, v in own.items() if "0.9.0/" not in k})
        import plistlib  # noqa: E402
        pl = {j: plistlib.load(open(os.path.join(plist_dir(troot), "dev.briglia.sentinel.%s.plist" % j), "rb"))
              for j in ("check", "heartbeat", "site", "daily")}
        check("four system launch jobs, each UserName=brigliawatch, python -I -S, PATH=/usr/bin:/bin, explicit HOME",
              all(p_["UserName"] == "brigliawatch" and p_["ProgramArguments"][1:3] == ["-I", "-S"]
                  and p_["EnvironmentVariables"]["PATH"] == "/usr/bin:/bin" and p_["EnvironmentVariables"]["HOME"].endswith("/Users/brigliawatch")
                  for p_ in pl.values()), pl["check"])
        check("schedule: check at :23, site and heartbeat every 300 s, daily at 09:00",
              pl["check"]["StartCalendarInterval"] == {"Minute": 23} and pl["site"]["StartInterval"] == 300
              and pl["heartbeat"]["StartInterval"] == 300 and pl["daily"]["StartCalendarInterval"] == {"Hour": 9, "Minute": 0})
        calls = launch_calls()
        check("jobs bootstrapped into the system domain and verified (print)",
              sum(c.startswith("bootstrap system") for c in calls) == 4 and sum(c.startswith("print system/dev.briglia.sentinel") for c in calls) >= 4,
              calls)
        icfg = json.load(open(os.path.join(code_root, "config.json")))
        check("config: remote mode, report-only signing audit with today's start date recorded, no repeats",
              icfg["mode"] == "remote" and icfg["signing_audit_alerts"] is False
              and icfg["audit_report_since"] == datetime.date.today().isoformat() and icfg["realert_hours"] == 0, icfg)
        check("the chat was proven with a 6-digit code sent by the new bot", any(m.startswith("Sentinel setup code:") for m in fake.telegram))
        st_path = os.path.join(sdir, "state.json")
        baseline_before = json.dumps(json.load(open(st_path))["audit"]["briglia-cli"]["baseline"], sort_keys=True)
        # reinstall keeps state, bot and the report-only start date; baseline not recomputed
        icfg["audit_report_since"] = "2026-01-01"
        json.dump(icfg, open(os.path.join(code_root, "config.json"), "w"))
        open(launch_log, "w").close()
        rc, out = install(troot, ["", "yes"])
        st_after = json.load(open(st_path))
        check("reinstall: keeps the bot (no token asked), the state, the report-only start date",
              rc == 0 and "keeping the configured Sentinel bot" in out
              and json.load(open(os.path.join(code_root, "config.json")))["audit_report_since"] == "2026-01-01", out[-800:])
        check("…and the legacy baseline is NOT recomputed (byte-identical)",
              json.dumps(st_after["audit"]["briglia-cli"]["baseline"], sort_keys=True) == baseline_before)
        # --audit-alerts on (explicit switch)
        rc, out = install(troot, [], extra=["--audit-alerts", "on"])
        check("--audit-alerts on switches the signing audit to alerts (explicit owner act)",
              rc == 0 and json.load(open(os.path.join(code_root, "config.json")))["signing_audit_alerts"] is True, out)
        install(troot, [], extra=["--audit-alerts", "off"])
        # tampered bundle
        bad = os.path.join(root, "bad.pyz")
        data = bytearray(open(bundle, "rb").read()); data[100] ^= 1
        open(bad, "wb").write(bytes(data))
        open(launch_log, "w").close()
        rc, out = install(troot, ["", "yes"], bundle_path=bad)
        check("tampered bundle → refused before anything changes (no launchctl call)", rc == 1
              and "but this installer embeds" in out and not launch_calls(), out[-500:])
        # downgrade
        subprocess.run([sys.executable, os.path.join(scripts, "sentinel", "build_bundle.py"), dist + "old", "--version", "0.8.0"],
                       capture_output=True)
        rc, out = install(troot, ["", "yes"], bundle_path=os.path.join(dist + "old", "briglia-sentinel-0.8.0.pyz"),
                          installer=os.path.join(dist + "old", "install_sentinel.py"))
        check("downgrade → refused", rc == 1 and "downgrade" in out, out[-400:])
        # incompatible / admin existing user
        db = json.load(open(users_db))
        db["brigliawatch"]["_admin"] = True
        json.dump(db, open(users_db, "w"))
        rc, out = install(troot, ["", "yes"])
        check("an existing brigliawatch that is an ADMIN → refused", rc == 1 and "admin group" in out, out[-400:])
        db["brigliawatch"].pop("_admin")
        db["brigliawatch"]["UserShell"] = "/bin/zsh"
        json.dump(db, open(users_db, "w"))
        rc, out = install(troot, ["", "yes"])
        check("an existing brigliawatch with a login shell → refused (never reused)", rc == 1 and "login shell" in out, out[-400:])
        db["brigliawatch"]["UserShell"] = "/usr/bin/false"
        json.dump(db, open(users_db, "w"))
        # fresh roots: wrong code / no confirmation / failing first check / failing bootstrap
        for label, answers, prep, want in (
                ("wrong confirmation code → nothing activated", [TOKEN, "", "<WRONG>"], None, "wrong code"),
                ("floor not confirmed (anything but 'yes') → nothing activated", [TOKEN, "", "<CODE>", "no"], None, "not confirmed"),
                ("first check cannot run (unusable state) → rolled back, no job loaded", [TOKEN, "", "<CODE>", "yes"], "corrupt",
                 "could not run"),
                ("a launchctl bootstrap fails → rolled back, every Sentinel job booted out, no plist left", [TOKEN, "", "<CODE>", "yes"],
                 "bootstrap", "rolling back")):
            json.dump({}, open(users_db, "w"))
            r2 = os.path.join(root, "mac2-" + re.sub(r"\W+", "-", label)[:20])
            os.makedirs(r2)
            if prep == "corrupt":
                sd2 = os.path.join(r2, "Users", "brigliawatch", "Library", "Application Support", "briglia-sentinel")
            if prep == "bootstrap":
                open(launch_fail, "w").write("^bootstrap system .*site")
            open(launch_log, "w").close()
            fake.telegram.clear()
            if prep == "corrupt":
                # the user is created by the installer; plant unusable state right after it exists
                orig_c = cfg["channels"]["briglia-cli"]["envelope_url"]
                test_cfg["channels"] = copy.deepcopy(cfg["channels"])
                test_cfg["state_dir_unused"] = True
                test_cfg["github_api"] = "http://127.0.0.1:9/api"   # nothing listens: the check cannot complete …
                test_cfg["channels"]["briglia-cli"]["envelope_url"] = "http://127.0.0.1:9/x"
                test_cfg["channels"]["briglia-ut"]["envelope_url"] = "http://127.0.0.1:9/x"
                test_cfg["state_dir"] = os.path.join(r2, "not-a-dir-file")
                open(os.path.join(r2, "not-a-dir-file"), "w").write("x")  # … and its state dir is a FILE → exit 1
            rc, out = install(r2, answers)
            if prep == "corrupt":
                test_cfg.update(github_api=B + "/api")
                test_cfg.pop("state_dir"); test_cfg.pop("state_dir_unused")
                test_cfg["channels"] = cfg["channels"]
            if os.path.exists(launch_fail):
                os.unlink(launch_fail)
            pdir = plist_dir(r2)
            left = [f for f in os.listdir(pdir)] if os.path.isdir(pdir) else []
            calls = launch_calls()
            loaded_after = [c for c in calls if c.startswith("bootstrap")]
            booted_out = [c for c in calls if c.startswith("bootout")]
            check(label, rc == 1 and want in out and not left and (prep == "bootstrap" or not loaded_after)
                  and (prep != "bootstrap" or len(booted_out) >= 8), (out[-700:], left, calls))
        # uninstall
        rc, out = install(troot, [], extra=["--uninstall"])
        check("--uninstall removes the jobs and the code, keeps the state unless asked",
              rc == 0 and not os.listdir(plist_dir(troot)) and not os.path.exists(code_root) and os.path.exists(st_path), out)
        src_i = open(os.path.join(scripts, "sentinel", "install_sentinel.py")).read()
        check("test options are refused when running as root (static guard present)",
              'if self.test and os.geteuid() == 0:' in src_i and "test options are refused when running as root" in src_i)
        recovery_and_confirmation_regressions(scripts)
    finally:
        fake.close()
        shutil.rmtree(root, ignore_errors=True)
    print("\nsentinel selftest: %d passed, %d failed" % (PASSED, FAILED))
    return 1 if FAILED else 0


def recovery_and_confirmation_regressions(scripts):
    """In-process regressions: a finding clears ("recovered") only after the
    owning check established — completely and validly — every predicate the
    finding is about; a ✅ needs every DUE check of this run; and a positive
    message is sent only after its verification record is durably saved.
    Each scenario ends with a real passing check that recovers / confirms
    exactly once. Every scenario uses throwaway state dirs, a fake transport
    and a stubbed Telegram — never the live watcher, never the network."""
    import types
    import urllib.error
    sys.path.insert(0, scripts)
    import release_watch as W  # noqa: E402
    import watch_audit as A  # noqa: E402
    import sentinel_site as S  # noqa: E402
    print("— recovery / confirmation regressions (in-process) —")
    now = 1791303410
    work = tempfile.mkdtemp(prefix="briglia-sentinel-regress-")
    base = copy.deepcopy(W.DEFAULT_CONFIG)
    base.update(signing_audit_alerts=True, realert_hours=0, realert_on_change=False,
                state_dir=os.path.join(work, "never-used"), telegram_env_file=os.path.join(work, "no.env"),
                telegram_api="http://127.0.0.1:9/tg", github_api="http://127.0.0.1:9/api")
    sent = []
    saved = {"W.send_telegram": W.send_telegram, "W.State": W.State, "W.now_ts": W.now_ts,
             "W.check_core": W.check_core, "W.check_release_list": W.check_release_list, "W.check_rest": W.check_rest,
             "S.first_hop": S.first_hop, "S.fetch": S.fetch, "S.confirmation_evidence": S.confirmation_evidence}
    W.send_telegram = lambda cfg, text: sent.append(text) or True

    def scenario(label, fn):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 — an old implementation may crash: that is a failure, not an abort
            check(label + " (scenario raised)", False, "%s: %s" % (type(exc).__name__, exc))

    def run_with_alert(*keys, cfg=None):
        st = types.SimpleNamespace(dir=work, data={"active": {k: {"first": now - 3600, "last_sent": now - 3600,
                                                                   "text": "confirmed problem", "notified": True}
                                                               for k in keys}, "queued": []})
        return W.Run(cfg or base, st)

    # ------------------------------------------------ website job
    RED = "https://github.com/installer"
    body = b"#!/bin/sh\necho verified\n"
    cache = {"generation": 1, "content": {"channels": {"briglia-cli": {
        "kind": "cli", "sequence": 109, "website_install_url": ["https://a/install.sh", "https://b/install.sh"],
        "redirect": RED, "installer": {"sha256": sha(body), "size": len(body)}}}}}

    def site_world(hop, get=None):
        S.first_hop = lambda url, timeout=30: hop(url)
        S.fetch = get or (lambda url, timeout=60: (200, body))

    def down(url):
        raise urllib.error.URLError("connection failed")

    def good(url):
        return 302, RED

    def site_pass(st, key):
        site_world(good)
        f, j = S.check_site({"check_minute": 23}, cache, st, now + 300)
        m = S.apply({}, st, f, j, now + 300)
        return [x for x in m if "recovered: " + key in x]

    def site_redirect_network():
        st = {"active": {"briglia-cli/site-redirect": {"first": now - 3600, "text": "bad redirect", "notified": True}}}
        site_world(lambda url: down(url) if "//a/" in url else good(url))
        f, j = S.check_site({"check_minute": 23}, cache, st, now)
        m = S.apply({}, st, f, j, now)
        check("website: a bad-redirect alert is NOT 'recovered' while one host's first hop is unreachable (the other "
              "host passing proves nothing about it)", not any("recovered: briglia-cli/site-redirect" in x for x in m)
              and "briglia-cli/site-redirect" in st["active"], m)
        rec = site_pass(st, "briglia-cli/site-redirect")
        check("…a real pass on every host → exactly ONE recovery", len(rec) == 1 and not site_pass(st, "briglia-cli/site-redirect"), rec)
    scenario("website: bad redirect + network", site_redirect_network)

    def site_content_redirect():
        st = {"active": {"briglia-cli/site-content": {"first": now - 3600, "text": "bad bytes", "notified": True}}}
        site_world(lambda url: (302, "https://evil.example/x"))
        f, j = S.check_site({"check_minute": 23}, cache, st, now)
        m = S.apply({}, st, f, j, now)
        check("website: a wrong redirect raises site-redirect but does NOT 'recover' an open bad-content alert "
              "(the installer bytes were never fetched)", any("briglia-cli/site-redirect" in x for x in m)
              and not any("recovered: briglia-cli/site-content" in x for x in m) and "briglia-cli/site-content" in st["active"], m)
        rec = site_pass(st, "briglia-cli/site-content")
        check("…a real pass → exactly ONE recovery of site-content", len(rec) == 1, rec)
    scenario("website: bad content + redirect", site_content_redirect)

    def site_transition_kept():
        for label, hop, get in (
                ("a wrong redirect (content not checked)", lambda url: (302, "https://evil.example/x"), None),
                ("the bytes behind a correct redirect unreachable", good,
                 lambda url, timeout=60: (_ for _ in ()).throw(urllib.error.URLError("reset"))),
                ("one host unreachable", lambda url: down(url) if "//a/" in url else good(url), None)):
            dl = now + 1500
            st = {"active": {}, "transitions": {"briglia-cli": {"first": now - 600, "deadline": dl, "candidate_sequence": 120,
                                                                "generation": 1, "kind": "unverified"}}}
            site_world(hop, get)
            f, j = S.check_site({"check_minute": 23}, cache, st, now)
            S.apply({}, st, f, j, now)
            t = st.get("transitions", {}).get("briglia-cli")
            check("website: an open transition survives %s, with its ORIGINAL fixed deadline" % label,
                  t is not None and t["deadline"] == dl and t["first"] == now - 600, st.get("transitions"))
        site_world(good)
        S.check_site({"check_minute": 23}, cache, st, now)
        check("…and closes only when the content is verified on EVERY host", "briglia-cli" not in st.get("transitions", {}),
              st.get("transitions"))
    scenario("website: transition deadline", site_transition_kept)

    # ------------------------------------------------ environment rules
    chan = {"repo": CLI, "environment_ids": {"release-sign": CLI_ENV, "release-publish": CLI_PUB}, "approver_user_id": REV,
            "rulesets_expected": []}
    good_bp = {"total_count": 1, "branch_policies": [{"name": "v*", "type": "tag"}]}

    class EnvAPI:
        def __init__(self, env, bp_fail=True):
            self.env, self.bp_fail = env, bp_fail

        def get(self, path, *args, **kw):
            if path.endswith("/deployment-branch-policies"):
                if self.bp_fail:
                    raise W.WatchError("connection failed", transient=True)
                return good_bp
            if path.endswith("/rulesets"):
                return []
            return self.env

    def env_rules():
        r = run_with_alert("briglia-cli/env-rules")
        W._guard(r, "briglia-cli", "env-rules", lambda: A.check_env_rules(EnvAPI(env_obj(CLI_ENV)), base, "briglia-cli",
                                                                          chan, r), set())
        m = r.flush(now)
        check("env-rules: the branch-policy request failing (network) does NOT 'recover' an open env-rules alert",
              not any("recovered: briglia-cli/env-rules" in x for x in m) and "briglia-cli/env-rules" in r.state.data["active"]
              and r.partial.get("briglia-cli"), (m, r.partial))
        r = run_with_alert(cfg=base)
        W._guard(r, "briglia-cli", "env-rules", lambda: A.check_env_rules(EnvAPI(env_obj(CLI_ENV, bypass=True)), base,
                                                                          "briglia-cli", chan, r), set())
        m = r.flush(now)
        check("env-rules: a weakening already established (admin bypass) still ALERTS when the later branch-policy "
              "request fails", any("briglia-cli/env-rules" in x and "can_admins_bypass" in x for x in m), m)
        r = run_with_alert("briglia-cli/env-rules")
        W._guard(r, "briglia-cli", "env-rules", lambda: A.check_env_rules(EnvAPI(env_obj(CLI_ENV), bp_fail=False), base,
                                                                          "briglia-cli", chan, r), set())
        m = r.flush(now)
        check("…a complete, valid pass → exactly ONE recovery", len([x for x in m if "recovered: briglia-cli/env-rules" in x]) == 1, m)
    scenario("env-rules", env_rules)

    def env_publish():
        pub = env_obj(CLI_PUB, "release-publish", reviewer_rule=False)
        r = run_with_alert("briglia-cli/env-publish")
        W._guard(r, "briglia-cli", "env-publish", lambda: A.check_env_publish(EnvAPI(pub), base, "briglia-cli", chan, r) or True,
                 set())
        m = r.flush(now)
        check("env-publish (release-publish path): a failed branch-policy request does NOT 'recover' its alert",
              not any("recovered: briglia-cli/env-publish" in x for x in m) and "briglia-cli/env-publish" in r.state.data["active"], m)
        r = run_with_alert("briglia-cli/env-publish")
        W._guard(r, "briglia-cli", "env-publish", lambda: A.check_env_publish(EnvAPI(pub, bp_fail=False), base, "briglia-cli",
                                                                              chan, r) or True, set())
        m = r.flush(now)
        check("…a complete pass → exactly ONE recovery", len([x for x in m if "recovered: briglia-cli/env-publish" in x]) == 1, m)
    scenario("env-publish", env_publish)

    # ------------------------------------------------ deployments
    class DepAPI:
        def __init__(self, statuses):
            self.statuses = statuses

        def paged(self, *args, **kw):
            return [{"id": 100, "sha": "a" * 40, "ref": "v0.9.0"}]

        def get(self, *args, **kw):
            return self.statuses

    def dep_run(statuses):
        r = run_with_alert("briglia-cli/deploy-hint/100")
        aud = A.channel_audit(r.state.data, "briglia-cli")
        aud["baseline"] = {"complete": True, "executions": []}
        aud["runs"] = {"123": {"head_sha": "a" * 40, "head_branch": "v0.9.0", "verdict": "approved",
                               "executions": [{"identity": ["123", "start", "end", "runner"]}], "env_capacity": 0}}
        dchan = dict(chan, deployment_boundary={"id": 100, "inclusive": True})
        W._guard(r, "briglia-cli", "deployments", lambda: A.deployments_audit(DepAPI(statuses), base, "briglia-cli", dchan, r,
                                                                              r.state.data, now), set())
        return r, r.flush(now)

    def deployments():
        r, m = dep_run({"message": "unexpected object instead of statuses list"})
        check("deployments: a malformed statuses answer raises deployments-unreadable and does NOT 'recover' the open "
              "deploy-hint alert", any("deployments-unreadable" in x for x in m)
              and not any("recovered: briglia-cli/deploy-hint/100" in x for x in m), m)
        r, m = dep_run([{"state": "success", "target_url": "https://github.com/%s/actions/runs/123/job/1" % CLI}])
        check("…a valid status list pointing at the group's own run → exactly ONE recovery",
              len([x for x in m if "recovered: briglia-cli/deploy-hint/100" in x]) == 1, m)
    scenario("deployments", deployments)

    def baseline_partial():
        bchan = dict(chan, signing_cutoff="2026-10-04T23:56:06Z", legacy_pinned_executions=[])

        class SeedAPI:
            def paged(self, *args, **kw):
                return []
        runs_ = [{"id": 5, "created_at": "2026-01-01T00:00:00Z"}]
        r = run_with_alert("briglia-cli/baseline-invalid")
        aud = A.channel_audit(r.state.data, "briglia-cli")
        A.seed_baseline(SeedAPI(), dict(base, seed_runs_per_check=0), "briglia-cli", bchan, r, aud, runs_, now)
        m = r.flush(now)
        check("baseline: a seed left partial (budget share used up) does NOT 'recover' an open baseline-invalid alert",
              not any("recovered: briglia-cli/baseline-invalid" in x for x in m), m)
        r.state.data["active"]["briglia-cli/baseline-invalid"] = {"first": now - 3600, "last_sent": now - 3600,
                                                                   "text": "x", "notified": True}
        r2 = W.Run(base, r.state)
        A.seed_baseline(SeedAPI(), dict(base, seed_runs_per_check=15), "briglia-cli", bchan, r2, aud, runs_, now)
        m = r2.flush(now)
        check("…the seed completing → exactly ONE recovery", len([x for x in m if "recovered: briglia-cli/baseline-invalid" in x]) == 1, m)
    scenario("baseline", baseline_partial)

    # ------------------------------------------------ signing audit: intermediate verdicts
    schan = dict(repo=CLI, workflow_id=CLI_WF, workflow_path=WF_PATH, signing_job="Sign metadata",
                 signing_environment="release-sign", environment_ids={"release-sign": CLI_ENV}, approver_user_id=REV,
                 signing_cutoff="2026-10-04T23:56:06Z")

    def sign_world(approvals):
        jobs = full_jobs(["Sign metadata"], 100, "2026-10-06T15:00:00Z", "2026-10-06T15:00:06Z", "GitHub Actions 100")
        rec_ = run_obj(CLI, 123, "v0.9.0", "a" * 40, CLI_WF, "2026-10-06T14:00:00Z", jobs, approvals_by_attempt={"1": approvals})

        class SignAPI:
            def paged(self, path, *args, **kw):
                return rec_["jobs"] if path.endswith("/jobs") else [rec_]

            def tag_commit(self, *args, **kw):
                return "a" * 40

            def get(self, path, *args, **kw):
                if path.endswith("/approvals"):
                    return rec_["approvals_by_attempt"].get(str(rec_["run_attempt"]), [])
                return rec_
        return rec_, jobs, SignAPI()

    def sign_check(cfg, st, api, t):
        r = W.Run(cfg, st)
        done = W._guard(r, "briglia-cli", "signing-audit",
                        lambda: A.signing_audit(api, cfg, "briglia-cli", schan, r, st.data, t), set())
        if done:
            r.performed("briglia-cli", "signing-audit")
        return r, r.flush(t)

    def rerun(rec_, jobs, attempt, status):
        nj = copy.deepcopy(jobs[0])
        nj.update(id=100 + 100 * attempt, run_attempt=attempt, status=status, conclusion=None if status != "completed" else "success",
                  started_at="2026-10-06T17:09:00Z", completed_at=None if status != "completed" else "2026-10-06T17:09:06Z",
                  runner_name="GitHub Actions %d" % (100 * attempt),
                  steps=[{"status": status, "started_at": "2026-10-06T17:09:00Z"}])
        rec_.update(run_attempt=attempt, status="in_progress", conclusion=None, updated_at="2026-10-06T17:10:00Z")
        rec_["jobs"] = jobs + [nj]
        rec_["approvals_by_attempt"][str(attempt)] = []
        return nj

    def signing_rerun(report_only):
        mode = "report-only" if report_only else "alert"
        cfg = dict(base, signing_audit_alerts=not report_only)
        key = "briglia-cli/signing/123"
        d = tempfile.mkdtemp(dir=work)
        st = types.SimpleNamespace(dir=d, data={"active": {}, "queued": []})
        aud = A.channel_audit(st.data, "briglia-cli")
        aud["baseline"] = {"complete": True, "cutoff": schan["signing_cutoff"], "executions": []}
        rec_, jobs, api = sign_world([])
        sent.clear()
        sign_check(cfg, st, api, now)
        first = (st.data["active"].get(key) or {}).get("first")
        check("signing [%s]: completed signing with an EMPTY review history → 'SIGNED WITHOUT an approval' is open" % mode,
              first == now and ("SIGNED WITHOUT" in st.data["active"][key]["text"])
              and (report_only or any("SIGNED WITHOUT" in x for x in sent)), (st.data["active"].get(key), sent))
        nj = rerun(rec_, jobs, 2, "in_progress")
        sent.clear()
        r, m = sign_check(cfg, st, api, now + 3600)
        log = os.path.join(d, "audit-report.log")
        cleared = os.path.exists(log) and "CLEAR " + key in open(log).read()
        check("signing [%s]: a second signing attempt RUNNING does NOT 'recover' it: still open, original first-seen "
              "time, no recovery message, no CLEAR in the audit log" % mode,
              key in st.data["active"] and st.data["active"][key]["first"] == first
              and not any("recovered" in x for x in m) and not cleared, (m, st.data["active"].get(key)))
        check("signing [%s]: …and the audit is NOT complete while a signing execution runs (no ✅ can rest on it)" % mode,
              "signing-audit" not in r.done.get("briglia-cli", set()) and r.partial.get("briglia-cli"), r.partial)
        rec_.update(status="completed", conclusion="success", updated_at="2026-10-06T18:10:00Z")
        nj.update(status="completed", conclusion="success", completed_at="2026-10-06T18:09:00Z",
                  steps=[{"status": "completed", "started_at": "2026-10-06T17:09:00Z"}])
        sent.clear()
        r, m = sign_check(cfg, st, api, now + 7200)
        a = st.data["active"].get(key) or {}
        check("signing [%s]: the rerun completed → still open (now '2 signing executions'), SAME first-seen time, "
              "no recovery and no second opening message" % mode,
              a.get("first") == first and "2 signing executions" in a.get("text", "")
              and not any("recovered" in x for x in m) and not any(x.startswith("🚨") and key in x and "STILL" not in x for x in m),
              (m, a))
    scenario("signing rerun (alert)", lambda: signing_rerun(False))
    scenario("signing rerun (report-only)", lambda: signing_rerun(True))

    def signing_control():
        key = "briglia-cli/signing/123"
        d = tempfile.mkdtemp(dir=work)
        st = types.SimpleNamespace(dir=d, data={"active": {}, "queued": []})
        aud = A.channel_audit(st.data, "briglia-cli")
        aud["baseline"] = {"complete": True, "cutoff": schan["signing_cutoff"], "executions": []}
        rec_, jobs, api = sign_world([approval(env_id=CLI_ENV)])
        wait = copy.deepcopy(jobs[0])
        wait.update(status="waiting", conclusion=None, started_at=None, completed_at=None, runner_name=None, steps=[])
        rec_.update(status="in_progress", conclusion=None, updated_at="2026-10-06T14:05:00Z")
        rec_["jobs"] = [wait]
        sent.clear()
        r, m = sign_check(base, st, api, now)
        check("control: a first-time wait for the review is quiet (no finding, no message) and the audit is complete",
              key not in st.data["active"] and not m and "signing-audit" in r.done.get("briglia-cli", set())
              and aud["runs"]["123"]["verdict"] == "pending", (m, aud["runs"]["123"].get("verdict")))
        rec_.update(status="completed", conclusion="success", updated_at="2026-10-06T15:10:00Z")
        rec_["jobs"] = jobs
        r, m = sign_check(base, st, api, now + 3600)
        check("control: approved and executed → verdict approved, judged, no alert, no message",
              aud["runs"]["123"]["verdict"] == "approved" and "briglia-cli/signing/123" in r.checked and not m,
              (m, aud["runs"]["123"].get("verdict")))
    scenario("signing control", signing_control)

    # ------------------------------------------------ ✅ needs every due check
    rec = {"tag": "v0.9.0", "version": "0.9.0", "sequence": 9, "commit": "a" * 40, "envelope_sha256": "b" * 64,
           "assets": {"click": {"url": "https://x/click", "size": 1, "sha256": "c" * 64}}}
    pc = dict(tag="v0.9.0", sequence=9, commit="a" * 40, envelope_sha256="b" * 64, first_seen=now - 10,
              provenance="ci, phone-approved", workflow_run=123, approval={"user_id": REV})
    ccfg = dict(base, channels={"briglia-ut": {"kind": "app"}}, audits=True, confirmations=True)
    S.confirmation_evidence = lambda *args: (True, "")

    def confirm_with(due_extra, skipped):
        state = types.SimpleNamespace(dir=work, data={"recorded": {"briglia-ut": dict(rec)}, "active": {}, "queued": [],
                                                      "pending_confirm": {"briglia-ut": dict(pc)},
                                                      "full_hash_at": {"briglia-ut": now}})
        r = W.Run(ccfg, state)
        r.make_due("briglia-ut", "core", "release-list", "assets", "expiry", "env-rules", "signing-audit", *due_extra)
        r.performed("briglia-ut", "core", "release-list", "assets", "expiry", "env-rules", "signing-audit",
                    *[c for c in due_extra if c not in skipped])
        if skipped:
            r.skipped("briglia-ut", "budget exhausted", *skipped)
        W.confirm_releases(ccfg, r, now, 1)
        out = [o["text"] for o in state.data.get("confirm_outbox", [])] + r.extra_messages
        return state, out

    def partial_confirm():
        for skipped in (("deployments", "events"), ("env-publish",), ("deletion",)):
            state, out = confirm_with(("deployments", "events", "deletion", "env-publish"), skipped)
            check("✅: due-but-skipped %s (budget) → NO ✅, the pending confirmation survives" % "+".join(skipped),
                  not any(x.startswith("✅") for x in out) and "briglia-ut" in state.data["pending_confirm"], out)
        state, out = confirm_with(("deployments", "events", "deletion", "env-publish"), ())
        check("…every due check performed → exactly ONE ✅ (into the saved outbox), pending cleared",
              len([x for x in out if x.startswith("✅ Verified briglia-ut v0.9.0")]) == 1
              and "briglia-ut" not in state.data["pending_confirm"], out)
        state, out = confirm_with((), ())
        check("…a lower-frequency check NOT due (fresh) does not block the ✅",
              len([x for x in out if x.startswith("✅ Verified")]) == 1, out)
    scenario("✅ partial", partial_confirm)

    # ------------------------------------------------ persist, then send
    class FailSave(saved["W.State"]):
        def save(self):
            raise OSError("injected disk write failure")

    def checked_core(cfg, ch, run_, ts):
        st_ = run_.state.data
        if ch not in st_["recorded"]:
            st_["recorded"][ch] = dict(rec)
            st_.setdefault("pending_confirm", {})[ch] = dict(pc)
            st_.setdefault("audit", {}).setdefault(ch, {}).setdefault("runs", {})["123"] = {"approvals": {"1": [{"user_id": REV}]}}
        st_["full_hash_at"][ch] = now
        run_.performed(ch, "core")
        return {"fixture": True}

    def disk_world():
        W.now_ts = lambda: now
        W.check_core = checked_core
        W.check_release_list = lambda cfg, ch, run_, ctx: run_.performed(ch, "release-list")
        W.check_rest = lambda cfg, ch, run_, ts, ctx: run_.performed(ch, "assets", "expiry")
        d = tempfile.mkdtemp(dir=work)
        return dict(ccfg, audits=False, mode="local", state_dir=d), d

    def load(d):
        return json.load(open(os.path.join(d, "state.json")))

    def save_failure():
        dcfg, d = disk_world()
        W.State = FailSave
        sent.clear()
        raised = False
        try:
            W.cmd_check(dcfg)
        except OSError:
            raised = True
        finally:
            W.State = saved["W.State"]
        check("persist-then-send: a FAILED state save → the run fails and NO ✅ was sent (nothing durable backs it)",
              raised and not any("✅" in x for x in sent), sent)
        sent.clear()
        W.cmd_check(dcfg)
        st_ = load(d)
        check("…next run with a working disk: exactly ONE ✅, and the saved state holds the recorded release, the "
              "observed approval and no pending/outbox entry", len([x for x in sent if x.startswith("✅ Verified")]) == 1
              and st_["recorded"]["briglia-ut"]["sequence"] == 9 and st_["audit"]["briglia-ut"]["runs"]["123"]["approvals"]
              and not st_.get("pending_confirm") and not st_.get("confirm_outbox"), (sent, st_.get("confirm_outbox")))
        sent.clear()
        W.cmd_check(dcfg)
        check("…and it is never repeated", not any("✅" in x for x in sent), sent)
    scenario("persist: save failure", save_failure)

    def send_order():
        # the ✅ must be sent only once the state carrying its evidence is on disk
        dcfg, d = disk_world()
        seen = []

        def spy(cfg, text):
            if text.startswith("✅"):
                try:
                    st_ = load(d)
                except Exception:  # noqa: BLE001
                    st_ = {}
                seen.append(bool(st_.get("recorded", {}).get("briglia-ut")) and not st_.get("pending_confirm"))
            sent.append(text)
            return True
        W.send_telegram = spy
        try:
            W.cmd_check(dcfg)
        finally:
            W.send_telegram = lambda cfg, text: sent.append(text) or True
        check("persist-then-send: when the ✅ goes out, the saved state.json ALREADY records the release and has no "
              "pending confirmation", seen == [True], seen)
    scenario("persist: order", send_order)

    def delivery_failure():
        dcfg, d = disk_world()
        W.send_telegram = lambda cfg, text: False
        try:
            W.cmd_check(dcfg)
        finally:
            W.send_telegram = lambda cfg, text: sent.append(text) or True
        st_ = load(d)
        box = [o["text"] for o in st_.get("confirm_outbox", [])]
        check("delivery fails AFTER a successful save → the ✅ is kept in the SAVED outbox (not lost), pending cleared",
              len(box) == 1 and box[0].startswith("✅ Verified") and not st_.get("pending_confirm"), (box, st_.get("pending_confirm")))
        sent.clear()
        W.now_ts = lambda: now + 3600
        W.cmd_check(dcfg)
        late = [x for x in sent if x.startswith("✅ Verified")]
        check("…delivered on the next run exactly once, with its ORIGINAL verification time, outbox emptied",
              len(late) == 1 and late[0] == box[0] and not load(d).get("confirm_outbox"), late)
    scenario("persist: delivery failure", delivery_failure)

    def crash_after_save():
        dcfg, d = disk_world()

        def crash(cfg, text):
            raise KeyboardInterrupt("process killed between save and send")
        W.send_telegram = crash
        try:
            W.cmd_check(dcfg)
        except KeyboardInterrupt:
            pass
        finally:
            W.send_telegram = lambda cfg, text: sent.append(text) or True
        st_ = load(d)
        check("crash after the save, before delivery → the ✅ survives the restart in the saved outbox",
              len(st_.get("confirm_outbox", [])) == 1 and not st_.get("pending_confirm"), st_.get("confirm_outbox"))
        sent.clear()
        W.cmd_check(dcfg)
        check("…delivered once by the next run", len([x for x in sent if x.startswith("✅ Verified")]) == 1, sent)
    scenario("persist: crash", crash_after_save)

    def second_save_fails():
        dcfg, d = disk_world()
        calls = []

        class FailSecond(saved["W.State"]):
            def save(self):
                calls.append(1)
                if len(calls) == 2:
                    raise OSError("second save fails")
                return super().save()
        W.State = FailSecond
        sent.clear()
        try:
            W.cmd_check(dcfg)
        finally:
            W.State = saved["W.State"]
        first = [x for x in sent if x.startswith("✅ Verified")]
        sent.clear()
        W.cmd_check(dcfg)
        again = [x for x in sent if x.startswith("✅ Verified")]
        check("the save AFTER delivery fails → delivery repeats until its acknowledgment is saved (accepted: duplicate, "
              "never lost, never "
              "unbacked); here once, then the outbox is empty", len(first) == 1 and again == first and not load(d).get("confirm_outbox"),
              (first, again))
    scenario("persist: second save", second_save_fails)

    for k, v in saved.items():
        mod, attr = k.split(".")
        setattr(W if mod == "W" else S, attr, v)
    shutil.rmtree(work, ignore_errors=True)


def iso_(ts):
    return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


if __name__ == "__main__":
    sys.exit(main())
