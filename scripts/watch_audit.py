#!/usr/bin/env python3
"""GitHub-history audits for scripts/release_watch.py (off-Mac watcher plan §4.1–4.3).

Imported by release_watch.py only. Every GitHub call goes through the `api`
object the checker hands in (budget guard, retries, remote mode without
credentials); nothing here talks to the network on its own, and nothing
here spawns a process.

  * environment rules  — `release-sign` (hourly) and `release-publish` +
    rulesets (every 6 h), compared as normalized sets and stable ids;
  * signing audit      — every run of the pinned release workflow, re-
    validated whenever its GitHub-generated fingerprint changes: each
    signing EXECUTION (identity: run id, started_at, completed_at, runner)
    needs exactly one approval by the pinned reviewer id for the pinned
    environment id in the run's review history, observed while the run was
    in attempt 1; the fixed per-channel legacy baseline exempts pre-gate
    executions only;
  * deployments        — `release-sign` deployments used as discovery
    pointers only: a count per (sha, ref) against the unique signing
    instances of the pinned workflow (a consistency check, never proof);
  * event feed         — supplemental: unconfirmed releases, tag deletions,
    non-v<semver> tags.

Rehearsal evidence (public throwaway repo, 2026-10-06) that shapes the
rules below:
  * a job waiting for review: status "waiting", runner_name null, steps [];
  * rejected at review: completed/failure, runner_name "", steps [];
  * cancelled while waiting: completed/cancelled, runner_name "", steps [];
  * skipped (dependency failed / never reached): completed/skipped,
    runner_name null, steps [];
  * every re-run form (whole run, failed jobs, single job) raises
    run_attempt and updated_at;
  * a re-run REPLACES the run's review history: GET …/approvals afterwards
    lists only the reviews of the newest attempt. Approval evidence is
    therefore recorded per attempt at the time it is observed, and an
    attempt-1 history that was never observed cannot be reconstructed.
"""

import datetime
import re

TAG_RE = re.compile(r"^v\d+\.\d+\.\d+$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
PENDING_STATUSES = ("queued", "waiting", "pending")
PENDING_INFO_AFTER = 48 * 3600
EXPECTED_SIGN_RULES = {"required_reviewers", "branch_policy"}


class BudgetStop(Exception):
    """Raised by the checker's api when the GitHub request budget is spent.
    (release_watch.py defines its own subclass; this is the base it catches.)"""


def parse_ts(value):
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=datetime.timezone.utc).timestamp()
    except ValueError:
        return None


def _int(v):
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def _short(sha):
    return str(sha)[:12]


def channel_audit(st, channel):
    aud = st.setdefault("audit", {}).setdefault(channel, {})
    aud.setdefault("runs", {})
    aud.setdefault("deployments", {})
    aud.setdefault("anomalies", {})
    aud.setdefault("event_findings", {})
    aud.setdefault("event_releases", {})
    return aud


# ------------------------------------------------------------ §4.1 env rules

def _reviewer_set(rule):
    out = set()
    for r in rule.get("reviewers") or []:
        if not isinstance(r, dict) or not isinstance(r.get("reviewer"), dict):
            raise ValueError("reviewer entry has an unexpected shape")
        out.add((r.get("type"), _int(r["reviewer"].get("id"))))
    return out


def _branch_policies(api, repo, env_name, priority):
    bp = api.get("/repos/%s/environments/%s/deployment-branch-policies" % (repo, env_name),
                  {"per_page": 100}, priority=priority)
    if not isinstance(bp, dict) or not isinstance(bp.get("branch_policies"), list):
        raise ValueError("branch policies answer has an unexpected shape")
    if _int(bp.get("total_count")) != len(bp["branch_policies"]):
        raise ValueError("branch policies list is incomplete (total_count %r, listed %d)"
                         % (bp.get("total_count"), len(bp["branch_policies"])))
    return {(p.get("name"), p.get("type")) for p in bp["branch_policies"] if isinstance(p, dict)}, \
        len(bp["branch_policies"])


def check_env_rules(api, cfg, channel, chan, run):
    """release-sign rules (hourly). A confirmed 404 is an integrity alert; a
    fetch failure raises to the caller (not checked, never 'missing')."""
    repo = chan["repo"]
    env_name = chan.get("signing_environment") or "release-sign"
    want_id = _int((chan.get("environment_ids") or {}).get(env_name))
    want_reviewer = _int(chan.get("approver_user_id"))
    key, drift_key = channel + "/env-rules", channel + "/env-drift"
    env = api.get("/repos/%s/environments/%s" % (repo, env_name), priority=1, allow_404=True)
    run.judged(key, drift_key)
    if env is None:
        run.alert(key, "environment %s does not exist (confirmed 404) — the signing gate is gone" % env_name)
        return
    problems, drift = [], []
    try:
        if not isinstance(env, dict):
            raise ValueError("environment answer is not an object")
        if want_id is None or _int(env.get("id")) != want_id:
            problems.append("environment id %r ≠ pinned %r (recreated environment)" % (env.get("id"), want_id))
        if env.get("can_admins_bypass") is not False:
            problems.append("can_admins_bypass is %r (admins may deploy without review)" % env.get("can_admins_bypass"))
        rules = env.get("protection_rules")
        if not isinstance(rules, list) or any(not isinstance(r, dict) for r in rules):
            raise ValueError("protection_rules has an unexpected shape")
        types = [r.get("type") for r in rules]
        extra = sorted({str(t) for t in types} - EXPECTED_SIGN_RULES)
        if extra:
            drift.append("unexpected protection rule type(s) %s (configuration drift)" % ", ".join(extra))
        rev = [r for r in rules if r.get("type") == "required_reviewers"]
        if len(rev) != 1:
            problems.append("%d required_reviewers rule(s), expected exactly 1" % len(rev))
        else:
            got = _reviewer_set(rev[0])
            if want_reviewer is None or got != {("User", want_reviewer)}:
                problems.append("reviewers are %s, expected exactly User id %r" % (
                    sorted(got, key=str) or "none", want_reviewer))
            if rev[0].get("prevent_self_review") is not True:
                problems.append("prevent_self_review is %r" % rev[0].get("prevent_self_review"))
        if types.count("branch_policy") != 1:
            problems.append("%d branch_policy rule(s), expected exactly 1" % types.count("branch_policy"))
        dbp = env.get("deployment_branch_policy")
        if dbp != {"protected_branches": False, "custom_branch_policies": True}:
            problems.append("deployment_branch_policy is %r, expected custom policies only" % (dbp,))
        else:
            pols, _ = _branch_policies(api, repo, env_name, 1)
            if pols != {("v*", "tag")}:
                problems.append("branch policies are %s, expected exactly (v*, tag)" % sorted(pols, key=str))
    except ValueError as exc:
        problems.append("unreadable answer: %s" % exc)
    if problems:
        run.alert(key, "%s on %s is WEAKER than pinned: %s" % (env_name, repo, "; ".join(problems)))
    if drift:
        run.alert(drift_key, "%s on %s: %s — reported as drift, not as a weakening" % (env_name, repo, "; ".join(drift)))
    if not problems and not drift:
        run.ok("%s rules match the pinned expectation (env id, one reviewer id, no bypass, self-review blocked, v* tags)" % env_name)


def check_env_publish(api, cfg, channel, chan, run):
    """release-publish rules and rulesets (every 6 h)."""
    repo = chan["repo"]
    key, rs_key = channel + "/env-publish", channel + "/rulesets"
    want_id = _int((chan.get("environment_ids") or {}).get("release-publish"))
    env = api.get("/repos/%s/environments/release-publish" % repo, priority=7, allow_404=True)
    rulesets = api.get("/repos/%s/rulesets" % repo, {"per_page": 100}, priority=7)
    run.judged(key, rs_key)
    problems = []
    if env is None:
        problems.append("environment release-publish does not exist (confirmed 404)")
    else:
        try:
            if want_id is None or _int(env.get("id")) != want_id:
                problems.append("environment id %r ≠ pinned %r" % (env.get("id"), want_id))
            if env.get("can_admins_bypass") is not False:
                problems.append("can_admins_bypass is %r" % env.get("can_admins_bypass"))
            rules = env.get("protection_rules")
            if not isinstance(rules, list) or [r.get("type") for r in rules if isinstance(r, dict)].count("branch_policy") != 1:
                problems.append("no single branch_policy rule")
            if env.get("deployment_branch_policy") != {"protected_branches": False, "custom_branch_policies": True}:
                problems.append("deployment_branch_policy is %r" % (env.get("deployment_branch_policy"),))
            else:
                pols, _ = _branch_policies(api, repo, "release-publish", 7)
                if pols != {("v*", "tag")}:
                    problems.append("branch policies are %s" % sorted(pols, key=str))
        except ValueError as exc:
            problems.append("unreadable answer: %s" % exc)
    if problems:
        run.alert(key, "release-publish on %s differs from the pinned rules: %s" % (repo, "; ".join(problems)))
    want = set(chan.get("rulesets_expected") or [])
    got = {r.get("name") for r in rulesets if isinstance(r, dict) and r.get("enforcement") == "active"} \
        if isinstance(rulesets, list) else set()
    if want - got:
        run.alert(rs_key, "informational: active ruleset(s) missing on %s: %s" % (repo, ", ".join(sorted(want - got))))
    if not problems and not (want - got):
        run.ok("release-publish rules and rulesets as pinned")


# ---------------------------------------------------- §4.2 signing executions

def compact_record(j):
    """The fields the audit judges, keeping the difference between a missing
    key and an empty value (a missing key is never 'no runner')."""
    out = {k: j.get(k) for k in ("id", "name", "run_attempt", "status", "conclusion", "started_at", "completed_at")}
    if "runner_name" in j:
        out["runner_name"] = j["runner_name"]
    steps = j.get("steps", "<missing>") if "steps" in j else "<missing>"
    if isinstance(steps, list):
        out["steps"] = [{"status": s.get("status"), "started_at": s.get("started_at")} if isinstance(s, dict) else "<bad>"
                        for s in steps]
    else:
        out["steps"] = "<missing>" if steps == "<missing>" else "<bad>"
    return out


def classify(rec):
    """→ (kind, why). kind ∈ pending | skipped | ended | executed | executing | malformed.

    'Not executed' needs the documented empty values to be PRESENT: the
    runner_name key present and null/"" and a steps list in which no step
    has started. Any missing key or wrong type is malformed (unverified)."""
    if not isinstance(rec, dict):
        return "malformed", "record is not an object"
    if "runner_name" not in rec:
        return "malformed", "runner_name key is missing"
    runner = rec["runner_name"]
    if runner is not None and not isinstance(runner, str):
        return "malformed", "runner_name has an unexpected type"
    steps = rec.get("steps")
    if not isinstance(steps, list):
        return "malformed", "steps are missing or not a list"
    status, conclusion = rec.get("status"), rec.get("conclusion")
    if not isinstance(status, str):
        return "malformed", "status missing"
    started_step = any(not isinstance(s, dict) or s.get("started_at") or s.get("status") not in ("queued", "pending")
                       for s in steps)
    if runner in (None, "") and not started_step:
        if status in PENDING_STATUSES:
            return "pending", ""
        if status == "completed" and conclusion == "skipped":
            return "skipped", ""
        if status == "completed" and conclusion in ("failure", "cancelled"):
            # rehearsal: rejected at review / cancelled while waiting
            return "ended", conclusion
        return "malformed", "no runner and no step, but status %r / conclusion %r" % (status, conclusion)
    if status == "completed":
        return "executed", ""
    if status == "in_progress":
        return "executing", ""
    return "malformed", "ran on a runner but status is %r" % status


def identity(run_id, rec):
    ident = (run_id, rec.get("started_at"), rec.get("completed_at"), rec.get("runner_name"))
    return ident if all(isinstance(x, str) and x for x in ident[1:]) else None


def fingerprint(r):
    return [r.get("run_attempt"), r.get("status"), r.get("conclusion"), r.get("updated_at")]


def _env_entries(approvals, env_id):
    """Review-history entries for env_id, compacted; ValueError on any odd shape."""
    if not isinstance(approvals, list):
        raise ValueError("the review history is not a list")
    out = []
    for a in approvals:
        if not isinstance(a, dict) or not isinstance(a.get("environments"), list) \
                or not isinstance(a.get("user"), dict) or not isinstance(a.get("state"), str):
            raise ValueError("a review-history entry has an unexpected shape")
        ids = [_int(e.get("id")) if isinstance(e, dict) else None for e in a["environments"]]
        if None in ids:
            raise ValueError("a review-history environment has no id")
        if env_id in ids:
            out.append({"state": a["state"], "user_id": _int(a["user"].get("id")), "login": a["user"].get("login")})
    return out


def baseline_identities(aud):
    b = aud.get("baseline") or {}
    if not b.get("complete"):
        return None
    return {tuple(x) for x in b.get("executions", [])}


def validate_run(api, cfg, chan, r, aud, now, fetch_jobs=True):
    """Full validation of one pinned-workflow run (plan §4.2 steps 1–7).

    Returns a dict with `verdict` ∈ approved | legacy | pending | executing |
    settled-unexecuted | unverified | reopen, `reason`, and the evidence
    (executions, pending attempt, review-reached capacity). Budget/network
    errors propagate (the obligation stays open); everything else that is
    odd is 'unverified', never success and never 'not executed'."""
    repo = chan["repo"]
    sign_name = chan.get("signing_job") or ""
    env_name = chan.get("signing_environment") or "release-sign"
    env_id = _int((chan.get("environment_ids") or {}).get(env_name))
    want_reviewer = _int(chan.get("approver_user_id"))
    rid = _int(r.get("id"))
    res = {"verdict": "unverified", "reason": "", "executions": [], "pending_attempt": None, "env_capacity": 0,
           "fp": fingerprint(r), "head_sha": r.get("head_sha"), "head_branch": r.get("head_branch"),
           "created_at": r.get("created_at"), "approval": None}

    def bad(reason):
        res["verdict"], res["reason"] = "unverified", reason
        return res

    # 1. identity of the run itself
    problems = []
    if rid is None:
        problems.append("run has no id")
    if (r.get("repository") or {}).get("full_name") != repo:
        problems.append("repository %r" % (r.get("repository") or {}).get("full_name"))
    if r.get("path") != chan.get("workflow_path"):
        problems.append("workflow path %r" % r.get("path"))
    if _int(r.get("workflow_id")) != _int(chan.get("workflow_id")):
        problems.append("workflow id %r" % r.get("workflow_id"))
    if r.get("event") != "push":
        problems.append("event %r (only tag pushes run the release)" % r.get("event"))
    if not isinstance(r.get("head_branch"), str) or not TAG_RE.match(r["head_branch"]):
        problems.append("ref %r is not a v<semver> tag" % r.get("head_branch"))
    if not isinstance(r.get("head_sha"), str) or not SHA_RE.match(r["head_sha"]):
        problems.append("head_sha malformed")
    attempt_now = _int(r.get("run_attempt"))
    if attempt_now is None or attempt_now < 1:
        problems.append("run_attempt %r" % r.get("run_attempt"))
    if problems:
        return bad("run %s does not match the pinned release workflow: %s" % (rid, "; ".join(problems)))

    # 2. the tag still names the run's commit
    commit = api.tag_commit(repo, r["head_branch"], priority=3)
    if commit is None:
        return bad("tag %s was deleted (run %d signed %s)" % (r["head_branch"], rid, _short(r["head_sha"])))
    if commit != r["head_sha"]:
        return bad("tag %s moved: now %s, the run built %s" % (r["head_branch"], _short(commit), _short(r["head_sha"])))

    # 3. every job record of the run (all attempts, every page)
    rs = aud["runs"].get(str(rid)) or {}
    cache = rs.get("sig_cache")
    if not fetch_jobs and cache and cache.get("fp") == res["fp"]:
        records = cache["records"]
    else:
        try:
            jobs = api.paged("/repos/%s/actions/runs/%d/jobs" % (repo, rid), "jobs", {"filter": "all"}, priority=3)
        except ValueError as exc:
            return bad("job list of run %d unreadable: %s" % (rid, exc))
        records = [compact_record(j) for j in jobs if isinstance(j, dict) and j.get("name") == sign_name]
        if any(not isinstance(j, dict) for j in jobs):
            return bad("job list of run %d holds a malformed record" % rid)
        res["sig_cache"] = {"fp": res["fp"], "records": records}
    if any(_int(x.get("run_attempt")) is None or _int(x["run_attempt"]) > attempt_now for x in records):
        res["verdict"] = "reopen"
        res["reason"] = "the run changed while its jobs were read"
        return res
    if not records:
        return bad("run %d has no record of the signing job '%s' — cannot tell whether it signed" % (rid, sign_name))

    # 4–5. classify; unique executions by GitHub-generated identity
    completed = r.get("status") == "completed"
    executions, executing, pending, ended = {}, [], [], []
    for rec in records:
        kind, why = classify(rec)
        if kind == "malformed":
            return bad("signing record %s of run %d is malformed (%s)" % (rec.get("id"), rid, why))
        if kind == "pending":
            if completed:
                return bad("run %d is completed but its signing record %s is still %s" % (rid, rec.get("id"), rec.get("status")))
            pending.append(rec)
        elif kind == "ended":
            ended.append(rec)
        elif kind == "executing":
            if completed:
                return bad("run %d is completed but its signing job is still in progress" % rid)
            executing.append(rec)
        elif kind == "executed":
            ident = identity(str(rid), rec)
            if ident is None:
                return bad("an executed signing record of run %d lacks started_at/completed_at/runner_name" % rid)
            executions.setdefault(ident, []).append(rec)
    execs = []
    for ident, recs in executions.items():
        first = min(recs, key=lambda x: (_int(x.get("run_attempt")) or 0, _int(x.get("id")) or 0))
        if any(x.get("conclusion") != first.get("conclusion") for x in recs):
            return bad("copies of one signing execution of run %d disagree on its conclusion" % rid)
        execs.append({"identity": list(ident), "attempt": _int(first.get("run_attempt")),
                      "conclusion": first.get("conclusion")})
    res["executions"] = execs
    cur = [p for p in pending if _int(p.get("run_attempt")) == attempt_now]
    res["pending_attempt"] = attempt_now if cur else None
    res["pending_job_ids"] = [_int(p.get("id")) for p in cur]

    # review history: observed per attempt (a re-run replaces it)
    obs = {str(k): v for k, v in (rs.get("approvals") or {}).items()}
    need_history = bool(execs) or bool(ended) or bool(executing)
    legacy = baseline_identities(aud)
    # an execution can only be legacy if it started before the cutoff or is
    # one of the explicitly pinned pre-gate executions
    cutoff = parse_ts(chan.get("signing_cutoff"))
    pinned = {(str(p["run_id"]), p["started_at"], p["completed_at"], p["runner_name"])
              for p in chan.get("legacy_pinned_executions") or []}
    candidates = [e for e in execs if tuple(e["identity"]) in pinned
                  or cutoff is None or (parse_ts(e["identity"][1]) or 0) < cutoff]
    if candidates and legacy is None:
        res["verdict"], res["reason"] = "reopen", "legacy baseline not complete yet"
        return res
    all_legacy = bool(execs) and legacy is not None and all(tuple(e["identity"]) in legacy for e in execs) \
        and not executing
    if need_history and not all_legacy:
        if env_id is None:
            return bad("no pinned environment id for %s" % env_name)
        try:
            entries = _env_entries(api.get("/repos/%s/actions/runs/%d/approvals" % (repo, rid), priority=3), env_id)
        except ValueError as exc:
            return bad("review history of run %d: %s" % (rid, exc))
        # bind the history to the attempt it belongs to: re-read the run and
        # refuse to combine two snapshots
        again = api.get("/repos/%s/actions/runs/%d" % (repo, rid), priority=3)
        if not isinstance(again, dict) or fingerprint(again) != res["fp"]:
            res["verdict"], res["reason"] = "reopen", "the run changed while its review history was read"
            return res
        prev = obs.get(str(attempt_now))
        if prev is not None and any(p not in entries for p in prev):
            return bad("the review history of run %d attempt %d lost entries it had when last observed" % (rid, attempt_now))
        obs[str(attempt_now)] = entries
    res["approvals"] = obs

    # capacity for attempts that reached the environment and ended unexecuted:
    # only with lifecycle evidence (observed waiting before, or a rejection in
    # the observed history of that very attempt)
    seen_waiting = set(rs.get("seen_waiting") or [])
    cap_attempts = set()
    for rec in ended:
        att = str(_int(rec.get("run_attempt")))
        rejected_here = any(e["state"] == "rejected" for e in obs.get(att, []))
        if _int(rec.get("id")) in seen_waiting or (rec.get("conclusion") == "failure" and rejected_here):
            cap_attempts.add(att)
    res["env_capacity"] = len(cap_attempts)
    res["seen_waiting"] = sorted(seen_waiting | {i for i in res["pending_job_ids"] if i is not None})

    # 6. nothing executed
    if executing:
        res["verdict"], res["reason"] = "executing", "signing job of run %d is running" % rid
        return res
    if not execs:
        if not completed:
            res["verdict"] = "pending"
            res["reason"] = "run %d (%s) is waiting for the signing review" % (rid, r["head_branch"])
        else:
            res["verdict"] = "settled-unexecuted"
            res["reason"] = "run %d (%s) completed without executing the signing job" % (rid, r["head_branch"])
        return res

    # 7. something executed
    if all_legacy:
        res["verdict"] = "legacy"
        res["reason"] = "legacy provenance (pre-gate), not phone-approved: run %d (%s)" % (rid, r["head_branch"])
        return res
    legacy = legacy or set()
    if len(execs) != 1:
        return bad("%d signing executions in run %d (%s) — one approval cannot cover more than one signing"
                   % (len(execs), rid, r["head_branch"]))
    e = execs[0]
    if tuple(e["identity"]) in legacy:
        res["verdict"], res["reason"] = "legacy", "legacy provenance (pre-gate), not phone-approved: run %d" % rid
        return res
    if e["attempt"] != 1:
        return bad("the signing job of run %d (%s) executed in attempt %r — only attempt-1 signing is covered by an approval"
                   % (rid, r["head_branch"], e["attempt"]))
    hist = obs.get("1")
    if hist is None:
        return bad("run %d (%s) signed in attempt 1, but its attempt-1 review history was never observed before a "
                   "re-run replaced it — approval unverified" % (rid, r["head_branch"]))
    states = sorted({h["state"] for h in hist if h["state"] != "approved"})
    if states:
        return bad("run %d (%s): the review history holds a %s entry for %s" % (rid, r["head_branch"], "/".join(states), env_name))
    approved = [h for h in hist if h["state"] == "approved"]
    if not approved:
        return bad("run %d (%s) SIGNED WITHOUT an approval for %s (id %r) in its review history"
                   % (rid, r["head_branch"], env_name, env_id))
    if len(approved) > 1:
        return bad("run %d: %d approval entries for %s" % (rid, len(approved), env_name))
    if want_reviewer is None or approved[0]["user_id"] != want_reviewer:
        return bad("run %d (%s) was approved by user id %r (%s), not the pinned reviewer id %r"
                   % (rid, r["head_branch"], approved[0]["user_id"], approved[0]["login"], want_reviewer))
    res["verdict"] = "approved"
    res["approval"] = {"user_id": want_reviewer, "login": approved[0]["login"], "environment_id": env_id,
                       "run_attempt": 1, "execution": e["identity"]}
    res["reason"] = "run %d (%s): one execution in attempt 1, one approval by %d" % (rid, r["head_branch"], want_reviewer)
    return res


def store_result(aud, r, res, now):
    rid = str(r.get("id"))
    rs = aud["runs"].setdefault(rid, {})
    for k in ("fp", "head_sha", "head_branch", "created_at", "executions", "pending_attempt", "env_capacity",
              "approvals", "seen_waiting", "sig_cache", "approval"):
        if k in res:
            rs[k] = res[k]
    rs["verdict"], rs["reason"] = res["verdict"], res["reason"]
    if res["verdict"] in ("approved", "legacy", "settled-unexecuted", "unverified"):
        rs["validated_fp"] = res["fp"]
    else:
        rs.pop("validated_fp", None)
    if res["verdict"] == "pending":
        rs.setdefault("pending_since", now)
    else:
        rs.pop("pending_since", None)
        rs.pop("pending_info_sent", None)
    return rs


def seed_baseline(api, cfg, channel, chan, run, aud, runs, now):
    """Build the fixed legacy baseline (once). Returns True when complete.

    Members: every executed signing record of the pinned workflow whose
    GitHub-generated started_at is before the channel's cutoff, plus the
    explicitly pinned legacy executions (each validated against its pinned
    run, ref, sha, job name and attempt). Never recomputed once complete."""
    b = aud.get("baseline")
    cutoff_s = chan.get("signing_cutoff")
    cutoff = parse_ts(cutoff_s)
    if b and b.get("complete"):
        if b.get("cutoff") != cutoff_s:
            run.alert(channel + "/baseline-config",
                      "the pinned signing cutoff changed (%s → %s); the recorded legacy baseline is kept as it was "
                      "seeded and is NOT recomputed" % (b.get("cutoff"), cutoff_s))
        else:
            run.judged(channel + "/baseline-config")
        return True
    if cutoff is None:
        raise ValueError("signing_cutoff missing or malformed for %s" % channel)
    if b is None:
        b = aud["baseline"] = {"version": 1, "cutoff": cutoff_s, "complete": False, "executions": [], "done_runs": [],
                               "pinned_ok": [], "started": now}
    pinned = chan.get("legacy_pinned_executions") or []
    pinned_runs = {int(p["run_id"]) for p in pinned}
    sign_name = chan.get("signing_job") or ""
    todo = [r for r in runs if (parse_ts(r.get("created_at")) or 0) < cutoff or _int(r.get("id")) in pinned_runs]
    run.judged(channel + "/baseline-invalid")
    for r in todo:
        rid = _int(r.get("id"))
        if rid is None or rid in b["done_runs"]:
            continue
        jobs = api.paged("/repos/%s/actions/runs/%d/jobs" % (chan["repo"], rid), "jobs", {"filter": "all"}, priority=3)
        recs = [compact_record(j) for j in jobs if isinstance(j, dict) and j.get("name") == sign_name]
        for rec in recs:
            kind, _ = classify(rec)
            ident = identity(str(rid), rec)
            if kind == "executed" and ident and (parse_ts(rec.get("started_at")) or cutoff) < cutoff:
                if list(ident) not in b["executions"]:
                    b["executions"].append(list(ident))
        for p in pinned:
            if int(p["run_id"]) != rid:
                continue
            ident = [str(rid), p["started_at"], p["completed_at"], p["runner_name"]]
            match = [x for x in recs if identity(str(rid), x) and list(identity(str(rid), x)) == ident]
            ok = (r.get("head_branch") == p["ref"] and r.get("head_sha") == p["sha"] and r.get("path") == chan.get("workflow_path")
                  and _int(r.get("workflow_id")) == _int(chan.get("workflow_id")) and len(match) >= 1
                  and min(_int(x.get("run_attempt")) or 0 for x in match) == 1
                  and all(x.get("conclusion") == "success" for x in match))
            if not ok:
                run.alert(channel + "/baseline-invalid",
                          "the pinned legacy execution of run %s (%s @ %s) does not match GitHub's records — "
                          "baseline NOT completed" % (rid, p["ref"], _short(p["sha"])))
                return False
            if ident not in b["executions"]:
                b["executions"].append(ident)
            if rid not in b["pinned_ok"]:
                b["pinned_ok"].append(rid)
        b["done_runs"].append(rid)
        rs = aud["runs"].setdefault(str(rid), {})
        rs["sig_cache"] = {"fp": fingerprint(r), "records": recs}
    missing = pinned_runs - set(b["pinned_ok"])
    if missing:
        run.alert(channel + "/baseline-invalid",
                  "pinned legacy run(s) %s not found among the pinned workflow's runs — baseline NOT completed"
                  % ", ".join(str(m) for m in sorted(missing)))
        return False
    b["complete"] = True
    b["completed_at"] = now
    b["executions"].sort()
    newest = max(b["executions"], key=lambda x: x[1]) if b["executions"] else None
    run.info("%s: legacy signing baseline recorded ONCE (cutoff %s): %d pre-gate execution(s)%s — fixed from now on"
             % (channel, cutoff_s, len(b["executions"]),
                (", newest run %s started %s" % (newest[0], newest[1])) if newest else ""))
    return True


def signing_audit(api, cfg, channel, chan, run, st, now):
    """The primary audit. Returns True when the check reached a verdict for
    every run (coverage), False when anything was left open."""
    aud = channel_audit(st, channel)
    repo = chan["repo"]
    wf_id = _int(chan.get("workflow_id"))
    if wf_id is None or not chan.get("workflow_path"):
        raise ValueError("workflow_id/workflow_path not pinned for %s" % channel)
    runs = api.paged("/repos/%s/actions/workflows/%d/runs" % (repo, wf_id), "workflow_runs", priority=3)
    if any(not isinstance(r, dict) or _int(r.get("id")) is None for r in runs):
        raise ValueError("runs listing holds a malformed entry")
    listed = {str(r["id"]): r for r in runs}
    # a known run missing from a complete listing: confirm deletion
    for rid in sorted(aud["runs"]):
        if rid in listed or aud["runs"][rid].get("deleted"):
            continue
        got = api.get("/repos/%s/actions/runs/%s" % (repo, rid), priority=3, allow_404=True)
        if got is None:
            aud["runs"][rid]["deleted"] = now
            run.alert(channel + "/run-deleted/" + rid,
                      "signing-workflow run %s (%s) was DELETED — confirmed 404; its signing and approval evidence "
                      "is gone" % (rid, aud["runs"][rid].get("head_branch")))
        else:
            listed[rid] = got
    for rid, rs in aud["runs"].items():
        if rs.get("deleted"):
            run.alert(channel + "/run-deleted/" + rid,
                      "signing-workflow run %s (%s) was DELETED — confirmed 404" % (rid, rs.get("head_branch")))
    if not seed_baseline(api, cfg, channel, chan, run, aud, runs, now):
        run.skipped(channel, "signing audit (legacy baseline not complete)", "signing-audit")
        return False
    complete = True
    for rid, r in sorted(listed.items(), key=lambda kv: int(kv[0])):
        rs = aud["runs"].get(rid) or {}
        key = channel + "/signing/" + rid
        fp = fingerprint(r)
        settled = rs.get("validated_fp") == fp and r.get("status") == "completed"
        if settled:
            if rs.get("verdict") == "unverified":
                run.alert(key, "signing/approval UNVERIFIED — %s" % rs.get("reason"))
            continue
        try:
            res = validate_run(api, cfg, chan, r, aud, now, fetch_jobs=not (rs.get("sig_cache") or {}).get("fp") == fp
                               or r.get("status") != "completed")
        except BudgetStop:
            raise
        if res["verdict"] == "reopen":
            run.skipped(channel, "signing audit: %s (run %s)" % (res["reason"], rid), "signing-audit")
            complete = False
            continue
        rs = store_result(aud, r, res, now)
        run.judged(key)
        if res["verdict"] == "unverified":
            run.alert(key, "signing/approval UNVERIFIED — %s" % res["reason"])
        elif res["verdict"] == "pending":
            if now - rs.get("pending_since", now) >= PENDING_INFO_AFTER and not rs.get("pending_info_sent"):
                rs["pending_info_sent"] = now
                run.info("%s: run %s (%s) has been waiting for the signing review for more than 48 h"
                         % (channel, rid, r.get("head_branch")))
        else:
            run.ok("signing audit: %s" % res["reason"])
    return complete


# ------------------------------------------------------------ deployments

def _group_key(sha, ref):
    return "%s@%s" % (ref, _short(sha))


def deployments_audit(api, cfg, channel, chan, run, st, now):
    """Count check per (sha, ref) over unique signing instances (§4.2,
    secondary audit). Requires this run's signing audit to be complete."""
    aud = channel_audit(st, channel)
    repo = chan["repo"]
    env_name = chan.get("signing_environment") or "release-sign"
    bnd = chan.get("deployment_boundary") or {}
    bid, inclusive = _int(bnd.get("id")), bnd.get("inclusive")
    if bid is None or not isinstance(inclusive, bool):
        raise ValueError("deployment_boundary not pinned for %s" % channel)
    deps = api.paged("/repos/%s/deployments" % repo, None, {"environment": env_name}, priority=5,
                     stop=lambda page: any(_int(d.get("id")) is not None and d["id"] <= bid for d in page if isinstance(d, dict)))
    if any(not isinstance(d, dict) or _int(d.get("id")) is None for d in deps):
        raise ValueError("deployments listing holds a malformed entry")
    run.judged(channel + "/deploy-boundary")
    if not any(d["id"] == bid for d in deps):
        run.alert(channel + "/deploy-boundary",
                  "the pinned boundary deployment %d is not in the %s deployment list (deleted?)" % (bid, env_name))
    audited = [d for d in deps if d["id"] > bid or (inclusive and d["id"] == bid)]
    known = aud["deployments"]
    listed_ids = {str(d["id"]) for d in audited}
    for did, info in list(known.items()):
        if did in listed_ids or info.get("deleted"):
            continue
        got = api.get("/repos/%s/deployments/%s" % (repo, did), priority=5, allow_404=True)
        if got is None:
            info["deleted"] = now
    for did, info in known.items():
        if info.get("deleted"):
            run.alert(channel + "/deployment-deleted/" + did,
                      "%s deployment %s (%s) was DELETED — confirmed 404" % (env_name, did, info.get("ref")))
    runs = {rid: rs for rid, rs in aud["runs"].items() if not rs.get("deleted")}
    groups = {}
    for d in audited:
        if not isinstance(d.get("sha"), str) or not SHA_RE.match(d["sha"]) or not isinstance(d.get("ref"), str):
            raise ValueError("deployment %s has a malformed sha/ref" % d.get("id"))
        groups.setdefault((d["sha"], d["ref"]), []).append(d)
        known.setdefault(str(d["id"]), {"sha": d["sha"], "ref": d["ref"], "created_at": d.get("created_at")})
    legacy = baseline_identities(aud) or set()
    all_done = True
    for (sha, ref), ds in sorted(groups.items(), key=lambda kv: kv[0][1]):
        gk = _group_key(sha, ref)
        akey = channel + "/deploy-unexplained/" + gk
        ukey = channel + "/deploy-group-unverified/" + gk
        members = {rid: rs for rid, rs in runs.items() if rs.get("head_sha") == sha and rs.get("head_branch") == ref}
        if any(rs.get("verdict") not in ("approved", "legacy", "pending", "executing", "settled-unexecuted", "unverified")
               for rs in members.values()):
            all_done = False
            continue
        execs = sum(1 for rs in members.values() for e in rs.get("executions") or [] if tuple(e["identity"]) not in legacy)
        pend = sum(1 for rs in members.values() if rs.get("pending_attempt") or rs.get("verdict") == "executing")
        reached = sum(int(rs.get("env_capacity") or 0) for rs in members.values())
        settled_cap = execs + reached
        capacity = settled_cap + pend
        run.judged(akey, ukey)
        bad_runs = sorted(rid for rid, rs in members.items() if rs.get("verdict") == "unverified")
        if bad_runs:
            run.alert(ukey, "%s deployment group %s contains signing run(s) that are UNVERIFIED: %s"
                      % (env_name, gk, ", ".join(bad_runs)))
        # target_url / log_url are only hints, re-read while the group is open
        group_runs = set(members)
        if not all(known[str(d["id"])].get("settled") for d in ds):
            for d in ds:
                hkey = channel + "/deploy-hint/" + str(d["id"])
                statuses = api.get("/repos/%s/deployments/%d/statuses" % (repo, d["id"]), {"per_page": 100}, priority=5)
                run.judged(hkey)
                if not isinstance(statuses, list):
                    raise ValueError("deployment statuses answer is not a list")
                pat = re.compile(r"^https://github\.com/%s/actions/runs/(\d+)(?:/job/\d+)?/?$" % re.escape(repo))
                for s in statuses:
                    for u in (s.get("target_url"), s.get("log_url")) if isinstance(s, dict) else ():
                        if u:
                            m = pat.match(u)
                            if not m or m.group(1) not in group_runs:
                                run.alert(hkey, "deployment %d (%s) carries a status pointing at %s, which is not a "
                                          "pinned-workflow run of the same tag/commit — UNVERIFIED (statuses are "
                                          "writable by any push caller)" % (d["id"], gk, u))
                                break
        count = len(ds)
        prev = aud["anomalies"].get(gk)
        if capacity == 0 or count > capacity:
            text = ("%d %s deployment(s) for %s but only %d unique signing instance(s) of the pinned workflow "
                    "(executions %d, waiting %d, reached-review %d) — release-sign deployment NOT EXPLAINED by the "
                    "pinned workflow" % (count, env_name, gk, capacity, execs, pend, reached))
            aud["anomalies"][gk] = text
            run.alert(akey, text)
        elif prev:
            if pend or count > settled_cap:
                run.alert(akey, prev + " (kept: a pending signing instance never clears an earlier anomaly)")
            else:
                aud["anomalies"].pop(gk, None)
        if not pend and not prev and gk not in aud["anomalies"] and all(
                rs.get("verdict") in ("approved", "legacy", "settled-unexecuted", "unverified") for rs in members.values()):
            for d in ds:
                known[str(d["id"])]["settled"] = True
    return all_done


def deletion_recheck(api, cfg, channel, chan, run, st, now):
    """1-in-N rotation: re-read one settled deployment (GET /deployments/{id})."""
    aud = channel_audit(st, channel)
    settled = sorted(d for d, i in aud["deployments"].items() if i.get("settled") and not i.get("deleted"))
    if not settled:
        return True
    idx = int(aud.get("recheck_idx", 0)) % len(settled)
    did = settled[idx]
    got = api.get("/repos/%s/deployments/%s" % (chan["repo"], did), priority=8, allow_404=True)
    aud["recheck_idx"] = idx + 1
    if got is None:
        aud["deployments"][did]["deleted"] = now
        run.alert(channel + "/deployment-deleted/" + did,
                  "release-sign deployment %s (%s) was DELETED — confirmed 404" % (did, aud["deployments"][did].get("ref")))
    return True


# ------------------------------------------------------------ §4.3 events

def events_audit(api, cfg, channel, chan, run, st, now, confirmed_tags):
    aud = channel_audit(st, channel)
    repo = chan["repo"]
    cursor = aud.get("events_cursor")
    new, reached = [], False
    for page in (1, 2, 3):
        evs = api.get("/repos/%s/events" % repo, {"per_page": 100, "page": page}, priority=6)
        if not isinstance(evs, list) or any(not isinstance(e, dict) or not str(e.get("id", "")).isdigit() for e in evs):
            raise ValueError("events page %d has an unexpected shape" % page)
        for e in evs:
            if cursor is not None and int(e["id"]) <= cursor:
                reached = True
            else:
                new.append(e)
        if reached or len(evs) < 100 or cursor is None:
            break
    if cursor is None:
        aud["events_cursor"] = max([int(e["id"]) for e in new] or [0])
        run.ok("event feed: cursor seeded at %s (history before installation is not judged)" % aud["events_cursor"])
        return True
    if not reached and new:
        aud["event_findings"][channel + "/events-gap"] = (
            "the event feed did not reach the last processed event %s within 3 pages — events in between were NOT "
            "audited (coverage gap; acknowledge with `release_watch.py acknowledge-finding %s/events-gap`)" % (cursor, channel))
    for e in sorted(new, key=lambda x: int(x["id"])):
        p = e.get("payload") if isinstance(e.get("payload"), dict) else {}
        typ = e.get("type")
        if typ == "ReleaseEvent":
            tag = (p.get("release") or {}).get("tag_name") if isinstance(p.get("release"), dict) else None
            if p.get("action") in ("published", "released", "created") and isinstance(tag, str) and tag not in confirmed_tags:
                aud["event_releases"].setdefault(tag, {"seen": now, "checks": 0, "event": e["id"]})
        elif typ == "DeleteEvent" and p.get("ref_type") == "tag":
            aud["event_findings"]["%s/event-tag-deleted/%s" % (channel, p.get("ref"))] = (
                "tag %s was DELETED (event %s at %s, by %s)" % (p.get("ref"), e["id"], e.get("created_at"),
                                                                (e.get("actor") or {}).get("login")))
        elif typ == "CreateEvent" and p.get("ref_type") == "tag" and not TAG_RE.match(str(p.get("ref"))):
            aud["event_findings"]["%s/event-bad-tag/%s" % (channel, p.get("ref"))] = (
                "tag %s (not v<semver>) was created (event %s at %s)" % (p.get("ref"), e["id"], e.get("created_at")))
        aud["events_cursor"] = max(aud["events_cursor"], int(e["id"])) if aud.get("events_cursor") else int(e["id"])
    for tag, info in list(aud["event_releases"].items()):
        key = "%s/event-release-unconfirmed/%s" % (channel, tag)
        if tag in confirmed_tags:
            aud["event_releases"].pop(tag)
            aud["event_findings"].pop(key, None)
            run.judged(key)
            continue
        info["checks"] = int(info.get("checks", 0)) + 1
        if info["checks"] >= 2:
            aud["event_findings"][key] = ("release %s was published (event %s) but never confirmed by this watcher; it may "
                                         "have been deleted since" % (tag, info.get("event")))
    for key, text in aud["event_findings"].items():
        run.alert(key, text)
    return True
