#!/usr/bin/env python3
"""Deliberate breaks for the signed-release CI pieces (UT signing-in-CI
plan §8.1): each break re-introduces one weakness into a throwaway copy of
this repository and the named suite MUST go red. A break that leaves its
suite green means that suite does not guard the property.

    python3 scripts/ci_release_breaks.py [--only NAME]
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.dirname(HERE)

# name: (file, old, new, suite, what must turn red). `old` may instead be a
# list of (old, new) pairs (then `new` is None): every anchor is replaced,
# for a break that only re-creates the weakness when several guards go.
BREAKS = [
    ("drop-repro-gate", ".github/workflows/release-signed.yml",
     'cmp -s "linux/$FILENAME" "macos/$FILENAME" ||', 'true ||',
     "ci_release_selftest.py", "static: reproducibility gate"),
    ("skip-publish-supersession", ".github/workflows/release-signed.yml",
     'run: WHEN="before publish" ./scripts/release/check-supersession.sh', 'run: "true"',
     "ci_release_selftest.py", "static: publish gates"),
    ("skip-prego-live-gate", "scripts/release/publish-github-release.sh",
     'if ! "$PREPUBLISH_VERIFY" draft "$RELEASE_ID"; then', 'if false; then',
     "publish_selftest.py", "tampered draft goes live"),
    ("accept-equal-sequence", "scripts/release/check-supersession.sh",
     '[ "$SEQUENCE" -gt "$LIVE_SEQ" ]', '[ "$SEQUENCE" -ge "$LIVE_SEQ" ]',
     "ci_release_selftest.py", "equal sequence passes"),
    ("verify-production-unauthenticated-latest", "scripts/release/verify-public-release.sh",
     'echo "✖ the public LATEST envelope is neither this release nor an authenticated previous state — $WHICH is live but NOT recorded; investigate before anything else"; exit 1',
     'break',
     "publish_selftest.py", "unauthenticated latest accepted"),
    ("accept-skipped-required-jobs", "scripts/release_watch.py",
     'if latest.get("conclusion") != "success":', 'if latest.get("conclusion") not in ("success", "skipped"):',
     "watch_approval_selftest.py", "skipped required job accepted"),
    ("remove-run-attempt-guard", ".github/workflows/release-signed.yml",
     '[ "$RUN_ATTEMPT" = "1" ] || {', 'true || {',
     "ci_release_selftest.py", "static: attempt-1 guard"),
    # ---- release watcher (Mac mini + Sentinel): coverage, shapes, judgments
    ("flush-clears-unjudged-findings", "scripts/release_watch.py",
     "                if key not in self.checked:\n                    # Not judged",
     "                if False:\n                    # Not judged",
     "watch_selftest.py", "skipped check announced as recovered"),
    ("partial-run-counts-clean", "scripts/release_watch.py",
     "        if not alerting and not partial and not preserved:", "        if not alerting:",
     "sentinel_selftest.py", "last_clean advanced by a partial run"),
    ("freshness-clears-asset-hash", "scripts/release_watch.py",
     [("    if not problems and (now - last_full >= FULL_HASH_INTERVAL):\n        run.judged(channel + \"/asset-hash\")",
       "    run.judged(channel + \"/asset-hash\")\n    if not problems and (now - last_full >= FULL_HASH_INTERVAL):")], None,
     "watch_selftest.py", "not-due full hash clears its finding"),
    ("list-judged-before-validation", "scripts/release_watch.py",
     [("        for r in releases:\n            gh_shape(r, dict, \"releases[]\")\n            if \"tag_name\" not in r or not isinstance(r.get(\"draft\"), bool):\n"
       "                raise ShapeError(\"GitHub API releases[] → unexpected response shape (tag_name/draft missing)\")\n",
       "        releases = [r for r in releases if isinstance(r, dict)]\n")], None,
     "watch_selftest.py", "malformed release list judged and 'recovered'"),
    ("no-latest-shape-validation", "scripts/release_watch.py",
     'latest = gh_shape(gh_json(cfg, "/repos/%s/releases/latest" % repo), dict, "releases/latest")',
     'latest = gh_json(cfg, "/repos/%s/releases/latest" % repo)',
     "watch_selftest.py", "malformed latest crashes the channel"),
    ("endless-list-judged-complete", "scripts/release_watch.py",
     '    raise ShapeError("GitHub API %s: more than %d pages — refusing to judge a truncated list" % (path, max_pages))',
     '    return items',
     "watch_selftest.py", "a list that never ends is judged complete"),
    ("crashed-channel-keeps-judgments", "scripts/release_watch.py",
     [("            run.checked = {k for k in run.checked if not k.startswith(ch + \"/\") or k in run.findings}\n            run.done.pop(ch, None)\n",
       "            run.done.pop(ch, None)\n"),
      ("        evaluate_coverage(cfg, run, now)\n        for ch in crashed:\n            run.checked = {k for k in run.checked if not k.startswith(ch + \"/\") or k in run.findings}\n",
       "        evaluate_coverage(cfg, run, now)\n")], None,
     "watch_selftest.py", "crashed channel run announces recoveries"),
    ("no-coverage-warning", "scripts/release_watch.py",
     "            if now - since > coverage_limit(cfg, check):", "            if False:",
     "watch_selftest.py", "stale coverage never alerted"),
    ("publication-log-above-cutoff", "scripts/release_watch.py",
     'if kind == "app" and not above:', 'if kind == "app":',
     "watch_approval_selftest.py", "local log accepted above the cutoff"),
    # ---- signing audit (approval binding, executions, legacy baseline)
    ("approvals-any-reviewer", "scripts/watch_audit.py",
     'if want_reviewer is None or approved[0]["user_id"] != want_reviewer:', 'if False:',
     "watch_approval_selftest.py", "approval by another user id accepted"),
    ("accept-attempt-2-execution", "scripts/watch_audit.py",
     '    if e["attempt"] != 1:', '    if False:',
     "watch_approval_selftest.py", "attempt-2 signing approved"),
    ("record-copies-are-executions", "scripts/watch_audit.py",
     '            executions.setdefault(ident, []).append(rec)',
     '            executions.setdefault(ident + (rec.get("id"),), []).append(rec)',
     "sentinel_selftest.py", "carried copies counted as separate executions"),
    ("exempt-whole-old-run", "scripts/watch_audit.py",
     'all(tuple(e["identity"]) in legacy for e in execs)', 'any(tuple(e["identity"]) in legacy for e in execs)',
     "sentinel_selftest.py", "new execution on the pinned legacy run exempted"),
    ("baseline-recomputed", "scripts/watch_audit.py",
     [("    if b and b.get(\"complete\"):", "    if False:"), ("    if b is None:", "    if True:")], None,
     "sentinel_selftest.py", "baseline recomputed on a later run / reinstall"),
    ("no-pinned-legacy-execution", "scripts/watch_audit.py",
     '    pinned = chan.get("legacy_pinned_executions") or []', '    pinned = []',
     "sentinel_selftest.py", "CLI v0.2.49 (signed 3 s after the cutoff) alerts forever"),
    ("missing-runner-key-is-no-runner", "scripts/watch_audit.py",
     [('    if "runner_name" not in rec:\n        return "malformed", "runner_name key is missing"\n', ''),
      ('    runner = rec["runner_name"]', '    runner = rec.get("runner_name")')], None,
     "sentinel_selftest.py", "missing runner_name key treated as 'no runner'"),
    ("missing-sign-record-not-executed", "scripts/watch_audit.py",
     '    if not records:\n        return bad(',
     '    if not records:\n        res["verdict"] = "settled-unexecuted"\n        return res\n        return bad(',
     "sentinel_selftest.py", "missing signing record settled as not executed"),
    ("failure-is-not-executed", "scripts/watch_audit.py",
     '    if status == "completed":\n        return "executed", ""',
     '    if status == "completed":\n        return ("ended", "") if conclusion == "failure" else ("executed", "")',
     "sentinel_selftest.py", "failed-after-start signing treated as not executed"),
    ("ignore-fingerprint-change", "scripts/watch_audit.py",
     '        settled = rs.get("validated_fp") == fp and r.get("status") == "completed"',
     '        settled = rs.get("validated_fp") is not None and r.get("status") == "completed"',
     "sentinel_selftest.py", "re-run of a settled run never re-validated"),
    ("settle-on-budget-stop", "scripts/watch_audit.py",
     '        except BudgetStop:\n            raise',
     '        except BudgetStop:\n            aud["runs"].setdefault(rid, {})["validated_fp"] = fp\n            continue',
     "sentinel_selftest.py", "unexamined run settled when the budget ran out"),
    # ---- deployments (count check)
    ("trust-target-url", "scripts/watch_audit.py",
     '                            if not m or m.group(1) not in group_runs:', '                            if not m:',
     "sentinel_selftest.py", "status target_url into another group trusted"),
    ("deployments-matched-across-groups", "scripts/watch_audit.py",
     '        members = {rid: rs for rid, rs in runs.items() if rs.get("head_sha") == sha and rs.get("head_branch") == ref}',
     '        members = dict(runs)',
     "sentinel_selftest.py", "a deployment explained by runs of another tag/commit"),
    ("pending-slot-clears-anomaly", "scripts/watch_audit.py",
     '            if pend or count > settled_cap:', '            if count > capacity:',
     "sentinel_selftest.py", "a later pending slot clears an earlier anomaly"),
    ("rejection-adds-two-slots", "scripts/watch_audit.py",
     '    res["env_capacity"] = len(cap_attempts)', '    res["env_capacity"] = len(cap_attempts) + len(ended)',
     "sentinel_selftest.py", "a rejected attempt explains two deployments"),
    ("capacity-without-lifecycle-evidence", "scripts/watch_audit.py",
     '        if _int(rec.get("id")) in seen_waiting or (rec.get("conclusion") == "failure" and rejected_here):',
     '        if True:',
     "sentinel_selftest.py", "unobserved cancelled attempt given capacity"),
    ("dropped-off-listing-is-deleted", "scripts/watch_audit.py",
     '        got = api.get("/repos/%s/deployments/%s" % (repo, did), priority=5, allow_404=True)\n        if got is None:',
     '        got = None\n        if got is None:',
     "sentinel_selftest.py", "deployment missing from a listing reported deleted"),
    # ---- remote mode, report-only, anti-noise, logs
    ("remote-sends-authorization", "scripts/release_watch.py",
     "    elif token:\n        headers[\"Authorization\"]", "    if token:\n        headers[\"Authorization\"]",
     "sentinel_selftest.py", "credentials sent in remote mode"),
    ("report-only-leaks-to-telegram", "scripts/release_watch.py",
     "            if self.is_report_only(key):", "            if False:",
     "sentinel_selftest.py", "report-only audit finding sent to Telegram"),
    ("report-only-switches-itself", "scripts/release_watch.py",
     '    return cfg.get("signing_audit_alerts") is False\n',
     '    return cfg.get("signing_audit_alerts") is False and (cfg.get("audit_report_since") or "9999") > '
     '(datetime.date.today() - datetime.timedelta(days=14)).isoformat()\n',
     "sentinel_selftest.py", "report-only ends automatically after 14 days"),
    ("repeat-on-text-change", "scripts/release_watch.py",
     '        on_change = cfg.get("realert_on_change", True) is not False', '        on_change = True',
     "sentinel_selftest.py", "a persisting finding repeated when its text changes"),
    ("heartbeat-repeats", "scripts/release_heartbeat.py",
     '        elif prev.get("kind") != kind or (realert and now - float(prev.get("last_sent", 0)) >= realert):',
     '        elif True:',
     "sentinel_selftest.py", "heartbeat alert repeated every run"),
    ("no-log-rotation", "scripts/release_watch.py",
     "            if os.path.getsize(self.path) < self.max_bytes:\n                return",
     "            return",
     "sentinel_selftest.py", "logs grow without bound"),
    # ---- confirmations and the website job
    ("confirm-with-partial-coverage", "scripts/release_watch.py",
     [("        if missing:\n            reasons.append(\"not checked in this run: \"",
       "        if False:\n            reasons.append(\"not checked in this run: \""),
      ("        if run.partial.get(channel):\n            reasons.append(\"partial run: \"",
       "        if False:\n            reasons.append(\"partial run: \"")], None,
     "sentinel_selftest.py", "✅ sent with a check not performed"),
    ("confirm-with-stale-site-beacon", "scripts/sentinel_site.py",
     "    if now - completed > max_age or completed > now + 600:", "    if False:",
     "sentinel_selftest.py", "✅ sent while the site job is stale"),
    ("warn-before-freshness-limit", "scripts/release_watch.py",
     '        if now - pc["first_seen"] > hourly_limit and not pc.get("warned"):', '        if not pc.get("warned"):',
     "sentinel_selftest.py", "⚠️ sent before the freshness limit (noise)"),
    ("excuse-on-newer-envelope", "scripts/sentinel_site.py",
     "            excusable = all(len(p) > 3", "            excusable = True or all(len(p) > 3",
     "sentinel_selftest.py", "a newer envelope alone excuses a website mismatch"),
    ("deadline-waits-for-checker", "scripts/sentinel_site.py",
     '            if now < t["deadline"]:', '            if now < t["deadline"] or t.get("generation") == cache["generation"]:',
     "sentinel_selftest.py", "deadline applied only once the hourly check ran"),
    ("deadline-extended", "scripts/sentinel_site.py",
     '            t["candidate_sequence"] = max(t["candidate_sequence"], cand["sequence"])   # never extends the deadline',
     '            t.update(candidate_sequence=cand["sequence"], deadline=next_deadline(now, minute))',
     "sentinel_selftest.py", "a higher candidate extends the deadline"),
    ("old-generation-applied", "scripts/sentinel_site.py",
     "            if gen_now != gen:", "            if False:",
     "sentinel_selftest.py", "a result for an old cache generation applied"),
    ("site-job-calls-api", "scripts/sentinel_site.py",
     '                kind, text, got = probe_installer(url, entry.get("redirect"), entry.get("installer"))',
     '                fetch(url.split("/site/")[0].split("/domain/")[0] + "/api/rate_limit")\n'
     '                kind, text, got = probe_installer(url, entry.get("redirect"), entry.get("installer"))',
     "sentinel_selftest.py", "the website job calls the GitHub API"),
    ("installer-skips-bundle-hash", "scripts/sentinel/install_sentinel.py",
     "    if got != BUNDLE_SHA256:", "    if False:",
     "sentinel_selftest.py", "tampered bundle installed"),
    # ---- a finding clears only on a complete, valid pass of its owning check;
    # ✅ only with every due check; positive messages only after the save
    ("site-redirect-judged-unreached", "scripts/sentinel_site.py",
     "        if redirect_known:\n            judged.add(rkey)", "        if True:\n            judged.add(rkey)",
     "sentinel_selftest.py", "bad redirect 'recovered' while a host is unreachable"),
    ("site-content-judged-unfetched", "scripts/sentinel_site.py",
     "        if content_known:\n            judged.add(ckey)", "        if True:\n            judged.add(ckey)",
     "sentinel_selftest.py", "bad content 'recovered' by a redirect-only probe"),
    ("site-transition-closed-unverified", "scripts/sentinel_site.py",
     "            if content_known:\n                trans.pop(channel, None)", "            if True:\n                trans.pop(channel, None)",
     "sentinel_selftest.py", "transition (and its deadline) lost without verified content"),
    ("env-rules-judged-before-branch-policies", "scripts/watch_audit.py",
     "    elif deferred is None:\n        run.judged(key)\n    if drift:", "    else:\n        run.judged(key)\n    if drift:",
     "sentinel_selftest.py", "env-rules 'recovered' when the branch-policy fetch failed"),
    ("env-rules-drops-established-weakening", "scripts/watch_audit.py",
     "            except Exception as exc:  # noqa: BLE001 — budget/network: not checked; re-raised below\n"
     "                deferred = exc\n            else:\n                if pols != {(\"v*\", \"tag\")}:\n"
     "                    problems.append(\"branch policies are %s, expected exactly",
     "            except Exception as exc:  # noqa: BLE001\n"
     "                raise\n            else:\n                if pols != {(\"v*\", \"tag\")}:\n"
     "                    problems.append(\"branch policies are %s, expected exactly",
     "sentinel_selftest.py", "established admin-bypass weakening lost on a later fetch failure"),
    ("env-publish-judged-before-branch-policies", "scripts/watch_audit.py",
     "    elif deferred is None:\n        run.judged(key)\n    want =", "    else:\n        run.judged(key)\n    want =",
     "sentinel_selftest.py", "release-publish 'recovered' when the branch-policy fetch failed"),
    ("deploy-hint-judged-before-validation", "scripts/watch_audit.py",
     "                if not isinstance(statuses, list) or any(",
     "                run.judged(hkey)\n                if not isinstance(statuses, list) or any(",
     "sentinel_selftest.py", "deploy-hint 'recovered' by a malformed statuses answer"),
    ("baseline-invalid-judged-on-partial-seed", "scripts/watch_audit.py",
     "    # baseline-invalid is judged only when the seed COMPLETES",
     "    run.judged(channel + \"/baseline-invalid\")\n    # baseline-invalid is judged only when the seed COMPLETES",
     "sentinel_selftest.py", "baseline-invalid 'recovered' by a partial seed"),
    ("confirm-ignores-due-checks", "scripts/release_watch.py",
     [("        missing = sorted((needed | run.due.get(channel, set())) - run.done.get(channel, set()))",
       "        missing = sorted(needed - run.done.get(channel, set()))"),
      ("        if run.partial.get(channel):\n            reasons.append(\"partial run: \"",
       "        if False:\n            reasons.append(\"partial run: \"")], None,
     "sentinel_selftest.py", "✅ with due deployment/event checks skipped"),
    ("send-before-save", "scripts/release_watch.py",
     "        prune_state(st)\n        state.save()      # the evidence",
     "        prune_state(st)\n        messages += deliver_outbox(cfg, state)\n        state.save()      # the evidence",
     "sentinel_selftest.py", "✅ sent before its verification record is saved"),
    ("confirmation-through-flush", "scripts/release_watch.py",
     '            run.positive(channel, rec["tag"], msg)', "            run.extra_messages.append(msg)",
     "sentinel_selftest.py", "✅ delivered by flush() before the save"),
    ("outbox-drops-undelivered", "scripts/release_watch.py",
     [("        else:\n            keep.append(item)", "        else:\n            pass"),
      ("    if sent:\n        try:\n            state.save()", "    if True:\n        try:\n            state.save()")], None,
     "sentinel_selftest.py", "undelivered ✅ lost"),
    ("signing-intermediate-verdict-judged", "scripts/watch_audit.py",
     '        if res["verdict"] == "unverified":\n            run.alert(key, "signing/approval UNVERIFIED',
     '        run.judged(key)\n        if res["verdict"] == "unverified":\n            run.alert(key, "signing/approval UNVERIFIED',
     "sentinel_selftest.py", "unapproved signing 'recovered' while a rerun signs"),
    ("signing-executing-counts-complete", "scripts/watch_audit.py",
     '            complete = False\n        elif res["verdict"] in ("approved", "legacy", "settled-unexecuted"):',
     '            pass\n        elif res["verdict"] in ("approved", "legacy", "settled-unexecuted"):',
     "sentinel_selftest.py", "audit complete while a signing execution runs"),
    # ---- Sentinel's extra release assets (installer + bundle)
    ("stage-extras-unrecorded", "scripts/release/prepublish-verify.py",
     '        if got != recorded[os.path.basename(e)]:', '        if False:',
     "ci_release_selftest.py", "tampered Sentinel bundle staged"),
    ("stage-ignores-embedded-hash", "scripts/release/prepublish-verify.py",
     [("        if 'VERSION = \"%s\"' % a.version not in text or 'BUNDLE_SHA256 = \"%s\"' % sha256_file(pyz[0]) not in text:",
       "        if False:")], None,
     "ci_release_selftest.py", "bundle swapped and re-recorded passes"),
    ("assemble-skips-sentinel-repro", ".github/workflows/release-signed.yml",
     'cmp -s "linux/$f" "macos/$f" ||', 'true ||',
     "ci_release_selftest.py", "static: Sentinel reproducibility gate"),
    ("unverified-not-held", "scripts/release_watch.py",
     '            if hold and _HOLD_KEY_RE.match(key)', '            if False and hold and _HOLD_KEY_RE.match(key)',
     "sentinel_selftest.py", "unverified state alerted at once (noise)"),
    ("draft-gate-skips-bytes", "scripts/release/prepublish-verify.py",
     'if os.path.getsize(got) != size or sha256_file(got) != sha256_file(want):', 'if False:',
     "publish_selftest.py", "byte-different draft passes when no digest"),
    ("candidate-skips-shipped-verifier-check", "scripts/release/verify-candidate.py",
     "if shipped != p.stdout:", "if False:",
     "ci_release_selftest.py", "live verifier ≠ pinned commit accepted"),
    # Codex 2026-10-05 round-1 findings: each break restores one removed
    # guard (or the whole old behaviour) of the owner restore check and the
    # break-glass quiesce tool.
    ("restore-old-empty-compare", "scripts/release/restore-check.sh",
     [('    if [ "$want_rc" != 0 ] || ! ed25519_spki_ok "$want"; then', '    if false; then'),
      ('    if [ "$got_rc" != 0 ] || ! ed25519_spki_ok "$got"; then', '    if false; then')], None,
     "ci_release_selftest.py", "malformed key + failed decryption reports MATCH"),
    ("restore-trust-expected-key", "scripts/release/restore-check.sh",
     '    if [ "$want_rc" != 0 ] || ! ed25519_spki_ok "$want"; then', '    if false; then',
     "ci_release_selftest.py", "invalid / non-Ed25519 expected key not named"),
    ("restore-trust-backup-conversion", "scripts/release/restore-check.sh",
     '    if [ "$got_rc" != 0 ] || ! ed25519_spki_ok "$got"; then', '    if false; then',
     "ci_release_selftest.py", "failed decryption not named"),
    ("quiesce-status-filtered-discovery", "scripts/release/breakglass-quiesce.py",
     'runs = all_pages("/repos/%s/actions/workflows/%d/runs" % (repo, wf_id), "workflow_runs")',
     'runs = [x for s_ in ("queued", "waiting", "in_progress", "requested", "pending", "action_required") '
     'for x in all_pages("/repos/%s/actions/workflows/%d/runs" % (repo, wf_id), "workflow_runs", "&status=" + s_)]',
     "ci_release_selftest.py", "completed run with an active publisher skipped"),
    ("quiesce-completed-run-jobs-unchecked", "scripts/release/breakglass-quiesce.py",
     'return all(j["status"] == "completed" for j in jobs), r', 'return True, r',
     "ci_release_selftest.py", "active publisher job of a completed run ignored"),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only")
    ap.add_argument("--shard", help="I/N: run every N-th break starting at I (CI matrix)")
    a = ap.parse_args()
    failures = 0
    selected = [b for b in BREAKS if not a.only or b[0] == a.only]
    if a.shard:
        i, n = (int(x) for x in a.shard.split("/"))
        selected = selected[i::n]
    for name, path, old, new, suite, what in selected:
        work = tempfile.mkdtemp(prefix="briglia-ut-break-")
        try:
            copy = os.path.join(work, "repo")
            shutil.copytree(SRC, copy, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc", "build"))
            target = os.path.join(copy, path)
            text = open(target).read()
            pairs = old if isinstance(old, list) else [(old, new)]
            if any(text.count(o) != 1 for o, _ in pairs):
                print("✖ %s: an anchor is not present exactly once in %s — update the break list" % (name, path))
                failures += 1
                continue
            for o, n in pairs:
                text = text.replace(o, n)
            open(target, "w").write(text)
            p = subprocess.run([sys.executable, os.path.join(copy, "scripts", suite)], capture_output=True, text=True)
            out = p.stdout + p.stderr
            red = p.returncode != 0
            print("%s %-42s → %s %s (%s)" % ("✔" if red else "✖", name, suite,
                                           "RED as required" if red else "STILL GREEN", out.strip().splitlines()[-1] if out.strip() else ""))
            if not red:
                failures += 1
        finally:
            for dp, dn, fn in os.walk(work):
                try:
                    os.chmod(dp, 0o755)
                except OSError:
                    pass
            shutil.rmtree(work, ignore_errors=True)
    print("\nci release breaks: %d of %d caught" % (len(selected) - failures, len(selected)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
