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
    ("approvals-by-login", "scripts/release_watch.py",
     'if want is None or _int(user.get("id")) != want:', 'if user.get("login") != "matteoiannius-beep":',
     "watch_approval_selftest.py", "same login, other id approved"),
    ("accept-skipped-required-jobs", "scripts/release_watch.py",
     'if latest.get("conclusion") != "success":', 'if latest.get("conclusion") not in ("success", "skipped"):',
     "watch_approval_selftest.py", "skipped required job accepted"),
    ("remove-run-attempt-guard", ".github/workflows/release-signed.yml",
     '[ "$RUN_ATTEMPT" = "1" ] || {', 'true || {',
     "ci_release_selftest.py", "static: attempt-1 guard"),
    ("watcher-ignores-sign-attempt", "scripts/release_watch.py",
     'if _int(sign.get("run_attempt")) != 1 or sign.get("conclusion") != "success":',
     'if sign.get("conclusion") != "success":',
     "watch_approval_selftest.py", "attempt-2 signing approved"),
    ("carried-copy-counted-as-new-signing", "scripts/release_watch.py",
     'key = (j.get("started_at"), j.get("completed_at"), j.get("runner_name"))',
     'key = ("job-id", j.get("id"))',
     "watch_approval_selftest.py", "publish-only retry reported unverified"),
    ("all-signings-merged", "scripts/release_watch.py",
     'key = (j.get("started_at"), j.get("completed_at"), j.get("runner_name"))',
     'key = ("one", "one", "one")',
     "watch_approval_selftest.py", "genuine re-signing accepted"),
    ("draft-gate-skips-bytes", "scripts/release/prepublish-verify.py",
     'if os.path.getsize(got) != size or sha256_file(got) != sha256_file(want):', 'if False:',
     "publish_selftest.py", "byte-different draft passes when no digest"),
    ("candidate-skips-shipped-verifier-check", "scripts/release/verify-candidate.py",
     "if shipped != p.stdout:", "if False:",
     "ci_release_selftest.py", "live verifier ≠ pinned commit accepted"),
    ("publication-log-above-cutoff", "scripts/release_watch.py",
     'if kind == "app" and not above:', 'if kind == "app":',
     "watch_approval_selftest.py", "local log accepted above the cutoff"),
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
    a = ap.parse_args()
    failures = 0
    for name, path, old, new, suite, what in BREAKS:
        if a.only and a.only != name:
            continue
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
    print("\nci release breaks: %d of %d caught" % (len([b for b in BREAKS if not a.only or b[0] == a.only]) - failures,
                                                    len([b for b in BREAKS if not a.only or b[0] == a.only])))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
