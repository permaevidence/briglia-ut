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

# name: (file, old, new, suite, what must turn red)
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
    ("draft-gate-skips-bytes", "scripts/release/prepublish-verify.py",
     'if os.path.getsize(got) != size or sha256_file(got) != sha256_file(want):', 'if False:',
     "publish_selftest.py", "byte-different draft passes when no digest"),
    ("candidate-skips-shipped-verifier-check", "scripts/release/verify-candidate.py",
     "if shipped != p.stdout:", "if False:",
     "ci_release_selftest.py", "live verifier ≠ pinned commit accepted"),
    ("publication-log-above-cutoff", "scripts/release_watch.py",
     'if kind == "app" and not above:', 'if kind == "app":',
     "watch_approval_selftest.py", "local log accepted above the cutoff"),
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
            if text.count(old) != 1:
                print("✖ %s: the anchor is not present exactly once in %s — update the break list" % (name, path))
                failures += 1
                continue
            open(target, "w").write(text.replace(old, new))
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
