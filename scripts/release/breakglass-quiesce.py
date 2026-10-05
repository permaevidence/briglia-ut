#!/usr/bin/env python3
"""Break-glass step 2–5 (UT signing-in-CI plan §10): before ANY local
emergency publication, prove the CI release pipeline is quiet.

    breakglass-quiesce.py --repo OWNER/NAME [--workflow-path .github/workflows/release-signed.yml]
                          [--cancel] [--wait] [--delete-drafts] [--poll-seconds 15]

  1. Admission must already be closed: the repository variable
     RELEASE_CHANNEL_ENABLED must read exactly "false" (set it first; this
     tool never changes settings). Unreadable → refuse.
  2. Enumerate EVERY run of the release workflow, whatever status it
     reports — all pages; a list that does not end, or whose length
     disagrees with total_count, is a refusal (never a silently truncated
     list). A run that already says `completed` can still have a live job
     (a cancelled run whose publisher has not stopped yet), so the jobs of
     EVERY run are checked, on every invocation: nothing depends on what an
     earlier invocation saw (Codex 2026-10-05).
  3. --cancel: request cancellation of each outstanding run that is NOT
     waiting for approval. A run waiting for the signing approval is never
     touched through the API: the OWNER rejects it on the phone (the URL is
     printed). A cancellation request is not proof the publisher stopped.
  4. --wait: poll until every enumerated run is `completed` AND every one
     of its jobs is completed (no deadline shortcut; Ctrl-C to abort). Then
     the run list is read again: a new run, or a known run that is no
     longer completed (a re-run), is checked the same way.
  5. Reconcile: EVERY draft release is reported (deleted with
     --delete-drafts — the pipeline is the only draft creator); a PUBLISHED
     release for a tag a relevant run touched (one that was not quiet when
     this invocation started, or one created in the last 7 days, or one
     whose creation time is unknown) is reported as live — the emergency
     may no longer be needed, or needs a higher sequence.

Exit 0 only when admission is closed, no release run is outstanding, and
no draft release remains. Env: GH_TOKEN (admin: reading
variables and cancelling runs), GH_API_URL (default https://api.github.com).
Stdlib + curl only.
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone

API = os.environ.get("GH_API_URL", "https://api.github.com")
TOKEN = os.environ.get("GH_TOKEN", "")


class Refuse(Exception):
    pass


def call(method, path, params=""):
    url = API + path + params
    p = subprocess.run(["curl", "-sS", "-X", method, "-o", "-", "-w", "\n%{http_code}",
                        "-H", "Authorization: Bearer " + TOKEN, "-H", "Accept: application/vnd.github+json", url],
                       capture_output=True, text=True)
    body, _, status = p.stdout.rpartition("\n")
    try:
        data = json.loads(body) if body.strip() else None
    except ValueError:
        data = None
    return status.strip(), data


def get(path, params=""):
    status, data = call("GET", path, params)
    if status != "200" or data is None:
        raise Refuse("GET %s%s → HTTP %s" % (path, params, status))
    return data


def all_pages(path, key, extra=""):
    items, total = [], None
    for page in range(1, 51):
        data = get(path, "?per_page=100&page=%d%s" % (page, extra))
        chunk = data.get(key) if isinstance(data, dict) else None
        if not isinstance(chunk, list):
            raise Refuse("%s: no %r list" % (path, key))
        total = data.get("total_count", total)
        items += chunk
        if len(chunk) < 100:
            if isinstance(total, int) and total != len(items):
                raise Refuse("%s: listed %d item(s) but total_count says %d — refusing a possibly truncated list"
                             % (path, len(items), total))
            return items
    raise Refuse("%s: more than 50 pages — refusing to judge a truncated list" % path)


RECENT = timedelta(days=7)


def all_runs(repo, wf_id):
    """EVERY run of the workflow, unfiltered by status: a status filter
    would hide a run that already reports completed while one of its jobs
    is still running. Missing/inconsistent evidence is a refusal."""
    runs = all_pages("/repos/%s/actions/workflows/%d/runs" % (repo, wf_id), "workflow_runs")
    by_id = {}
    for r in runs:
        if not isinstance(r, dict) or not isinstance(r.get("id"), int) or not isinstance(r.get("status"), str):
            raise Refuse("a release run record has no id/status — refusing to judge incomplete evidence: %r" % (r,))
        by_id[r["id"]] = r
    return [by_id[k] for k in sorted(by_id)]


def recent(r, now):
    try:
        created = datetime.strptime(r["created_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (KeyError, TypeError, ValueError):
        return True   # unknown creation time: treat as relevant
    return now - created <= RECENT


def run_terminal(repo, rid):
    r = get("/repos/%s/actions/runs/%d" % (repo, rid))
    if not isinstance(r, dict) or r.get("id") != rid:
        raise Refuse("run %d: the run record does not describe that run" % rid)
    if r.get("status") != "completed":
        return False, r
    jobs = all_pages("/repos/%s/actions/runs/%d/jobs" % (repo, rid), "jobs", "&filter=all")
    for j in jobs:
        if not isinstance(j, dict) or not isinstance(j.get("status"), str):
            raise Refuse("run %d: a job record has no status — refusing to judge incomplete evidence" % rid)
    return all(j["status"] == "completed" for j in jobs), r


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", required=True)
    ap.add_argument("--workflow-path", default=".github/workflows/release-signed.yml")
    ap.add_argument("--cancel", action="store_true")
    ap.add_argument("--wait", action="store_true")
    ap.add_argument("--delete-drafts", action="store_true")
    ap.add_argument("--poll-seconds", type=float, default=15)
    a = ap.parse_args(argv)
    try:
        if not TOKEN:
            raise Refuse("GH_TOKEN is required")
        status, var = call("GET", "/repos/%s/actions/variables/RELEASE_CHANNEL_ENABLED" % a.repo)
        if status != "200" or not isinstance(var, dict) or var.get("value") != "false":
            raise Refuse("admission is not closed: RELEASE_CHANNEL_ENABLED reads %r (HTTP %s) — set it to false first"
                         % ((var or {}).get("value") if isinstance(var, dict) else None, status))
        print("✔ admission closed (RELEASE_CHANNEL_ENABLED=false): new tag pushes stop at authorize")
        wf = get("/repos/%s/actions/workflows/%s" % (a.repo, os.path.basename(a.workflow_path)))
        if wf.get("path") != a.workflow_path or not isinstance(wf.get("id"), int):
            raise Refuse("workflow %s not found by path" % a.workflow_path)
        now = datetime.now(timezone.utc)
        runs = all_runs(a.repo, wf["id"])
        print("release runs known to GitHub: %d — checking every one, jobs included" % len(runs))
        pending, quiet = set(), set()
        for r in runs:
            done, detail = run_terminal(a.repo, r["id"])
            if done:
                quiet.add(r["id"])
            else:
                pending.add(r["id"])
                r.update(status=detail.get("status"))
        relevant = [r for r in runs if r["id"] in pending or recent(r, now)]
        tags = sorted({r.get("head_branch") for r in relevant if r.get("head_branch")})
        out = [r for r in runs if r["id"] in pending]
        print("outstanding release runs: %d" % len(out))
        for r in out:
            print("  run %s  %s  %s  %s" % (r["id"], r.get("head_branch"), r.get("status"), r.get("html_url")))
        if a.cancel:
            for r in out:
                if r.get("status") == "waiting":
                    print("  ⚠ run %s is WAITING for the signing approval — the owner must REJECT it on the phone: %s"
                          % (r["id"], r.get("html_url")))
                    continue
                if r.get("status") == "completed":
                    print("  run %s already reports completed but a job is still running — nothing to cancel; waiting "
                          "for its jobs to stop" % r["id"])
                    continue
                st, _ = call("POST", "/repos/%s/actions/runs/%d/cancel" % (a.repo, r["id"]))
                print("  cancel requested for run %s (HTTP %s) — a request, not proof it stopped" % (r["id"], st))
        while True:
            while pending:
                for rid in sorted(pending):
                    done, r = run_terminal(a.repo, rid)
                    if done:
                        print("  ✔ run %s is conclusively terminal (%s, every job completed)" % (rid, r.get("conclusion")))
                        pending.discard(rid)
                        quiet.add(rid)
                if not pending:
                    break
                if not a.wait:
                    raise Refuse("%d release run(s) still not terminal (run or job still active): %s — rerun with --wait"
                                 % (len(pending), ", ".join(map(str, sorted(pending)))))
                time.sleep(a.poll_seconds)
            # Re-read the list: a new run, or a known run that no longer
            # reports completed (a re-run), must be judged the same way.
            again = [r for r in all_runs(a.repo, wf["id"]) if r["id"] not in quiet or r["status"] != "completed"]
            if not again:
                break
            for r in again:
                quiet.discard(r["id"])
                done, detail = run_terminal(a.repo, r["id"])
                if done:
                    quiet.add(r["id"])
                    continue
                if r.get("head_branch"):
                    tags = sorted(set(tags) | {r.get("head_branch")})
                if not a.wait:
                    raise Refuse("new or re-run release run %s appeared and is not terminal — rerun with --wait" % r["id"])
                pending.add(r["id"])
            if not pending:
                break
        releases = []
        for page in range(1, 51):
            chunk = get("/repos/%s/releases" % a.repo, "?per_page=100&page=%d" % page)
            if not isinstance(chunk, list):
                raise Refuse("release list is not a list")
            releases += chunk
            if len(chunk) < 100:
                break
        else:
            raise Refuse("release list does not end")
        leftover = []
        for rel in releases:
            if rel.get("tag_name") in tags or rel.get("draft"):
                if rel.get("draft"):
                    # Any draft is pipeline debris (the pipeline is the only
                    # draft creator) — a later invocation no longer knows
                    # which runs touched which tag, so drafts are judged
                    # repository-wide.
                    if a.delete_drafts:
                        st, _ = call("DELETE", "/repos/%s/releases/%d" % (a.repo, rel["id"]))
                        print("  draft %s (%s) deleted (HTTP %s)" % (rel["id"], rel.get("tag_name"), st))
                        if st != "204":
                            leftover.append(rel)
                    else:
                        leftover.append(rel)
                        print("  ⚠ draft %s for %s remains" % (rel["id"], rel.get("tag_name")))
                else:
                    print("  ⚠ %s is PUBLISHED (release %s) — it is the live release now; decide whether the emergency "
                          "is still needed and use a higher sequence if so" % (rel.get("tag_name"), rel["id"]))
        if leftover:
            raise Refuse("%d draft release(s) remain — reconcile them first (--delete-drafts)" % len(leftover))
    except Refuse as exc:
        print("✖ break-glass quiesce: %s — do NOT publish locally" % exc)
        return 1
    print("✔ CI is quiet: admission closed, no outstanding release run, no draft release. "
          "The local publisher still re-checks the live authenticated sequence right before publishing.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
