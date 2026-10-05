#!/usr/bin/env python3
"""Pre-publication gate for an app release (UT signing-in-CI plan §3.2).

Two modes, both fail closed (exit 1, nothing published):

  stage   Authenticate the envelope the PUBLISHING step is about to upload,
          with the committed key, and check it names exactly this release:
          channel, version, sequence, every platform URL ==
          <url-prefix for this version><filename>, and the sha256 + size of
          the exact file that will be uploaded. Then copy the verified files
          into a staging directory and make it read-only; only those paths
          are handed to the publisher.

            prepublish-verify.py stage --dist DIR --pub PEM --version V
                --sequence N --url-prefix 'https://…/download/v{version}/'
                --out STAGING [--channel briglia-ut] [--expect-file NAME]...
                [--extra PATH]... [--check-sidecars]

          Prints the staged asset paths, one per line, in upload order:
          platform files, extras, manifest.json, manifest.sig.json (last).

  draft   Run by publish-github-release.sh through PREPUBLISH_VERIFY after
          every upload and BEFORE the go-live PATCH. Reads the draft by
          release id and requires: still a draft, the right tag, the asset
          set exactly equal to the staged set, every asset "uploaded" with
          the staged size (and the staged sha256 when the API reports a
          digest), every asset's DOWNLOADED bytes equal to the staged copy,
          and the downloaded envelope authenticating with the committed key
          with a payload equal to the staged manifest.

            prepublish-verify.py draft <release-id>
            env: GH_TOKEN, REPO, REF_NAME, PREPUBLISH_STAGING, EXPECTED_PUB,
                 GH_API_URL (default https://api.github.com), CHANNEL

The draft check is not atomic against a separate administrator rewriting
draft assets between this read and the PATCH; that privileged-writer risk
is accepted and documented (plan §9, Codex round 2 answer 2).
Stdlib + curl + the committed verify-envelope.sh only.
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
VERIFY_ENVELOPE = os.path.join(HERE, "verify-envelope.sh")
MAX_ASSET_BYTES = 512 * 1024 * 1024


class GateError(Exception):
    pass


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def authenticate(envelope_path, pub, channel):
    """verify-envelope.sh with the committed key → authenticated payload bytes."""
    with tempfile.TemporaryDirectory(prefix="prepublish-") as work:
        out = os.path.join(work, "payload")
        p = subprocess.run([VERIFY_ENVELOPE, envelope_path, pub, channel, out],
                           capture_output=True, text=True)
        if p.returncode != 0:
            raise GateError("envelope %s does not authenticate with the committed key: %s"
                            % (envelope_path, (p.stdout + p.stderr).strip().splitlines()[-1:]))
        with open(out, "rb") as f:
            return f.read()


# ------------------------------------------------------------------ stage

def cmd_stage(a):
    dist = a.dist
    env_path = os.path.join(dist, "manifest.sig.json")
    man_path = os.path.join(dist, "manifest.json")
    for p in (env_path, man_path):
        if not os.path.isfile(p) or os.path.islink(p):
            raise GateError("missing or non-regular %s" % p)
    payload = authenticate(env_path, a.pub, a.channel)
    with open(man_path, "rb") as f:
        if f.read() != payload:
            raise GateError("dist/manifest.json differs from the authenticated envelope payload")
    m = json.loads(payload.decode("utf-8"))
    if m.get("channel") != a.channel:
        raise GateError("payload channel %r is not %s" % (m.get("channel"), a.channel))
    if m.get("version") != a.version:
        raise GateError("payload version %r is not the authorized version %s" % (m.get("version"), a.version))
    if m.get("sequence") != int(a.sequence) or isinstance(m.get("sequence"), bool):
        raise GateError("payload sequence %r is not the authorized sequence %s" % (m.get("sequence"), a.sequence))
    prefix = a.url_prefix.replace("{version}", a.version)
    platforms = m.get("platforms")
    if not isinstance(platforms, dict) or not platforms:
        raise GateError("payload lists no platforms")
    files = []
    for name, entry in sorted(platforms.items()):
        url = entry.get("url", "")
        if not url.startswith(prefix):
            raise GateError("%s: url %s is outside %s" % (name, url, prefix))
        filename = url[len(prefix):]
        if not filename or "/" in filename or filename in (".", ".."):
            raise GateError("%s: url does not end in a plain file name" % name)
        path = os.path.join(dist, filename)
        if not os.path.isfile(path) or os.path.islink(path):
            raise GateError("%s: the file to upload (%s) is missing or not a regular file" % (name, path))
        size = os.path.getsize(path)
        if size != entry.get("size") or sha256_file(path) != entry.get("sha256"):
            raise GateError("%s: %s does not match the signed sha256/size" % (name, filename))
        files.append(filename)
    if a.expect_file and sorted(a.expect_file) != sorted(files):
        raise GateError("signed platform files %s are not the expected %s" % (sorted(files), sorted(a.expect_file)))
    if os.path.exists(a.out):
        raise GateError("staging directory %s already exists" % a.out)
    os.makedirs(a.out)
    order = []
    for filename in files:
        shutil.copyfile(os.path.join(dist, filename), os.path.join(a.out, filename))
        order.append(filename)
    for extra in a.extra or []:
        name = os.path.basename(extra)
        if name in order or name in ("manifest.json", "manifest.sig.json"):
            raise GateError("extra asset %s collides with a signed asset" % name)
        shutil.copyfile(extra, os.path.join(a.out, name))
        order.append(name)
    if a.check_sidecars:
        for name in order:
            if name.endswith(".sha256"):
                target = name[:-len(".sha256")]
                if target not in files:
                    raise GateError("sidecar %s names no signed asset" % name)
                want = "%s  %s\n" % (sha256_file(os.path.join(a.out, target)), target)
                with open(os.path.join(a.out, name)) as f:
                    if f.read() != want:
                        raise GateError("sidecar %s does not match the staged %s" % (name, target))
    shutil.copyfile(man_path, os.path.join(a.out, "manifest.json"))
    shutil.copyfile(env_path, os.path.join(a.out, "manifest.sig.json"))
    order += ["manifest.json", "manifest.sig.json"]
    # Re-check the COPIES (what will actually be uploaded), then freeze them.
    for filename in files:
        entry = next(e for e in platforms.values() if e["url"].endswith("/" + filename))
        p = os.path.join(a.out, filename)
        if os.path.getsize(p) != entry["size"] or sha256_file(p) != entry["sha256"]:
            raise GateError("staged copy of %s does not match the signed sha256/size" % filename)
    if authenticate(os.path.join(a.out, "manifest.sig.json"), a.pub, a.channel) != payload:
        raise GateError("staged envelope differs from the verified one")
    for name in order:
        os.chmod(os.path.join(a.out, name), 0o444)
    os.chmod(a.out, 0o555)
    for name in order:
        print(os.path.join(a.out, name))
    print("✔ staged %d asset(s) for v%s sequence %s (envelope authenticated, hashes match)"
          % (len(order), a.version, a.sequence), file=sys.stderr)


# ------------------------------------------------------------------ draft

def curl(args, out=None):
    """Run curl; return (http_status, body_bytes or None)."""
    cmd = ["curl", "-sS", "-w", "%{http_code}"] + (["-o", out] if out else ["-o", "-"]) + args
    p = subprocess.run(cmd, capture_output=True)
    if out:
        status = p.stdout.decode(errors="replace")[-3:]
        return status, None
    status = p.stdout[-3:].decode(errors="replace")
    return status, p.stdout[:-3]


def api_json(api, token, path):
    status, body = curl(["-H", "Authorization: Bearer " + token, "-H", "Accept: application/vnd.github+json",
                         api + path])
    if status != "200":
        raise GateError("GET %s → HTTP %s" % (path, status))
    try:
        return json.loads(body.decode("utf-8"))
    except ValueError:
        raise GateError("GET %s → invalid JSON" % path)


def cmd_draft(a):
    token = os.environ.get("GH_TOKEN") or ""
    repo = os.environ.get("REPO") or ""
    tag = os.environ.get("REF_NAME") or ""
    staging = os.environ.get("PREPUBLISH_STAGING") or ""
    pub = os.environ.get("EXPECTED_PUB") or ""
    channel = os.environ.get("CHANNEL") or "briglia-ut"
    api = os.environ.get("GH_API_URL") or "https://api.github.com"
    for k, v in (("GH_TOKEN", token), ("REPO", repo), ("REF_NAME", tag),
                 ("PREPUBLISH_STAGING", staging), ("EXPECTED_PUB", pub)):
        if not v:
            raise GateError("%s is required" % k)
    if not a.release_id.isdigit():
        raise GateError("release id %r is not numeric" % a.release_id)
    staged = sorted(n for n in os.listdir(staging) if not n.startswith("."))
    if "manifest.sig.json" not in staged or "manifest.json" not in staged:
        raise GateError("staging directory lacks the manifest/envelope")
    rel = api_json(api, token, "/repos/%s/releases/%s" % (repo, a.release_id))
    if rel.get("draft") is not True:
        raise GateError("release %s is no longer a draft" % a.release_id)
    if rel.get("tag_name") != tag:
        raise GateError("draft %s is for tag %r, not %s" % (a.release_id, rel.get("tag_name"), tag))
    assets, page = [], 1
    while True:
        chunk = api_json(api, token, "/repos/%s/releases/%s/assets?per_page=100&page=%d" % (repo, a.release_id, page))
        if not isinstance(chunk, list):
            raise GateError("asset list is not a list")
        assets += chunk
        if len(chunk) < 100:
            break
        page += 1
        if page > 10:
            raise GateError("asset list does not end")
    names = [x.get("name") for x in assets]
    if len(names) != len(set(names)):
        raise GateError("draft has duplicate asset names: %s" % names)
    if sorted(names) != staged:
        raise GateError("draft asset set %s is not exactly the staged set %s" % (sorted(names), staged))
    with tempfile.TemporaryDirectory(prefix="prepublish-draft-") as work:
        for x in assets:
            name = x["name"]
            want = os.path.join(staging, name)
            size = os.path.getsize(want)
            if x.get("state") not in (None, "uploaded"):
                raise GateError("asset %s is in state %r" % (name, x.get("state")))
            if x.get("size") != size:
                raise GateError("asset %s: API size %r ≠ staged %d" % (name, x.get("size"), size))
            digest = x.get("digest")
            if digest and digest != "sha256:" + sha256_file(want):
                raise GateError("asset %s: API digest %s ≠ staged sha256" % (name, digest))
            if not str(x.get("id", "")).isdigit():
                raise GateError("asset %s has no numeric id" % name)
            got = os.path.join(work, name)
            status, _ = curl(["-L", "--max-filesize", str(min(size + 1, MAX_ASSET_BYTES)),
                              "-H", "Authorization: Bearer " + token, "-H", "Accept: application/octet-stream",
                              "%s/repos/%s/releases/assets/%s" % (api, repo, x["id"])], out=got)
            if status != "200" or not os.path.isfile(got):
                raise GateError("downloading draft asset %s → HTTP %s" % (name, status))
            if os.path.getsize(got) != size or sha256_file(got) != sha256_file(want):
                raise GateError("draft asset %s: uploaded bytes differ from the verified staging copy" % name)
        payload = authenticate(os.path.join(work, "manifest.sig.json"), pub, channel)
        with open(os.path.join(staging, "manifest.json"), "rb") as f:
            if payload != f.read():
                raise GateError("the draft's envelope payload is not the staged manifest")
    print("✔ pre-publication gate: draft %s holds exactly the %d verified asset(s), envelope authenticates"
          % (a.release_id, len(assets)))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="mode", required=True)
    s = sub.add_parser("stage")
    s.add_argument("--dist", required=True)
    s.add_argument("--pub", required=True)
    s.add_argument("--version", required=True)
    s.add_argument("--sequence", required=True)
    s.add_argument("--url-prefix", required=True)
    s.add_argument("--out", required=True)
    s.add_argument("--channel", default="briglia-ut")
    s.add_argument("--expect-file", action="append")
    s.add_argument("--extra", action="append")
    s.add_argument("--check-sidecars", action="store_true")
    d = sub.add_parser("draft")
    d.add_argument("release_id")
    a = ap.parse_args(argv)
    try:
        (cmd_stage if a.mode == "stage" else cmd_draft)(a)
    except (GateError, OSError, ValueError, KeyError) as exc:
        # stderr: stage mode's stdout is the upload list the caller captures
        print("✖ pre-publication verification (%s) failed: %s — nothing goes live" % (a.mode, exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
