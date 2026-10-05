#!/usr/bin/env python3
"""Credential-free candidate verification for an app release (UT
signing-in-CI plan §3.2 a–f). Runs in the release-signed workflow's
verify-candidate job — no signing secret, read-only token — and in the
selftests against a fake channel.

  (a) the candidate envelope authenticates with the COMMITTED key and its
      payload is exactly the assembled manifest bytes;
  (b) the candidate click's OWN verifier (py/release_verify.py extracted
      from the built click's data.tar.gz) accepts the envelope under its
      production APP_POLICY, the sequence is the build's own
      APP_RELEASE_SEQUENCE and the version is the tag;
  (c) the verifier phones run TODAY, taken from the shipped bytes: the live
      envelope is authenticated with the committed key, the live click is
      downloaded and checked against its signed sha256 + size, its
      py/release_verify.py is extracted and must equal
      `git show <live commit>:py/release_verify.py` (commit pinned, not the
      tag name); that verifier must accept the candidate under its own
      production policy with floor = the live sequence;
  (d) the pinned v0.8.5 verifier fixture (file + committed sha256) accepts
      the candidate with floor = its own APP_RELEASE_SEQUENCE, so the 0.8.5
      population stays covered after `latest` moves on;
  (e) app identity unchanged vs the live click: package name,
      architecture, framework, maintainer, hooks (paths) and the apparmor
      file content; only the version may differ;
  (f) click sha256 + size == the authenticated manifest.

    verify-candidate.py --click C --manifest M --envelope E --pub PEM
        --version V --sequence N --live-commit SHA [--repo-root .]
        [--live-envelope-url URL] [--fixture PATH --fixture-sha256 HEX]
        [--channel briglia-ut]

Public downloads go through scripts/release/public-fetch.sh (no token).
Exit 0 only if every check passes; every failure names the check.
"""

import argparse
import gzip
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PUBLIC_FETCH = os.path.join(HERE, "public-fetch.sh")
VERIFY_ENVELOPE = os.path.join(HERE, "verify-envelope.sh")
IDENTITY_FIELDS = ("name", "architecture", "framework", "maintainer", "hooks")


class CandidateError(Exception):
    pass


# ------------------------------------------------------------ click files

def ar_members(data):
    if not data.startswith(b"!<arch>\n"):
        raise CandidateError("not an ar archive")
    out, pos = {}, 8
    while pos < len(data):
        header = data[pos:pos + 60]
        if len(header) < 60 or header[58:60] != b"`\n":
            raise CandidateError("malformed ar header")
        name = header[:16].decode("ascii").strip().rstrip("/")
        size = int(header[48:58].decode("ascii").strip())
        out[name] = data[pos + 60:pos + 60 + size]
        pos += 60 + size + (size % 2)
    return out


def tar_files(gz_bytes):
    raw = gzip.decompress(gz_bytes)
    files = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tar:
        for m in tar.getmembers():
            if m.isfile():
                name = m.name[2:] if m.name.startswith("./") else m.name
                files[name] = tar.extractfile(m).read()
    return files


def click_parts(data):
    members = ar_members(data)
    for need in ("debian-binary", "control.tar.gz", "data.tar.gz"):
        if need not in members:
            raise CandidateError("click lacks %s" % need)
    return tar_files(members["control.tar.gz"]), tar_files(members["data.tar.gz"])


def identity(data):
    control, payload = click_parts(data)
    try:
        manifest = json.loads(control["manifest"].decode("utf-8"))
    except (KeyError, ValueError):
        raise CandidateError("click control area has no valid manifest")
    ident = {k: manifest.get(k) for k in IDENTITY_FIELDS}
    hooks = manifest.get("hooks") or {}
    apparmor = {}
    for app, h in sorted(hooks.items()):
        path = (h or {}).get("apparmor")
        if not path or path not in payload:
            raise CandidateError("hook %s: apparmor file %r missing from the click" % (app, path))
        apparmor[app] = hashlib.sha256(payload[path]).hexdigest()
        if (h or {}).get("desktop") and h["desktop"] not in payload:
            raise CandidateError("hook %s: desktop file %r missing from the click" % (app, h["desktop"]))
    ident["apparmor_sha256"] = apparmor
    return ident, manifest.get("version"), payload


def load_verifier(source_bytes, label):
    d = tempfile.mkdtemp(prefix="verifier-%s-" % label)
    path = os.path.join(d, "release_verify.py")
    with open(path, "wb") as f:
        f.write(source_bytes)
    spec = importlib.util.spec_from_file_location("release_verify_" + label, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run_verifier(mod, envelope, floor, version, sequence, label):
    """The phone's code path: verify_envelope under the module's own
    production APP_POLICY, then the floor the device would hold."""
    try:
        m = mod.verify_envelope(envelope, mod.APP_POLICY)
    except mod.ReleaseVerifyError as exc:
        raise CandidateError("%s verifier REJECTS the candidate: %s" % (label, exc))
    effective = max(int(mod.APP_POLICY.min_sequence), int(floor))
    if not m["sequence"] > effective:
        raise CandidateError("%s verifier: sequence %d is not above its floor %d" % (label, m["sequence"], effective))
    if (m["version"], m["sequence"]) != (version, sequence):
        raise CandidateError("%s verifier: accepted v%s seq %d, expected v%s seq %d"
                             % (label, m["version"], m["sequence"], version, sequence))
    return m


def fetch(url, out, limit):
    status = subprocess.run([PUBLIC_FETCH, url, out, str(limit)], capture_output=True, text=True).stdout.strip()
    if status != "200":
        raise CandidateError("public fetch of %s → HTTP %s" % (url, status))
    with open(out, "rb") as f:
        return f.read()


def authenticate(path, pub, channel):
    with tempfile.TemporaryDirectory(prefix="vc-") as work:
        out = os.path.join(work, "payload")
        p = subprocess.run([VERIFY_ENVELOPE, path, pub, channel, out], capture_output=True, text=True)
        if p.returncode != 0:
            raise CandidateError("%s does not authenticate with the committed key" % path)
        with open(out, "rb") as f:
            return f.read()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--click", required=True)
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--envelope", required=True)
    ap.add_argument("--pub", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--sequence", required=True, type=int)
    ap.add_argument("--live-commit", required=True)
    ap.add_argument("--repo-root", default=".")
    ap.add_argument("--live-envelope-url")
    ap.add_argument("--fixture")
    ap.add_argument("--fixture-sha256")
    ap.add_argument("--channel", default="briglia-ut")
    a = ap.parse_args(argv)
    step = "setup"
    try:
        with open(a.click, "rb") as f:
            click = f.read()
        with open(a.envelope, "rb") as f:
            envelope = f.read()
        with open(a.manifest, "rb") as f:
            manifest_bytes = f.read()

        step = "(a) committed-key authentication"
        payload = authenticate(a.envelope, a.pub, a.channel)
        if payload != manifest_bytes:
            raise CandidateError("authenticated payload differs from the assembled manifest")
        signed = json.loads(payload.decode("utf-8"))
        print("✔ (a) envelope authenticates with the committed key; payload == assembled manifest")

        step = "(f) artifact hash"
        entry = (signed.get("platforms") or {}).get("click") or {}
        if set(signed.get("platforms") or {}) != {"click"}:
            raise CandidateError("manifest platforms are %s, expected exactly {click}" % sorted(signed.get("platforms") or {}))
        if entry.get("sha256") != hashlib.sha256(click).hexdigest() or entry.get("size") != len(click):
            raise CandidateError("click sha256/size differ from the authenticated manifest")
        if not entry.get("url", "").endswith("/v%s/%s" % (a.version, os.path.basename(a.click))):
            raise CandidateError("signed click URL %s does not name v%s/%s" % (entry.get("url"), a.version, os.path.basename(a.click)))
        print("✔ (f) click sha256 + size match the authenticated manifest")

        step = "(b) candidate's own verifier"
        cand_ident, cand_version, cand_payload = identity(click)
        if cand_version != a.version:
            raise CandidateError("click manifest version %r is not the tag version %s" % (cand_version, a.version))
        cand = load_verifier(cand_payload["py/release_verify.py"], "candidate")
        if int(cand.APP_RELEASE_SEQUENCE) != a.sequence:
            raise CandidateError("candidate APP_RELEASE_SEQUENCE %s is not the signed sequence %d"
                                 % (cand.APP_RELEASE_SEQUENCE, a.sequence))
        run_verifier(cand, envelope, 0, a.version, a.sequence, "candidate")
        print("✔ (b) the candidate click's own verifier accepts it under its production APP_POLICY")

        step = "(c) live phones' verifier"
        live_url = a.live_envelope_url or cand.APP_POLICY.envelope_url
        work = tempfile.mkdtemp(prefix="vc-live-")
        fetch(live_url, os.path.join(work, "live.sig.json"), 131072)
        live_payload = json.loads(authenticate(os.path.join(work, "live.sig.json"), a.pub, a.channel).decode("utf-8"))
        live_entry = live_payload["platforms"]["click"]
        live_click = fetch(live_entry["url"], os.path.join(work, "live.click"), 64 * 1024 * 1024)
        if hashlib.sha256(live_click).hexdigest() != live_entry["sha256"] or len(live_click) != live_entry["size"]:
            raise CandidateError("the live click does not match its signed sha256/size")
        live_ident, live_version, live_files = identity(live_click)
        if live_version != live_payload["version"]:
            raise CandidateError("live click version %r ≠ live manifest %r" % (live_version, live_payload["version"]))
        shipped = live_files.get("py/release_verify.py")
        p = subprocess.run(["git", "-C", a.repo_root, "show", "%s:py/release_verify.py" % a.live_commit],
                           capture_output=True)
        if p.returncode != 0:
            raise CandidateError("cannot read py/release_verify.py at live commit %s" % a.live_commit)
        if shipped != p.stdout:
            raise CandidateError("the live click's verifier differs from py/release_verify.py at its commit %s"
                                 % a.live_commit[:12])
        run_verifier(load_verifier(shipped, "live"), envelope, live_payload["sequence"], a.version, a.sequence, "live v%s" % live_version)
        print("✔ (c) the verifier shipped in live v%s (seq %d, == source at %s) accepts it above floor %d"
              % (live_version, live_payload["sequence"], a.live_commit[:12], live_payload["sequence"]))

        step = "(d) pinned v0.8.5 verifier"
        if a.fixture:
            with open(a.fixture, "rb") as f:
                fixture = f.read()
            if hashlib.sha256(fixture).hexdigest() != (a.fixture_sha256 or "").strip():
                raise CandidateError("fixture %s does not match its pinned sha256" % a.fixture)
            fx = load_verifier(fixture, "fixture")
            run_verifier(fx, envelope, int(fx.APP_RELEASE_SEQUENCE), a.version, a.sequence, "pinned fixture")
            print("✔ (d) the pinned verifier fixture accepts it above floor %d" % int(fx.APP_RELEASE_SEQUENCE))
        else:
            raise CandidateError("no pinned verifier fixture given")

        step = "(e) app identity"
        diffs = [k for k in cand_ident if cand_ident[k] != live_ident.get(k)]
        if diffs:
            raise CandidateError("app identity changed vs live v%s: %s" % (live_version, ", ".join(diffs)))
        print("✔ (e) app identity unchanged vs live v%s (name, architecture, framework, maintainer, hooks, apparmor)"
              % live_version)
    except (CandidateError, OSError, ValueError, KeyError) as exc:
        print("✖ candidate verification %s failed: %s" % (step, exc))
        return 1
    print("✔ candidate v%s sequence %d verified" % (a.version, a.sequence))
    return 0


if __name__ == "__main__":
    sys.exit(main())
