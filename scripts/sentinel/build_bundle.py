#!/usr/bin/env python3
"""Build Sentinel's two release assets, reproducibly (off-Mac watcher plan §11).

    python3 scripts/sentinel/build_bundle.py OUT_DIR [--version X.Y.Z]

Writes
  OUT_DIR/briglia-sentinel-<version>.pyz   the code (zip: fixed timestamps,
                                           sorted entries, fixed modes)
  OUT_DIR/install_sentinel.py              the one file Matteo downloads;
                                           it embeds the version and the
                                           bundle's sha256 and fetches the
                                           bundle from the SAME immutable
                                           release (never from an input)

The version defaults to the app version in manifest.json: Sentinel ships as
two extra assets of a normal phone-approved UT release. Building twice — on
any machine — gives byte-identical files.
"""

import argparse
import hashlib
import io
import json
import os
import re
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
FILES = [  # (source, name inside the bundle)
    ("scripts/release_watch.py", "release_watch.py"),
    ("scripts/watch_audit.py", "watch_audit.py"),
    ("scripts/sentinel_site.py", "sentinel_site.py"),
    ("scripts/release_heartbeat.py", "release_heartbeat.py"),
    ("py/release_verify.py", "py/release_verify.py"),
]
FIXED_DATE = (1980, 1, 1, 0, 0, 0)
RELEASE_BASE = "https://github.com/permaevidence/briglia-ut/releases/download/v%s/"


def build_pyz(version):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        entries = [(name, open(os.path.join(REPO, src), "rb").read()) for src, name in FILES]
        entries.append(("SENTINEL_VERSION", (version + "\n").encode()))
        for name, data in sorted(entries):
            info = zipfile.ZipInfo(name, date_time=FIXED_DATE)
            info.external_attr = (0o100644 << 16)
            info.create_system = 3
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    return buf.getvalue()


def build_installer(version, bundle_sha):
    src = open(os.path.join(HERE, "install_sentinel.py")).read()
    for ph, val in (("@SENTINEL_VERSION@", version), ("@BUNDLE_SHA256@", bundle_sha)):
        if src.count(ph) != 1:
            raise SystemExit("installer template must contain %s exactly once" % ph)
        src = src.replace(ph, val)
    return src.encode()


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--version")
    a = ap.parse_args(argv)
    version = a.version or json.load(open(os.path.join(REPO, "manifest.json")))["version"]
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise SystemExit("bad version %r" % version)
    os.makedirs(a.out, exist_ok=True)
    pyz = build_pyz(version)
    sha = hashlib.sha256(pyz).hexdigest()
    with open(os.path.join(a.out, "briglia-sentinel-%s.pyz" % version), "wb") as f:
        f.write(pyz)
    inst = build_installer(version, sha)
    with open(os.path.join(a.out, "install_sentinel.py"), "wb") as f:
        f.write(inst)
    print("briglia-sentinel-%s.pyz %s" % (version, sha))
    print("install_sentinel.py %s" % hashlib.sha256(inst).hexdigest())
    return 0


if __name__ == "__main__":
    sys.exit(main())
