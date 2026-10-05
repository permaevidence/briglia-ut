#!/usr/bin/env python3
"""The app channel's release manifest generator — extracted unchanged from
scripts/publish_click.sh so the local publisher and the release-signed
workflow emit byte-identical manifests for the same inputs.

    build-manifest.py <version> <sequence> <click-url> <sha256> <size> [published-at] [expires-days]

published-at: "%Y-%m-%dT%H:%M:%SZ" (default: now, UTC); expires-days: 180.
Writes the manifest JSON (indent 2, sorted keys, trailing newline) to stdout.
"""
import datetime
import json
import sys


def main(argv):
    if len(argv) < 5:
        sys.exit(__doc__)
    version, sequence, url, sha, size = argv[:5]
    published_at = argv[5] if len(argv) > 5 else ""
    days = argv[6] if len(argv) > 6 and argv[6] else "180"
    now = (datetime.datetime.strptime(published_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
           if published_at else datetime.datetime.now(datetime.timezone.utc))
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    print(json.dumps({
        "channel": "briglia-ut",
        "expires": (now + datetime.timedelta(days=int(days))).strftime(fmt),
        "platforms": {"click": {"sha256": sha, "size": int(size), "url": url}},
        "published": now.strftime(fmt),
        "schema": 1,
        "sequence": int(sequence),
        "version": version,
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main(sys.argv[1:])
