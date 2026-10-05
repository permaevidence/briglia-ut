#!/bin/bash
# Supersession gate, shared by publish_click.sh (twice: before the build and
# right before the release is created) and by the release-signed workflow
# (authorize, and again inside publish).
#
# The LIVE envelope must authenticate with the COMMITTED key and carry a
# sequence strictly lower than ours. An absent live envelope is a refusal
# (the signed app channel was bootstrapped once, v0.7.4, and never restarts
# from nothing); anything served that does not authenticate is a hard stop,
# never "absent".
#
# Env (required): SEQUENCE        candidate sequence (positive integer)
#                 EXPECTED_PUB    committed public key PEM
#                 LIVE_URL        …/releases/latest/download/manifest.sig.json
# Env (optional): CHANNEL         default briglia-ut
#                 WHEN            label for messages (default "check")
#                 LIVE_OUT        file to append live_version=/live_sequence= to
#                 LIVE_PAYLOAD_OUT  where to copy the authenticated live payload
set -euo pipefail
: "${SEQUENCE:?SEQUENCE is required}"
: "${EXPECTED_PUB:?EXPECTED_PUB is required}"
: "${LIVE_URL:?LIVE_URL is required}"
CHANNEL="${CHANNEL:-briglia-ut}"
WHEN="${WHEN:-check}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ "$SEQUENCE" =~ ^[1-9][0-9]*$ ]] || { echo "✖ candidate sequence '$SEQUENCE' is not a positive integer"; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
STATUS="$("$HERE/public-fetch.sh" "$LIVE_URL" "$WORK/live.sig.json" 131072)"
case "$STATUS" in
    200)
        "$HERE/verify-envelope.sh" "$WORK/live.sig.json" "$EXPECTED_PUB" "$CHANNEL" "$WORK/live-payload.json" >/dev/null 2>&1 || {
            echo "✖ the LIVE envelope does not authenticate against the committed key — hard stop (never treated as absent)"; exit 1; }
        ;;
    404)
        echo "✖ no live signed release reachable at $LIVE_URL — refusing (bootstrap retired after v0.7.4; publishing never restarts from nothing)"; exit 1;;
    *)  echo "✖ cannot read the live envelope (HTTP $STATUS) — refusing to guess"; exit 1;;
esac
read -r LIVE_SEQ LIVE_VER < <(python3 - "$WORK/live-payload.json" "$CHANNEL" <<'PYEOF'
import json, re, sys
m = json.load(open(sys.argv[1]))
seq, ver = m.get("sequence"), m.get("version")
if m.get("channel") != sys.argv[2] or isinstance(seq, bool) or not isinstance(seq, int) or seq < 1 \
        or not isinstance(ver, str) or not re.fullmatch(r"\d+\.\d+\.\d+", ver):
    print("BAD BAD")
else:
    print(seq, ver)
PYEOF
)
[ "$LIVE_SEQ" != "BAD" ] || { echo "✖ the authenticated live payload has no valid channel/sequence/version"; exit 1; }
echo "  live ($WHEN): v$LIVE_VER sequence $LIVE_SEQ"
[ "$SEQUENCE" -gt "$LIVE_SEQ" ] || {
    echo "✖ superseded ($WHEN): sequence $SEQUENCE is not greater than live $LIVE_SEQ — bump APP_RELEASE_SEQUENCE"; exit 1; }
if [ -n "${LIVE_OUT:-}" ]; then
    { echo "live_version=$LIVE_VER"; echo "live_sequence=$LIVE_SEQ"; } >> "$LIVE_OUT"
fi
if [ -n "${LIVE_PAYLOAD_OUT:-}" ]; then
    cp "$WORK/live-payload.json" "$LIVE_PAYLOAD_OUT"
fi
