#!/bin/bash
# Re-verify a just-published app release through the PUBLIC path, byte for
# byte — shared by publish_click.sh (step 6) and the release-signed
# workflow's verify-production job.
#
# The public `latest` envelope is authenticated with the COMMITTED key
# first. GitHub's `latest` pointer lags a just-published release by up to a
# couple of minutes (Stage-7 rehearsal, 2026-09-01): an AUTHENTICATED
# previous state — a strictly lower sequence — means "not yet" and is
# waited out, bounded; anything else served is a hard stop, never waited
# out. Then: the public envelope and click must be byte-identical to the
# candidate; the release must be non-draft and immutable; refs/tags/<tag>
# (resolved through the refs API) must name EXPECTED_COMMIT.
#
# Env (required): REPO, VERSION, SEQUENCE, EXPECTED_PUB, CANDIDATE_ENVELOPE,
#                 CANDIDATE_CLICK, EXPECTED_COMMIT (40-hex), GH_TOKEN (read)
# Env (optional): CHANNEL (briglia-ut), GH_API_URL, LIVE_ENVELOPE_URL,
#                 PUBLIC_DOWNLOAD_BASE, RELEASE_ID (must match when given),
#                 PUBLIC_RETRY_SLEEP (5), PUBLIC_PROPAGATION_ATTEMPTS (60)
set -euo pipefail
: "${REPO:?}"; : "${VERSION:?}"; : "${SEQUENCE:?}"; : "${EXPECTED_PUB:?}"
: "${CANDIDATE_ENVELOPE:?}"; : "${CANDIDATE_CLICK:?}"; : "${EXPECTED_COMMIT:?}"; : "${GH_TOKEN:?}"
CHANNEL="${CHANNEL:-briglia-ut}"
API="${GH_API_URL:-https://api.github.com}"
LIVE_URL="${LIVE_ENVELOPE_URL:-https://github.com/$REPO/releases/latest/download/manifest.sig.json}"
DOWNLOAD_BASE="${PUBLIC_DOWNLOAD_BASE:-https://github.com/$REPO/releases/download}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TAG="v$VERSION"
FILENAME="$(basename "$CANDIDATE_CLICK")"
WHICH="release ${RELEASE_ID:-$TAG}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fetch_public() {  # url out
    local url="$1" out="$2" attempt status
    for attempt in 1 2 3 4 5 6 7 8 9 10 11 12; do
        status="$("$HERE/public-fetch.sh" "$url" "$out" 33554432)"
        [ "$status" = "200" ] && return 0
        sleep "${PUBLIC_RETRY_SLEEP:-5}"
    done
    echo "✖ public fetch of $url failed (last HTTP $status)"; return 1
}
PROPAGATION_ATTEMPTS="${PUBLIC_PROPAGATION_ATTEMPTS:-60}"   # × PUBLIC_RETRY_SLEEP (5s) = 5 minutes
attempt=0
while :; do
    fetch_public "$LIVE_URL" "$WORK/public.sig.json"
    # Authenticate FIRST: identity with the candidate is only meaningful for
    # bytes the committed key vouches for.
    if "$HERE/verify-envelope.sh" "$WORK/public.sig.json" "$EXPECTED_PUB" "$CHANNEL" "$WORK/public-payload.json" >/dev/null 2>&1; then
        cmp -s "$WORK/public.sig.json" "$CANDIDATE_ENVELOPE" && break
        PUB_SEQ="$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['sequence'])" "$WORK/public-payload.json")"
        PUB_VER="$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['version'])" "$WORK/public-payload.json")"
        [[ "$PUB_SEQ" =~ ^[1-9][0-9]*$ ]] && [ "$PUB_SEQ" -lt "$SEQUENCE" ] || {
            echo "✖ the public LATEST envelope authenticates but is NOT this release (v$PUB_VER sequence $PUB_SEQ; ours v$VERSION sequence $SEQUENCE) — a sibling publication got ahead; $WHICH is live but NOT recorded; investigate before anything else"; exit 1; }
        WHAT="the previous release (authenticated v$PUB_VER, sequence $PUB_SEQ)"
    else
        echo "✖ the public LATEST envelope is neither this release nor an authenticated previous state — $WHICH is live but NOT recorded; investigate before anything else"; exit 1
    fi
    attempt=$((attempt + 1))
    [ "$attempt" -lt "$PROPAGATION_ATTEMPTS" ] || {
        echo "✖ the public LATEST still serves $WHAT after $PROPAGATION_ATTEMPTS attempts — $WHICH ($TAG) is live and immutable but NOT recorded; once https://github.com/$REPO/releases/latest points at $TAG, re-verify and record it by hand (RELEASE_RUNBOOKS.md)"; exit 1; }
    echo "  …latest still serves $WHAT — waiting for GitHub's latest pointer (attempt $attempt)"
    sleep "${PUBLIC_RETRY_SLEEP:-5}"
done
fetch_public "$DOWNLOAD_BASE/$TAG/$FILENAME" "$WORK/public.click"
cmp -s "$WORK/public.click" "$CANDIDATE_CLICK" || { echo "✖ the public click differs from the built one"; exit 1; }
REL_STATUS="$(curl -sS -o "$WORK/rel.json" -w '%{http_code}' -H "Authorization: Bearer $GH_TOKEN" \
    -H "Accept: application/vnd.github+json" "$API/repos/$REPO/releases/tags/$TAG" 2>/dev/null || echo 000)"
[ "$REL_STATUS" = "200" ] || { echo "✖ cannot read the published release (HTTP $REL_STATUS)"; exit 1; }
python3 - "$WORK/rel.json" "${RELEASE_ID:-}" <<'PYEOF'
import json, sys
rel = json.load(open(sys.argv[1]))
if sys.argv[2]:
    assert str(rel.get("id")) == sys.argv[2], "release id mismatch"
assert rel.get("draft") is False, "release is still a draft"
assert rel.get("immutable") is True, "release is NOT immutable — enable immutable releases on the repository"
PYEOF
# Independent tag binding check: the published tag, resolved through the
# refs API (never the release's target_commitish echo), must name the
# reviewed commit.
TAG_COMMIT="$(GH_API_URL="$API" "$HERE/resolve-tag-commit.sh" "$REPO" "$TAG")" || {
    echo "✖ cannot resolve refs/tags/$TAG after publication — NOT recorded; investigate"; exit 1; }
[ "$TAG_COMMIT" = "$EXPECTED_COMMIT" ] || {
    echo "✖ refs/tags/$TAG names commit $TAG_COMMIT, not the reviewed HEAD $EXPECTED_COMMIT — the published release is bound to the wrong commit; NOT recorded; investigate before anything else"; exit 1; }
echo "✔ public state verified: $TAG immutable, tag → ${EXPECTED_COMMIT:0:12}, envelope + click byte-identical"
