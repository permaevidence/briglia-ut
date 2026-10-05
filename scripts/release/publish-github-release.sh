#!/bin/bash
# Publish ONE immutable GitHub Release for a tag: assemble a draft, upload
# every asset with the signed envelope LAST, then flip the draft live in a
# single PATCH with explicit make_latest. Generic twin of briglia-cli's
# .github/scripts/publish-release.sh (same logic, assets passed in), used by
# scripts/publish_click.sh and exercised against a fake Releases API by
# scripts/publish_selftest.py.
#
# Env (required): GH_TOKEN, REPO (owner/name), REF_NAME (tag), VERSION,
#                 TITLE, ASSETS (newline-separated file paths; the LAST one
#                 must be the signed envelope manifest.sig.json),
#                 TARGET_COMMITISH (the exact reviewed commit SHA the tag
#                 must name)
#                 PREPUBLISH_VERIFY (MANDATORY pre-go-live gate: an executable
#                 run as `$PREPUBLISH_VERIFY draft <release-id>` after every
#                 upload and before the go-live PATCH, with this script's
#                 environment; it must read the draft's assets back and prove
#                 they are the verified bytes — scripts/release/prepublish-verify.py.
#                 Unset, not executable, failed or inconclusive → no PATCH,
#                 the draft stays unpublished, exit 1)
# Env (optional): GH_API_URL (default https://api.github.com),
#                 GH_UPLOADS_URL (default https://uploads.github.com)
#
# Tag binding: target_commitish is only a CREATION hint — GitHub ignores it
# whenever refs/tags/<REF_NAME> already exists, and the release's echoed
# target_commitish proves nothing. So the tag is resolved through the Git
# References API (resolve-tag-commit.sh, annotated tags followed): before
# the draft is created and again right before publication it must either
# not exist or already name TARGET_COMMITISH exactly; after publication it
# must name TARGET_COMMITISH exactly, or this script exits 1 so the caller
# records nothing and investigates.
#
# Exit 0 only when the release is CONFIRMED published (re-read from the API,
# draft=false). An ambiguous PATCH is re-checked: live → success; still a
# draft → reported failure, the draft is left for the next run's cleanup.
# The token only ever travels in a request header, never echoed.
set -euo pipefail
: "${GH_TOKEN:?GH_TOKEN is required}"
: "${REPO:?REPO is required}"
: "${REF_NAME:?REF_NAME is required}"
: "${VERSION:?VERSION is required}"
: "${TITLE:?TITLE is required}"
: "${ASSETS:?ASSETS is required}"
: "${TARGET_COMMITISH:?TARGET_COMMITISH is required (the reviewed commit SHA the tag must name)}"
[[ "$TARGET_COMMITISH" =~ ^[0-9a-f]{40}$ ]] || { echo "✖ TARGET_COMMITISH must be a full 40-hex commit SHA, not a branch name"; exit 1; }
: "${PREPUBLISH_VERIFY:?PREPUBLISH_VERIFY is required (the pre-go-live draft read-back gate)}"
[ -x "$PREPUBLISH_VERIFY" ] || { echo "✖ PREPUBLISH_VERIFY ($PREPUBLISH_VERIFY) is not executable — refusing to publish without the pre-go-live gate"; exit 1; }
API="${GH_API_URL:-https://api.github.com}"
UPLOADS="${GH_UPLOADS_URL:-https://uploads.github.com}"
RESOLVE_TAG="$(dirname "$0")/resolve-tag-commit.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

api() {
    local method="$1" url="$2"; shift 2
    BODY_FILE="$WORK/body.$$.$RANDOM"
    STATUS="$(curl -sS -o "$BODY_FILE" -w '%{http_code}' -X "$method" \
        -H "Authorization: Bearer $GH_TOKEN" \
        -H "Accept: application/vnd.github+json" \
        "$@" "$url" 2>/dev/null || echo 000)"
}
jget() { python3 -c 'import json,sys; v=json.load(open(sys.argv[1]))
for k in sys.argv[2].split("."): v=v[k]
print(v)' "$1" "$2"; }

# Tag binding (see header). `require_tag <when> <mode>`: mode absent-or-exact
# tolerates a missing tag (GitHub creates it at TARGET_COMMITISH on publish);
# mode exact requires it to exist. Any resolver failure is a refusal.
require_tag() {
    local when="$1" mode="$2" tag_commit
    tag_commit="$(GH_API_URL="$API" "$RESOLVE_TAG" "$REPO" "$REF_NAME")" || {
        echo "✖ cannot resolve refs/tags/$REF_NAME ($when) — refusing to continue"; exit 1; }
    if [ "$tag_commit" = "NONE" ]; then
        [ "$mode" = "absent-or-exact" ] || { echo "✖ refs/tags/$REF_NAME does not exist ($when) although the release is published"; exit 1; }
        echo "  tag ($when): absent — will be created at ${TARGET_COMMITISH:0:12}"
        return 0
    fi
    [ "$tag_commit" = "$TARGET_COMMITISH" ] || {
        echo "✖ refs/tags/$REF_NAME already names commit $tag_commit, not the reviewed HEAD $TARGET_COMMITISH ($when) — a pre-existing or stale tag; GitHub would keep it and silently ignore target_commitish. Delete/move the tag only after review, then rerun"; exit 1; }
    echo "  tag ($when): exists and names the reviewed HEAD ${TARGET_COMMITISH:0:12}"
}

# Every asset must exist before anything touches the API, envelope last.
LAST=""
while IFS= read -r asset; do
    [ -n "$asset" ] || continue
    [ -f "$asset" ] || { echo "✖ asset missing: $asset"; exit 1; }
    LAST="$asset"
done <<< "$ASSETS"
[ "$(basename "$LAST")" = "manifest.sig.json" ] || {
    echo "✖ the last asset must be the signed envelope manifest.sig.json (got $(basename "$LAST"))"; exit 1; }

# 1. A PUBLISHED release for this tag is immutable — republish is a hard
#    error, never a retry loop. (This endpoint never returns drafts.)
api GET "$API/repos/$REPO/releases/tags/$REF_NAME"
case "$STATUS" in
    200) echo "✖ a published release for $REF_NAME already exists — immutability forbids republish; cut a new version"; exit 1;;
    404) ;;
    *)   echo "✖ cannot determine whether $REF_NAME is already published (HTTP $STATUS) — refusing to guess"; exit 1;;
esac

# 2. Stale DRAFTS from a previously failed run are not immutable — remove
#    them so retries are idempotent.
page=1
while :; do
    api GET "$API/repos/$REPO/releases?per_page=100&page=$page"
    [ "$STATUS" = "200" ] || { echo "✖ listing releases failed (HTTP $STATUS)"; exit 1; }
    STALE="$(python3 -c 'import json,sys
rel=json.load(open(sys.argv[1])); tag=sys.argv[2]
print("\n".join(str(r["id"]) for r in rel if r.get("draft") and r.get("tag_name")==tag))
print("MORE" if len(rel)==100 else "END", file=sys.stderr)' "$BODY_FILE" "$REF_NAME" 2>"$WORK/more")"
    for stale in $STALE; do
        echo "deleting stale draft $stale"
        api DELETE "$API/repos/$REPO/releases/$stale"
        [ "$STATUS" = "204" ] || { echo "✖ deleting stale draft $stale failed (HTTP $STATUS)"; exit 1; }
    done
    [ "$(cat "$WORK/more")" = "MORE" ] || break
    page=$((page + 1))
done

# 3. The tag must be absent or already name the reviewed commit — then
#    create the draft and address it by ID from here on (a draft cannot be
#    resolved by tag).
require_tag "before draft" absent-or-exact
python3 -c 'import json,sys
req = {"tag_name": sys.argv[1], "draft": True, "name": sys.argv[2] + " " + sys.argv[3],
  "target_commitish": sys.argv[4],
  "body": "Signed release " + sys.argv[3] + ". Clients authenticate manifest.sig.json with the pinned Ed25519 key before trusting any asset."}
print(json.dumps(req))' \
    "$REF_NAME" "$TITLE" "$VERSION" "$TARGET_COMMITISH" > "$WORK/create.json"
api POST "$API/repos/$REPO/releases" -H "Content-Type: application/json" --data-binary @"$WORK/create.json"
[ "$STATUS" = "201" ] || { echo "✖ creating the draft release failed (HTTP $STATUS)"; exit 1; }
RELEASE_ID="$(jget "$BODY_FILE" id)"
[ "$(jget "$BODY_FILE" draft)" = "True" ] || { echo "✖ created release is not a draft — refusing to continue"; exit 1; }
echo "draft release $RELEASE_ID created for $REF_NAME"

# 4. Assets in order, the signed envelope LAST — stable metadata cannot
#    precede what it describes even inside the draft.
upload() {
    local file="$1" name
    name="$(basename "$file")"
    api POST "$UPLOADS/repos/$REPO/releases/$RELEASE_ID/assets?name=$name" \
        -H "Content-Type: application/octet-stream" --data-binary @"$file"
    [ "$STATUS" = "201" ] || {
        echo "✖ uploading $name failed (HTTP $STATUS) — draft $RELEASE_ID left unpublished; the old release stays latest"; exit 1; }
    echo "  ↑ $name"
}
while IFS= read -r asset; do
    [ -n "$asset" ] || continue
    upload "$asset"
done <<< "$ASSETS"

# 4b. Pre-go-live gate (mandatory): read the draft back by id and prove its
#     asset set and every asset's bytes are exactly the verified inputs, and
#     that its envelope authenticates. Anything else → no PATCH.
export GH_TOKEN REPO REF_NAME GH_API_URL="$API"
if ! "$PREPUBLISH_VERIFY" draft "$RELEASE_ID"; then
    echo "✖ pre-publication verification of draft $RELEASE_ID FAILED — NOT published; the draft stays unpublished (removed by the next run), the old release stays latest"
    exit 1
fi

# 5. Last look at the tag (it is created by THIS publish if absent; if it
#    appeared meanwhile it must already be ours), then atomic go-live;
#    immutability locks at this moment. make_latest is explicit — never
#    GitHub's default.
require_tag "before publish" absent-or-exact
api PATCH "$API/repos/$REPO/releases/$RELEASE_ID" -H "Content-Type: application/json" \
    --data-binary '{"draft":false,"make_latest":"true"}'
PATCH_STATUS="$STATUS"

# 6. Confirm from the API, whatever the PATCH said: only an observed
#    draft=false is success. (A PATCH can time out AFTER GitHub applied it.)
api GET "$API/repos/$REPO/releases/$RELEASE_ID"
if [ "$STATUS" = "200" ] && [ "$(jget "$BODY_FILE" draft)" = "False" ] \
   && [ "$(jget "$BODY_FILE" tag_name)" = "$REF_NAME" ]; then
    if [ "$PATCH_STATUS" != "200" ]; then
        echo "⚠ publish PATCH answered HTTP $PATCH_STATUS but the release IS published (confirmed by re-read)"
    fi
    # 7. The published tag must name the reviewed commit — resolved through
    #    the refs API, never inferred from the release's target_commitish.
    require_tag "after publish" exact
    echo "✔ published immutable release $REF_NAME (id $RELEASE_ID) at commit ${TARGET_COMMITISH:0:12}"
    echo "$RELEASE_ID" > "${RELEASE_ID_OUT:-/dev/null}"
    exit 0
fi
echo "✖ draft publication FAILED (PATCH HTTP $PATCH_STATUS, re-read HTTP $STATUS) — release $RELEASE_ID remains a draft; the old release stays latest"
exit 1
