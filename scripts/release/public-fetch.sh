#!/bin/bash
# Bounded, unauthenticated download of a PUBLIC release URL — the only way
# the release tooling reads the live channel, so what it sees is what a phone
# sees (no token, no API). Never fails by itself: prints the HTTP status
# (000 on a transport failure) and leaves the body in <out>.
#
#   public-fetch.sh <url> <out> [max-bytes (default 33554432)]
#
# Callers decide what a status means; authentication always follows (a 200
# proves nothing until verify-envelope.sh or a signed hash agrees).
set -uo pipefail
URL="${1:?url required}"
OUT="${2:?output path required}"
MAX="${3:-33554432}"
curl -sSL --max-filesize "$MAX" -o "$OUT" -w '%{http_code}' "$URL" 2>/dev/null || echo 000
