#!/bin/bash
# Owner restore test (UT signing-in-CI plan §5 step 4, MANDATORY before any
# Mac key material or Keychain passphrase is deleted). For each encrypted
# key backup on the OFFLINE stick: read the passphrase silently (pasted
# from the password manager — never taken from the Keychain, never an
# argument, never logged), decrypt IN MEMORY, derive the public key, compare
# it with the committed expected public key, print only MATCH / NO MATCH.
# Nothing is written to disk; the decrypted key only ever lives in a pipe.
#
#   restore-check.sh <usb-backup-dir>
#
# The stick holds <keyId>.priv.pem.enc (openssl enc -aes-256-cbc -pbkdf2
# -iter 600000, the ceremony's parameters). Expected keys:
#   CLI: briglia-cli/.github/release-keys/briglia-cli-release.pub.pem
#        (keyId suffix 94d967bae0867c2e; file on the stick: ada-cli-release-v1-…)
#   UT:  briglia-ut/.release-keys/briglia-ut-release.pub.pem (suffix 7bb0163ac16c5cb3)
# Env overrides (selftest only): EXPECTED_CLI_PUB, EXPECTED_UT_PUB, CLI_SUFFIX, UT_SUFFIX, OPENSSL_BIN.
# Exit 0 only if BOTH keys say MATCH.
set -uo pipefail
DIR="${1:?usage: restore-check.sh <usb-backup-dir>}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/openssl-resolve.sh"
resolve_openssl >/dev/null 2>&1 || { echo "✖ no Ed25519-capable openssl"; exit 2; }
CLI_PUB="${EXPECTED_CLI_PUB:-$HOME/Desktop/briglia-cli/.github/release-keys/briglia-cli-release.pub.pem}"
UT_PUB="${EXPECTED_UT_PUB:-$HERE/../../.release-keys/briglia-ut-release.pub.pem}"
fail=0
check_one() {  # label suffix expected-pub
    local label="$1" suffix="$2" pub="$3" enc want got pass
    enc="$(ls "$DIR"/*-release-v1-"$suffix".priv.pem.enc 2>/dev/null | head -n 1)"
    if [ -z "$enc" ] || [ ! -f "$pub" ]; then
        echo "$label: NO MATCH (backup *-$suffix.priv.pem.enc or expected key not found)"; fail=1; return
    fi
    want="$("$OPENSSL" pkey -pubin -in "$pub" -outform DER 2>/dev/null | "$OPENSSL" dgst -sha256 -hex | awk '{print $NF}')"
    printf '%s passphrase (input hidden): ' "$label" >&2
    IFS= read -rs pass; echo >&2
    # The passphrase reaches openssl on its stdin through the printf BUILTIN:
    # never an argument, never an environment variable of a child process.
    got="$(printf '%s\n' "$pass" | "$OPENSSL" enc -d -aes-256-cbc -pbkdf2 -iter 600000 -pass stdin -in "$enc" 2>/dev/null \
            | "$OPENSSL" pkey -pubout -outform DER 2>/dev/null | "$OPENSSL" dgst -sha256 -hex | awk '{print $NF}')"
    pass=""
    if [ -n "$want" ] && [ "$got" = "$want" ]; then
        echo "$label: MATCH"
    else
        echo "$label: NO MATCH"; fail=1
    fi
}
check_one "CLI key" "${CLI_SUFFIX:-94d967bae0867c2e}" "$CLI_PUB"
check_one "UT key" "${UT_SUFFIX:-7bb0163ac16c5cb3}" "$UT_PUB"
[ "$fail" = 0 ] && echo "✔ both backups restore to the committed keys" || echo "✖ do NOT delete anything — at least one backup did not restore"
exit "$fail"
