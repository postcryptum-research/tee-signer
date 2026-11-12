#!/usr/bin/env bash
# Set, show or clear the owner-written hint of the ceremony enclave-signing key (C-SEC-1 hint rule).
# The hint is a plain `Hint: …` text line BEFORE the PEM block (OpenSSL skips leading text; verified:
# same public key, signing works); `scripts/ceremony-sign.sh` prints it before the passphrase prompt.
#   scripts/ceremony-key-hint.sh "password manager, entry tee-ceremony"   # set (the argument IS the hint text;
#   scripts/ceremony-key-hint.sh                                          #   without one the script asks for it)
#   scripts/ceremony-key-hint.sh --show | --clear                          # the passphrase is asked once when setting
# Setting asks the passphrase so that (a) it is checked to open THIS key and (b) the hint is refused if it
# contains the passphrase or the passphrase contains it (case-insensitive) — the same guard as owner-cli's
# check_hint. A hint says WHERE the passphrase is kept, never what it is or looks like (THREAT-MODEL §5:
# the hint is at-rest plaintext an exfiltrated file carries; "4 digits" / "same as the PIN" shrink the
# offline search the scrypt/AES bound relies on). The passphrase never reaches a command line.
set -euo pipefail
KEY=${CEREMONY_KEY:-$(cd "$(dirname "$0")/.." && pwd)/.local/ceremony/enclave-ceremony.pem}
PUB=$(cd "$(dirname "$0")/.." && pwd)/enclave/ceremony/ceremony_pub.pem
[ -f "$KEY" ] || { echo "no ceremony key at $KEY"; exit 1; }
pem_block() { sed -n '/^-----BEGIN/,$p' "$KEY"; }       # the PEM without any leading text lines
current() { grep -m1 '^Hint:' "$KEY" | sed 's/^Hint: *//' || true; }
case "${1:-}" in
  --show) h=$(current); echo "${h:-(no hint on the ceremony key)}"; exit 0;;
  --clear) T=$(mktemp "$KEY.XXXXXX"); pem_block > "$T"; chmod 600 "$T"; mv "$T" "$KEY"; echo "hint cleared"; exit 0;;
  "") read -r -p "hint text (where the passphrase is kept; shown before every prompt): " HINT_IN;;   # no argument: ask
  *) HINT_IN=$1;;
esac
HINT=$(printf '%s' "$HINT_IN" | sed 's/^ *//; s/ *$//')
[ -n "$HINT" ] || { echo "empty hint"; exit 1; }
[ "${#HINT}" -le 200 ] || { echo "hint too long (200 characters max)"; exit 1; }
case "$HINT" in *$'\n'*) echo "one line only"; exit 1;; esac
read -rs -p "passphrase of the ceremony key (to check the hint against it; never stored): " PASS; echo
# (a) the passphrase opens THIS key — passed on a file descriptor, never on the command line
openssl pkey -in "$KEY" -passin fd:3 -noout 3<<<"$PASS" 2>/dev/null || { echo "that passphrase does not open $KEY — nothing changed"; exit 1; }
# (b) containment, case-insensitive, both directions (owner-cli's check_hint)
hl=${HINT,,}; pl=${PASS,,}
if [[ "$hl" == *"$pl"* || "$pl" == *"$hl"* ]]; then echo "REFUSED: the hint contains the passphrase (or the passphrase contains the hint) — a hint says WHERE the passphrase is kept, never what it is"; exit 1; fi
T=$(mktemp "$KEY.XXXXXX"); { echo "Hint: $HINT"; pem_block; } > "$T"; chmod 600 "$T"
# the rewritten file still opens and still holds the pinned public key
openssl pkey -in "$T" -passin fd:3 -pubout 3<<<"$PASS" 2>/dev/null | diff -q - "$PUB" >/dev/null || { rm -f "$T"; echo "rewrite check failed (key or public key changed) — nothing changed"; exit 1; }
unset PASS
mv "$T" "$KEY"; echo "hint set on $KEY: $HINT"
