#!/usr/bin/env bash
# Run ON THE OPERATOR MACHINE (dev: this laptop). Fetch build/enclave_hash.hex of a ceremony build
# from the build host, sign it with the offline ceremony key (the only step that touches it), and
# push signature.hex back for `PHASE=catsig`. REQ-r6 §3.
#   scripts/ceremony-sign.sh <build-out-dir-on-the-host>   e.g. ~/tee-signer-out/build-5
set -euo pipefail
OUT=${1:?build output dir on the build host}
R=$(cd "$(dirname "$0")/.." && pwd); [ -f "$R/.local/hosts.env" ] && . "$R/.local/hosts.env"   # TEE_BUILD_HOST (gitignored)
HOST=${BUILD_HOST:-${TEE_BUILD_HOST:?set TEE_BUILD_HOST=user@host of the SGX build box, e.g. in .local/hosts.env}}
KEY=${CEREMONY_KEY:-$HOME/llm-btcpay-tee/.local/ceremony/enclave-ceremony.pem}
PUB=$(cd "$(dirname "$0")/.." && pwd)/enclave/ceremony/ceremony_pub.pem
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
# an owner-written reminder of WHERE the passphrase is kept may precede the PEM block (`Hint: …`, a plain text
# line openssl skips, like the Bag Attributes of a PKCS#12 export) — shown before the prompt. Add one with
#   { echo "Hint: <where it is kept>"; cat "$KEY"; } > "$KEY.new" && mv "$KEY.new" "$KEY" && chmod 600 "$KEY"
H=$(grep -m1 '^Hint:' "$KEY" 2>/dev/null || true); [ -n "$H" ] && echo "$H (ceremony key)"
scp -q "$HOST:$OUT/enclave_hash.hex" "$T/enclave_hash.hex"
echo "enclave_hash.hex: $(stat -c %s "$T/enclave_hash.hex") bytes, sha256 $(sha256sum "$T/enclave_hash.hex" | cut -c1-16)…"
if [ -n "${CEREMONY_PASS:-}" ]; then
  openssl dgst -sha256 -sign "$KEY" -passin "pass:$CEREMONY_PASS" -out "$T/signature.hex" "$T/enclave_hash.hex"
else
  openssl dgst -sha256 -sign "$KEY" -out "$T/signature.hex" "$T/enclave_hash.hex"
fi
openssl dgst -sha256 -verify "$PUB" -signature "$T/signature.hex" "$T/enclave_hash.hex" >/dev/null && echo "signature verifies under the pinned public key"
scp -q "$T/signature.hex" "$HOST:$OUT/signature.hex"
echo "signature.hex pushed to $HOST:$OUT — now run PHASE=catsig on the build host"
