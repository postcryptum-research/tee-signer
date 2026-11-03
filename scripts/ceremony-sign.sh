#!/usr/bin/env bash
# Run ON THE OPERATOR MACHINE (dev: this laptop). Fetch build/enclave_hash.hex of a ceremony build
# from the build host, sign it with the offline ceremony key (the only step that touches it), and
# push signature.hex back for `PHASE=catsig`. REQ-r6 §3.
#   scripts/ceremony-sign.sh <build-out-dir-on-the-host>   e.g. ~/tee-signer-out/build-5
set -euo pipefail
OUT=${1:?build output dir on the build host}
HOST=${BUILD_HOST:-andrey@94.130.18.162}
KEY=${CEREMONY_KEY:-$HOME/llm-btcpay-tee/.local/ceremony/enclave-ceremony.pem}
PUB=$(cd "$(dirname "$0")/.." && pwd)/enclave/ceremony/ceremony_pub.pem
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
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
