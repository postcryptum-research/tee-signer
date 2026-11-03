#!/usr/bin/env bash
# Run ON the SGX box: assemble the sidecar build context (binaries built on the box + the host's
# PSW runtime libraries) and build tee-signer/signerd:dev.
set -euo pipefail
CTX=${TEE_IMAGE_CTX:-$HOME/tee-signer-btcpay/signerd-image}
SRC=${TEE_SRC:-$HOME/tee-signer}
mkdir -p "$CTX/libs"
cp "$SRC/host/signerd/target/release/signerd" "$SRC/enclave/enclave.signed.so" "$SRC/btcpay/docker/Dockerfile.signerd" "$CTX/"
for l in libsgx_enclave_common.so.1 libsgx_urts.so.2 libsgx_launch.so.1; do
  cp "$(readlink -f /usr/lib/x86_64-linux-gnu/$l)" "$CTX/libs/$l"
done
dpkg -l | grep -E "libsgx-(urts|enclave-common|launch) " | awk '{print $2, $3}' > "$CTX/libs/PSW-VERSIONS.txt"
cd "$CTX" && docker build -f Dockerfile.signerd -t tee-signer/signerd:dev .
echo "built tee-signer/signerd:dev with PSW $(tr '\n' ' ' < libs/PSW-VERSIONS.txt)"
