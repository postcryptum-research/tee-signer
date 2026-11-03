#!/usr/bin/env bash
# Sync the working tree to the SGX build host (owner-approved dir ~/tee-signer), keeping the
# server-side build products (bridge archive, generated edger8r files, signed enclave, keys).
set -euo pipefail
HOST=${TEE_SGX_HOST:-andrey@94.130.18.162}
DEST=${TEE_SGX_DIR:-'~/tee-signer/'}
cd "$(dirname "$0")/.."
rsync -a --delete \
  --exclude target --exclude .git \
  --exclude 'enclave/App/libenclave_u.a' --exclude 'enclave/App/Enclave_u.*' \
  --exclude 'enclave/Enclave/Enclave_t.*' --exclude 'enclave/Enclave/*.o' --exclude 'enclave/Enclave/*.pem' \
  --exclude 'enclave/enclave.so' --exclude 'enclave/enclave.signed.so' --exclude 'enclave/build' --exclude 'enclave/.config_*' \
  --exclude '*.log' \
  ./ "$HOST:$DEST"
