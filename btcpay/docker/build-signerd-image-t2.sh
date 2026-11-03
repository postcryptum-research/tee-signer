#!/usr/bin/env bash
# Run ON the Hetzner box: assemble the T2 sidecar image from a pinned build's outputs
# (docker/build-enclave.sh → $OUT) and save it as a tarball to ship to the node.
#   ./build-signerd-image-t2.sh ~/tee-signer-out/build-1 [tag]
set -euo pipefail
OUT=${1:?build output dir}; TAG=${2:-tee-signer/signerd:t2}
CTX=$(mktemp -d); trap 'rm -rf "$CTX"' EXIT
cp "$OUT"/{signerd,dcap-quote-helper,enclave.signed.so,MANIFEST} "$CTX/"
cp "$(dirname "$0")/Dockerfile.signerd-t2" "$CTX/Dockerfile"
docker build -t "$TAG" "$CTX"
docker save "$TAG" | gzip > "$OUT/signerd-t2-image.tar.gz"
echo "built $TAG; tarball $OUT/signerd-t2-image.tar.gz ($(du -h "$OUT/signerd-t2-image.tar.gz" | cut -f1)); MRENCLAVE per $OUT/sigstruct.dump"
