#!/usr/bin/env bash
# Run ON the Hetzner build host (never on the cluster): build the pinned image, then sign + gates +
# SIGSTRUCT dump in a container with the dev signing key mounted read-only, and copy the outputs
# to $OUT. Run it twice and compare with docker/compare-builds.sh — that is gate 5 (reproducible).
set -euo pipefail
TAG=${TAG:-tee-signer-build:2.28}
KEY=${ENCLAVE_KEY:-$HOME/tee-signer-keys/enclave-dev-2.28.pem}
OUT=${OUT:-$HOME/tee-signer-out/$(date +%Y%m%d-%H%M%S)}
cd "$(dirname "$0")/.."
mkdir -p "$(dirname "$OUT")"
if [ ! -f "$KEY" ]; then
  mkdir -p "$(dirname "$KEY")"; openssl genrsa -out "$KEY" -3 3072 2>/dev/null; chmod 600 "$KEY"
  echo "generated DEV signing key $KEY (dev only, labeled; a release key is a ceremony)"
fi
DOCKER_BUILDKIT=1 docker build -f docker/Dockerfile.enclave-build -t "$TAG" . > "${OUT%/}.image.log" 2>&1 || { tail -40 "${OUT%/}.image.log"; exit 1; }
mkdir -p "$OUT"
C=$(docker create -v "$KEY":/keys/enclave.pem:ro "$TAG" bash -c 'source /opt/intel/sgxsdk/environment && make RELEASE=1 MITIGATION-CVE-2020-0551=LOAD Enclave_Test_Key=/keys/enclave.pem SDK_CPUID_LIST=sdk-cpuid-baseline-2.28.txt CARGO=/opt/cargo/bin/cargo CARGO_FLAGS=--offline enclave.signed.so gates; rc=$?; /opt/intel/sgxsdk/bin/x64/sgx_sign dump -enclave enclave.signed.so -dumpfile build/sigstruct.dump >/dev/null 2>&1; exit $rc')
docker start -a "$C" > "$OUT/build.log" 2>&1 && echo "build+gates: OK" || echo "build+gates: FAILED (see $OUT/build.log)"
for f in enclave/enclave.signed.so enclave/enclave.so enclave/build/cpuid-sites.txt enclave/build/lfence-count.txt enclave/build/sigstruct.dump enclave/App/libenclave_u.a host/signerd/target/release/signerd host/dcap-quote-helper MANIFEST; do
  docker cp "$C:/src/$f" "$OUT/" 2>/dev/null || echo "  missing: $f"
done
docker rm "$C" >/dev/null
echo "image: $(docker inspect --format '{{.Id}}' "$TAG")" >> "$OUT/MANIFEST"
tail -12 "$OUT/build.log"
echo "MRENCLAVE: $(grep -A2 'enclave_css.body.enclave_hash.m' "$OUT/sigstruct.dump" 2>/dev/null | tail -2 | tr -d ' \n' | sed 's/0x//g')"
echo "outputs: $OUT"
