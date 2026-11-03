# Ceremony enclave-signing key (REQ-r6 §3)

`ceremony_pub.pem` is the public half of the enclave-signing key (RSA-3072, public exponent 3 as
SGX requires); `mrsigner.txt` is its MRSIGNER (SHA-256 of the 384-byte modulus in the
little-endian order SIGSTRUCT stores it). The private key is an **offline file, encrypted at
rest, held by the operator** (dev: the operator laptop under `.local/ceremony/`, gitignored); it
is never on the build host, never in an image, never here.

Signing is the SDK's two-step flow, driven by `docker/build-enclave.sh`:

1. build host: `gendata` — `sgx_sign gendata` on the unsigned `enclave.so` → `enclave_hash.hex`;
2. operator machine: `scripts/ceremony-sign.sh <out-dir>` — `openssl dgst -sha256 -sign` with the
   ceremony key (the only step that touches it) → `signature.hex`;
3. build host: `catsig` — `sgx_sign catsig` with this public key → `enclave.signed.so`, then the
   gates, including **gate 7**: the signed enclave's MRSIGNER equals `mrsigner.txt` and its
   MRENCLAVE equals the reproducible one.

Honest label: *signed with the ceremony key held by the operator on a laptop* — the SMB posture;
an HSM-held key is a deployment choice, not a code change. A stolen ceremony key can only sign
the same MRENCLAVE the owner already pins (attest step 3), not a different enclave.
