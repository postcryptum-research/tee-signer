# REQ — R6 design: the owner key in hardware (TPM 2.0 first, YubiKey next) and the ceremony enclave-signing key

**Date:** 2026-11-03 · **From:** tee-signer dev session · **To:** the auditor · **Branch:**
`r6-owner-hw-key` of `github.com/77ph/BTCPayTEE`. **Requested verdict:** DESIGN-PASS /
CONDITIONAL / FAIL. **Gates:** C-R5-4 (production posture gated on a ceremony key + two-step
signing), D3 (owner key: any hardware, never on the BTCPay box), and the carried "hw-signer
backend" item from R2. **No TCB change is proposed**: the enclave verifies the same P-256 owner
signatures over the same message digests; where the private scalar lives is the owner's machine's
business. The owner's decision today: *for development, this laptop is the BTCPay operator's
machine; we play the scenarios in order — TPM 2.0 first, YubiKey after.*

## 1. Facts on the operator machine (this laptop, read-only)

| | |
|---|---|
| TPM | Intel PTT (`INTC`, firmware 2.0 family), `/dev/tpmrm0`, user in `tss`; `tpm2-tools 5.6`, `libtss2-esys 4.0.1` |
| Algorithms | ECC P-256/P-384, ECDSA, SHA-256, RSA (RSASSA/RSAPSS); persistent handles in use by other projects: `0x81000001` (SRK), `0x81000002`, `0x81000009`, `0x81010010`, `0x81010012` — never touched; ours: `0x81000100` (free) |
| Reused code | the owner's `TPM_sign` repo, crate `hw-signer` (trait `HardwareSigner { public_key(); sign_digest(&[u8;32]) -> (r,s) }`, backend `tpm` via `tss-esapi 7`: P-256 key created under the SRK with an authValue, persisted at a `0x81xxxxxx` handle, optional PCR sealing; backend `yubikey-piv` for later), pinned by git revision `9fa47b6`; its TPM backend builds and its hardware tests pass on this laptop |
| What hardware cannot hold | the **SGX enclave-signing key**: SGX requires RSA-3072 with public exponent **3**; TPM 2.0 (this one included) and YubiKey PIV create RSA keys with e = 65537 only. The ceremony key is therefore an **offline file**, never a TPM/PIV object |

## 2. The owner key on the TPM — what changes, what does not

- **Key locator instead of a path.** Every command that takes `--key` accepts either a keyfile
  path (unchanged) or `tpm:<handle>` (e.g. `tpm:0x81000100`). `keygen --backend tpm --handle
  0x81000100 --role owner` creates the P-256 key *inside* the TPM under the SRK with an authValue
  derived from the passphrase prompt (never stored), persists it, and prints the public key; the
  private scalar never exists outside the TPM, so there is no keyfile, no recovery blob of it, no
  passphrase-at-rest. `pubkey --key tpm:0x…` reads the public point from the TPM.
- **Signing.** `sign_message` hashes exactly as today (`Message::digest()`, SHA-256) and calls
  `HardwareSigner::sign_digest`; the (r, s) is low-s normalised and encoded as the same 64 bytes.
  The enclave sees an identical message. The authValue is presented per operation (one prompt per
  signature; `OWNER_PASSPHRASE` env only in the dev scripts, as now).
- **Scope of hardware keys: the owner key only.** The **recovery key** stays an encrypted keyfile
  on an offline machine: it must do ECDH to open the recovery blob (`hw-signer` has no ECDH and a
  recovery key is by design not a daily key). The witness key (R4) can be either.
- **Rotation is the migration path.** The deployed T2 wallet was initialised with the keyfile
  owner; `rotate-owner --key <old> --new-owner-pk <tpm pubkey>` (an existing owner message, R2)
  moves it to the TPM key — a live use of the rotation path, and after it the keyfile owner is a
  dead key for that enclave.
- **PCR sealing (option, not v1):** `hw-signer` can bind the key's policy to PCR values (boot
  state of the laptop). Deferred: it turns every firmware update into a key rotation; a labeled
  option for the operator, off by default.
- **YubiKey PIV (scenario 2):** the same locator (`piv:9c`), same trait, same messages; the PIN is
  the authValue; touch policy per the device. Nothing in the enclave or the message format
  changes between the two backends — that is the point of the trait.

## 3. The ceremony enclave-signing key and the two-step signing

- **Key:** RSA-3072, e = 3, generated offline with `openssl genrsa -3 3072` on the operator
  machine (dev: this laptop), stored encrypted at rest (PEM with AES-256 under a passphrase typed
  at use), **never on the build host, never in an image, never in git**. The public key and its
  MRSIGNER (`SHA-256(modulus)`) are pinned in the repo (`enclave/ceremony/mrsigner.txt` + the
  public PEM) and in the wallet record, labeled `ceremony key (held by the operator; dev: laptop)`.
- **Two-step signing (the SDK's release flow), executable:** build host (Hetzner, container):
  `sgx_sign gendata -enclave enclave.so -config cfg -out enclave_hash.hex` → the 256-byte hash
  goes to the operator machine (over the existing SSH path) → `openssl dgst -sha256 -sign
  ceremony.pem -out signature.hex enclave_hash.hex` (the only step that touches the key) → the
  signature goes back → `sgx_sign catsig -enclave enclave.so -config cfg -key ceremony_pub.pem
  -sig signature.hex -unsigned enclave_hash.hex -out enclave.signed.so`. `docker/build-enclave.sh
  sign-offline` drives it; the dev `Enclave_Test_Key` path stays for `make` on T1.
- **Gate 7 (build):** the signed enclave's MRSIGNER equals the pinned ceremony MRSIGNER, and
  MRENCLAVE equals the reproducible one (signing does not move it). `owner-cli attest
  --expect-mrsigner <ceremony>` is the owner-side check; `init` (fused, C-R5-6) refuses a record
  whose MRSIGNER is not the pinned ceremony key once `enclave/ceremony/mrsigner.txt` exists.
- **Redeploy without re-init:** sealing is MRENCLAVE-policy, so the T2 state unseals under the
  ceremony-signed build of the same sources; the record's MRSIGNER is re-pinned by `attest`
  (explicit `--expect-mrsigner`, never silently).
- **Honest label after R6:** "signed with the ceremony key held by the operator on a laptop" —
  which is the SMB posture the owner wants; the HSM/offline-ceremony variant is a deployment
  choice, not a code change.

## 4. Evidence the IMPL REQ will carry

TPM: key created and persisted at `0x81000100`, `pubkey` from the TPM, a wrong authValue refused
by the TPM, `rotate-owner` on the live T2 signer from the keyfile owner to the TPM owner, then
`unfreeze`/`policy-sign` signed inside the TPM and accepted by the enclave; the old keyfile owner's
message refused afterwards (`OWNER_SIG` or the existing refusal code). Ceremony: `build-5` signed
in two steps, gate 7, MRSIGNER changed and MRENCLAVE unchanged, T2 redeployed on it, the sealed
state unsealed, `attest --expect-mrsigner` passes with the new pin and fails with the old one;
the fused `init` on a throwaway instance refuses the dev-key MRSIGNER once the ceremony pin
exists. YubiKey: same evidence when the owner plugs it in (scenario 2, a later IMPL REQ).

## 5. Decisions to rule

- **D-R6-1** the owner key is the only hardware key in v1; recovery stays a keyfile offline.
- **D-R6-2** `hw-signer` from the owner's `TPM_sign` repo, pinned by revision, as the backend
  abstraction (owner-side code, not TCB).
- **D-R6-3** the ceremony key as an offline encrypted file with the SDK's two-step flow, MRSIGNER
  pinned in the repo and the record; no TPM/PIV for it (e = 3).
- **D-R6-4** PCR sealing of the TPM owner key deferred, labeled.
- **D-R6-5** rotation (not re-init) as the migration of the deployed wallet to the hardware owner.
