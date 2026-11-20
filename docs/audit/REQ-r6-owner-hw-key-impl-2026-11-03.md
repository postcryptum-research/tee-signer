# REQ — R6 IMPL: the owner key in the TPM, the ceremony enclave-signing key with two-step signing

**Date:** 2026-11-03 · **From:** tee-signer dev session · **To:** the auditor · **Branch:**
`r6-owner-hw-key` of `github.com/77ph/BTCPayTEE` (commit named in the sending message). **Design
of record:** `REQ-r6-owner-hw-key-design-2026-11-03.md` + `RESP-r6-…` (DESIGN-PASS, C-R6-1/2).
**Requested verdict:** IMPL-PASS / CONDITIONAL / FAIL for merging to `main`. **Gates:** C-R5-4
(production posture: ceremony key + two-step signing), C-R6-1, C-R6-2, D3. **TCB:** `git diff
main -- core enclave/rcore enclave/Enclave` is **empty**; the branch changes `owner/owner-cli`,
`enclave/Makefile` (gate 7 + `gendata`/`catsig` targets), `enclave/ceremony/` (public key, MRSIGNER
pin, README), `docker/build-enclave.sh` (`SIGN=ceremony`, `PHASE=gendata|catsig`),
`docker/compare-builds.sh` (field-based), `scripts/ceremony-sign.sh`.

## 1. C-R6-1 — `hw-signer` pin equals the audited behaviour

`hw-signer = { git = "https://github.com/postcryptum-research/agent-keys", rev = "9fa47b6", default-features =
false, features = ["tpm"] }`. The crate's history since the audit-fix commit `96d56ad`
("Audit 2026-10-20: fix F1–F7 and the code part of F8"): `git diff 96d56ad..9fa47b6 --stat --
signer/crates/hw-signer` = `Cargo.toml +6` (optional `yubikey`/`zeroize` deps + the
`yubikey-piv` feature), `src/lib.rs +3` (`#[cfg(feature = "yubikey-piv")] pub mod yubikey_piv;`),
`src/yubikey_piv.rs +297` (new file, feature-gated). **Under the `tpm` feature the compiled code
is byte-for-byte the audited revision**: `tpm.rs` and the trait are untouched. Its TPM hardware
tests (`cargo test -p hw-signer --features tpm -- --ignored`) pass on this laptop: sign+verify,
protected key signs only with its auth, sealed key follows PCR 16.

## 2. The owner key in the TPM — executed on the operator laptop (Intel PTT)

| Step | Result |
|---|---|
| **C-R6-2** `keygen --backend tpm --handle 0x81000001` (the SRK) and `0x81000002` (another project's key) | `REFUSED: TPM persistent handle … is already in use by another key; never evicted` — before anything is created (`TPM2_GetCapability(HANDLES)` pre-check, persistent range enforced) |
| `keygen --backend tpm --handle 0x81000100 --role owner` | key created under the SRK with an authValue (passphrase typed at use; never stored), persisted; public key `041e3d91…10e1`; `tpm2_getcap handles-persistent` lists `0x81000100`; a second `keygen` at the same handle refuses |
| `pubkey --key tpm:0x81000100` | the public point read from the TPM, no auth needed |
| wrong authValue on `unfreeze --key tpm:…` | `TPM sign: … the authorization HMAC check failed and DA counter incremented` — refused **by the TPM**, no message leaves the laptop. ⚠️ Labeled: the key has no `noDA`, so failed attempts count against the TPM's **shared** dictionary-attack counter (this laptop: counter 2 → 3 of max 31, lockout interval 600 s) — one attempt was made, deliberately |
| **live T2 wallet:** `rotate-owner --key <keyfile> --new-owner-pk <TPM pk>` | `{"applied":true}` — and, by design (DESIGN §7: owner rotation is a *loosening*), it is **pending**: `status.pending_owner = 329441` (= 329297 + 144 blocks). Until then the keyfile owner stands: its `unfreeze` is accepted, the TPM's is `POLICY_SIG`-refused. That is the timelock doing its job, not a defect; the recovery key could cancel it. Activation and the first TPM-signed message on the live wallet land after block 329441 (≈ one day; will be reported) |
| **throwaway T2 wallet initialised with the TPM key as owner** (second instance on the node, removed after) | fused `init --owner-pk <TPM pk>` → attested, record written; **`policy-sign --key tpm:0x81000100` (INSTALL, nonce 0) signed inside the TPM → `installed: true`**; `freeze` → `unfreeze --key tpm:…` → `applied`; the keyfile key's `unfreeze` → `POLICY_SIG`; `unfreeze` with the TPM again → `applied` (nonce 2). The enclave accepted P-256 signatures produced inside the TPM and refused the other key |
| recovery key | stays an encrypted keyfile; `OpenKey::scalar()` refuses for a TPM key with the reason (ECDH for the recovery blob) |

Wire format unchanged: `sign_message` hashes exactly as before and calls `HardwareSigner::sign_digest`;
(r, s) low-s normalised into the same 64 bytes. The enclave never learned which backend signed.

## 3. The ceremony enclave-signing key — executed

- Key: `openssl genrsa -3 3072` on the operator laptop, AES-256-encrypted PEM under
  `.local/ceremony/` (gitignored), passphrase typed at use. Public key + MRSIGNER pinned:
  `enclave/ceremony/ceremony_pub.pem`, `enclave/ceremony/mrsigner.txt` =
  `56b25ccb4c1e446df1be4b308cd305b2d43e3f44745c10118bd7bad7bb2c0d41` — computed as SHA-256 of the
  little-endian modulus **before** any signing, and equal to what `sgx_sign dump` later reported.
- Two-step signing, `build-5` on the Hetzner box: `PHASE=gendata` → `enclave_hash.hex` (256 bytes)
  → `scripts/ceremony-sign.sh` on the laptop (`openssl dgst -sha256 -sign`, verified under the
  pinned public key, pushed back) → `PHASE=catsig` → `CATSIG => enclave.signed.so (ceremony key)`;
  gates 1–4, 6 pass; **gate 7:** `MRSIGNER 56b25ccb… == pinned`.
- `compare-builds.sh build-3 build-5`: **REPRODUCIBLE** — MRENCLAVE `51dee44d…1fa6`, attributes/
  mask, misc, ProdID/SVN identical, `enclave.so` byte-identical. (The compare is now field-based:
  the measurement-covered SIGSTRUCT fields; signer and date excluded by construction.)
- **Redeploy without re-init:** the T2 sidecar recreated on the ceremony-signed image; the sealed
  state **unsealed** (installed, seq 3, nonce 3, `pending_owner` retained) — MRENCLAVE sealing.
- `attest` on the live wallet after the redeploy: with the record's old dev-key pin → `step 4
  refused: MRSIGNER 56b2…, expected 73f2…`; with `--expect-mrsigner <ceremony> --pin` → pass,
  record re-pinned, label `ceremony key held by the operator (dev: the operator laptop); two-step
  signed`.
- **Fused `init` with the ceremony pin compiled in** (`CEREMONY_MRSIGNER` from
  `enclave/ceremony/mrsigner.txt`, the default step-4 expectation when neither the record nor the
  command line names one): against a dev-key-signed enclave (a throwaway instance on the old
  image, removed after) → `REFUSED: … step 4 refused: MRSIGNER 73f2…, expected 56b2… (the pinned
  ceremony key; a dev-key enclave must be named explicitly with --expect-mrsigner and labeled)`,
  no record written.

## 4. Honest label after this round

The deployed T2 enclave is signed with **the ceremony key held by the operator on the operator
laptop**; the owner key of the live wallet is still the keyfile until block 329441, then the TPM.
"Production-safe" per C-R5-4 is now a deployment statement about *where the operator keeps these
two keys* (an offline machine or HSM for the ceremony key; PCR sealing for the TPM key), not a
code gap: the code enforces the ceremony pin (gate 7, attest step 4, fused init) and the TPM-only
owner path end to end.

## 5. Decisions / labeled

- **D-R6-6** the pending owner rotation is reported as evidence of the timelock; the live
  TPM-signed message on the production wallet is reported after activation (≈ 2026-11-04).
- Labeled: no `noDA` on the TPM key (shared DA counter); PCR sealing deferred (D-R6-4);
  YubiKey PIV = scenario 2 (same trait, `piv:` locator), a later IMPL REQ when the owner plugs it in.
