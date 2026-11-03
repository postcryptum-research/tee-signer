# REQ — R2 enclave shell, header verifier, daemon, owner tool: IMPL review

**Date:** 2026-11-03 · **From:** tee-signer dev session · **To:** the auditor · **Branch:**
`r2-enclave-shell` of `github.com/77ph/BTCPayTEE` (commit named in the sending message; this file
is added in the next commit). **Requested verdict:** IMPL-PASS / CONDITIONAL / FAIL for merging
`enclave/`, `host/signerd`, `owner/owner-cli`, the `headers`/`proto`/`bip39` additions to `core/`,
and `vectors/headers/` to `main`. Design of record: `docs/ENCLAVE.md` (written this round under the
DESIGN-PASS), `DESIGN.md`, `THREAT-MODEL.md`, `POLICY.md`. **Gates named for this round:** C-R3a–c,
C-R7, C-R8a–c, C-R9, C-R10a/c/d/e, C-R12c, C-R13a/b, C-R14, C-D3, C-D3b(1), C-D5, C-D5b, C-R1-1,
C-R1-2, C-R1-3, C-R2-1 (`CONDITIONS.md`).

## 1. What is on the branch

| Part | Where | Trust |
|---|---|---|
| Header verifier | `core/src/headers.rs`, `core/tests/headers.rs`, `vectors/headers/` | TCB |
| Ecall wire protocol | `core/src/proto.rs` | TCB |
| BIP39 (moved into the core) | `core/src/bip39.rs` | TCB |
| Chain view in the state, checkpoint with period data | `core/src/state.rs`, `core/src/mandate.rs` | TCB |
| Enclave FFI crate: envelope, SDK bindings, session mark, recovery blob, operations | `enclave/rcore/` | TCB (the only `unsafe`) |
| Enclave shell: EDL (one ecall, no ocalls), C glue, config, Makefile with gates, pinned SDK cpuid set | `enclave/` | TCB (C: 10 lines) |
| Daemon | `host/signerd/` | untrusted |
| Owner tool | `owner/owner-cli/` | owner's machine |
| Scripts | `scripts/sync-to-sgx.sh`, `scripts/e2e-local.sh`, `scripts/sgx-signerd-restart.sh` | — |

## 2. What the enclave enforces, where

| Property | Where | How |
|---|---|---|
| Two-step init: keys bound to the owner before any mandate | `rcore/src/ops.rs::init/install` | `INIT` generates seed + identity key from `sgx_read_rand`, binds `owner_pk`/`recovery_pk` into the keys-only envelope; `INSTALL` accepts only a mandate signed by the **bound** owner (`PolicyUpdate` nonce 0 for this `enclave_id`), with `validate`, network and wallet (fingerprint, `84'/coin'/0'`, P2WPKH) equal to the derived ones |
| I12: the seed leaves once, in the recovery blob | `ops.rs::build_init`, `rcore/src/recovery.rs` | ECIES to the recovery key, produced in `INIT` only; no op returns the seed or a function of it beyond public keys and signatures (C-R8c vector: `smoke` proves the blob opens with the recovery key, not the owner key) |
| Identity key distinct from the seed (C-R1-2) | `ops.rs::init` | drawn separately from `sgx_read_rand`; `enclave_id = SHA-256(identity_pk)` |
| Identity card (TOFU made checkable) | `proto::IdentityCard`, `ops.rs::build_init` | `{MRENCLAVE from the self-report, network, xpub, fingerprint, identity_pk, tier}` signed by the identity key; `owner-cli init` verifies it before writing the wallet record |
| Sealing under MRENCLAVE | `rcore/src/sgx.rs::seal/unseal` | `sgx_seal_data_ex(KEYPOLICY_MRENCLAVE, FLAGS_MASK 0xFF0000000000000B, MISC_MASK 0xF0000000)`, AAD `"tee-signer/envelope/v1"` checked on unseal; the blob is untrusted input (C-R7): a flipped byte is `STATE_UNSEALABLE` on hardware (smoke) |
| Two-phase signing, byte-exact | `ops.rs::judge_op/sign_op`, `envelope::LastJudged` | `JUDGE` charges, records `{SHA-256(PSBT bytes), txid, seq, receipt}` and returns the charged blob; `SIGN` signs only if the blob's record names these exact bytes and `seq == state.seq`; idempotent re-sign; a hint-stripped PSBT with the same txid refuses |
| Session high-water mark (seq-fork within one load) | `rcore/src/session.rs`, every state-taking op | input `state.seq < HWM` ⇒ `SEQ_BEHIND_SESSION`; a second `JUDGE` from one base blob refuses; a random per-load `session_id` goes into status and every `SignResponse`; `TEST_RESET_SESSION` (test builds) shows a reload lifts it — labeled |
| secp256k1 context randomization (C-R10c) | `ops.rs::secp` | `seeded_randomize` from `sgx_read_rand` at every entry |
| Header verifier (C-R3a–c) | `core/src/headers.rs` | attaches to best or a recent header; link, exact required `nBits` (retarget via `CompactTarget::from_next_work_required`, min-difficulty rule and walk-back equivalent for testnet4, no retarget on regtest), `validate_pow`, median-time-past of the previous eleven, cumulative work by checked 256-bit add; adopted only if strictly more work; a fork deeper than `maxReorg` **freezes** (`CHAIN_REORG`), the freeze is sealed; the checkpoint moves only to a verified recent header, or re-pins only while frozen |
| No wall clock anywhere | `headers.rs`, `judge.rs`, `state.rs` | the median-time rule consumes header timestamps only; windows, timelocks, validity, freshness are heights |
| Keys-only status | `ops.rs::status` | `installed=false` with identity and wallet facts only |

## 3. Build gates, as they are (the first hardware build corrected the design's gate 1)

| Gate | Result |
|---|---|
| 1 — cpuid | **our code: 0** (`librcore.a` carries 6 in an unreferenced `compiler_builtins` libm member that the link drops; the enclave objects carry 0). **The final `enclave.so` carries exactly the pinned SDK set** of 8 sites (`enclave/sdk-cpuid-baseline.txt`: `cpGetCacheSize`, `cpGetReg`, `cp_is_avx_extension`, `cp_is_avx512_extension`, `cpStartTsc(p)`, `cpStopTsc(p)` — IPP in `libsgx_tcrypto`, which `sgx_trts` requires through `sgx_init_crypto_lib`). The build diffs the site list and asserts the count. The first build found 12 extra from `aes` and `polyval` autodetection — removed by `--cfg aes_force_soft --cfg polyval_force_soft` (`rcore/.cargo/config.toml`) and `sha2 force-soft`. Please rule D-R2-1 below |
| 2 — test symbols | asserted absent for `RELEASE=1` (`test_init`, `hollow`, `reset_session`, `nosgx`); dev builds carry `test-init` |
| 3 — TEXTREL | 0 |
| 4 — config | `DisableDebug` rewritten from `RELEASE`; `TCSNum=1`, `TCSPolicy=1` |
| 5 — reproducible build (C-R1-3) | **not done this round** — carried to R5 with the T2 work; the method is agreed (MRENCLAVE + SIGSTRUCT minus `header.date`) |

## 4. Evidence

- Host: `core` 15 tests + 51 vectors; `rcore` unit tests + `tests/replay.rs` (full flow and all 51
  vectors through `rcore_call` in simulation); `signerd replay`/`smoke` in simulation;
  `scripts/e2e-local.sh` (owner flow: keygen, init, recovery verify, install, tighten applies,
  loosen pends and the recovery key cancels, freeze/unfreeze). `clippy -D warnings` clean.
- **Hardware (`94.130.18.162`, SGX1, debug launch):** `make` passes all gates; `signerd smoke`:
  tier `T1-debug`, MRENCLAVE reported, card verifies, recovery blob opens with the recovery key
  only, keys-only blob refused for everything but status/install, install refuses the recovery
  key's signature and a foreign fingerprint, 10 regtest headers accepted, judge → sign with the
  charged blob only and the exact bytes only, receipt verifies under the identity key, re-sign
  idempotent, second judge from the base blob `SEQ_BEHIND_SESSION`, reload lifts the mark with a
  new session id, freeze/unfreeze, **a flipped byte in the sealed blob is refused by the seal
  MAC**, a truncated blob refused; `signerd replay`: 51 vectors reproduced in 1.3 s.
- **Live on signet:** `signerd` runs on the box (`deploy/README.md`), feed from the shared signet
  node over the read-only RPC subset; from the laptop through an SSH tunnel: `owner-cli init`
  (keys in the real enclave, card verified), `recovery-verify` offline, `policy-build` with the
  checkpoint from mempool.space at height 329261, `policy-sign` nonce 0 installed; the enclave's
  chain view then followed the tip (329267) through the feed. ⏳ The first mandate-bound signature
  of a real signet transaction waits on funds reaching the wallet's first address.

## 5. Deviations and decisions to rule (supplement)

| # | What | Why |
|---|---|---|
| D-R2-1 | **Gate 1 is "our code zero + pinned SDK set", not "zero in the whole `.so`"** | `sgx_trts` calls `sgx_init_crypto_lib`, so `libsgx_tcrypto` (IPP) is mandatory; its dispatcher carries `cpuid` which the SDK emulates from host-supplied tables — the same host-decides-features residual trust-bridge's patch names. An EGETKEY-based own sealing was tried to drop tcrypto; it does not remove the dependency (trts itself needs it), so the SDK's `sgx_seal_data_ex` stays and the residual is pinned and labeled (`ENCLAVE.md §7`) |
| D-R2-2 | **Two-step init** (INIT binds keys; INSTALL takes the signed mandate) instead of one | the mandate names the wallet fingerprint, which exists only after the seed is drawn; binding the owner at INIT means a keys-only blob can only ever become a full one under a mandate the bound owner signed |
| D-R2-3 | `last_judged` binds `SHA-256(PSBT bytes)`, not only the txid | a PSBT with the same transaction but altered hints can change which inputs are own; same bytes or a new judge |
| D-R2-4 | `TCSPolicy=1`, daemon on one runtime thread | a bound TCS (`0`) fails every second host thread with `OUT_OF_TCS`; found live |
| D-R2-5 | `Recover` voids pending mandate and pending rotation; `RotateOwner` refuses the recovery key as the new owner; `INIT` refuses `owner_pk == recovery_pk` | C-D3b(1) and the recovery-as-backstop argument |
| D-R2-6 | Checkpoint carries `time`, `bits`, `period_start_time`, `period_bits`; a mandate update's checkpoint must be a header the enclave verified (or a re-pin only while frozen); the enclave's own records win over the mandate's fields | the verifier needs no headers before the checkpoint; the trust root moves only forward to verified work |
| D-R2-7 | Header feed in `signerd` extends from the enclave's best when the node's hash at that height agrees, else re-offers the last ten | the enclave judges forks from its recent window; the daemon only transports |
| D-R2-8 | Receipt log, token, blob at mode `0600`; atomic persist (tmp, fsync, rename, dir fsync); persist the charged blob **before** `SIGN`; persist a refusal's payload (disarm, chain freeze) | the ordering guarantee the design assigns to the shell |
| D-R2-9 | `owner-cli` keyfile = scrypt N=2^18, r=8, p=1 + AES-256-GCM; refuses to open below N=2^18; refuses equal owner/recovery keys at init; `policy-show --json` prints the field-by-field diff and the tightening/loosening classification before `policy-sign`; `policy-sign` prints the fields and the hash it signs (C-R14 WYSIWYS on the owner's machine) | D3 floor; no-blind-sign |
| D-R2-10 | `vectors/headers/signet-322560-324700.hex` fetched from the shared node (D5) | real retarget data for the consensus-critical verifier |

## 6. Known limits, stated

- The seq-fork across enclave reloads is detected, not prevented (`ENCLAVE.md §4a`); the monitor
  (R4) is specified, not built.
- Reproducible build (gate 5) and `RELEASE=1` on FLC hardware (T2) are R5.
- MRENCLAVE-policy sealing means every enclave rebuild orphans the previous blob — correct, and
  the reason a dev wallet was re-initialised twice today; the upgrade policy (MRSIGNER + ISVSVN) is
  a later REQ.
- D-11 cost (descriptor matching) was not measured this round: the live mandate has no trusted
  descriptor yet; carried.
- `signerd` holds no funds-affecting authority but is operationally trusted for availability; its
  bearer token is a rate-limit, as ruled (R11).
- The dev enclave on the box is a `test-init` build (debug launch, `TEST_INIT`/`TEST_RESET_SESSION`
  present); `RELEASE=1` builds exist only as a build check on this hardware.

## 7. Deliverable

`RESP-r2-enclave-shell-2026-11-03.md`: verdict and conditions, bound to the commit; committed
verbatim before any merge.
