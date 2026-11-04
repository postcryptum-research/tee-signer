# REQ — R7 IMPL: no signature after a restart until the owner arms the enclave

**Date:** 2026-11-05 · **Branch:** `r7-arm` (code `6022ce9`, docs `b392215`+) · **Asks:** IMPL-PASS for
`REQ-r7-arm-after-restart-design-2026-11-05.md` (DESIGN-PASS CONDITIONAL, `RESP-r7-…`), discharging
C-R7-0 … C-R7-10. Blocking checks named by the auditor: **C-R7-1** (in-enclave RDRAND) and
**C-R7-4** (completeness of every signing entrypoint).

## 1. What changed (every line a place the auditor can read)

| Where | Change |
|---|---|
| `core/src/update.rs` | `Message::Arm { enclave_id, nonce, boot_challenge: [u8; 32], seq_seen: u64, sig }`, domain `tee-signer/arm/v1`, tag 8; encode/decode/digest/verify like every owner message |
| `core/src/state.rs` | `State::apply_arm(&self, msg, boot_challenge: &[u8; 32])`: enclave id + signature under the sealed `owner_pk` (`POLICY_SIG`), next nonce (`POLICY_NONCE`, consumed), `boot_challenge` equality (`ARM_CHALLENGE`), `seq_seen ≤ s.seq` (`ARM_SEQ_BEHIND`); pure — the challenge is a parameter. `apply_message` refuses `Arm` (`POLICY_INVALID`): one path only |
| `core/src/reason.rs` | `NotArmed`, `ArmChallenge`, `ArmSeqBehind` → `NOT_ARMED`, `ARM_CHALLENGE`, `ARM_SEQ_BEHIND` |
| `core/src/proto.rs` | `StatusResponse` + `boot_armed`, `boot_challenge`, `auto_arm` (appended; strict decode) |
| `enclave/rcore/src/session.rs` | `CHALLENGE` (4×`AtomicU64`) drawn with the session id from `crate::sgx::read_rand` — `sgx_read_rand` inside the enclave, **never an OCALL** (C-R7-1); `ARMED: AtomicBool`, volatile, false at every load, **never part of the sealed envelope** (C-R7-0, C-R7-2); `challenge()`, `armed()`, `arm()`, `raise()`; `reset()` (test builds) clears all |
| `enclave/rcore/src/ops.rs` | `JUDGE` and `SIGN` refuse `NOT_ARMED` after the HWM check and before anything else (C-R7-4); `APPLY_MESSAGE` routes `Arm` to `apply_arm(&msg, &session::challenge())`, and on success `session::raise(ns.seq)` **then** `session::arm()` (C-R7-3: the mark ratchets to the armed blob's sequence); `INIT` and `TEST_INIT` arm the process they run in; `STATUS` reports the three fields; `tier_label()` appends `/AUTO_ARM` in an auto-arm build |
| `enclave/rcore/Cargo.toml`, `enclave/Makefile`, `docker/build-enclave.sh` | feature `auto-arm` ⇔ `AUTO_ARM=1` at **build time only**; `$(error …)` when `CEREMONY=1`; the build script passes `AUTO_ARM` through; no runtime read of any env/config anywhere (C-R7-8) |
| `enclave/rcore/src/sgx.rs` (`nosgx` stand-in only) | the deterministic test randomness starts from a per-process value, so a restarted T0 daemon draws a fresh challenge as hardware does. Not enclave code (the `nosgx` block is `cfg`'d out of every enclave build and gate 2 asserts the symbol is absent) |
| `host/signerd` | status passthrough; nothing else — the daemon cannot arm |
| `owner/owner-cli` | global `--wallet-record` (env `OWNER_WALLET`): every status read raises the record's `last_seen_seq` **on the owner's machine** (C-R7-5); `arm --key <locator>`: reads the record **before** talking to the daemon, refuses on `seq < last_seen_seq` with the exact regression named, `--i-have-investigated` overrides and is **logged in the record** (`rollback_acceptances`), builds `Arm { boot_challenge from status, seq_seen }`, signs on the owner device (PIN + touch on a YubiKey), submits, confirms `boot_armed`; `status` prints `NOT ARMED …` when unarmed and `AUTO_ARM: …` whenever the enclave says so (C-R7-7, C-R7-10); `init --accept-auto-arm` required for an auto-arm card; `attest` flags an auto-arm tier on every check and uses the base tier for the T2 decision |
| docs | `DESIGN.md §3/§6`, `ENCLAVE.md §4b`, `POLICY.md §6`, `CONTINUITY.md` (a reboot is a pause), `THREAT-MODEL.md §5`; `HOW_IT_WORKS`/`FAQ` (both languages) state the bound with the asterisk "pause build only; `AUTO_ARM` forfeits it" (C-R7-9) |

TCB: no new crate. The enclave's new code is one message type, three reasons, 32 volatile bytes
and one volatile bool.

## 2. C-R7-4 — completeness: every ecall that could move value, enumerated

| op | what it does | gated? |
|---|---|---|
| `INIT` (1), `TEST_INIT` | generates keys, signs the identity card with the stamp — no transaction key use; arms the process (attended owner operation on a fresh enclave) | n/a (no value) |
| `INSTALL` (9) | installs the nonce-0 mandate; no signature by the wallet key | n/a |
| `STATUS` (2), `POLICY` (3), `REPORT` (10) | read-only; `REPORT` signs an SGX report with the CPU's key, never with the wallet key | n/a |
| `APPLY_MESSAGE` (4) | owner/recovery transitions; `Arm` arms; nothing is signed by the wallet key | n/a (and C-R7-6: unarmed-accepted messages keep their semantics — e2e below) |
| `FREEZE` (5) | sets `frozen` | n/a |
| `HEADERS` (6) | chain view | n/a |
| **`JUDGE`** (7) | charges the budget for a PSBT and seals `last_judged` | **gated** (`NOT_ARMED`) |
| **`SIGN`** (8) | the **only** ecall that uses the wallet key: signs the charged PSBT, emits the receipt | **gated** (`NOT_ARMED`) |

There is no other PSBT path: a payout, a fee-bump, a consolidation, a sweep to cold storage and a
"recovery spend" are all PSBTs through `JUDGE`+`SIGN` (the recovery *of the seed* happens off the
box from the recovery blob and touches no ecall). `grep -n "sign_ecdsa\|sign_low_r\|SecretKey::" enclave/rcore/src/ops.rs`
finds the transaction-signing calls in `sign_op` only (the auditor can repeat it).

## 3. Evidence — host simulation (T0), 2026-11-05

- `cargo test` in `core/`: all green (the `bip39.rs:32` clippy line is the known local-1.95
  artefact, unchanged). `enclave/rcore`: `cargo test --features nosgx,test-init` 3/3 incl. the
  rewritten `full_flow_init_install_headers_judge_sign_and_fork_refusal`, which now proves, in one
  process with `TEST_RESET_SESSION` as the reload: **after reload `JUDGE` → `NOT_ARMED` and `SIGN`
  → `NOT_ARMED`**; `boot_armed == false`, a **different** `boot_challenge` and session id; a
  replayed `Arm` (the previous load's challenge) → **`ARM_CHALLENGE`**; an `Arm` with `seq_seen =
  2` on the rolled-back blob (#0) → **`ARM_SEQ_BEHIND`**; a thief's key → `POLICY_SIG`; a wrong
  nonce → `POLICY_NONCE`; still unarmed after all of them; the genuine `Arm` on the current blob
  (#2) accepted, nonce consumed (a second identical `Arm` → `POLICY_NONCE`), `boot_armed == true`;
  **C-R7-3**: `JUDGE` on the stale blob (#0) inside the armed process → `SEQ_BEHIND_SESSION`.
  `cargo check --tests --features nosgx,test-init,auto-arm` compiles (the pause compiled out).
- `host/signerd --features nosgx` builds and its replay passes; `owner-cli` 13/13 tests, clippy clean.
- `scripts/e2e-local.sh` (T0 daemon, regtest; appended drill): a loosening submitted (pending at
  +144), `freeze`, **daemon restarted** → `status`: `boot_armed false`, `frozen true`, the pending
  entry unchanged, `auto_arm false`; **`owner-cli --wallet-record wallet.json arm --key owner.key`**
  → prints the load's session id and boot challenge, "enclave remembers seq 0; you last saw seq 0",
  `{"applied":true}`, `armed`; `status`: `boot_armed true`, **`frozen` still true** (a freeze taken
  unarmed persists), **pending unchanged** (no acceleration) — C-R7-6; a second `arm` for the
  same load → refused "already armed"; then `unfreeze` and `cancel` proceed; `e2e-local: OK`.
  (One test artefact fixed on the way: the `nosgx` randomness stand-in was identical in every
  process, so a restarted T0 daemon drew the same challenge; it now starts per process.)

## 4. Evidence — hardware builds (appended when the build box finishes)

Pending: on the Hetzner build box, in the pinned container: (a) the pause build `RELEASE=1 SIGN=dev`
→ MRENCLAVE_A, all gates; (b) the opt-out `RELEASE=1 AUTO_ARM=1 SIGN=dev` → MRENCLAVE_B ≠ A, all
gates, `tier` ends in `/AUTO_ARM`; (c) `AUTO_ARM=1 CEREMONY=1` refused by the Makefile before any
compilation. Then the T1 dev sidecar on the pause build: a fresh `init` (MRENCLAVE changed, the old
sealed state is unopenable by design), `status` → `boot_armed true` (init arms), container restart
→ `boot_armed false`, `sign` → `NOT_ARMED`, `arm` with the TPM owner key → armed, `sign` accepted.
T2: after the YubiKey custody transition completes at signet 329586 (REQ-r6b §4.5 part 2), the
ceremony-signed pause build is deployed and the same restart drill runs on the live node with the
YubiKey owner.

## 5. Conditions

| Condition | Where discharged |
|---|---|
| C-R7-0 distinct volatile flag, never `s.armed` | `session.rs` `ARMED`; `ops.rs` gates on `session::armed()`; `s.armed` untouched and still only the witness's |
| C-R7-1 in-enclave RDRAND | `session.rs::ensure` → `sgx::read_rand` → `sgx_read_rand` (no OCALL in `sgx.rs`'s enclave branch) |
| C-R7-2 never sealed, false at load | `ARMED` is a static in enclave memory; `Envelope`/`State` encodings unchanged (no field added) |
| C-R7-3 one load per process / HWM ratchets on Arm | `ops.rs` `apply_message`: `raise` then `arm`; test: stale blob → `SEQ_BEHIND_SESSION` in the armed process |
| C-R7-4 completeness | §2 |
| C-R7-5 record on the owner's machine; loud, logged override | `owner-cli` `--wallet-record`, `arm` |
| C-R7-6 unarmed-accepted messages keep semantics | e2e: freeze persists, pending unchanged |
| C-R7-7 auto_arm through attestation every time | tier string `…/AUTO_ARM` is inside the signed card and the attested report; `attest` prints the warning on every run |
| C-R7-8 compile-time exclusion | `#[cfg(feature = "auto-arm")]` / `#[cfg(not(…))]` only; no env/config read; Makefile `$(error)` with `CEREMONY=1` |
| C-R7-9 the asterisk travels with the claim | `HOW_IT_WORKS`/`FAQ` both languages, README tier table |
| C-R7-10 degraded mode loudly visible | `owner-cli status`/`get` print `AUTO_ARM: rollback protection OFF …` whenever the enclave says `auto_arm`; `init` refuses without `--accept-auto-arm` |

## 6. Honest label after this round

Pause build (the pinned one): against root on a T2 server while the owner is absent, a rollback
yields a silent enclave; the residual is one window's budget per start the owner approves after a
rollback they did not notice, with owner-cli refusing on a sequence regression unless overridden in
writing. Cost: one signed `arm` after every restart; payouts wait for it. `AUTO_ARM` build: the
bound is gone, the exposure is the hot-wallet float, and every status, card and attestation says so.
T1: unchanged (root reads the seed). The transport (owner-cli over a tunnel today) is R8's subject
and does not touch any of the above: `Arm` is a self-contained signed message like every other.
