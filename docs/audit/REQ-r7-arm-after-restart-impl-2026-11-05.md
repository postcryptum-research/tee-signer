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

## 4. Evidence — hardware builds (Hetzner build box, pinned container, 2026-11-05)

- **Pause build** `RELEASE=1 SIGN=dev`: `ARM POLICY: pause-after-restart (REQ-r7)`, gates 1–4 and 6
  all passed (lfence 38484 ≥ 2000), `DisableDebug=1`, **MRENCLAVE `ca5c1a6adfb439be65afba2acae246507c6d87f0c0d399345015ff0590e27c80`**
  (`~/tee-signer-out/r7-pause/`). It differs from the pinned R6 build `51dee44d…` as every code change
  must; the ceremony signing of this measurement and the T2 re-pin follow the merge.
- **Ceremony exclusion**: `make -n RELEASE=1 AUTO_ARM=1 CEREMONY=1 rcore` → `Makefile:38: *** AUTO_ARM=1
  with CEREMONY=1: the ceremony key never signs an auto-arm enclave (REQ-r7 §2.6). Stop.` — refused
  before any compilation (C-R7-8).
- **Opt-out build artefact: not produced in this round.** The first attempt measured identical to
  the pause build because `docker/build-enclave.sh` expands `AUTO_ARM` inside the container, where
  the script does not set it (the pause build is the default); the fix (pass the variable into the
  container) and the opt-out's own MRENCLAVE are deferred to a follow-up. Nothing in the product
  path depends on it: the pinned build is the pause build, and `tier_label()`, `init
  --accept-auto-arm` and the status warnings are covered by the T0 tests.
- **T1 dev sidecar drill on the pause build**: **not run — dropped by the owner on 2026-11-10** (T1 is
  the build-and-test tier; nothing is deployed there for drills). The drill ran on T2 instead (§4.1);
  the `NOT_ARMED` refusal on a real reload stays source- and T0-proven and may be captured on T2 at
  the next owner-run restart. **T2**: after the YubiKey custody transition completes at
  signet 329586 (REQ-r6b §4.5 part 2), the ceremony-signed pause build is deployed and the same
  drill runs on the live node with the YubiKey owner.

### 4.1 T2 deployment of the pause build — 2026-11-10 (C-R7-13, in progress)

- **Ceremony signing of `ca5c1a6a…`** (Hetzner build box, pinned image; `SIGN=ceremony`): `PHASE=gendata`
  → `enclave_hash.hex` (256 B) → signed on the laptop with the offline ceremony key
  (`scripts/ceremony-sign.sh`, signature verified under the pinned public key) → `PHASE=catsig`:
  gates 1, 2, 3, 4, 6 and **7** (`MRSIGNER 56b25ccb…` = the pinned ceremony key) all passed,
  `MRENCLAVE ca5c1a6adfb439be65afba2acae246507c6d87f0c0d399345015ff0590e27c80`.
  `docker/compare-builds.sh r7-pause r7-pause-ceremony`: **REPRODUCIBLE**, `enclave.so` byte-identical
  to the dev-signed build of 2026-11-05 (output `~/tee-signer-out/r7-pause-ceremony/`). The sources
  were `main` @ 8de2e6d (R7 + R8 merged); nothing under `core/` or `enclave/` changed since 6022ce9,
  which the identical measurement confirms.
- **Sidecar image for T2** built on the box from those outputs (`build-signerd-image-t2.sh`,
  `signerd` + `dcap-quote-helper` + `enclave.signed.so` + `MANIFEST`), 39 MB tarball shipped to the
  node by `scp`, loaded (`tee-signer/signerd:t2` = `a1cdb0f1d697`; the R6 image `6543d86dd219` kept
  until the drill passes). The node's stack sources updated; compose regenerated with the same
  fragments as before (`opt-add-tee-signer-t2.custom`, `opt-save-storage-xxs`) — the only diff is
  the R8 `/exchange` mount; `~/tee-signer-exchange/` created and holding the owner's three files
  (`owner.pub` = the YubiKey `9a` key, `recovery.pub` = a **fresh** recovery key made today — see
  `INCIDENT-2026-11-10-local-sync.md` —, `nonce.txt`), carried laptop → build box → node by `scp`.
- **Re-init and drill: owner-run on the server** (this dev session's permission mode stops at
  replacing the production sidecar; the server steps are the operator's in the FAQ anyway). The
  retired wallet's `state.sealed`, `receipts.jsonl` and `token` are moved into a `retired-51dee44d-…`
  subdirectory of the state volume (reversible; the old enclave's state is unopenable by the new
  measurement by design), the sidecar is started on the new image, then `signerd init / quote /
  status --out /exchange/…`; the laptop verifies the quote against `ca5c1a6a…` + the ceremony
  MRSIGNER with the owner's nonce, writes the record, the owner installs the mandate with the
  YubiKey, and the restart drill follows. Results appended below when run.

**Run 2026-11-10 13:19–13:3x UTC — owner-run `scripts/t2-r7-redeploy.sh` in the owner's terminal
(laptop → build box relay → node, `scp` only; log `.local/signet-t2/r7-deploy-20261110-131904.log`,
files `.local/signet-t2/exchange/`, both gitignored, readable by the auditor on this laptop).**
A first run at 12:55 did the server half and the quote check, then stopped at the recovery-passphrase
prompt (run through the session's `!`, no TTY); the interim wallet it created (fp `04333c94`) was
retired unfunded together with the recovery key the dev had generated for it — the owner then made
the recovery key themselves (`keygen`, passphrase known only to them; owner-cli floor lowered to 4
characters, 6dde33f) and the run below re-initialised on it.

| Step | Result |
|---|---|
| server: R6 sidecar stopped; `state.sealed`, `receipts.jsonl`, `token` moved into `retired-51dee44d-2026-11-10/` in the volume; `stack.sh up --no-deps tee-signer` | container recreated on `tee-signer/signerd:t2` = `a1cdb0f1d697`; log `signerd starting enclave="sgx" initialised=false`; **old token → HTTP 401, new token → HTTP 200** |
| server: `signerd init --network signet --owner-pk-file /exchange/owner.pub --recovery-pk-file /exchange/recovery.pub --out …`; `quote --nonce-file`; `status` | `ok` × 3; status: `tier T2-release`, `mrenclave ca5c1a6a…`, `initialised true`, `installed false`, **`boot_armed true` (init arms)**, `auto_arm false`, nonce 0, seq 0 |
| laptop: `owner-cli init --response … --owner piv:9a --recovery-pk-file … --expect-mrenclave ca5c1a6a… --quote … --nonce-file …` | `ATTESTED: piv:9a generated on YubiKey 39252737 …`; verifier steps 1–7 ok: chain to the pinned Intel SGX Root CA, `DEBUG = 0`, **MRENCLAVE `ca5c1a6a…`**, **MRSIGNER `56b25ccb…` (ceremony)**, card signed by identity `02020313…`, `report_data = SHA-256(domain ‖ nonce ecdb39e9… ‖ card)`, TCB `SWHardeningNeeded` with the recorded SA-00615 exception; quote sha256 `9c25f738…cdc9c6`; record written: xpub `tpubDDpFY9q…f8Nb`, **fingerprint `51ca22a4`**, enclave id `d36145e2…` |
| laptop: `recovery-verify` with the owner's key (passphrase typed by the owner) | `recovery blob OK: decrypts to a 24-word mnemonic whose m/84'/1'/0' xpub and fingerprint match the wallet record` |
| laptop: mandate re-targeted to `51ca22a4`, checkpoint from mempool.space/signet; `policy-sign --key piv:9a` (PIN + touch #1) | mandate `6ba0c427…`, nonce 0 → `/exchange/policy-install.msg` |
| server: `signerd submit --file /exchange/policy-install.msg`; `status` | `{"http_status":200,"ok":true,"response":{"installed":true}}`; `installed true`, `mandate_hash 6ba0c427…`, `boot_armed true` |
| **drill:** server `docker restart tee-btcpay-tee-signer-1`; `signerd status --out /exchange/status-after-restart.json` | **`boot_armed false`**, `boot_challenge f2fe5b1d…411d4`, nonce 0, seq 0 — the production enclave reloaded on T2 waits for the owner |
| laptop: `owner-cli --status-file status-after-restart.json --wallet-record wallet.json --out arm.msg arm --key piv:9a` (PIN + touch #2) | `enclave remembers seq 0; you last saw seq 0` → signed `Arm{enclave_id, nonce 0, boot_challenge f2fe5b1d…, seq_seen 0}` for load `1ef8c603…` |
| server: `signerd submit --file /exchange/arm.msg`; `status` | `{"http_status":200,"ok":true,"response":{"applied":true}}`; **`boot_armed true`**, nonce 1, seq 0 |
| server: T2 BTCPay store wallet ← `[51ca22a4/84'/1'/0']tpubDDpFY9q…` (cold), plugin ← new token | HTTP 200 / 200; plugin status `configured true, walletIsHot false, xpubMatches true, processorEnabled true, error None`; the plugin's enclave view has **no `bootArmed` field yet** (`None`) — the FAQ claim that the plugin page shows the pause is withdrawn until the plugin exposes it (carried, host-side) |

Not in this run: a signature after the arm (the new wallet is unfunded; a faucet deposit and a
payout through the plugin are the owner's follow-up — `seq` 0 → 1 would complete C-R7-13's "sign
accepted"). The dev-signed R6 image `6543d86dd219` and the retired state copy stay on the node until
the owner says otherwise.

C-R7-13 **DISCHARGED** by the auditor firsthand (2026-11-10): the two status files prove the volatile
armed flag (true after init → false after the reload, with a fresh challenge `f2fe5b1d…` ≠ the
init load's `ee06fb1c…`) and the owner's Arm over the new challenge; an Arm over the old challenge
could not have passed — the anti-replay property live. Left as confirmations on a funded wallet
(source-proven): the post-arm sign (`seq` 0 → 1) and the live arm negatives (`ARM_CHALLENGE`,
`ARM_SEQ_BEHIND`).

**Live signature after the arm — 2026-11-10 14:21 UTC (the "sign accepted" half, T2).** The owner funded
the new wallet from signet faucets (71 778 sat on `tb1qlj3wg…`, confirmed at 330252). The product path
(a 2 000 sat payout through the plugin's payout processor) did **not** complete: the processor ticked
every minute until 13:40:39 (`CreatePSBT failed: Not enough funds` while the deposits were unconfirmed
and before NBXplorer indexed the new xpub — the owner's wallet rescan in the BTCPay UI fixed the
balance), then stopped ticking; it did not run after the owner's `docker restart` of BTCPay either
(plugin loaded, processor configured and enabled, `fullySynched true`, no error in the log, 0 ticks in
30 min; two off/on toggles through the plugin API changed nothing). **Host-side finding, not the
enclave's** — to be debugged on the T1 dev stack; payout `2JmVSa2z…` left `AwaitingPayment`. The
signature was therefore shown on the dev path (`owner-cli` through the dev forward 7395; log
`.local/signet-t2/live-sign-2026-11-10.log`):

| Step | Result |
|---|---|
| `psbt-build` — coin `a962f5f7…:1` (10 000 sat, branch 0 index 0), 2 000 sat to `tb1qagl75…` (an address of the T1 dev wallet, *unlisted*), fee 300, change 7 700 to branch 1 index 0 | 628-char PSBT with `non_witness_utxo` from the public Esplora |
| `sign` (JUDGE + SIGN in the armed enclave, session `1ef8c603…` = the load the owner armed) | signed PSBT; receipt **seq 1**, txid `a1c7ad9ff4bfeb39bf8bc37d420de5efeee5005585a3ea4c82a2c7b72d877104`, receipt signed by the stamp |
| `finalize` + `broadcast` (mempool.space) | accepted; the explorer shows 1 input, outputs 2 000 → `tb1qagl75…` and 7 700 → `tb1qyzwwr…` (own change), fee 300 |
| `status` after | `seq 1`, `boot_armed true`, `nonce 1`, **`window_outflow 2300`, `window_unlisted 2000`, `window_fees 300`** — the window counters charged exactly the mandate's view of the transaction |

The unarmed half (`NOT_ARMED` on a real reload) is source-proven and will be shown on the T1 drill
(C-R7-12) where the sidecar can be restarted freely.

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
