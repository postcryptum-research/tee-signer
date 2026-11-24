# REQ-r10 phase 2, pass (iii) — impl: `dispatch` (F10)

**Date:** 2026-11-24. **Status:** DRAFT → SENT for IMPL-PASS against C-R10-7 (a)/(b) for the F10 class, the pass-(iii)
row of the phase 2 design (`REQ-r10-fuzzing-phase2-design-2026-11-21.md`, DESIGN-PASS; RESP-r10 ruling "F10 = the
C-R9-C table + `SIGN ⇒ JUDGE accepted ⇒ seq+1` + the named safety invariants as DIRECT checks, no state-machine model";
RESP-r10 phase 2 Q1: the feature-unification record, Appendix A). **Branch:** `r10-p2-dispatch`, on top of
`r10-p2-classify-judge` (pass (ii), PR #8, awaiting its IMPL-PASS; this pass merges after it). **Scope:** `fuzz/` only —
`core/`, `enclave/`, `host/`, `owner/` untouched. `enclave/rcore` is *linked* by the harness (a path dependency with
`nosgx,test-init`, exactly what `signerd --features nosgx` links), not changed: no visibility change, no new
feature, `enclave/rcore/Cargo.lock` as it was.

## 1. What landed

| Path | What |
|---|---|
| `fuzz/src/dispatch.rs` | the target body: the ecall through the exported `rcore_call`; the nosgx envelope read back; the model of the volatile session and of the host's TPM; the per-op reading (ops.rs's order of gates, `signer-core`'s decisions); the scripted sequence and the raw mode; `carried_state` — the state a request carries, and the one rule of what is not sent (§6: the seal) |
| `fuzz/src/lib.rs` | `#![forbid(unsafe_code)]` → `#![deny(unsafe_code)]`, with `#[allow(unsafe_code)]` on the two functions that make the C call (`raw_call`, `abi_bad_args`) — the one `unsafe` of the harness is the real ecall's ABI |
| `fuzz/Cargo.toml` | `rcore = { path = "../enclave/rcore", features = ["nosgx", "test-init"] }`; the `dispatch` binary |
| `fuzz/fuzz_targets/dispatch.rs`, `fuzz/src/targets.rs` | the binary and the `TARGETS` row |
| `fuzz/tests/replay.rs` | `dispatch_seeds` (37: twelve honest requests as raw inputs, four raw edges, twenty-one scripted sequences S1–S20) in the gate and in `honest_objects_pass_their_targets` |
| `fuzz/corpus/dispatch` | the grown corpus after `cmin` |
| `fuzz/regressions/dispatch/REG-2026-11-24-harness-nosgx-seal-gap-*` | the two inputs of run 1 that did not terminate — the nosgx seal's missing MAC, not the enclave (§5); kept so the gate guards the harness's `carried_state` guard |
| `fuzz/injected-defects.sh` | nine new cases (§5 b); the script now refuses to start unless `enclave/rcore/src/` is clean too and restores it with `core/` |
| `fuzz/coverage.sh` | for `dispatch`, a second report over `enclave/rcore/src` (the shell's functions and lines) |
| `fuzz/run.sh`, `.github/workflows/fuzz-smoke.yml`, `fuzz/README.md` | limits (`dispatch` 16384/64), the smoke list, the layout row and the pass (iii) paragraph |

## 2. The target

### 2.1 The entry

The phase 2 design named `rcore::ops::dispatch`. `ops`, `envelope` and `session` are private modules of `rcore`;
the crate exports one symbol, `rcore_call(op, in, in_len, out, out_cap, out_len)`, which is what the edger8r bridge
calls. The harness calls that — the real ecall surface, so `rcore_call`'s own contract is under the oracles too:
`OK` for every input, `OUT_TOO_SMALL` with the needed length in `out_len` and a byte-identical retry at that length,
`BAD_ARGS` on a null output pointer or a null input pointer with a non-zero length. Making `ops` public would have been
an `enclave/` change; the harness needed none.

Under `nosgx` the SDK calls are stand-ins (`sgx.rs`): randomness is a deterministic SHA-256 stream seeded per process,
the seal is a tagged **unencrypted** container (`NOSGX-SEAL-V1 ‖ aad ‖ plaintext`), `MRENCLAVE` is zero, the report is
zero with `report_data` at its offset, the tier reads `T0-nosgx`. The harness reads the container back
(`dispatch::open_env`, a mirror of `Envelope::decode`): the state the enclave decided on, the seed and identity key
that must never move, the two-phase `last_judged` record — and predicts the sealed bytes of every response exactly,
since the container is deterministic. The hardware MAC is R2's smoke test, not this target's (§6).

### 2.2 The input

`[mode] ‖ …`:

- **mode 0, raw:** `[0, sel] ‖ bytes` — a reload, `TEST_INIT` with the regtest fixture, then `OPS[sel % 14]` (or an
  arbitrary op code from the next four bytes when `sel ≥ 14`) with `bytes` as the request. The seeds are every op's
  honest request on that signer, so the fuzzer mutates real blobs, real PSBTs, real messages.
- **mode 1, scripted:** `[1, flags] ‖ 8-byte steps`, at most 16 steps (the design's bound). `flags`: bit 1 a
  keys-only init (no state — `INSTALL` is a step), bit 2 the signet fixture state of the vectors instead of the
  regtest one, bit 4 the cold wallet's seed under the hot wallet's mandate, bit 8 an invalid identity key
  (`KEY_DERIVATION`, no blob at all), bit 16 the ABI checks and the recovery blob's mutation, bit 32 a testnet4 keys-only init (the regtest mandate then
  fails `INSTALL`'s network check), bit 64 a network byte that is no network (`POLICY_NETWORK`, no blob). Then `TEST_INIT` with
  seed `[0x01; 32]` — the vector suite's hot wallet, so the pass (ii) PSBT generator speaks for this enclave's keys —
  identity key `[0x55; 32]`, and the regtest fixture state of pass (i) (the base mandate on regtest, the mined
  checkpoint at height 100, `max_reorg` 6).

A step is `[kind, a, b, c, d, e, f, g]`:

| `kind % 14` | Op | `a` (variant) | other bytes |
|---|---|---|---|
| 0 | `STATUS` | — | |
| 1 | `POLICY` | — | |
| 2 | `REPORT` | 0 honest (`target_info` ‖ nonce), 1 one byte short, 2 an `extra` present, 3 one byte long | `c`/`d`/`e` fill the data |
| 3 | `FREEZE` | the deposit variant when the state is TPM-bound | |
| 4 | `HEADERS` | `a % 8 + 1` headers | `c % 8`: 0 honest extension of the state's best, 1 a fork `d % 8` below it, 2 bad `bits`, 3 bad `prev`, 4 a time at the parent's (not above the median), 5 not a multiple of 80, 6 an empty batch, 7 a duplicate header; `f` the deposit variant |
| 5 | `APPLY_MESSAGE` | `a % 13`: the same mandate, a tightening (unlisted cap halved), a loosening (doubled, capped by `max_per_tx`), freshness required with the witness key, `Cancel`, `Unfreeze`, `Rearm`, `Arm`, `Anchor`, `RotateOwner`, `Recover`, `WitnessToken`, `max_outputs = 1` (a tightening `classify` feels at `SIGN`) | `c`: 1 a stranger signs (the owner signs a `Recover`), 2 the wrong nonce, 4 another enclave id; `d`: 1 a stale challenge, 2 `seq_seen` ahead, 4 the owner's counter above the live one, 8 another AK in the anchor, 16 `seq` one behind, 32 another network, 64 another fingerprint, 128 a SHA-1 index Name in the anchor (`POLICY_INVALID` before a proof is read); `e` the deposit variant (`0x80` none) |
| 6 | `JUDGE` | `a & 4` the honest payout of the pass (ii) seeds (own 2 000 000 in, 900 000 unlisted + change out), else a scripted spend from the pass (ii) generator — `a & 1` with one of its fourteen lies, `a & 2` small amounts | `f % 4`: no token, a fresh token, a seq-behind token (the disarm), a `Cancel` offered as the token; `f & 4` garbage `extra`; `d`: 8 another tip hash, 16 a lagging tip, 32 a stranger signs the token; `g` the deposit variant |
| 7 | `SIGN` | `a % 4`: the bytes the last `JUDGE` charged for, another PSBT, the charged bytes with one byte changed, garbage | `g` the deposit variant |
| 8 | `TPM_NONCE` | — | |
| 9 | `TPM_PROOF` | the certify variant (below) for the live nonce (or a made-up one); `a & 0x80` truncated | |
| 10 | reload | `TEST_RESET_SESSION`: unarmed, mark 0, a new challenge (read back by `STATUS`) | |
| 11 | raw | `a < 14` a known op, else an op code from `c..f`; `c % 4`: no bytes, the blob, an honest `InitRequest`, the blob ‖ junk | |
| 12 | `INSTALL` | the regtest mandate signed over the identity-derived enclave id; `a % 7`: honest, signed by the recovery key, another fingerprint, another network, no signature, invalid mandate bytes, a mandate that decodes but fails `validate` (`timelock_blocks = 0`) | |
| 13 | `TEST_INIT` | the `flags` variants above, mid-sequence | |

Every step: `b` chooses the blob the request carries — 0 the current one, 1–7 an older one from the host's history
(how `SEQ_BEHIND_SESSION` and legitimate same-`seq` forks are reached), ≥ 8 a mutated copy of the current one (a flipped
byte at `c`, a truncation, an inserted byte, a swap — a copy whose state still opens but whose mandate fails `validate` is not
sent, §6); `g & 0x80` applies one byte-level change to the final request
bytes; `g & 0x40` makes the host **forget the counter increment** after persisting a TPM-bound blob (the next `Fresh`
op is `STATE_STALE`).

The host's TPM (`Tpm`): the harness's throwaway AK, an index Name under SHA-256, a counter starting at 1000 that only
increments — after every TPM-bound blob the host persists, as the product's `signerd` does. A deposit (variant `v`):
`TPM_NONCE`, then `TPM_PROOF` with `TPM2_NV_Certify` over the live nonce — 0 honest; 1 the counter + 1; 2 the counter
− 1; 3 signed by another AK; 4 another index Name; 5 another nonce; 6 a malformed attest (the deposit accepts it: only
the proof's shape is checked there — the verdict is the next `Fresh` op's); 7 no deposit at all.

### 2.3 Where the sequence can go

Within 16 steps on the regtest fixture: install → headers → judge → sign (the receipt and the signatures verify
by construction of the oracle); a reload → `NOT_ARMED` → `Arm` → signing again; `FREEZE` → `FROZEN` → `Unfreeze`;
`Anchor` → every `Fresh` op gated by the TPM → stale counters, lying proofs, a forgotten increment; a rotation pending,
a loosening pending (the timelock of 144 blocks is not reachable in 16 steps of ≤ 8 headers — the invariant reads as
"the installed mandate does not change", which `STATUS`/`POLICY` pin); a deep fork → `CHAIN_REORG` and the frozen
chain; freshness required → the witness token's `FRESHNESS_MISSING`/`FRESHNESS_TIP`/`FRESHNESS_SEQ_BEHIND` and the
disarm through the dispatcher — the one refusal that changes the blob; every lie of the pass (ii) generator through
`JUDGE`. The seeds (`tests/replay.rs` `dispatch_seeds`, S1–S17) walk each of these; `TEE_FUZZ_TRACE=1` prints the
verdict of every call so a seed's path can be read. The first coverage pass (on the shakeout corpus) added four of them: a testnet4 signer and a network byte that is none, INSTALL with a mandate that decodes but fails `validate`, a tightening `classify` feels between `JUDGE` and `SIGN` (`max_outputs = 1`: the re-classification at `SIGN` refuses — the one way `sign_op`'s classify arm is reached), an `Anchor` naming a SHA-1 index Name.

## 3. The oracles, as implemented

The reading is **`ops.rs`'s order of gates for each op**, computed from the very request bytes (so a byte-level
mutation needs no special case: the harness decodes the request as the shell does and follows), with every decision
taken by `signer-core`'s own function on the state read back from the blob — `State::apply_message` / `apply_arm` /
`apply_anchor` / `freeze`, `headers::apply_headers`, `classify::classify`, `judge::judge`, `sign::sign_own_inputs`,
`tpm_attest::verify_nv_certify` / `certified_counter`, `Mandate::decode` / `validate`, `State::new_at_init`. No DESIGN
§3/§6 state machine is modelled; the harness's own knowledge is the volatile session and the host's TPM:

- **the session model** (`Shell`): `armed` (false after a reload; true after `TEST_INIT`/`INIT`, an accepted `Arm` or
  `Anchor`, a verified fresh counter proof), the high-water mark (raised to the `seq` of every blob a `Fresh` op accepts,
  `Arm` included — C-R7-3), the live nonce and the deposited proof (both consumed by the next blob-reading `Fresh` op
  or `Anchor`, whatever the verdict; a new nonce forgets the deposit), `tpm_last_fresh`; the per-load challenge and
  session id are **learned** from the first `STATUS` after each load (random per load), never predicted;
- **the host's TPM** (`Tpm`): the counter the harness certifies, incremented after every TPM-bound blob persisted.

Per op (the response must be **exactly** the predicted one — `ok`, the reason codes in the core's order, the payload
bytes; a plain refusal carries no payload):

| Op | The reading |
|---|---|
| `STATUS` | open (`STATE_UNSEALABLE`) → network → derive → identity; keys-only or installed report with `activate_pending` + `roll_window` applied as the enclave does; `boot_armed`/`boot_challenge`/`session_id`/`tpm_last_fresh` from the model; `mrenclave` zero, tier `T0-nosgx`, `auto_arm` false |
| `POLICY` | open full stale (`STATE_UNSEALABLE` on keys-only) → the mandate bytes, its signature, the nonce, the pending record |
| `REPORT` | `SealedWith` of exactly 544 bytes and no `extra` (`ENCODING`) → open → the card recomputed from the envelope; `report_data = SHA-256(DOMAIN ‖ nonce ‖ card) ‖ 0[32]` at offset 320 of a zero report |
| `FREEZE` | open full **fresh** (the TPM gate) — no session mark check (as the code: a freeze on any blob that opens) → `state.freeze()` → sealed |
| `HEADERS` | decode with `MAX_HEADERS·80` (`HEADER_INVALID`) → length % 80 → open fresh → mark → `apply_headers`; the new blob is returned **on refusal too** (`HeadersResponse{sealed, 0, best_height}` beside the reasons: a freeze the host must persist) |
| `APPLY_MESSAGE` | decode (`POLICY_INVALID`) → `Message::decode` → `Anchor` opens **stale**, everything else fresh → mark → `apply_arm(msg, challenge)` / `anchor_live_counter` (nonce + proof consumed; identity from the sealed anchor when bound; `well_formed`; `certified_counter` over the live nonce) then `apply_anchor(msg, challenge, live)` / `apply_message` → on `Ok`: mark raised, armed on `Arm`/`Anchor`, sealed |
| `JUDGE` | decode (`PSBT_PARSE`) → open fresh → mark → `NOT_ARMED` → `extra` must decode to a `WitnessToken` (`FRESHNESS_SIG`) → `classify` with the state's bound → `judge`; `Accept`: `seq + 1` exactly, `last_judged = (sha256(psbt), txid, seq, receipt)`, the receipt `Receipt::from_summary`, mark raised; `Refuse` with a disarm: the disarmed state sealed beside the reasons, nothing else moves |
| `SIGN` | decode → open fresh → mark → `NOT_ARMED` → `last_judged` present, `psbt_hash == sha256(bytes)` and `lj.seq == seq` (`PSBT_PARSE`) → `classify` at the bound + gap → `sign_own_inputs` with the derived account key → the receipt's identity signature; **the response bytes are predicted exactly** (RFC 6979 makes the ECDSA signatures deterministic), and the bytes signed equal the harness's own copy of what `JUDGE` charged for |
| `INSTALL` | decode with `MAX_MANDATE_BYTES` → open → a state present (`POLICY_PENDING`) → 64-byte `extra` (`POLICY_SIG`) → network → derive → the `PolicyUpdate` nonce 0 over `sha256(identity_pk)` verifies under the sealed owner key → `Mandate::decode`/`validate` → network → `WalletSpec{fingerprint, m/84'/coin'/0', [P2wpkh]}` (`POLICY_WALLET`) → `State::new_at_init` |
| `TPM_NONCE` | 32 bytes, never the previous nonce; the model's live nonce, the deposit forgotten |
| `TPM_PROOF` | `TpmProof::decode` (`TPM_PARSE`) → a live nonce and ≤ 576 bytes (`TPM_NONCE`) → stored |
| `TEST_INIT` | decode → network → the injected state decodes (`STATE_UNSEALABLE`) → derive/identity (`KEY_DERIVATION`) → the recovery key is a point (`RECOVERY_BLOB`); then the init facts (below); the sealed state is the injected one (`tpm.expected + 1` if bound) |
| `INIT` | decode → network → both keys parse and differ (`POLICY_INVALID`); then the init facts: the blob opens to a keys-only envelope with the request's keys and network; `xpub`/`fingerprint`/`identity_pk` are what the sealed seed and identity key derive; the card names them, tier `T0-nosgx`, and its signature is the identity key's over `card.digest()`; the recovery blob is 113 bytes, opens with the recovery key to the sealed seed, and to nothing with the owner key, another fingerprint or another xpub |
| anything else | `UNKNOWN_OP` |

Every blob a `Fresh` op returns re-opens (the container, the AAD, the strict envelope decoder) and **re-encodes to the
same plaintext** (C-R10-2 on the envelope); its seed, identity key, owner key, recovery key and network are the
init's; its state is the core's result (`bump_tpm` applied when bound); `last_judged` moves only on an accepted
`JUDGE`. `Stale` and `NoBlob` ops return no blob by type (`StatusResponse`/`PolicyResponse`/`ReportResponse`, the
nonce, nothing) — C-R9-C's table as the oracle: the blob the host holds changes only when a `Fresh` op hands a new one
back.

**The direct invariants** are read off the state the core returns and off `STATUS`/`POLICY`, field by field — at most
one pending mandate and one pending owner (`Option`s in the state; a second `RotateOwner` is `POLICY_PENDING`, S5), a
loosening installed only at its activation height (`mandate_hash` unchanged while pending, S5), a freeze taken while
unarmed still frozen after the `Arm` (C-R7-6, S4), `armed == false` after the rollback-suspected refusal until `Rearm`
(S10), `NOT_ARMED` before an `Arm` on the pause build (S3), `TPM_REQUIRED` after a TPM-bound state (S6, S7). They are
not asserted as a second model: the core's state says them, the dispatcher must carry that state unchanged, and the
`STATUS` report must say what the state says.

**The recovery blob** (`recovery::decrypt`, public in `rcore`): opens to the seed with the recovery key; a single-byte
change at any position (the fuzzer's choice), the owner key, another fingerprint or another xpub ⇒ `None` (AES-GCM over
ECDH with the wallet binding as AAD).

## 4. The gate

`cargo test --no-default-features`: **4 655 inputs over 16 targets** (seeds + corpora + regressions; `dispatch` 1 242 of
them: 1 203 corpus after `cmin`, 37 seeds, 2 regressions); fmt and clippy clean (the four deprecation warnings printed
while compiling `rcore` are `rcore`'s own — `generic-array` methods behind the `sha2`/`aes-gcm` versions the harness's
lock resolves — shown, not denied: `-D warnings` applies to the harness crate). The gate takes **4½–6 min on the
laptop** (267 s and 347 s for the replay test in two measurements, the fifteen earlier targets ~40 s of it in pass
(ii)): a `dispatch` input costs ~200–260 ms in the unoptimised test build, because every op of every step derives the wallet from the seed inside
the enclave — BIP39's PBKDF2, 2048 rounds of HMAC-SHA512 — and a scripted input makes up to sixteen such calls plus
the deposits (the harness derives once per (network, seed), cached; the enclave's cost is the enclave's). The replay
of `dispatch` inputs is serial by construction (one process-global session, §6). CI's `fuzz-replay` job took **5 min 3 s**
on this PR's head (about 1 min before this pass; the 60-second smoke job 18 min with the new target); if that is judged
too long, the two levers are an `opt-level` for the harness crate's test profile
(the oracles do not change) or a smaller committed corpus — the auditor's and the owner's call, not taken here.

## 5. Runs and C-R10-7

All runs on the laptop (`fuzz/run.sh`, libFuzzer fork mode, the pinned nightly, `-timeout=10`); logs in the gitignored
`.local/fuzz-runs/` (`shake-p2iii-dispatch`, `hour-p2iii-dispatch`, `hour-p2iii-dispatch-final`):

| Run | Harness | Workers | Wall time | Executions | oom/timeout/crash | Outcome |
|---|---|---|---|---|---|---|
| shakeout | c0ea6a0 | 2 | 309 s | 10 639 | 0/0/0 | clean; cov 8 371; corpus 648 — the first coverage pass read this corpus and added four seeds (b76137c) |
| run 1 | c0ea6a0 | 4 | 3 631 s | 189 292 | 0/**2**/0 | two timeouts, both the nosgx seal (below) — no finding in the shell or the core; cov 8 961, ft 43 416; corpus 1 475 |
| run 2 | 84c5bbf | 4 | 1 404 s, killed | 60 177 | 0/0/0 | clean until killed: cov 9 057, ft 44 449, no artifact; the laptop's memory pressure stopped the session's background task (as in pass (ii), run 2) — not a fuzzing result |
| **run 3 (final)** | **84c5bbf**, on the shared build host at the owner's direction | 4, `nice -n 19` | **3 624 s** | **57 042** | **0/2/0** | **clean**: cov 9 146, ft 45 244; the two "timeouts" and four "slow units" replay on the laptop in **0.19–0.35 s each** (below) — wall-clock starvation, not computation; corpus 1 259 (the laptop's 1 133 ⊂ it) → **1 203** after `cmin`, committed |

Run 3 is the hour the laptop could not give: `fuzz/run.sh` says "laptop only" (REQ-r10 §4) and that remains the rule; the
owner sent this one run to the shared Hetzner build host (8 cores, 62 GB; load ≈ 12 from the other projects there)
after the memory kill. The run lived in its own directory (`~/tee-signer-fuzz`, a clone at 84c5bbf plus the laptop's
corpus), in the user's own toolchain (the pinned nightly and cargo-fuzz 0.13.2 — the laptop's versions), with no sudo
and no other project touched; the workers ran at `nice -n 19`, so they took idle cycles only — ~5 executions per
second per worker against ~18 on the idle laptop. At that share a 10-second wall-clock budget is about two and a half
seconds of CPU, and libFuzzer's `-timeout` measures wall time: the two inputs it reported (16 and 20 `HEADERS` steps —
each op a PBKDF2 inside the enclave under ASan) take 0.22 s and 0.28 s on the laptop, the four slow units 0.19–0.35 s.
Nothing was found; the log is `.local/fuzz-runs/hour-p2iii-dispatch-server.log`, the artifacts `artifacts/dispatch-server/`
(gitignored), the server directory is removed by its enumerated path when this pass closes.

No input in `findings/`. The target runs at ~13–20 exec/s per worker: every call derives the wallet inside the enclave
(BIP39's PBKDF2, 2048 rounds of HMAC-SHA512, under ASan and the coverage counters) and a scripted input makes up to
sixteen of them plus the deposits — so the hour is few executions by the decoders' standard, and the corpus, not the
count, is what the gate replays.

**Harness mistake the runs caught (one, as two inputs — none a core finding; both kept as regressions):**

1. **The nosgx seal has no MAC, and the harness sent it what the SGX seal never would.** Both timeouts opened a blob
   with one byte changed inside the plaintext: the trusted descriptor's `gap` read **6 881 300** and **2 555 924**
   instead of 20, the state decoded (`State::decode` is strict about shape, not about bounds — the bounds are
   `validate`'s, established at `INSTALL`/`APPLY_MESSAGE`), and `classify`'s descriptor scan (`wallet::matches_trusted`,
   `for i in 0..gap { derive_pub }`) derived that many keys for the one unlisted output: the libFuzzer stack at the
   alarm is `matches_trusted ← classify_inner ← judge_op` and `… ← sign_op`; the instrumented binary had not finished
   the first input after ten minutes at 99 % CPU (memory flat — `-malloc_limit_mb` never fired). One blob was placed by
   `blob_for`'s flip (step 5 of the first input, `JUDGE`); the other was **carried into the current blob by a refused
   `HEADERS`**, which re-seals the state it opened and hands it back beside the reasons — as the shell does and the
   reading predicts (§3) — so a later honest `SIGN` on the host's current blob ran into it. Under SGX the AES-GCM tag
   refuses such a blob before a field is read. The fix is in the harness alone: `carried_state` reads the state a
   request carries (a raw blob, the `sealed` of a `SealedWith`, the `state` of a `TEST_INIT` — the one op that installs
   a state as given), and `perform` sends nothing whose mandate fails `validate` (`TEE_FUZZ_TRACE=1` prints the skip).
   Everything else a change produces — a different seed, a different key, a changed amount, a changed `seq` — is still
   sent and read. Commit 84c5bbf; both inputs replay in ~150 ms.

**Observations for the auditor — not findings, named for a ruling:**

- **The enclave trusts every bound in an unsealed state.** No op re-runs `Mandate::validate` on the state it opens;
  the seal's MAC is the sole integrity of `gap`, `branches`, `max_inputs`/`max_outputs`, the window, the chain record.
  On hardware that is the design (the SDK's AES-GCM seal, R2's smoke test). Under `nosgx` — T0, the CI build, what
  `signerd --features nosgx` links — a blob with a changed byte that still decodes is **accepted**, and a `gap` in the
  millions turns `JUDGE`/`SIGN` into hours of CPU. `TEST_INIT` (behind `test-init`, refused by the release build)
  installs a state as given, no `validate`. Whether a `validate` on open (or in `State::decode`) is wanted as defence in
  depth is the auditor's call: it is code, so if wanted it is a current-work item, by REQ, not a mainnet note.
- **The descriptor scan's price, within the bounds.** Per *unlisted* output, `matches_trusted` derives
  `Σ_trusted branches × gap` keys before answering "unlisted" — at the bounds (`MAX_TRUSTED` 64 × `MAX_BRANCHES` 2 ×
  `MAX_GAP` 1000) 128 000 point multiplications per output, times up to `max_outputs` (≤ 500) per PSBT; the fixture's
  one descriptor × one branch × 20 costs 20. The host chooses the PSBT, the owner the mandate; the host already holds
  the enclave's availability, so this is a latency note for `POLICY.md`/`ENCLAVE.md` ("`gap` prices every unlisted
  output") if the auditor wants one, not a finding.

**(b) Injected defects — 30 cases, 30 caught, `core/` and `enclave/rcore/src/` clean after each** (log
`.local/fuzz-runs/injected-defects-p2iii-2026-11-24.log`); the nine new ones — eight in the shell, one in the core's
TPM equality — and what catches each:

| Reverted guard | Caught by |
|---|---|
| `ops.rs`: `SIGN`'s two-phase check dropped (`lj.psbt_hash`/`lj.seq`) | S2 — `SIGN` with another PSBT on the charged blob is accepted ⇒ "accepted although the reading refuses [PSBT_PARSE]" |
| `session.rs`: `check_seq` always true (C-R7-3) | S2/S3 — the pre-charge blob is accepted where `SEQ_BEHIND_SESSION` is read |
| `ops.rs`: `JUDGE` no longer checks the boot-arm (C-R7-4) | S3 — `JUDGE` after a reload is accepted ⇒ "accepted although the reading refuses [NOT_ARMED]" |
| `ops.rs`: `SIGN` no longer checks the boot-arm (C-R7-4) | S3 — `SIGN` after a reload |
| `ops.rs`: a `Fresh` op without a deposited proof proceeds (`TPM_REQUIRED` dropped) | S6 — `JUDGE` on the TPM-bound state without a deposit is accepted |
| `tpm_attest.rs`: the counter equality dropped (C-R9-C: any certified value is fresh) | S6 — the stale-counter proof passes where `STATE_STALE` is read |
| `ops.rs`: the `Anchor` pins `live + 1` instead of the live certified counter (REQ-r9a C3) | S6/S7 — the anchored blob's `tpm.expected` differs from the reading's |
| `ops.rs`: the mark no longer ratchets on an accepted owner message (C-R7-3) | S3 — the old blob after the `Arm` is accepted where `SEQ_BEHIND_SESSION` is read |
| `ops.rs`: `INSTALL` skips the wallet check | S8 — the mandate for another fingerprint installs where `POLICY_WALLET` is read |

**(a) Reachability** (`fuzz/coverage.sh dispatch`, after the runs and `cmin`; the shell's files reported beside
`core/src`):

`dispatch` target (inputs: corpus 1 203 after `cmin`, 37 seeds, 2 regressions): **`enclave/rcore/src` 97.31 % of lines**
(74/77 functions, regions 94.51 %; the three unreached: `_unused`, `seal_or`'s failure closure, `sgx::abort`) —
`ops.rs` **96.67 %** (39/41 functions), `session.rs` **100 %**, `envelope.rs` **100 %** (regions 93.94 %),
`recovery.rs` 96.61 %, `sgx.rs` 96.72 % (6/7: `abort`), `lib.rs` 100 %, `allocator.rs` 87.50 %. Through the shell,
`core/src` is at 88.52 % of lines (190/249 functions): every function the reading names is reached — `classify`
(`classify_inner` 141/151 lines), `judge`, `apply_message`/`apply_arm`/`apply_anchor`/`freeze`, `apply_headers`,
`sign_own_inputs` (36/38), `verify_nv_certify`/`certified_counter`, `Mandate::decode`/`validate`, `State::new_at_init`
(30/30), `Receipt::from_summary`, `derive_keys`, `Account::pubkey_at`; the core functions never reached are the ones
the enclave never calls — `sign::finalize_own_inputs` and `sign::verify_digest_secp` (the host's and a verifier's
side; hence `sign.rs` 50.63 %) and the host-side response decoders `PolicyResponse::decode`/`SignResponse::decode`
(the harness decodes those with its own mirrors). The lines of `classify.rs` (90.62 %), `judge.rs` (87.19 %),
`headers.rs` (82.00 %), `state.rs` (91.26 %), `mandate.rs` (91.29 %), `tpm_attest.rs` (93.62 %) the dispatcher does not
reach are the ones passes (i) and (ii) list and explain for the targets that drive those files directly; this target's
claim is the shell.

Lines of `enclave/rcore/src` the inputs do not execute, and why:

| Lines | What | Why no input executes them |
|---|---|---|
| `ops.rs` 217–218, 261–262 | `TPM_PARSE` when the deposited proof does not decode — at the `Fresh` gate and at the `Anchor`'s read | `TPM_PROOF` decoded the same bytes before storing them (`TPM_PARSE` is reached there, S17); a stored proof decodes — unreachable after a deposit by construction |
| `ops.rs` 321 | the closing brace of `init`'s identity-key loop (`read_rand` until `SecretKey::from_slice` accepts) | the retry: the first 32 random bytes are a valid key with probability 1 − 2⁻¹²⁸; the brace is the loop's second pass, no statement |
| `ops.rs` 342–344 | `KEY_DERIVATION` when `derive_keys` fails on the seed | the seed is 32 bytes mapped through BIP39 and HMAC-SHA512 to the master key, invalid with probability 2⁻¹²⁸ and not choosable by an input; the identity-key arm two lines below (`identity_pk` on `[0; 32]`) **is** reached (S14, flag 8) |
| `ops.rs` 366, 427, 614, 630, 663, 716, 725 | `Err(r) => r` after `seal_or` — `SEAL_FAILED` at `INIT`/`TEST_INIT`, `INSTALL`, `APPLY_MESSAGE`, `FREEZE`, `HEADERS`, `JUDGE` (the accept and the disarm) | the nosgx seal cannot fail (an unencrypted container); on hardware `sgx_seal_data` can — R2's smoke test |
| `ops.rs` 422 | `POLICY_INVALID` from `State::new_at_init` at `INSTALL` | the constructor validates a mandate `validate` accepted three lines above (RESP-r10-F01 C-F01-3: the write-site invariant, not a second opinion) — unreachable by construction |
| `ops.rs` 771 | `SIGN`'s refusal from `sign_own_inputs` | every refusal of `sign_own_inputs` (`PSBT_PARSE` on the input count or the sighash, `INPUT_NOT_OWN` on the path or the key, `INPUT_NO_PREV_TX`, `INPUT_PREV_TX_MISMATCH`) restates a check `classify` made on the same bytes two lines above — unreachable after `classify`'s `Ok` (its own two unexecuted lines are these) |
| `ops.rs` 808 | `fn _unused(_: String) {}` | a `#[allow(dead_code)]` placeholder, never called |
| `recovery.rs` 42 | the brace of the ephemeral-key loop | as `ops.rs` 321: the first draw is a valid P-256 key |
| `recovery.rs` 79 | `pt.len() != 32` after a successful AES-GCM decrypt | the tag binds the length: a 32-byte plaintext was sealed, so a decrypt the tag passes yields 32 bytes — unreachable without a forgery (every single-byte change is `None` at the tag, S15) |
| `sgx.rs` 104–106 | `abort()` | `#[allow(dead_code)]`; the shell never calls it |
| `allocator.rs` 19 | `memalign` for alignments above 16 | no type the shell allocates asks for one |

## 6. Deviations, stated

- **`rcore_call`, not `ops::dispatch`.** The design named the private function; the harness calls the exported
  symbol through one `unsafe` block (`#![forbid]` → `#![deny]` with an allow on `raw_call`/`abi_bad_args`). The
  pointers are the harness's own live buffers; `rcore_call` checks them before dereferencing. Stronger than the
  design's wording: the ABI's `BAD_ARGS`/`OUT_TOO_SMALL`/retry contract is under the oracles as well.
- **The nosgx seal has no MAC.** "An arbitrary sealed blob ⇒ `STATE_UNSEALABLE`" holds for everything the container
  or the strict envelope decoder refuses — the raw seeds and every truncation, every change of the tag or a length,
  most changes inside the state (`State::decode` is strict, phase 1). A change that yields *another valid envelope*
  (a seed byte, a bit of the owner key) is accepted by `nosgx` and followed by the reading as a different signer
  (the derived wallet changes with it; the oracle still holds), and must still be canonical — with one exception the
  first hour run forced (§5): a changed state whose mandate fails `validate` is **not sent** (`carried_state`), because
  the enclave accepts it under `nosgx` and a corrupted `gap` makes the descriptor scan run for hours; the SGX seal would
  have refused it. On hardware the SDK's MAC refuses every such change; that is R2's smoke test (`enclave/rcore/tests/replay.rs` says so at the truncated-blob check). The
  design's "`Envelope::unseal` returns `None` on every mutation" is therefore claimed for the decoder half only;
  `recovery::decrypt` is AEAD and the claim holds in full.
- **The harness reads the blob.** `open_env` decodes the nosgx container and the envelope (a mirror of
  `envelope.rs`, ~60 lines) to see the state the enclave decided on and to predict the sealed bytes. Test leverage, not
  a product property: on hardware the blob is opaque to the host.
- **The reading mirrors the shell's marshalling order** (one function per op, each a transcription of the
  corresponding `ops.rs` function with the core's calls kept and the SDK calls replaced by the mirrors), the session's
  rules (`session.rs`) and `derive_keys`. This is the F10 oracle the RESP asked for — the C-R9-C table and the named
  invariants as direct checks — not a model of the policy's state machine: whatever `apply_*`/`judge`/`classify`
  decide is taken as decided. A drift between the mirror and the shell fires as a harness mistake (visible, kept as a
  regression), never as a weakened oracle.
- **Random per-load facts are learned, not predicted:** the challenge and the session id (`STATUS` after each load),
  the TPM nonce (the `TPM_NONCE` response). `INIT` (op 1) draws its seed from the nosgx stream, so its response is
  checked structurally (every field against the blob it returns; the recovery blob's round trip) rather than
  byte-exactly; `TEST_INIT` is exact.
- **`TEST_INIT` skips `init`'s public-key checks** (a recovery key that is not a point fails at the blob,
  `RECOVERY_BLOB`; an owner key that is not a point is stored as given). Mirrored as it is: the op exists only behind
  `test-init`, which the release build refuses (the `rcore` manifest and the Makefile).
- **Observation, not a finding — `TPM_PROOF`'s store:** `session::TPM_PROOF` holds 576 bytes; a `TpmProof` whose
  attest is `MAX_ATTEST_LEN` (512) encodes to 4 + 512 + 64 = 580 bytes and is refused at the deposit with
  `TPM_NONCE` (the store's "too long" shares the code of "no live nonce"). Fail-closed and unreachable with a real
  `TPMS_ATTEST` (~150–200 bytes); the mirror predicts it; named here for the auditor's ruling on whether a line in
  `ENCLAVE.md` should say so.
- **`FREEZE` takes any blob that opens** — no session mark check (as the code: a freeze is fail-safe). A freeze
  derived from an older blob leaves a blob whose `seq` is behind the mark, so every later `Fresh` op on it is
  `SEQ_BEHIND_SESSION` until a reload. Mirrored; an observation.
- **One enclave = one process:** the session is process-global, so the target serialises inputs with a mutex and
  starts every input with `TEST_RESET_SESSION`. The replay gate's tests run in parallel threads; the mutex is what
  keeps them from sharing a session.

## 7. For the auditor's run

```bash
cd fuzz && cargo test --no-default-features                       # the gate, 16 targets
./injected-defects.sh                                             # 30/30, core/ and enclave/rcore/src/ clean after
./run.sh dispatch 60 1                                            # nightly
./coverage.sh dispatch                                            # core/src and enclave/rcore/src reached by the target
TEE_FUZZ_TRACE=1 cargo test --no-default-features --test replay honest_objects -- --nocapture 2>&1 | grep F10-trace
                                                                  # the verdict of every call of every seed
```

## Appendix A — the feature record (RESP-r10 phase 2 Q1)

`signer-core` is compiled with `{default, std}` only, requested by the harness itself; `rcore`'s `nosgx`/`test-init`
forward nothing into it; `hollow-test` appears nowhere. The same with and without the harness's `libfuzzer` feature:

```
$ cargo tree -e features -i signer-core --no-default-features
signer-core v0.1.0 (<repo>/core)
└── rcore v0.1.0 (<repo>/enclave/rcore)
    ├── rcore feature "default"
    │   └── tee-signer-fuzz v0.1.0 (<repo>/fuzz)
    ├── rcore feature "nosgx"
    │   └── tee-signer-fuzz v0.1.0 (<repo>/fuzz)
    └── rcore feature "test-init"
        └── tee-signer-fuzz v0.1.0 (<repo>/fuzz)
├── signer-core feature "default"
│   └── tee-signer-fuzz v0.1.0 (<repo>/fuzz)
└── signer-core feature "std"
    └── tee-signer-fuzz v0.1.0 (<repo>/fuzz)

$ cargo tree -e features -i signer-core   (with the libfuzzer feature)
signer-core v0.1.0 (<repo>/core)
└── rcore v0.1.0 (<repo>/enclave/rcore)
    ├── rcore feature "default"
    │   └── tee-signer-fuzz v0.1.0 (<repo>/fuzz)
    │       ├── tee-signer-fuzz feature "default" (command-line)
    │       └── tee-signer-fuzz feature "libfuzzer"
    │           └── tee-signer-fuzz feature "default" (command-line)
    ├── rcore feature "nosgx"
    │   └── tee-signer-fuzz v0.1.0 (<repo>/fuzz) (*)
    └── rcore feature "test-init"
        └── tee-signer-fuzz v0.1.0 (<repo>/fuzz) (*)
├── signer-core feature "default"
│   └── tee-signer-fuzz v0.1.0 (<repo>/fuzz) (*)
└── signer-core feature "std"
    └── tee-signer-fuzz v0.1.0 (<repo>/fuzz) (*)

$ cargo tree -e features -i rcore --no-default-features
rcore v0.1.0 (<repo>/enclave/rcore)
├── rcore feature "default"
│   └── tee-signer-fuzz v0.1.0 (<repo>/fuzz)
├── rcore feature "nosgx"
│   └── tee-signer-fuzz v0.1.0 (<repo>/fuzz)
└── rcore feature "test-init"
    └── tee-signer-fuzz v0.1.0 (<repo>/fuzz)
```
