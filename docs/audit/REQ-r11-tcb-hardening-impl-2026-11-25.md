# REQ-r11 — the TCB hardening round: impl (SafeMath in the TCB, validate-on-open, the scan cost bound, one TCS)

**Date:** 2026-11-25. **Status:** SENT for IMPL-PASS against `RESP-r11-tcb-hardening-design-2026-11-25.md`
(DESIGN-PASS at `7f77006`) and its conditions C-R11-1 … C-R11-5. **Branch:** `r11-tcb-hardening` (PR to `main`; the
head hash in the PR). **Scope:** `core/`, `enclave/rcore`, `enclave/Makefile`, `fuzz/`, CI, docs; `host/` and `owner/`
untouched. **MRENCLAVE changes** (A, C, D are enclave diffs; B's comment rides): the build, the ceremony and the T2
migration follow the IMPL-PASS and are the owner's direct steps (§9).

## 1. What landed

| Path | What |
|---|---|
| `core/Cargo.toml`, `enclave/rcore/Cargo.toml` | `[lints.clippy] arithmetic_side_effects / cast_possible_truncation / cast_sign_loss = "deny"`; `overflow-checks = true` in `[profile.release]` and `[profile.dev]` |
| `enclave/rcore/src/lib.rs` | `#![deny(clippy::arithmetic_side_effects, clippy::cast_possible_truncation, clippy::cast_sign_loss)]` next to `core`'s |
| `core/src/reason.rs` | `Reason::StateInvalid` → `STATE_INVALID`, `Reason::PolicyTooExpensive` → `POLICY_TOO_EXPENSIVE`, their hints |
| `core/src/wallet.rs` | `DERIVATION_CAP = 128_000`, `TrustedMatches`, `match_trusted_outputs` (the one pass with the counter), `derivation_cap_from_bounds`; `matches_trusted` kept as the reference |
| `core/src/classify.rs` | the output loop leaves non-own outputs `Unlisted` and remembers them; one `match_trusted_outputs` after the loop rewrites the matched ones to `Trusted { dest }` |
| `core/src/tpm_attest.rs` | the two `as u16` casts of the attest builder → `u16::try_from(..).unwrap_or(u16::MAX)` (a size the verifier refuses) |
| `core/tests/trusted_scan.rs` (new), `core/tests/{common/mod.rs, headers.rs, vectors.rs}` | the scan's tests (§5); the test fixtures' eight arithmetic sites converted (`checked_*` with `expect`) |
| `enclave/rcore/src/ops.rs` | `open()`: `state.mandate.validate()` when a state is present → `STATE_INVALID` before anything else (§4) |
| `enclave/rcore/src/session.rs` | the TCS-invariant comment on `ensure()` (§3); `word()`; every byte-offset loop as `chunks_exact` / `zip`; `TPM_PROOF_MAX`; `usize::try_from` on the stored length |
| `enclave/rcore/src/sgx.rs` | the nosgx RNG by `chunks_mut`; the nosgx container with `u32::try_from` lengths and a split-based parser (`strip_prefix`, `split_first_chunk`, `split_at_checked`) — a malformed container is `None`, never a panic |
| `enclave/rcore/src/recovery.rs` | the capacity hint `saturating_add` |
| `enclave/rcore/tests/replay.rs` | the four fixture sites converted; the vector `validate_on_open_refuses_an_invalid_state_and_leaves_the_proof_unconsumed` |
| `enclave/Makefile` | gate 8: `TCSNum 1` and `TCSPolicy 1` in `Enclave.config.xml` or the build fails |
| `.github/workflows/ci.yml` | the same check in the `rcore-nosgx` job |
| `fuzz/src/dispatch.rs` | the carried-state skip removed; `invalid_state()` predicts `STATE_INVALID` at every opener (`open_stale`, STATUS, REPORT, INSTALL); `pub fn raw` for the gate's own vectors |
| `fuzz/src/policy.rs` | classify knob 8: the one trusted destination an ADDRESS (the cold wallet's index 1); the oracle's Cold rule written from the mandate's first matcher |
| `fuzz/tests/replay.rs` | seeds: the Address arm both ways (knob 8, index 1 / 2), `negative-invalid-version`, `negative-invalid-too-many-trusted`; the detector tests `validate_on_open_refuses_a_mangled_state_and_keeps_the_proof`, `derivation_cap_refuses_during_the_scan` |
| `fuzz/injected-defects.sh` | two cases: the hook removed, the cap's refusal removed |
| `docs/DESIGN.md`, `docs/ENCLAVE.md`, `docs/POLICY.md`, `docs/FAQ.md`, `docs/FAQ_ru.md`, `CLAUDE.md`, `fuzz/README.md` | the round's semantics for readers and operators (§8) |

## 2. Item A — SafeMath in the TCB (C-EXT1-1; C-R11-1)

**Enforcement.** The three lints as `[lints.clippy]` tables in both manifests (they reach `tests/`), the same three
as `#![deny]` at the top of `enclave/rcore/src/lib.rs` (visible at the source, as `core`'s attribute), `overflow-checks
= true` in release and dev of both. `enclave/rcore/Cargo.toml` is the root manifest of the enclave build — `make`
runs `cargo build --release --locked` in `enclave/rcore` (`enclave/Makefile:138`, gate 3) — so its profile governs
`signer-core` compiled into the enclave; with `panic = "abort"` a missed overflow aborts the ecall
(`SGX_ERROR_ENCLAVE_CRASHED`, nothing charged). CI: the `core` and `rcore-nosgx` jobs already run
`cargo clippy --all-targets -- -D warnings`; both are green with the tables.

**The sites (the design REQ's 29) and what each became:**

| Where | Was | Now |
|---|---|---|
| `core/src/tpm_attest.rs:211, :220` | `len as u16` ×2 | `u16::try_from(..).unwrap_or(u16::MAX)` — a Name longer than a u16 cannot be honest and gets a size the verifier refuses |
| `rcore session.rs` `ensure()` | `16 + 8 * i`, `off + 8` | `b.chunks_exact(8)` zipped with the atomic words (the zero fallback of `word()` unreachable — stated in its doc) |
| `rcore session.rs` `challenge()`, `tpm_nonce_value()` | `8 * i .. 8 * i + 8` ×2 | `out.chunks_exact_mut(8).zip(words)` |
| `rcore session.rs` `tpm_nonce_issue()` | `8 * i .. 8 * i + 8` | `TPM_NONCE.iter().zip(b.chunks_exact(8))` |
| `rcore session.rs` `tpm_proof_store()` | `72 * 8`, `8 * i`, `start + 8`, `end − start` | `TPM_PROOF_MAX` (576), `bytes.chunks(8)` with the last chunk zero-padded by its own length |
| `rcore session.rs` `tpm_proof_take()` | `as usize` | `usize::try_from(..).ok()?` |
| `rcore sgx.rs` nosgx RNG | `buf.len() − off`, `off + n`, `off += n` | `buf.chunks_mut(32)` |
| `rcore sgx.rs` nosgx seal | `len as u32` ×2 | `u32::try_from(..).ok()?` |
| `rcore sgx.rs` nosgx unseal | `tag.len() + 8`, `p + 4` ×2, `p += 4` ×2, `p + al`, `p += al`, `p + tl`, `p + tl != len`, `as usize` ×2 | `strip_prefix` → `split_first_chunk::<4>` → `split_at_checked(usize::try_from(len))` ×2 → `rest.is_empty()`: no offsets at all |
| `rcore recovery.rs:56` | `65 + ct.len()` | `65usize.saturating_add(ct.len())` (a capacity hint) |
| the test sides: `core/tests/common/mod.rs` (1), `core/tests/headers.rs` (5: `salt as u8`, `nonce += 1`, `t0 + 10 * (i + 1)`, `salt + i`, `height += len as u32`), `core/tests/vectors.rs` (2), `enclave/rcore/tests/replay.rs` (4) | bare operators and casts in fixtures | `checked_*` with `expect` (a fixture that overflows is a test failure), `to_le_bytes()[0]` for the salt byte, `Some(seq) != v.seq.checked_add(1)` for the comparison |

**The real-SGX arms (`cfg(not(feature = "nosgx"))`, Q3 / C-R11-1) — the hand-read list, every arithmetic
expression in them:** `seal`: `u32::try_from(aad.len())`, `u32::try_from(plain.len())` (checked), `size as usize`
(u32 → usize, a widening on the only target the enclave builds for); `unseal`: `sealed.len() < 560` (a compare),
`aad_len as usize`, `txt_len as usize` (widenings), three compares of the SDK's out-lengths; `report`: none;
`mrenclave`: WAS `report[MRENCLAVE_OFFSET..MRENCLAVE_OFFSET + 32]` — a constant sum — NOW `report[MRENCLAVE_OFFSET..][..32]`
(no operator); `debug_attribute_set`: `report[48..56]` (a literal range), `flags & 0x2` (bitwise); `read_rand`,
`abort`: none. Nothing else. These arms compile only in the enclave build; `overflow-checks` stands behind them.

## 3. Item B — the TCS invariant (C-EXT1-2; C-R11-2, blocking)

The comment on `session::ensure()` names what its safety rests on — `TCSNum 1`, `TCSPolicy 1`, one ecall at a time
from any host thread (and the single-threaded `nosgx` harness and daemon) — and says that raising `TCSNum` requires a
proper once-init first (an `AtomicBool` compare-exchange or a `Once`), the race being a torn session id / challenge
that the owner's `Arm` would then fail against. **Fail-closed, the condition:** the enclave Makefile's **gate 8**
fails the build unless `Enclave/Enclave.config.xml` contains `<TCSNum>1</TCSNum>` and `<TCSPolicy>1</TCSPolicy>`,
naming `session.rs` in the message; the CI `rcore-nosgx` job runs the same two greps, so a config change trips the
PR before the box. The dev chose the gate over rewriting `ensure()`: the invariant is true today and the gate makes
its violation loud at the place the config changes.

## 4. Item C — validate-on-open (C-EXT1-3; C-R11-3)

`ops::open()` — the one door: `Envelope::unseal` (MAC, AAD, strict decode) and then, when `env.state` is `Some`,
`state.mandate.validate()`; a failure refuses `Reason::StateInvalid`. `open_full_stale` and `open_full_fresh` go
through `open()`, so the check precedes `session::tpm_proof_take()` — the single-use counter proof is **not**
consumed on `STATE_INVALID`; the two direct `open()` callers (INSTALL over an existing state, the recovery path)
are covered by the same line. The code is distinct from `STATE_UNSEALABLE` (Q2): the seal opened, the bounds failed.

**Vectors.** `enclave/rcore/tests/replay.rs::validate_on_open_refuses_an_invalid_state_and_leaves_the_proof_unconsumed`:
a valid regtest state made invalid by one bound (`own_index_gap = MAX + 1`), TPM-bound, installed as given by
TEST_INIT; STATUS and POLICY refuse `STATE_INVALID`; nonce → deposit → FREEZE refuses `STATE_INVALID` and a second
deposit is **accepted** (the nonce still live); the control — the same proof over the valid bound state — is consumed
by FREEZE and the second deposit refuses `TPM_NONCE`. The same vector through the fuzz gate
(`validate_on_open_refuses_a_mangled_state_and_keeps_the_proof`, over `rcore_call`). The fuzz `dispatch` oracle now
predicts `STATE_INVALID` at every opener and the two pass-(iii) regressions (the run-1 timeouts, states with a gap in
the millions) are refused in milliseconds where they used to be skipped.

## 5. Item D — the descriptor-scan cost bound (C-EXT1-4; C-R11-4, blocking)

**The one pass.** `wallet::match_trusted_outputs(secp, trusted, scripts, cap)`: for each trusted destination in list
order — an `Address` compares its script against every still-unmatched output; a `Descriptor` (skipped when no
unmatched P2WPKH output remains, as the per-output walk skips non-P2WPKH) derives each branch key once and each
candidate once, compares the candidate's P2WPKH script against every still-unmatched output, and marks the matches
with the destination index. An output already matched is never re-matched, so the first destination in list order
wins — exactly the per-output `matches_trusted`, which stays in the crate as the reference. `classify` calls it once
after its output loop over the outputs that are neither OP_RETURN nor own.

**The counter and the cap.** Candidate derivations are counted as they happen; when the count would pass `cap` the
scan returns `PolicyTooExpensive` **inside the loop** (the per-branch key derivations — at most 128 — are not
counted; the count is the candidates). `DERIVATION_CAP = 128_000 = MAX_TRUSTED × MAX_BRANCHES × MAX_GAP`
(`derivation_cap_from_bounds()` and the test `cap_is_the_bounds_product` hold it) — the validated worst case, so a
mandate that passed `validate` is never refused (Q1: the bounds product, the wall time recorded, not enforced).

**The semantics proof (C-R11-4).** (i) The `classify` fuzz oracle (`policy.rs::expected()`) is unchanged on the
descriptor path and the whole gate is green over the committed corpus and regressions (4 655+ inputs, 264 s — the
only oracle change is the new Address rule for knob 8, written from the mandate's first matcher). (ii) Every existing
classify / judge / vector test in `core/tests` is green unchanged. (iii) `core/tests/trusted_scan.rs::one_pass_equals_the_per_output_walk_in_every_order`:
five destinations (three descriptors over two wallets with different gaps and branch lists, one Address, one
descriptor over a wallet's change branch) against fifteen outputs (inside and beyond gaps, both branches, the
address, strangers, an OP_RETURN, a duplicate) — the one pass equals the per-output reference, in every rotation of
the output order, and the spelled-out expected mapping; the count is `5 + 2·7 + 3 + 4 = 26`.
`first_match_in_list_order_wins`: two descriptors over one xpub, an Address after and before a descriptor, a
descriptor whose xpub does not decode (matches nothing, stops nothing). `address_matcher_both_directions_and_no_derivation`.

**The cap, both directions.** `the_cap_refuses_during_the_scan_and_never_at_the_boundary`: 22 candidates against a cap
of 22 pass with the count 22; a cap of 21 refuses; a cap of 5 refuses inside the first descriptor before the second —
the one that would match — is touched; sixty-four descriptors of gap 1000 under a cap of 5 refuse within two seconds
(128 000 derivations take about four), the wall-clock witness that the refusal comes during the scan. The ignored
`the_validated_worst_case_fits_the_cap_exactly` (64 × 2 × 1000 against 500 stranger outputs): **128 000 derivations,
not refused, 3.88 s** in release on the dev laptop (`cargo test --release --test trusted_scan -- --ignored`); the
same on T2 after the migration goes into the deploy row.

## 6. Item E — the fuzz ratchet (C-R10P2-3, C-R10-F)

- **Oracles.** `dispatch`: `invalid_state()` at every opener predicts `STATE_INVALID`; the skip of pass (iii) is gone;
  the shell model keeps the deposit on that refusal (the oracle's `open_stale` returns before the TPM gate, as the
  enclave's `open()` does). `classify`: knob 8 — the one trusted destination the cold wallet's index 1 as an Address;
  the oracle's Cold rule reads the mandate's first matcher (a descriptor covers every index below its gap, an Address
  exactly one script, no destination nothing). Any `POLICY_TOO_EXPENSIVE` the production code returned for a valid
  mandate would already be a false refusal under both oracles — no change needed for direction 2.
- **Seeds.** classify: knob 8 with out 0 at cold index 1 (trusted by the exact compare) and at index 2 (not);
  mandate_decode: `negative-invalid-version` (version 2), `negative-invalid-too-many-trusted` (`MAX_TRUSTED + 1`).
- **Not seeded, by construction (the auditor's two remaining lines):** `classify.rs`'s `!prevout.script_pubkey.is_p2wpkh()`
  for an own input sits behind `script == prevout.script_pubkey` with `script` a derived P2WPKH — unreachable, the
  check is a belt; `state.rs`'s `compare` `Network` arm (and its `Wallet` twin) sits behind `apply_message`'s own
  `new.network != s.network` → `POLICY_NETWORK` (and `new.wallet != s.wallet` → `POLICY_WALLET`) a few lines above
  the `compare` call — the seed "another network" is refused there, the arm in `compare` is the belt for `compare`'s
  other callers. Both named so the union coverage can carry them as unreachable rather than missing.
- **Mutation.** `injected-defects.sh`: "validate-on-open removed" → the gate RED (the detector test and the
  regressions); "the cap's refusal removed" → RED (the detector test). Results: §7.

## 7. What was run

| Check | Result |
|---|---|
| `core`: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` (the three lints), `cargo test` | green — 3 + 4 + 7 + 12 + 5 (+1 ignored) + 1 tests |
| `core`: the ignored worst case in release | 128 000 derivations, 3.88 s, not refused |
| `rcore`: fmt, clippy `--features nosgx,test-init --all-targets -- -D warnings`, `cargo test` | green — 2 unit + 6 replay tests (the new vector among them) |
| `fuzz`: fmt, clippy `--no-default-features`, `cargo test --no-default-features` (the replay gate) | green — 7 tests, the corpus and regressions in 264 s |
| `fuzz/injected-defects.sh` (32 cases: the 30 of pass (iii) + the two of R11) | **32/32 caught**; `core/` and `enclave/rcore/src/` restored clean. The R11 cases: the hook removed → 2 tests red (the detector and the corpus replay — the regressions now assert `STATE_INVALID`); the cap's refusal removed → the detector red (that case replays the whole corpus, 295 s, since no corpus verdict depends on the cap — the designed shape: the cap is unreachable for a valid mandate) |
| `scripts/e2e-local.sh` (signerd nosgx linking the new rcore — the validate-on-open door live in the daemon's in-process enclave — with owner-cli) | green: `e2e-local: OK (incl. REQ-r9 TPM counter)` — the full owner flow, the TPM counter path, the rollback drill |
| `fuzz/coverage.sh classify`, `fuzz/coverage.sh dispatch` (nightly-2026-06-21, the regenerated `seeds/`) | `classify`: `classify.rs` 93.37 % of lines (pass (ii): 93.23 %), `wallet.rs` 65.77 % — `match_trusted_outputs` reached, the **Address arm executed both ways** (lines 164/166 ×3: the compare; 167 ×1: the match — the knob-8 seeds), `matches_trusted` 0 (the reference, test-only now), the cap's refusal line 0 (unreachable for a valid mandate by design; covered by `core/tests` and the gate's detector); `dispatch`: core/src 87.01 % of lines, `enclave/rcore/src` **97.30 %** (ops.rs 96.70 %, session.rs 100 %), `ops::open` 9/9 regions — the validate line executed 10 700 times and the `STATE_INVALID` refusal 350 times; the dispatch fixtures carry no Address matcher (its Address arm is the classify target's) |
| CI on the PR head | the 8 checks |

## 8. Docs

`DESIGN.md` (the seal door: validate-on-open; classify: the one pass and the bound), `ENCLAVE.md` (gate 8; the
arithmetic paragraph — the lints, `overflow-checks` through the root manifest, the abort semantics, the hand-read
arms), `POLICY.md §6` (`STATE_INVALID`, `POLICY_TOO_EXPENSIVE`), `FAQ.md` / `FAQ_ru.md` (what `STATE_INVALID` means
for the operator and what to do), `CLAUDE.md` rule 9 (status: every product crate converted), `fuzz/README.md` (the
skip became a prediction). `REPRODUCIBLE-BUILD.md` and `deploy/README.md` get their rows with the build (§9).

## 9. After the IMPL-PASS (owner-direct)

Three builds of the merge commit on the build box (the rsync tree, a fresh clone with the dev key,
`SIGN=ceremony PHASE=gendata`), `compare-builds.sh` REPRODUCIBLE, the owner's ceremony signature
(`scripts/ceremony-sign.sh`), `PHASE=catsig` with every gate (gate 8 among them, gate 7 the MRSIGNER pin), the T2
image from the ceremony output, and the T2 migration as the 2026-11-21 rows document — the new MRENCLAVE cannot open
the old sealed state, so the wallet is retired and re-created, the mandate re-installed, the anchor re-done, the
BTCPay store re-pointed: owner-run; the dev prepares the worked-example script with this build's values.

## 10. Questions to the auditor

- **Q1** — the two unreachable-by-construction lines of §6 (`classify.rs`'s own-input P2WPKH belt, `state.rs`'s
  `compare` Network/Wallet arms behind `apply_message`'s own checks): carried as "unreachable, a belt" in the coverage
  record, or do you want the belts removed so the code says what is reachable?
- **Q2** — the T2 wall time of the worst case: recorded after the migration in the deploy row, or do you want it
  measured on the box's hardware before the PASS?

## 11. Status log

| Date | Event |
|---|---|
| 2026-11-25 | impl on `r11-tcb-hardening`: A, B, C, D, E landed; core / rcore / fuzz green; the worst case measured; this REQ drafted while the injected-defects and e2e runs finish |
| 2026-11-25 | injected-defects 32/32 caught; e2e-local OK on the new rcore; the real-SGX `mrenclave` offset sum replaced by a slice of a slice (the hand-read list of §2 now has no operator left); coverage for `classify` and `dispatch` re-run (§7) |
| 2026-11-25 | `seeds/` regenerated (`TEE_FUZZ_SEEDS_OUT=seeds … write_seeds`: classify 48 → 50, the two mandate_decode negatives) and the classify coverage re-run with them: the Address match line executes; REQ SENT with the PR |
