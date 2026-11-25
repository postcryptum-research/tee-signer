# REQ-r11 — the TCB hardening round: SafeMath in the TCB, validate-on-open, the descriptor-scan cost bound, the `ensure()` invariant (design)

**Date:** 2026-11-25. **Status:** **DESIGN-PASS** (`RESP-r11-tcb-hardening-design-2026-11-25.md`, same day) → impl on `r11-tcb-hardening`, conditions C-R11-1…5. **Owner's word:** «REQ раунда ядра» (2026-11-25).
**Scope:** `core/` and `enclave/rcore` (the TCB) plus the `fuzz/` ratchet that goes with every core round (C-R10-F); one
host-side item is *asked about* (§7 F), not assumed. **One MRENCLAVE:** the four conditions below are each an enclave diff;
they land together, get one ceremony-signed build and one T2 migration — the activation and the deploy stay the owner's
direct decision. **Hard rule 1:** no code in `core/` or `enclave/` is written before this REQ has a DESIGN-PASS; the
branch `r11-tcb-hardening` opens after it. **Conditions carried:** C-EXT1-1 (blocking for this round), C-EXT1-2,
C-EXT1-3, C-EXT1-4, C-R10P2-3; C-R10-F (the fuzz ratchet) is standing.

## 1. Why one round

Four conditions came out of 2026-11-25 (the external review's triage and the fuzz passes' observations), each touching
the enclave: the TCB's own SafeMath lint gap (C-EXT1-1, the auditor's word: blocking for the very next core round), the
`ensure()` invariant comment (C-EXT1-2), validate-on-open (C-EXT1-3), the descriptor-scan cost bound (C-EXT1-4). Any one
of them changes MRENCLAVE; four ceremonies and four migrations for four small diffs would be waste and risk. This REQ
bundles them, and the fuzz ratchet that every core round carries (new seeds C-R10P2-3, the oracles extended to the two
new refusals).

## 2. Item A — SafeMath in the TCB (C-EXT1-1)

**Today.** `core/src/lib.rs` carries `#![deny(clippy::arithmetic_side_effects)]`; nothing else in the TCB is linted for
it: no `[lints.clippy]` table in `core/Cargo.toml` or `enclave/rcore/Cargo.toml`, no `#![deny]` in `rcore`'s `lib.rs`,
`overflow-checks` unset in every profile (the release profiles set `lto`, `codegen-units = 1`, `panic = "abort"`,
`opt-level = 2`). The host crates got the three lints and `overflow-checks` in PR #25 (RESP-ext1 PR B).

**The sites, counted with the three lints on 2026-11-25** (`cargo clippy --all-targets` with `arithmetic_side_effects`,
`cast_possible_truncation`, `cast_sign_loss` as deny; `rcore` under `nosgx,test-init`, the features CI lints):

| Crate | File | Sites | What they are | Conversion proposed |
|---|---|---|---|---|
| `core` | `src/tpm_attest.rs:211, :220` | 2 | `signer_name.len() as u16`, `NV_NAME_LEN as u16` when building the TPMS_ATTEST test fixture | `u16::try_from(..)` with a refusal, or the constant written as `u16` — no truncation path |
| `rcore` | `src/session.rs:39–40, :59, :106, :116, :130–133` | 11 | byte-offset arithmetic over the four `AtomicU64` words of the challenge / mark (`8 * i`, `16 + 8 * i`, `start + 8`, `end − start`) | iterate with `chunks_exact(8)` / `enumerate` so no offset is computed; where an offset stays, `checked_*` with `unwrap_or` to the zero word is NOT acceptable — the loop bounds are constants, so the conversion is structural |
| `rcore` | `src/session.rs:152` | 1 | `TPM_PROOF_LEN.load() as usize` | `usize::try_from(..)` → `None` (no deposit) on failure |
| `rcore` | `src/recovery.rs:56` | 1 | `Vec::with_capacity(65 + ct.len())` | `saturating_add` — a capacity hint |
| `rcore` | `src/sgx.rs:88–90` (nosgx stand-in RNG), `:146, :148` (nosgx container lengths as `u32`), `:186–197` (the nosgx container parser) | 14 | the deterministic test RNG's offsets; the unencrypted test container's length fields and parser arithmetic | `checked_add` with `?` / `None` (the parser refuses a malformed container instead of panicking — it is a stand-in, but a stand-in that panics would hide a bug in the test build); `u32::try_from` for the lengths |

Total 29; none on the signing or policy path (those are already under core's `#![deny]`, which is how PR B's host
conversion found core clean). **The real-SGX arms** of `sgx.rs` (`#[cfg(not(feature = "nosgx"))]`: the SDK FFI for
sealing, randomness, the report) are compiled only inside the enclave build and never by CI's clippy; this round reads
them by hand against the same rule and lists every arithmetic expression in them in the impl REQ — **Q3** asks whether
that is the acceptable form of enforcement for code no linter reaches.

**The change.**
1. `[lints.clippy] arithmetic_side_effects = "deny"`, `cast_possible_truncation = "deny"`, `cast_sign_loss = "deny"` in
   `core/Cargo.toml` and `enclave/rcore/Cargo.toml` (reach `tests/` and bins, which the crate attribute does not), and
   `#![deny(clippy::arithmetic_side_effects, clippy::cast_possible_truncation, clippy::cast_sign_loss)]` at the top of
   `enclave/rcore/src/lib.rs` next to `core`'s existing attribute (redundant with the table; the rule is visible at the
   source).
2. `overflow-checks = true` in `[profile.release]` and `[profile.dev]` of both manifests. The enclave build's root
   manifest is `enclave/rcore/Cargo.toml` (`cargo build --locked --release` there, gate 3), so its profile governs
   `signer-core` compiled into the enclave as well; `core`'s own profile governs its host tests. **Semantics in the
   enclave:** `panic = "abort"` stands; an arithmetic overflow that the conversion missed panics → the enclave aborts the
   ecall (`sgx.rs` `abort()`); the SDK reports `SGX_ERROR_ENCLAVE_CRASHED` (0x1006) to the host and nothing is charged
   (signerd already names this case); the enclave is unusable until reloaded, and a reload comes up NOT ARMED until the
   REQ-r9 counter arms it — fail-closed, and §7 F asks whether signerd should reload by itself.
3. Every site of the table converted as proposed; no `#[allow]` without its reason on the line, and in the TCB the
   reason is the auditor's to accept (rule 9).
4. CI: the existing `core` and `rcore-nosgx` jobs already run `cargo clippy --all-targets -- -D warnings`; the tables
   make the three lints fail them. `CLAUDE.md` rule 9's status line changes to "every product crate converted".

## 3. Item B — the `ensure()` invariant (C-EXT1-2)

`enclave/rcore/src/session.rs:28` `fn ensure()` initialises the session id and the boot challenge from in-enclave
randomness on the first call, with a plain load/store on `INIT`. A comment is added that names what its safety rests on,
verbatim as the auditor shaped it: *"Two concurrent first callers cannot happen: `Enclave.config.xml` sets `TCSNum 1`,
`TCSPolicy 1` — the SGX runtime admits one ecall at a time from any host thread (and under `nosgx` the harness and the
daemon are single-threaded, `signerd` serialising its ecalls under one mutex besides). If `TCSNum` is ever raised above
1, this function must first become a proper once-init (an `AtomicBool` compare-exchange or a `Once`) — the race it
would otherwise have is a torn session id / challenge, which the owner's `Arm` would then fail against."* No code change;
the comment is the deliverable, read by the auditor.

## 4. Item C — validate-on-open (C-EXT1-3)

**Today.** `ops::open()` unseals (`Envelope::unseal`: SDK MAC, AAD, strict decode) and hands the envelope on; the
`State`'s mandate bounds are trusted as sealed. Under SGX the AES-GCM tag makes that sound — every bound was
`validate()`d at its write site (INSTALL, APPLY_MESSAGE) and the seal preserves it. Under `nosgx` the container has no
MAC, so a flipped plaintext byte reaches the gates (fuzz pass (iii) run 1: a gap of 6 881 300 and a scan of minutes).

**The change.** In `ops::open()`, after a successful unseal: if `env.state` is `Some(state)`, `state.mandate.validate()`;
on `Err(_)` refuse with a new reason `Reason::StateInvalid` → `"STATE_INVALID"` (core `reason.rs`, with a hint: *"the
sealed state's policy fails its own bounds — impossible under the seal; a corrupted state file or a test build; restore
the last written state, nothing signs until then"*). `open()` is the one door: `open_full_stale` and `open_full_fresh`
go through it, so STATUS, POLICY, REPORT, APPLY_MESSAGE (Anchor included), FREEZE, HEADERS, JUDGE, SIGN all refuse an
invalid state before any gate reads a bound; the two direct `open()` callers (INSTALL over an existing state, and the
recovery path) are covered by the same line. `validate()` is the existing bounds check — cheap, no new logic. Belt and
suspenders under SGX; it closes the nosgx mangled-bound DoS, and it makes the write-site invariant explicit at the read
site, where a reader looks for it.

**What it does not do:** it does not re-validate anything but the mandate's bounds (the chain state, the window, the
sequence are the enclave's own numbers, sealed and not host-shaped); it does not change any accepted input.

**TEST_INIT** (the `test-init` feature, never in a release enclave) installs a state as given; with this change an op
over such a state refuses `STATE_INVALID` — the fuzz harness's `carried_state` skip of pass (iii) becomes a predicted
refusal (§6), one guard fewer in the harness.

## 5. Item D — the descriptor-scan cost bound (C-EXT1-4)

**Today.** `classify` (core `classify.rs:343`) asks `wallet::matches_trusted` for every non-own output and every
trusted destination; for a `Matcher::Descriptor` the function derives every candidate key — `branches × gap`
derivations — and compares scripts, returning at the first match. The cost per PSBT is therefore
`outputs × Σ_trusted(branches_i × gap_i)` derivations; at the validated bounds (`MAX_OUTPUTS 500`, `MAX_TRUSTED 64`,
`MAX_BRANCHES 2`, `MAX_GAP 1000`) that is 64 000 000 secp256k1 point multiplications for one PSBT — minutes inside the
enclave. The auditor graded it liveness/DoS, not safety (the host already owns the enclave's availability, the enclave
is single-threaded, a long scan cannot breach `max_tip_lag`); the fix is hardening.

**The change, two parts.**

1. **Derive once, compare against every output.** The scan is inverted: for each trusted descriptor in list order, each
   candidate key is derived once and its P2WPKH script compared against every output not yet classified (own outputs
   are classified first, as today; an output already matched by an earlier descriptor is not re-matched — first match in
   list order wins, exactly today's result). The `Address` matcher stays an exact byte compare. Cost per PSBT becomes
   `Σ_trusted(branches_i × gap_i)` derivations plus `Σ × outputs` 22-byte compares: at the bounds 128 000 derivations
   (500× less) and 64 000 000 compares (microseconds). No extra memory beyond one `Option<usize>` per output (≤ 500).
2. **A derivation counter with a cap, as the belt.** The scan counts its derivations; when the count would exceed
   `DERIVATION_CAP` it refuses with a new reason `Reason::PolicyTooExpensive` → `"POLICY_TOO_EXPENSIVE"`. **The constant
   is derived, not picked:** `DERIVATION_CAP = MAX_TRUSTED × MAX_BRANCHES × MAX_GAP = 128 000`, the legitimate worst case
   by construction — a mandate that passed `validate()` can never need more, so for a valid mandate the refusal is
   unreachable and the fuzz oracle asserts exactly that (direction 2); the counter exists so the bound is explicit in the
   code and testable, not implied by a loop shape (direction 1, a unit test with an injected smaller cap). **Q1** asks
   whether the auditor wants a tighter, measured constant instead (a time budget per PSBT from a measured derivation
   rate on the T2 hardware, padded) — the dev's reading of "derived from the legitimate worst case" is the bounds
   product, which refuses nothing legitimate; a measured budget would need a re-measurement at every hardware change.

**Semantics preserved:** the set of outputs classified `Trusted { dest }` and their `dest` indices are identical to
today's for every PSBT and mandate — the inversion changes the order of work, not its result; the existing classify
vectors prove it, and the `classify` fuzz target's independent oracle (`policy.rs::expected()`) must agree unchanged.

## 6. Item E — the fuzz ratchet (C-R10-F, C-R10P2-3)

- Seeds (the auditor's two cheap additions): a mandate with a `Matcher::Address` trusted destination and a PSBT with a
  matching and a non-matching output (`wallet.rs:101`, both directions); a bad-`version` mandate; a `trusted.len() >
  MAX_TRUSTED` mandate; a network-changing `PolicyUpdate` (`state.rs:459`); a non-P2WPKH own input (`classify.rs:278`).
- Oracles: `dispatch` predicts `STATE_INVALID` for any carried state whose mandate fails `validate()` (the pass-(iii)
  `carried_state` skip removed); `classify` and `dispatch` assert `POLICY_TOO_EXPENSIVE` is never returned for a valid
  mandate; the `classify` oracle unchanged (the inversion must not move a verdict).
- `injected-defects.sh`: two new cases — validate-on-open removed (the oracle must fire on a TEST_INIT state with a bad
  bound); the counter's refusal removed (the direction-1 unit test must fail).
- Coverage: the two new refusals and `wallet.rs:101` leave the uncovered list.

## 7. Vectors, tests, docs, build, deploy

**Vectors (rule 5).** (a) STATUS over a sealed state whose mandate has `gap = MAX_GAP + 1` → `STATE_INVALID` (nosgx
replay; under SGX the vector is unreachable by the MAC and labeled so); the same state → every Fresh op refuses before
the counter proof is consumed? — **no**: the proof is consumed first in `open_full_fresh` today; the hook sits in
`open()`, which runs before the proof check, so the proof is NOT consumed on `STATE_INVALID` (the blob never opened in
the meaningful sense) — the vector asserts that too. (b) A valid mandate at the bounds (64 descriptors × 2 branches × gap
1000) with a 500-output PSBT: classified, no `POLICY_TOO_EXPENSIVE`, the derivation count = 128 000 exactly, wall time
recorded in the impl REQ on the laptop and on T2. (c) The same scan with an injected cap of 10 → `POLICY_TOO_EXPENSIVE`.
(d) Two descriptors both matching one output → `dest` = the first in list order (unchanged). (e) An `Address` matcher
matching / not matching (the seed of §6). (f) Every converted arithmetic site that had a reachable overflow gets its
boundary vector (the impl REQ lists them site by site; the nosgx container parser's malformed inputs among them).

**Docs.** `DESIGN.md` (the seal section: validate-on-open; the classify section: the scan's cost bound), `ENCLAVE.md`
(`overflow-checks` and the abort semantics; the TCS invariant), `POLICY.md` (the two new refusal codes), `FAQ.md` /
`FAQ_ru.md` (`STATE_INVALID`: what the operator sees and does), `CLAUDE.md` rule 9 (status: every product crate
converted), `REPRODUCIBLE-BUILD.md` (the new MRENCLAVE row after the build), `deploy/README.md` (the migration row).

**Build and deploy (after IMPL-PASS).** Three builds of the merge commit on the build box (the rsync tree, a fresh clone
with the dev key, `SIGN=ceremony PHASE=gendata`); `compare-builds.sh` REPRODUCIBLE; the owner's ceremony signature
(`scripts/ceremony-sign.sh`, YubiKey); `PHASE=catsig` with the gates incl. gate 7 (MRSIGNER pin); the T2 sidecar image
from the ceremony output; the T2 migration as the 2026-11-21 rows document — a new MRENCLAVE cannot open the old sealed
state, so the wallet is retired and re-created, the mandate re-installed, the anchor re-done: **owner-run, owner-direct**;
the dev prepares the worked-example script with this build's values.

**F — a question, not an item.** With `overflow-checks` on, a missed overflow aborts the enclave; signerd today returns
the 0x1006 error and keeps the dead enclave until the daemon restarts. Should this round include (host side, no
MRENCLAVE) signerd re-creating the enclave on `SGX_ERROR_ENCLAVE_CRASHED` — the state reloads from disk, the load comes
up NOT ARMED and the counter arms it — so one aborted ecall is a refused request, not an outage until an operator acts?
**Q4.**

## 8. Out of scope

The host crates (converted in ext1); the #23 info items; the `tpm_expected` display; P2TR / PSBTv2 and the rest of the
"later" row; any change to what the enclave accepts.

## 9. Questions to the auditor

- **Q1** — the cost cap's constant: the bounds product (128 000, refuses nothing legitimate by construction) or a
  measured time budget (padded, re-measured per hardware)? The dev proposes the bounds product with the measured wall
  time recorded, not enforced.
- **Q2** — a distinct `STATE_INVALID` (the dev's proposal: honest about what failed) or the existing `STATE_UNSEALABLE`?
- **Q3** — the real-SGX `cfg` arms of `sgx.rs`, which no linter reaches: a hand-read list of their arithmetic in the impl
  REQ, read by you — acceptable as the enforcement for that code?
- **Q4** — item F (signerd reload on a crashed enclave) in this round or its own later REQ?
- **Q5** — the `session.rs` conversion: structural (`chunks_exact`) rather than `checked_*` with a fallback — the
  dev's proposal, since a fallback word of zero would be a silent wrong challenge.

## 10. Status log

| Date | Event |
|---|---|
| 2026-11-25 | the owner: «REQ раунда ядра»; this design REQ written and sent; no code until the DESIGN-PASS |
| 2026-11-25 | **DESIGN-PASS** at `7f77006` — `RESP-r11-tcb-hardening-design-2026-11-25.md`: all five items accepted; Q1 the bounds product (128 000); Q2 distinct `STATE_INVALID`; Q3 the hand-read list of the real-SGX arms, `overflow-checks` the runtime backstop; Q4 item F (signerd reload) its own later host REQ — C-R11-5; Q5 structural `chunks_exact`. Blocking impl conditions: C-R11-2 (the TCS invariant fail-closed — the dev takes the Makefile gate plus the CI check), C-R11-4 (the inversion proven by the unchanged classify oracle, the counter refusing during the scan). The branch `r11-tcb-hardening` opens |
