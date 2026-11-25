# RESP-r10 phase 2 — the union-of-passes coverage cross-check (the auditor's pass, on the owner's word) — PASS

**From:** the auditor session (`security-audit-playbook`), received 2026-11-25 as a cross-session message. **Asked for by
the owner** («пусть сделает», 2026-11-25) after the auditor's own caveat in `RESP-r10-fuzzing-p2ii-p2iii-impl-2026-11-25.md`.
**Regenerated at:** `main` @ `515d2e9`, all 16 fuzz targets. **Recorded verbatim by the dev; nothing edited.** The two
corpus additions are recorded as condition C-R10P2-3 (harness only; with the next fuzz ratchet).

---

**REQ-r10 phase-2 — union-of-passes coverage cross-check (auditor's pass, on the owner's word)**

**Method (firsthand).** Regenerated coverage for ALL 16 fuzz targets at the current ref `515d2e9` — necessary, not a convenience: core/src and enclave/rcore/src changed across the original run window (F01 `2b5c4e1`, O01 `a9daa59`, F02 `4b1497e` touched state.rs/mandate.rs/ops.rs/session.rs), so the 11-21…11-25 per-target profdata were built against inconsistent sources and could not be merged honestly. Rebuilt each (`coverage.sh`, nightly-2026-06-21), merged 16 profdata into one union, reported over core/src + enclave/rcore/src with all 16 objects. **Zero llvm-cov warnings** — every object's mapping is consistent with `515d2e9`, so the union is sound.

**Union coverage.** core/src **95.69% lines** (105/2438 missed, 230/4726 regions); enclave/rcore/src **97.31% lines** (24/891 missed, 101/1840 regions). 100 uncovered executable lines, every one classified:

- **A — display/diagnostic (23):** reason.rs `hint_for_code` + `ChainStale` Display string — fuzzers assert the refusal CODE, not the hint text.
- **B — hardware-only / dead stub (4):** sgx.rs `abort()`, allocator.rs `memalign`, ops.rs `_unused`.
- **C — fail-closed error/refuse paths (≈46):** ops.rs `Err(r)=>r` forwards + `TpmParse`×2 + KDF-fail `zeroize`+`refuse_code("KEY_DERIVATION")` + `PolicyInvalid`; sign.rs 2 `Err` returns; classify.rs `PsbtParse`/`InputScriptType` rejects + skip-`continue`; state.rs `PolicyInvalid`; recovery.rs `return None`; judge.rs block-closer regions. Uncovered = the failure wasn't triggered; every path **refuses** — the safe direction.
- **D — real decision branches not straddled (named, low-risk):**
  - **wallet.rs:101 `Matcher::Address` arm of `matches_trusted`** — the one accept-side gap (returns true when an output's script == a trusted Address). Confirmed firsthand: corpus drives the `Descriptor` arm **3,900×**, the Address arm **0×**. Trivial exact-byte compare, trivially correct, but unexercised.
  - mandate.rs:493 `Invalid::Version` + :510 `Invalid::TooManyTrusted` — validate rejects the corpus never triggers (neighbouring `AccountPath`/`ScriptTypes` ARE covered). Fail-closed.
  - state.rs:459 `Network`-immutability reject + :356 checkpoint-reset on `activate_pending`.
  - classify.rs:106-108 the 3/5/9-byte `varint_len` arms — length arithmetic, non-decision.
  - headers.rs:33 `Testnet4` params + 94-98 the testnet 20-min min-difficulty rule + :101 in-period bits carry — network-variant, **not** the signet path.
- **E — covered-elsewhere by design:** sign.rs `finalize_own_inputs`/sighash — the phase-2 design-pass scoped sighash to the replay-vector suite (vectors.rs BIP143 recompute + `verify_ecdsa` on every accept vector), not the corpus. `sign_own_inputs` itself IS in the union (count 140).

**Verdict.** No fund-releasing ACCEPT on the hot path is left unexercised. The primary accept-side decisions are union-covered: judge `Accept`, classify own-input/own-output detection on the descriptor path (3.9k hits), apply_message, SIGN byte-for-byte. The uncovered set is display text, hardware/stubs, fail-closed refuse paths, one trivially-correct exact-compare accept branch, fail-closed validate rejects, network-variant difficulty, and the by-design vector-covered signing path. **Pass.**

**Two cheap corpus additions (recommended, not blocking):**
1. A mandate with a `Matcher::Address` trusted destination + a matching and a non-matching output (covers wallet.rs:101, both directions).
2. A bad-`version` mandate, a `trusted.len() > MAX_TRUSTED` mandate, a network-changing PolicyUpdate (state.rs:459), and a non-P2WPKH own input (classify.rs:278) — all fail-closed, cheap to seed.

— Session Auditor review
