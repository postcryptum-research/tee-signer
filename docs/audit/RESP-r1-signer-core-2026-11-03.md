# RESP-r1-signer-core-2026-11-03 (auditor's text, verbatim)

**Auditor:** `security-audit-playbook-13`, 2026-11-03. Bound to code `e4afa1d` + REQ `fbd3eaa`,
branch `r1-signer-core`. Recorded verbatim per `PROTOCOL.md`; the dev's disposition follows.

---

RESP-r1-signer-core-2026-11-03 (commit verbatim before merge; English). Bound to code `e4afa1d` + REQ `fbd3eaa`, branch `r1-signer-core`.

# VERDICT: IMPL-PASS (merge `core/` + `vectors/r1/` to main)
I read the full crown firsthand — `classify.rs` (I1/I2/I3/I4/I7 + D-1/D-2/D-3/D-4), `judge.rs` (I5/I6/I8/I11/R13 + C-R5/C-R12e + D-5), `mandate.rs::compare` (I9 + C-R6 + D-6). Every claimed invariant is present, correct, and in the SAFE direction; the deviations are sound (most are strict improvements). Mechanics (`wallet/sign/state/update/encoding/receipt`) accepted on the 51-vector both-direction suite + 4 hollow mutation proofs + `clippy -D` + `forbid(unsafe)` + `deny(arithmetic_side_effects)` — `sign.rs` in particular is validated against an INDEPENDENT host signer (the NOSTD-LAB byte-identical BIP143/RFC6979 proof), not circularly. `#![forbid(unsafe_code)]` holds.

**Firsthand confirmations (the load-bearing ones):**
- **I2/D-2** classify.rs:236-256 — `non_witness_utxo` required for EVERY input, txid recomputed, a disagreeing `witness_utxo` → `InputPrevTxMismatch`. Lying-witness closed on both the outflow and fee sides.
- **I1/D-4** :260-290 — own only if the hint's derivation reproduces the key AND the prevout P2WPKH script; wrong key → `InputNotOwn`; no hint → foreign (unsigned).
- **I3/D-3** :315-354 — own output only via verified hint within bound+gap; a lying hint → `OutputScriptType` refuse; a MISSING hint → unlisted (charged). Mis-classification is always conservative (over-charge), never value-out.
- **I5 + C-R5a/b** judge.rs:244-300 — `net_outflow = own_in − own_out` (includes the fee algebraically); trusted outputs are not own_out so they count in net_outflow → `window_max_outflow` bounds fee+trusted+unlisted; plus a separate `w_fees`/`max_fee_per_window`. (This is exactly my R5 correction — the fee bound is the window, realized.)
- **C-R12e** — every sum `checked_add`→`Overflow`; `all_out>all_in` refuses (no negative fee).
- **I11** — the charged state is returned in `Verdict::Accept{state}` for the shell to seal BEFORE `sign`.
- **R13** :146-170 — two checks (lag ≤ maxTipLag ∧ tip∈{best}∪recent; `last_seen_seq ≤ seq` else **disarm** armed=false with state returned to seal) + `!armed`→refuse until Rearm. Idempotent disarm (re-triggers if its seal is lost).
- **C-R6** mandate.rs:586-651 — `compare` fails toward loosening BY CONSTRUCTION: `tight=true`, every field only clears it, no set-back branch; network/wallet → `Immutable` (refused outright); add-trusted / any-matcher-change / changed-witness-key / lowered-timelock / removed-fee-cap → Loosening. Verified field by field.
- hollow knobs present (`require_prevtx`, `verify_own_output_script`, `commit_before_sign`, `window_caps`), `std`-only, release build asserts their absence (R2).

# Deviations (REQ §3) — ruled as a supplement, ALL ACCEPTED
- **D-1 (lower-bound vsize) ✅ CORRECT** — the strict direction (smaller vsize → smaller fee ceiling → more refusals). ⚠️liveness: can over-refuse a *fair* fee on a tx larger than the lower-bound estimate; `maxFeeAbs` is the hard backstop and `maxFeeRate` should be set with lower-bound semantics. Not a safety issue.
- **D-2 (every input) ✅** stricter; closes the foreign-input fee understatement. Moot under `payjoin=none` (v1) but harmless.
- **D-3 (hint-based own output, missing⇒unlisted) ✅ an improvement** — bounded enclave cost, still cryptographic (the hint is a pointer, the derivation match is the proof); a stripped hint can only over-charge (DoS), never admit value out. ⚠️operational: relies on NBXplorer supplying change hints.
- **D-4 (own input hint, no fallback search, no-hint⇒foreign) ✅.**
- **D-5 (own inputs raise bounds) ✅** — can't admit foreign (classification is a derivation match); fixes a false-refuse of a self-send to a recent receive index. Monotonic within the account path.
- **D-6 (enable-witness=tightening / key-change=loosening) ✅** matches POLICY §5.
- **D-7 (any update while pending refuses, cancel-first) ✅** stricter, keeps the timelock linear. ⚠️confirm (it holds): `freeze` is still available while pending (separate unauthenticated path), so the owner's response to a malicious pending is freeze+cancel, not tighten-over.
- **D-8 (Rearm{nonce,seq} = max) ✅** — exactly my C-R13a (a Rearm can't lower the sequence).
- **D-9 (Recover voids pending mandate AND rotation) ✅** — the old owner key may be the thief's.
- **D-10 (receipt identity key secp256k1, compact over `domain_digest("tee-signer/receipt/v1",…)`) ✅ format** — domain-separated from the BIP143 sighash (no cross-replay). ⚠️R2: the identity key must be DISTINCT from the wallet/tx key (an attestation key, not seed-derived) — confirm in the R2 seal layout.
- **D-11 (descriptor matching derives branches×gap per unlisted-candidate) ⚠️COST, R2 gate** — D-3 removed the own-output search, but trusted-descriptor matching still derives up to branches×gap per unlisted-candidate output; this is now the DOMINANT per-tx derivation cost (≤ branches×gap×#candidates EC mults). Not a safety hole (bounded, gap≤1000). MEASURE on hardware (R2) and size `maxOutputs`×gap so a worst-case PSBT fits the enclave time/heap budget (else DoS-refuse). Fold the cost note into PROVENANCE.

# Conditions carried to R2/R3 (the gates not closable in a pure core)
- **C-R10a/b/c (R2 build):** the `objdump` no-`cpuid` assertion over the final `.so`; `--gc-sections`; `secp256k1` context randomization → `sgx_read_rand`; and the REPRODUCIBLE BUILD by my corrected SGX method — compare **MRENCLAVE + all SIGSTRUCT fields except `header.date`(+its signature), NOT the `.so` sha256** (the enclave .so is not byte-identical across days; sgx-dev's correction, which I've adopted stack-wide).
- **I11 ordering (R2 shell):** `judge` produces the charged state; the shell MUST seal it before calling `sign` — the ordering guarantee lives in the shell, the core only makes it possible. The hollow `commit_before_sign` proves the core charges before producing the signable state.
- **I12 / secrets (R2):** the seed/account-xpriv/identity key are not in `State` (confirmed — core holds no secrets); the seal layout + the once-at-init recovery blob are the R2 REQ.
- The header verifier (R4) — `state.chain` is caller-set here; the shell must only ever set it through the verifier.

# What I did NOT read line-by-line (honest scope)
`wallet.rs` (derivation/`matches_trusted`), `sign.rs` (BIP143/low-s/RFC6979), `state.rs` (`roll_window`/`activate_pending`), `update.rs` (D-7/8/9), `encoding.rs`, `receipt.rs` — accepted on the both-direction vectors (incl. sign→verify-BIP143→finalise→extract, independently host-verified in the lab) + the hollow mutations + clippy. If you want belt-and-suspenders on `sign.rs` specifically (the one module where a subtle sighash bug = a wrong signature), say so and I'll read it firsthand before the R2 shell wraps it.

Merge R1. The R2 REQ (enclave shell: seal, sign-ordering, recovery blob, build gates) is next — I rule it firsthand at its commit. Careful, disciplined work — the hollow-test suite and the fail-toward-loosening classifier are exactly the bar.

---

**Dev's disposition (2026-11-03):** merged to `main`. R1 gates C-R4a–c, C-R5b, C-R6, C-R10b,
C-R12a/b/d/e marked DISCHARGED in `CONDITIONS.md`; new carried items C-R1-1 (D-11 derivation cost
measured on hardware, `maxOutputs × gap` sized), C-R1-2 (identity key distinct from the seed —
R2 seal layout), C-R1-3 (reproducible build compared on MRENCLAVE + SIGSTRUCT minus `header.date`),
C-R1-4 (D-1 liveness: `maxFeeRate` documented with lower-bound semantics), C-R1-5 (D-7: the
owner's answer to a malicious pending is freeze + cancel — documented). The auditor's offer to read
`sign.rs` firsthand is accepted (asked the same day).
