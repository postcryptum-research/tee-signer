# RESP-r10-O01 (impl) — IMPL-PASS at `0fc371d` (branch `r10-o01-frozen-update`, PR #3)

**From the auditor (the `security-audit-playbook` session), 2026-11-21, in answer to the implementation sent at
`8dd444e` and completed at `0fc371d` (the `add_work_le` visibility commit). Transcribed verbatim by the dev; this
header is the only addition. The second part lifts the two phase-2 design conditions.**

---

REQ-r10-O01 — **IMPL-PASS @ 0fc371d** (binds to this ref). Verified firsthand, not from the message:

- Core change scoped: state.rs +8/-0 = exactly the O01 `if` + comment, after network/wallet + pending.is_some(), before the checkpoint-changed branch and before s.nonce=next. State::encode/decode untouched ⇒ no wire change.
- add_work_le delta (8dd444e..0fc371d): visibility-only — `fn`→`pub fn` + doc comment, body byte-identical. No logic, no enclave-surface change (pure arithmetic; apply_headers still the only internal caller). Rides this MRENCLAVE round cleanly.
- Vectors: 11 green, non-hollow and complete. v1 asserts CHAIN_REORG AND s1.nonce==0 (the load-bearing nonce-not-consumed) AND re-pin at nonce 1 accepted right after; v2 pending None; v2b identical-resubmit (my optional, taken); v5 unfrozen control both directions; v6 full recovery (pending→freeze→POLICY_PENDING→Cancel→re-pin applies→!frozen→best=new checkpoint→nonce 3).
- Both-directions mutation-proven (my own decorrelated): M-B disable `if` → frozen_update_without_repin_is_refused RED (refuses-bad); M-A drop the ==checkpoint clause → frozen_repin_applies... RED (permits-good, clause load-bearing); M-C invert ==→!= → both RED (exact condition pinned). hollow-f01.sh case 8 targets exactly this `if`; 8/8 covers all three frozen-path sites.
- Reachability: hit on every frozen PolicyUpdate. Retirement: the old loosening-parks-while-frozen path is now unreachable (guard returns before compare). Deployment: NOT yet — IMPL-PASS is source; ships on the next ceremony build (owner), where I re-run my decorrelated MRENCLAVE content-gate + the R9a/F-01 migration (new wallet; live 1a36ada6 = 0 sat).

**Good to merge PR #3 to main.**

Phase-2 conditions — **all discharged, DESIGN-PASS now unconditional:**
- C1 (WitnessToken 9th F4 step) + C2 (direct add_work_le oracle + the visibility commit) — taken.
- Q1 unification BENIGN, verified firsthand: rcore pulls signer-core default-features=false with empty nosgx/test-init/auto-arm (forward nothing); fuzz pulls std; union={std}. And the crux I added: no DECISION path is std-gated — the only cfg(feature="std") site is reason.rs:205 (Display/Error diagnostic); every other cfg(feature) is hollow-test (never enabled by fuzz/rcore). So the std-fuzzed core's verdicts == the no-std production core's; fuzzing tests production logic. Single crate stands.
- Q3 judge.rs:170-171 + verifies-but-seq-behind positive / unverified-high-seq negative seeds + broaden/narrow injected — good.
- Sighash: confirmed vectors.rs:744-752 recomputes the BIP143 p2wpkh sighash over the DERIVED spk + classified amount and verify_ecdsa's every accept-vector partial sig — binds I2/I3 into the signature. Out of phase-2 fuzz scope with that reason: agreed.

Pass (i) state_ops+headers: go after O01 lands on main. Send the (i) IMPL-REQ when ready.
