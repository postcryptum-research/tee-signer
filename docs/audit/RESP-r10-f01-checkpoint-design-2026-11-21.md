# RESP-r10-F01 (design) — DESIGN-PASS CONDITIONAL at `3473e41`

**From the auditor (the `security-audit-playbook` session), 2026-11-21, in answer to
`REQ-r10-f01-checkpoint-impl-2026-11-20.md` (status SENT at `3473e41`). Transcribed verbatim by the dev; this
header is the only addition. Conditions carried in `CONDITIONS.md` as `C-F01-1 … C-F01-5`.**

---

DESIGN-PASS CONDITIONAL. The unfrozen legs are right; the frozen path has a brick I need you to fix before you write code. I read the mechanism firsthand at 3473e41.

APPROVED as drafted:
- Leg 1 on the UNFROZEN path: `clear(new.checkpoint == installed.checkpoint || new.checkpoint.height > installed.checkpoint.height)` — correct. Same-height-different-content → loosening → timelock is exactly right when not frozen.
- Leg 2: the field table is right, and the signet/testnet4 handling is correct — period_start_time/period_bits pinned against chain.period_start_time/period_bits only when r is in the current retarget period, else PolicyInvalid; bits against r.bits (so a min-difficulty r is handled). Fail-closed where un-pinnable. Good.
- Leg 3 invariant: enforce at the write site, yes.

⛔ Q1 — option (ii) PERMANENTLY BRICKS the signer. Not "one timelock cost" — a deadlock. The proof, firsthand:
- The timelock is block-height anchored: activation_height = best + timelock_blocks (state.rs:456), and activate_pending only fires when best >= activation_height (state.rs:350).
- apply_headers REFUSES EVERY header while frozen: headers.rs:110-111, `if state.chain.frozen { return Err(ChainReorg) }` — it's the first thing it does. chain.best is written ONLY by apply_headers (state.rs:65). So while frozen, best is PINNED.
- Therefore a frozen re-pin routed to `pending` can never reach activation_height → never installs → the chain is never reset from the new checkpoint → the freeze is never cleared. Permanent brick. Option (ii) is self-defeating: it timelocks the very action that would let the clock start again.

⛔ And leg 1 AS DRAFTED already bricks the frozen SAME-HEIGHT re-pin, independently of Q1:
- A reorg deeper than max_reorg that lands at the SAME tip height (different hash) is a real recovery scenario. The owner re-pins to that same-height tip. Leg 1 reclassifies it Loosening. But the repin branch resets the chain only for Tightening (state.rs:445-447); a Loosening falls through to the pending branch (458) and the chain is never reset → same permanent brick.

RULING on the frozen path: a frozen re-pin MUST apply AT ONCE — reset the chain from the new checkpoint and install, bypassing the Tightening/Loosening timelock branch entirely — for BOTH a forward and a same-height re-pin. The block-height timelock is simply inapplicable while frozen; the compare/timelock machinery is for unfrozen updates. Concretely: handle `repin` before the compare branch, always `s.chain = from_checkpoint(new.checkpoint); s.mandate = new; s.mandate_sig = *msg.sig(); return Ok(s)`. So the answer to Q1 is neither (i)-as-written nor (ii): it's "frozen re-pin is immediate by necessity," and the residual is handled by labeling, not by a timelock that cannot run.

The residual, framed honestly (for THREAT-MODEL.md, not left silent):
- On the frozen path there is NO local reference to validate the checkpoint against — the deep reorg invalidated the local view. That's inherent: while frozen, the owner signature is the irreducible root of trust for recovery. Leg 2 cannot apply on the frozen path, and no mechanism can replace it there.
- To FORCE a freeze an attacker needs a reorg deeper than max_reorg — on mainnet ≈ 51% hashpower. So the residual precondition is V5 (stolen owner key) ∧ force->max_reorg-reorg. Label it (V5 ∧ frozen); name it, don't deny the whole.
- Recommended hardening (your call, the base precondition is extreme so I'm not making it blocking): keep the frozen re-pin CHECKPOINT-ONLY — refuse a frozen re-pin that differs from the installed mandate in any field but the checkpoint. Recovery only needs the new trust root; this keeps the frozen path from doubling as a dest/limit-change path, so a stolen key still can't swap destinations in one atomic frozen step. Cheap, and it stops the recovery path from becoming a policy bypass.

Q2 — Result, not debug_assert. debug_assert is a no-op in release, so it's a silent footgun: a release build could store an unvalidated mandate. Result is the write-site enforcement I asked for, fail-closed in release. The signature change + two test-caller unwraps are a small price. Use Result.

Q3 — spell it out in POLICY.md §5. The spec's "forward" wording WITHOUT the content caveat is the ORIGIN of F-01; code-only invites the same spec/code drift that caused it. Add both: "same height with different content is not forward" to the chain.checkpoint row, and the §2 install rule as a sentence.

Vectors — your 11 are good; keep vector 11 (the hollow red/green). ADD:
- a frozen SAME-HEIGHT-different-content re-pin ⇒ applies at once AND clears the freeze (this is the brick-regression test — it's what catches both the (ii) brick and leg-1-without-the-carve-out);
- a frozen FORWARD re-pin ⇒ applies at once, chain resets;
- if you take the checkpoint-only hardening: a frozen re-pin that changes a non-checkpoint field ⇒ refused.

So: implement legs 1/2/3 as drafted on the unfrozen path, rework the frozen path to apply-at-once (no timelock, with the carve-out + the honest residual label), Q2=Result, Q3=spell it out. Open the branch, and send for IMPL-PASS with the brick-regression vectors green. Nothing merges without IMPL-PASS; MRENCLAVE bump + ceremony + deploy are the owner's, direct.
