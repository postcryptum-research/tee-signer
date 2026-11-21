# RESP-r10-O01 (design) — DESIGN-PASS at `28775df`

**From the auditor (the `security-audit-playbook` session), 2026-11-21, in answer to
`REQ-r10-o01-frozen-update-2026-11-21.md`. Transcribed verbatim by the dev; this header is the only addition.**

---

REQ-r10-O01 — **DESIGN-PASS**. Verified the three load-bearing facts firsthand @fae6a84, not from the REQ text:
- PolicyUpdate arm (state.rs:407-468): trap confirmed — frozen + checkpoint-unchanged skips the re-pin block (426 false) → compare → Loosening parks in pending (461-464) at best+timelock.
- best written ONLY by apply_headers (headers.rs:200), which refuses at the top while frozen (headers.rs:110-112, before any best-write) ⇒ the frozen loosening's activation_height is truly unreachable. Parks forever. Real trap.
- re-pin branch already enforces checkpoint-only (438-440: rest.checkpoint=installed; rest!=mandate→PolicyInvalid); judge refuses CHAIN_REORG while frozen (judge.rs:141) so tightening-at-once is harmless. ⇒ post-fix the frozen path has exactly one accepted shape.

**Q1 reason code — ChainReorg, AGREE.** The update is well-formed; what blocks it is the frozen chain, so CHAIN_REORG names the real cause+remedy (re-pin), reuses the exact code judge already emits for a frozen chain (no new wire enum, one `if`), and a machine client's CHAIN_REORG→re-pin reflex is correct here (re-pin is both the only accepted update AND what ends the freeze). PolicyInvalid is a category error — the policy is valid, the chain state isn't. The overload (apply_headers-reorg vs PolicyUpdate-blocked) is coherent: same cause, same remedy.

**Q2 pending-first — AGREE.** Preserves the existing invariant (a pending gates all updates uniformly) and surfaces the real blocker (POLICY_PENDING→Cancel) as the operator's first action. Frozen-first would hide a queued pending behind CHAIN_REORG and force a re-pin that then hits POLICY_PENDING anyway — worse two-step, misleading middle code. Vector 6 is the correct end-to-end recovery.

**Vectors — thorough.** The both-directions control (v5 unfrozen) and the hollow gate (v7) are exactly right. One load-bearing assertion to hold explicit: v1 must assert the nonce is NOT consumed — today's tightening-at-once consumes it at state.rs:454, and the fix must return before 454; you have it, keep it. Optional/non-blocking: a v2b for an identical re-submit while frozen (new==mandate) → also CHAIN_REORG, nonce not consumed — closes the no-change corner of the compare input; skip if v1's tightening path already covers compare(identical).

**Placement nit (non-blocking):** the draft `if s.chain.frozen && new.checkpoint == s.mandate.checkpoint` needs `new` (decoded 415) and lands after the network/wallet checks (417-422), so a frozen + checkpoint-unchanged + identity-mismatch update surfaces PolicyWallet/PolicyNetwork rather than CHAIN_REORG. Fine — identity mismatches should always win, and they refuse before 454 so no pending parks. Deliberate; just naming it.

**Docs — correct.** THREAT-MODEL unchanged is right (liveness, not a security boundary). The deploy/README T2 label on 2ae88422 as a known liveness trap with the Cancel→re-pin recovery (not a defect) is the right LOUD-surfacing of a trap that lives on the deployed build until the next ceremony — and live 1a36ada6 has 0 sat, so no funds ride on it. POLICY.md + FAQ EN/RU good.

**Consequence acknowledged:** signer-core change → new MRENCLAVE → next ceremony build → my decorrelated content-gate again → R9a/F-01 migration (new wallet). No wire change (State::encode untouched) is the right scoping.

Implement on r10-o01-frozen-update; IMPL-PASS before merge (I'll re-run hollow-f01.sh + a decorrelated mutation on the new `if`, both directions). Phase-2 fuzzing I'm reading now — separate reply.
