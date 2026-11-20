# RESP-r10 (impl, phase 1) — IMPL-PASS at `9e2d2fc`

**From the auditor (the `security-audit-playbook` session), 2026-11-21, in answer to
`REQ-r10-fuzzing-impl-2026-11-20.md`. Transcribed verbatim by the dev; this header is the only addition.**

---

REQ-r10 phase-1 (the fuzz harness) — IMPL-PASS, verified firsthand in my own pinned clone at 9e2d2fc, against the claimed scope C-R10-1/2/3/5/7/F + C-R9-A. C-R10-4 (disarms, F8) and C-R10-6 (work no-wrap, F6) are correctly marked phase 2 and NOT claimed — I'm not gating on them here.

What I ran myself:
- The forward gate (C-R10-F): cd fuzz && cargo test --no-default-features → green. 5 replay tests pass (compare_over_the_seed_pairs, retagged_message_does_not_verify, honest_messages_verify_and_are_bound_to_every_field, honest_objects_pass_their_targets, every_target_replays_its_corpus_and_regressions). Confirmed core/ enclave/ host/ owner/ untouched in 9e2d2fc — only deploy/README label; MRENCLAVE unchanged.
- C-R10-7(b): ./injected-defects.sh → all 9 reverted guards turn the gate red, "every injected defect was caught", core/ restored clean (empty diff). I read the nine sed exprs first, so I know they are real guard reversions (finish() ×4, UNFREEZE→CANCEL domain, nonce→TpmSig, safe>1→safe>255, Dec::list bound→usize::MAX, version reflexivity ==→!=).
- MY OWN decorrelated injected defect, in a dimension none of your nine touch: I dropped `.u32(*tip_height)` from the WITNESS signing preimage in update.rs signed_bytes (line 230) ONLY — leaving the wire encode/decode intact, so tip_height stops being bound to the signature while everything still round-trips. honest_messages_verify_and_are_bound_to_every_field FAILED at targets.rs:425 (it tweaked tip_height, the sig still verified → panic). So C-R10-3's "bound to every field" oracle bites on an inner-field binding loss, not just the domain tag. Reverted clean.
- C-R10-7(a) — I didn't re-run the full cargo-fuzz coverage (nightly), I credit your per-function fractions as your attested run; but I verified the ONE audit-critical sub-claim firsthand: the two uncovered validate arms are genuinely unreachable through decode, not a hidden gap. Invalid::Version — decode pins the version at mandate.rs:399-400 before validate:488 (your :619 comment says so). Invalid::TooManyTrusted — decode bounds the list with d.list(bounds::MAX_TRUSTED, …) at :407 before validate:505. Honest defense-in-depth. I also noted the per-target validate figures differ (mandate_decode 84/86 reaches the duplicate arms but not Version/TooManyTrusted; mandate_compare 82/86 feeds only valid mandates so it skips the duplicate arms too) — both honest, all unreached arms named, so no nitpick.

Credited as your attested laptop runs (consistent, well-characterized, nothing contradicts them): the 1-hour ×10 parallel runs (nine clean; mandate_compare 560 fork-mode crashes all classified F-01 by the differing field), the corpus provenance (324 seeds + 1783 cmin'd), and the 100% decoder line coverage.

Deviations (REQ §8): all reasonable. The two worth a word — coverage.sh not replaying findings/ (correct: you can't profile an aborting reproducer), and mandate_compare delegating C-R10-2 to mandate_decode (same decoder, no duplication needed) — both fine.

On F-2026-11-20-01: the harness correctly carries it as an OPEN finding that the gate asserts still fires, reproducers under findings/ before any fix — that is exactly right, and it's part of why this harness IMPL-PASS is clean. Send the fix REQ (REQ-r10-f01-checkpoint-impl) as the NEXT, SEPARATE pass — not folded into this one. It changes core/ (compare line + install-time period pinning + new_at_init → Result), so it re-grades on its own merits: I'll want the leg-1 compare fix break-tested in both directions, the leg-2 install period-field rule proved fail-closed (current retarget period only, else PolicyInvalid), the new_at_init write-site enforced, and the four F-01 reproducers moved findings/ → regressions/ and passing C-R10-5 both ways. Your Q1 (forward re-pin while frozen) and Q2 (debug_assert vs Result) I'll rule in that pass.

Phase-1 harness: PASS. Nothing here deploys anything — the harness is outside the TCB and MRENCLAVE is unchanged. Good, disciplined work.
