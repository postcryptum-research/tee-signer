# RESP-r10 phase 2, pass (i) — IMPL-PASS (scoped) at `14e1965`; F-2026-11-21-01 ruled a DEFECT; the `timelock_blocks` cap supported

**From the auditor (the `security-audit-playbook` session), 2026-11-21, in answer to
`REQ-r10-fuzzing-p2i-impl-2026-11-21.md` (PR #4). Transcribed verbatim by the dev; this header is the only addition.
Dev's note on §1's stacking remark: PR #4's base on GitHub is `main` at `97d3684`, which already carries PR #2 (F-01)
and PR #3 (O01); `gh pr diff 4 --name-only` lists no file under `core/`, `enclave/`, `host/` or `owner/` — the PR is
harness-only against the real `main` (the auditor's local `origin/main` was behind). The F-01 and O01 rulings stand on
their own, as he says.**

---

Verified 14e1965 firsthand against both origin/main and your f01 base (2b5c4e1). Three rulings.

## 1. Phase-2 pass (i) — IMPL-PASS (scoped), with a stacking note
Your "harness only" is true **against your local main** (f01 + O01 already merged), but PR #4's base on GitHub is origin/main, which has NEITHER — so the PR's GitHub diff carries f01 (core/src/state.rs, mandate.rs, ops.rs) and O01 (the ChainReorg freeze-refuse) as well as the harness. Worth one line in the PR body so whoever merges knows it's stacked: f01 and O01 must land first or they ride along. My phase-2 IMPL-PASS does **not** re-bless f01/O01 — their own rulings stand.

The genuinely-phase-2 production delta (2b5c4e1...HEAD, excluding O01) is a single line: `add_work_le` → `pub` in headers.rs. I read it — pure function, body unchanged, honest comment ("fuzz harness only … nothing in the enclave calls it from outside this module"). A no-wrap oracle next to apply_headers is a reasonable reason to widen it; it adds no logic and no enclave surface. Fine. Everything else is fuzz/ (structured.rs, gen.rs, replay.rs, seed corpus) + tests.

Coverage/injected-defect accounting (apply_message 118/120, apply_arm 21/21, apply_anchor 30/30, apply_headers 83/84, 15/15 defects, the three harness-model fixes, the vacuous-signet-batch gap you caught by coverage) I take as your harness self-knowledge — I verified the security-relevant claim and the production footprint firsthand, which is the right rigor for a harness PR. The actual proof is the fuzz-green CI/server run; forward the 44921792918 conclusion and the server chain-test (modes 4/5 crossing the retarget boundary) and this closes.

## 2. F-2026-11-21-01 — DEFECT; fix it. Not an accepted inconsistency.
Confirmed firsthand: apply_arm (:552) and apply_anchor (:607) both do `msg.verify(&self.owner_pk)` BEFORE `s.activate_pending()`; apply_message (:400) activates first, then verifies against `s.owner_pk`. activate_pending (:350) flips owner_pk at `best >= activation_height`. So at a due rotation the old key signs one more Arm/Anchor and the new key is refused — exactly your reproducer.

Where I diverge from your framing: **Anchor is not "within the installed mandate / pure liveness."** apply_anchor re-pins the TPM anchor — ak_pk, nv_name, and the expected-counter lower bound — which is the rollback-protection root. So the being-retired owner getting one more Anchor at the boundary is a one-shot ability to re-root rollback trust onto hardware they may control, past the point they should be retired. It's bounded (the new owner's next Anchor overwrites it, and a spend in the window still needs the installed mandate), so severity is LOW — but it's the reason this is a defect to fix, not an inconsistency to document. And the direction is backwards for what rotation is FOR: you rotate to retire a key (often because it's compromised), and this hands the old key one more operation while locking out the new one.

Your fix is correct: activate first, then verify against `s.owner_pk`, matching apply_message. Two lines moved in each function, no other effect (activate_pending only needs s.chain.best, already cloned). Break-test BOTH directions, per the guard discipline:
- at/after activation_height: new owner accepted, old owner refused (POLICY_SIG);
- before activation_height: old owner still accepted, new owner refused (rotation not yet due);
- non-rotation path unchanged.
This is CODE, written now on testnet (owner RULE 1) — not mainnet-gated.

## 3. §4 timelock_blocks cap — support it.
The OVERFLOW refusal is fail-closed and safe in itself, but a huge timelock_blocks silently bricks the owner's own future loosening AND rotation — a self-inflicted brick of the recovery path, which is the one path you never want unreachable. Cap it in validate() so it fail-closes LOUDLY at install instead of silently later (auditor-forbids-silent-footgun). ≤ 52 560 (~1 yr) is a reasonable bound; the exact value is the owner's design call. CODE now; fine to ride the next core round with F-2026-11-21-01 since both are small core changes.

## Discipline
Good: found by state_ops within 10 min of shakeout, reported with a reproducer the gate still fires, proposed but did NOT write the fix (your hard rule 1). That's exactly right. IMPL-PASS will be when the fix lands at a ref I can read — and note your own ops.rs commit says it: the MRENCLAVE bump, ceremony build and deploy stay owner-DIRECT. My ruling is a fix authorization, not a go.
