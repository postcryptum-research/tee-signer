# tee-signer audit protocol

Follows the **AUDIT-PROTOCOL v1.0** REQ/RESP cycle used by `77ph/SGX_project`,
`77ph/xrpl-perp-dex-enclave` and `77ph/trust-bridge` (canonical text: auditor-side
`security-audit-playbook`). This file is the thin repo-specific wrapper.

- **One auditor, star routing.** All audit traffic — REQs, design questions, ruling requests,
  IMPL-review requests, findings — goes to the single auditor session and nowhere else. No
  project-to-project audit messages; cross-project input is surfaced to the auditor.
- **Naming.** `REQ-<slug>-<YYYY-MM-DD>.md` / `RESP-<slug>-<YYYY-MM-DD>.md`, one pair per audited
  unit; `QUERIES-<slug>-<date>.md` for in-round clarifications (append-only). RESP text is committed
  verbatim by the dev session.
- **Verdicts.** DESIGN-PASS (write the impl on a branch) · IMPL-PASS (merge to `main`) ·
  CONDITIONAL (pass only with listed conditions carried into the impl REQ) · FAIL (rework).
- **Gates.** No `signer-core` policy logic and no `enclave/` module before its DESIGN-PASS; no merge
  before its IMPL-PASS. A material design change after a DESIGN-PASS needs a supplement REQ.
- **Claims are time-stable in both directions** (trust-bridge rule): a label that outruns the code,
  or a caveat the code has outgrown, is a defect; actionable findings go in the carried table
  (`INDEX.md`), not only in a round's prose.
- **Carried from TPM_sign `AUDIT-2026-10-20`:** owner/agent separation must be enforced by code and
  by default deployment (F8) — here: the enclave holds only the owner's *public* key and no path
  opens an owner private key on the merchant's box; a software owner key is refused for every
  state-changing command unless built with an explicit test-only feature (F1); every metered
  quantity is metered (F2: here, every output class and the fee); double execution is guarded in the
  trusted layer, not the host (F4: here, the budget is charged inside the enclave before the
  signature exists).

## The queue

`CONDITIONS.md` is the worked table of every carried condition (round, status). A condition is
discharged only by a RESP that names it.

## Rounds

| REQ | Date | Status |
|---|---|---|
| pre-questions Q1–Q3 | 2026-11-03 | RULED → `RESP-prequestions-2026-11-03.md` (all tiers acceptable, labels exact; freshness witness recommended) |
| `REQ-design-2026-11-03.md` | 2026-11-03 | **DESIGN-PASS (CONDITIONAL)** → `RESP-design-2026-11-03.md`; conditions worked in `CONDITIONS.md` |
| `REQ-r1-signer-core-2026-11-03.md` | 2026-11-03 | **IMPL-PASS** → `RESP-r1-signer-core-2026-11-03.md` at `e4afa1d`; merged to `main`; eleven deviations ruled as a supplement, all accepted |
| `REQ-r2-enclave-shell-2026-11-03.md` | 2026-11-03 | **IMPL-PASS** → `RESP-r2-enclave-shell-2026-11-03.md` at `fd64e1e`; merged to `main`; ten deviations accepted; enforce prerequisites carried to R4 (monitor) and R5 (repro build, RELEASE=1 on FLC/DCAP) |
| `REQ-r10-fuzzing-design-2026-11-20.md` | 2026-11-20 | **DESIGN-PASS (CONDITIONAL)** → `RESP-r10-fuzzing-design-2026-11-20.md` (same day); C1–C7 + forward condition carried in `CONDITIONS.md` as `C-R10-*`; owner's go 2026-11-20, phase 1 implemented → next row |
| `REQ-r10-fuzzing-impl-2026-11-20.md` | 2026-11-21 | **IMPL-PASS** → `RESP-r10-fuzzing-impl-2026-11-20.md` at `9e2d2fc` (same day; the auditor's own run incl. his own decorrelated injected defect, caught). Phase 1 on `main`: the `fuzz/` crate, ten targets with named oracles, the stable replay gate as CI job `fuzz-replay`, the `fuzz-smoke` workflow, injected defects 9/9, per-target reachability). First finding F-2026-11-20-01 (`compare`, same-height checkpoint) ruled a **DEFECT** by the auditor the same day, two legs; its fix is its own impl REQ, `REQ-r10-f01-checkpoint-impl-2026-11-20.md` (SENT 2026-11-21 as the next, separate pass — the auditor's instruction; branch `r10-f01-checkpoint` only after its DESIGN-PASS, IMPL-PASS before merge, new MRENCLAVE with the next ceremony build) |
| `REQ-r10-f01-checkpoint-impl-2026-11-20.md` | 2026-11-21 | **DESIGN-PASS (CONDITIONAL)** → `RESP-r10-f01-checkpoint-design-2026-11-21.md` (same day): the unfrozen legs (compare rule, install-time pinning of every checkpoint field, `new_at_init` write-site invariant) approved as drafted; the frozen path re-ruled — a frozen re-pin applies at once, forward or same-height (the block-height timelock cannot run while frozen: option (ii) and leg 1 without a carve-out would brick the signer permanently), checkpoint-only hardening taken, residual (V5 ∧ frozen) labelled; Q2 `Result`, Q3 spell it out; `C-F01-1 … 6`. Implementation on branch `r10-f01-checkpoint`: **IMPL-PASS** → `RESP-r10-f01-checkpoint-impl-2026-11-21.md` (CONDITIONAL at `6e05716` on one test addition — a vector only the current-period boundary gate refuses, plus its hollow mutation — then **clean at `10f6770`**, the auditor's own mutation re-run); merged to `main` via PR #2 at `e0b0f4f` (2026-11-21); **deployed on T2 2026-11-21** (build of `fae6a84`, MRENCLAVE `2ae88422…`, the auditor's decorrelated build as the content gate, owner-run migration — `deploy/README.md`); MRENCLAVE changes — the rebuild (ENFORCE=1, the auditor's decorrelated build), ceremony and deploy are the owner's |
| `REQ-r10-o01-frozen-update-2026-11-21.md` | 2026-11-21 | **DESIGN-PASS** → `RESP-r10-o01-frozen-update-design-2026-11-21.md` (same day; `ChainReorg`, pending-first; implementation on branch `r10-o01-frozen-update`, IMPL-PASS before merge) — the auditor's observation from RESP-r10-F01 impl: while the chain is frozen a `PolicyUpdate` is a checkpoint re-pin or it is refused (`CHAIN_REORG`), so a loosening can no longer park in `pending` behind a freeze and block the re-pin; vectors incl. the `Cancel` → re-pin recovery; POLICY/FAQ wording; a new MRENCLAVE with the next ceremony build |
| `REQ-r10-fuzzing-phase2-design-2026-11-21.md` | 2026-11-21 | **SENT** for DESIGN-PASS — phase 2 of the fuzzing programme: `state_ops` (F4), `headers` (F6, C-R10-6), `classify` (F7), `judge` (F8, C-R10-4 both directions), `dispatch` (F10, the C-R9-C table + direct invariants); harness-only; Q1 crate layout for rcore, Q2 three impl passes, Q3 the `disarms` set, Q4 the no-wrap input |
