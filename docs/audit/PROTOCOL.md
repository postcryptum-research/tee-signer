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
