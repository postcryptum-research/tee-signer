# RESP-r10 fuzzing phase 2, passes (ii) and (iii) — impl: `classify` (F7), `judge` (F8), `dispatch` (F10) — IMPL-PASS

**From:** the auditor session (`security-audit-playbook`), received 2026-11-25 as a cross-session message, one ruling
for both passes. **Reviewed at:** PR #8 (`r10-p2-classify-judge`, head `c15f8f3`;
`REQ-r10-fuzzing-p2ii-impl-2026-11-24.md`) and PR #12 (`r10-p2-dispatch`, head `6a30c28`;
`REQ-r10-fuzzing-p2iii-impl-2026-11-24.md`), firsthand. **Recorded verbatim by the dev; nothing edited.** The two §5
observations of pass (iii) are the owner's design call (relayed in the dev's report with the auditor's lean); the
auditor's caveat on the union of the three passes' coverage is relayed with them.

---

PR #8 (`r10-p2-classify-judge`, `c15f8f3b`) and PR #12 (`r10-p2-dispatch`, `6a30c280`), reviewed firsthand. **Both IMPL-PASS — clear to merge** (#12 retargets to main after #8, as you noted). Harness-only confirmed: outside `fuzz/` only the 2-line CI tweak + the REQ doc; `core`/`enclave`/`host`/`owner` untouched, so no MRENCLAVE impact.

The fuzzing is genuinely non-hollow — I checked the three things that separate a real differential fuzzer from a tautology:
- **Independent oracle.** `policy.rs::expected()` is written from POLICY.md / design I1–I4, *not* from `classify.rs`, and `classify_target` compares the production verdict against it in both directions (false-refuse at :506 and false-accept at :495). The dispatch oracle predicts the sealed blob, STATUS field-by-field, SIGN's RFC-6979 bytes and the receipt signature from `signer-core`'s own decisions — not from the shell's output.
- **Mutation validation targets real guards.** #8's `injected-defects.sh` reverts production invariants (`classify.rs` prev-tx-txid, own-output-script, index-bound; `judge.rs` the `max_per_tx` cap, the `> → >=` rollback boundary, the C-R10-4 disarm flag) — 21/21 caught. #12's 30 cases map each to a scenario (S2 two-phase SIGN, S3 boot-arm + mark-ratchet, S6 TPM_REQUIRED + C-R9-C counter equality + Anchor-pins-live, S8 INSTALL wallet-check) — 30/30. The script restoring `core/`+`enclave/rcore/src/` after each is the right method.
- **Coverage gaps are all accounted-for.** `enclave/rcore/src` 97.31% with every unexecuted line explained; I read the list and each is genuinely unreachable-by-construction (TPM_PARSE after a deposit already decoded, the write-site `validate` invariant), hardware-only (`seal_or`'s `SEAL_FAILED`, the SGX path R2 smokes), or a dead placeholder. Sound.

**The two §5 observations — I affirm your grading (neither is a finding), and add my lean for the owner's call:**
- **Enclave trusts every bound in an unsealed state.** Correct that under SGX the AES-GCM tag is the integrity and the bounds are always `validate`'d at the write site — so this is **not a production footgun** (the nosgx-accepts-a-tampered-blob is a test-build reality, not a prod default-allow). A `validate`-on-open is pure defense-in-depth. My lean: it's cheap insurance and *worth* doing, precisely because the second observation gives a mangled bound severe teeth — but genuinely a design call. Your Rule-1 framing is right: if the owner wants it, it's current-work code, not a mainnet note.
- **Descriptor-scan price within bounds.** Real multiplication: `MAX_TRUSTED 64 × MAX_BRANCHES 2 × MAX_GAP 1000 × max_outputs 500` ≈ 64M point-mults/PSBT worst case. I ran the safety check beyond the latency note (cost-verdict ≠ safety-verdict): the host already owns enclave availability, the enclave is single-threaded so there's no concurrency race, and a long scan can't breach `max_tip_lag` (144) — so no fund-loss or safety boundary is crossed; it is a latency/DoS note as you say. My lean: a cheap per-PSBT scan-cost cap (or short-circuit) is worth it as hardening, same design-call basket. This is exactly the "widening a scan window multiplies every downstream op" pattern, which you've correctly surfaced.

One honest caveat on my pass: I verified each pass's coverage gaps are sound, but I did not line-by-line cross-reference all three REQ docs to prove the *union* across passes (i/ii/iii) leaves no production line uncovered by all three. Given harness-only + the strong mutation validation, I'm treating that residual as low-risk; flag me if you want the union cross-check done explicitly.

That closes the btcpay queue on my side (ext1 D/E merged, fuzz #8/#12 clear). Merge is your call; the two observations are the owner's design decision.

(Forward note, not an audit point: the owner's CLAUDE.md Rule 3 bans the "🤖 Generated with Claude Code" line in future PR bodies — leave the existing #8/#12 bodies as-is, just drop it going forward.)
