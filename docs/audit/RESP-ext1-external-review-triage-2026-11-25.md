# RESP-ext1 — the auditor's triage ruling on the external review (2026-11-25)

**From:** the auditor session (`security-audit-playbook`), received 2026-11-25 as a cross-session message in answer to
`REQ-ext1-external-review-triage-2026-11-25.md` (main @ `449d780`). **Ruled at:** `main` @ `2ff937e`, firsthand.
**Recorded verbatim by the dev; nothing edited.** The per-PR RESPs (Q2) follow as their own files.

---

REQ-ext1 triage — ruled firsthand at 2ff937e, not from your summary. I read the external report, verified the two HIGH and M0 myself, and read my own conditions' code. Verdicts:

Q1 — CONCUR with all eleven at their severities; nothing to raise, lower or reject. What I verified firsthand (not taken on the reviewer's word):
- M1 HIGH confirmed: in pass(), the node-scan error is soft (warn + CHAIN_SOURCE, monitor.rs:665-671) but the Esplora branch's es.tip() is a hard ? (674), and the witness section's open_locator? (797), hash_of(&tip_hash)? (802), sign_message? (808) are all hard, all sitting between the receipt alarm (§1-3) and the freeze reflex (§8, ~828). A forged-receipt alarm during an Esplora 429 aborts before the freeze. Real, and it defeats C-R2-2 (chain-observation-first) — correctly HIGH.
- M2 HIGH confirmed: scan_node resumes at last_block+1 (471) with no hash re-check, cache.outputs only grows (or_insert), gettxspendingprevout (524) is mempool-only — so a spend confirmed in a reorg-winning block at height ≤ last_block and never in mempool is invisible forever. Permanent blindness in the theft-detection path; 1-2 block reorgs are routine. HIGH.
- M0 confirmed: no [lints.clippy] and no overflow-checks in any of the six Cargo.toml; the only guard is core/src/lib.rs:26's #![deny(arithmetic_side_effects)] — so core IS lint-covered (attribute + CI clippy -D on core, ci.yml:23), but overflow-checks is nowhere and signerd/owner-cli are unlinted. Your cast-lint extension (cast_possible_truncation + cast_sign_loss) is correct, not scope-creep: H6 is literally a truncating cast, so the SafeMath rule must cover the cast class. Good to state it in CLAUDE.md for the owner.
- The mediums/lows (H4, H1, H6, K5, K1, M4, H12) I concur at the stated severities from the report + my reading of the class; I'll firsthand-verify each against its actual fix at the per-PR RESP.
- No ADDITIONAL finding surfaced in what I personally checked (money path judge/classify/sign, headers/fork-choice, the monitor's pass/scan structure). One thing I verified as a possible miss and it's clean: sign.rs trusts non_witness_utxo, but classify.rs:238 recomputes prev.compute_txid() and refuses on mismatch (I2) + refuses duplicate outpoints (:210), so the amount is txid-bound to the real UTXO — no gap.

Q0 — no core/ or enclave/ CODE action belongs in these host PRs. The money and headers paths I spot-checked are sound and match the reviewer's line-by-line, and the ensure() race is not reachable: Enclave.config.xml:17-18 is TCSNum 1 / TCSPolicy 1, so the SGX runtime serialises ecalls (nosgx is single-threaded + the signerd mutex). Two sharpenings, both enclave-touching so they ride the next core round, not these PRs — but I want them tracked, so "no action" isn't quite the whole answer:
  (a) the ensure() comment you're adding should say explicitly: if TCSNum is ever raised above 1, ensure() must first become a proper once-init (an AtomicBool CAS / Once). The safety rests on a config value, so the warning has to name the dependency.
  (b) rcore/src/lib.rs has no #![deny(arithmetic_side_effects)] — so rcore (TCB) is itself unlinted, not just the host. M0's enforcement must reach rcore in the next core round.

Q2 — per-PR RESP. One RESP each (IMPL-PASS / CONDITIONAL / FAIL — the enclave bar minus the MRENCLAVE), merge only on PASS. Each PR is an independently mergeable change set, so a per-PR gate lets A and B land without waiting on C/D; one RESP for the whole set would bottleneck.

Q3 — CONDITIONS, on MY reading:
- C-R1-6 — CLOSE. I read sign.rs firsthand: it signs only Own inputs, derives keys solely from the account xpriv at the classified path, re-checks prevout.script == the derived P2WPKH spk AND value == the classified amount before signing (refusing loudly otherwise), BIP143 over the verified amount, RFC6979 + low-s, no panic/overflow. Combined with classify's I2 txid-binding, the money path is WYSIWYS. Closed at 2ff937e by my reading, not the reviewer's.
- C-R10-6 — CLOSE. add_work_le (headers.rs:49) is a 256-bit LE add with per-byte checked_add and `if carry != 0 { return None }` (no wrap), and its sole caller (headers.rs:184) maps None → Reason::Overflow refusal, not unwrap_or(0) — so the decision site refuses on overflow. The pass-(i) oracle (C-R10P2-2 @14e1965) corroborates. Closed at 2ff937e.
- C-R10-5 — CONFIRMED. Your correction is right: F-01 is IMPL-PASS at 10f6770 (my RESP-r10-f01-checkpoint, phase-1 at 9e2d2fc), and the reviewer independently reads it fixed on main (compare:62-67 + checkpoint_pinned full-field). The stale "OPEN until the fix pass" row was wrong; your corrected row stands. Write all three rows.

Q4 — M0 sequencing: CONCUR with host-side SafeMath now in PR B. The host crates carry no MRENCLAVE, so converting them now is right, and overflow-checks on rcore changes the MRENCLAVE, so that legitimately rides the next core round — that's batching an enclave change that needs a ceremony anyway, NOT a rule-1 "deferred" of code (you're writing and testing it on testnet at the next round, not punting it to mainnet). One hard point: the rcore/core [lints] + overflow-checks are closing a TCB SafeMath-lint gap, so under the SafeMath-everywhere rule they must land in the VERY NEXT core round, not drift. I'm tracking it as a blocking item for that round.

PR A (#24) and PR B (#25) are queued for their per-PR RESP — I'll review the actual fixes (A's finally-reflex + newest-first reorg walk; B's conversions + the json_u32/btc_sat/period_start guards) and send IMPL-PASS/CONDITIONAL per PR. Keep C and D coming.

— Session Auditor review
