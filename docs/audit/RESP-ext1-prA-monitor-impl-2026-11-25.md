# RESP-ext1 PR A — `owner-cli` monitor: the reflex and the reorg (#13, #14) — IMPL-PASS

**From:** the auditor session (`security-audit-playbook`), received 2026-11-25 as a cross-session message. **Reviewed
at:** PR #24, head `a8c7313` (branch `ext1-monitor-reflex-reorg`), firsthand. **Recorded verbatim by the dev; nothing
edited.** Merge cleared per the per-PR protocol (`RESP-ext1-external-review-triage-2026-11-25.md`, Q2).

---

PR A (#24, a8c7313) — IMPL-PASS. Reviewed the actual fix firsthand, not the summary. Clears for merge per the per-PR protocol.

M1 (#13) — fixed and complete:
- The only hard ? that can end a pass are the wallet and mandate config reads at the very top (727-728); the hwm read is soft (unwrap_or_default). es.tip() is now a match → soft CHAIN_SOURCE WARN with tip (0,""), not a hard ? (the exact original abort at the old 674). I scanned the whole pass body 740-1008 for a bare hard ? and the only ones are the four inside the witness `built` closure (open_locator/hex/try_from/sign_message) — closure-local, their Err becomes WITNESS_REFUSED, so they can't abort the pass. Sections 3/4/6 are all soft (match / codes.push / save_state).
- Section 6 is the subtle one and you got it right: Some(_) if tip_height == 0 → WITNESS_SKIPPED, no token — a token over no tip would assert freshness to the enclave you can't back. Not lying to the enclave is the correct call.
- Section 8 reflex is reached whatever failed; the journal write is soft (stderr after the verdict is printed and returned). The reproducer the_reflex_fires_when_the_chain_source_is_down is genuine: it .expect()s pass() to return Ok where main @2ff937e returns Err("chain tip"), and asserts exactly one POST /v1/freeze + verdict ALARM + RECEIPT_SIG + CHAIN_SOURCE in the journal. Red on main, green here.

M2 (#14) — fixed and complete, and more thorough than the minimum:
- scan_node section 0 walks cache.walked newest-first, finds the newest remembered (height,hash) that still matches the node = the common ancestor; a==last_block → resume; a<last_block → rewind to a+1 and re-walk (restarted:false); nothing stands → restart from tip−window + UTXO re-read (restarted:true). rewind() unconfirms spends above the ancestor (confirmed=false, height=None) — fail-closed: they keep their alarm, lose confirmation until the re-walk re-finds them. REMEMBERED_BLOCKS=288 (2 days), walked.drain bounds it, common no-reorg case is one getblockhash.
- The reproducer a_spend_confirmed_only_in_the_winning_fork_is_found is genuine: block 101 replaced by one spending our output, never in mempool; it panics unless pass 2 sees the spend, where main "resumes at 102 and sees nothing". Plus the orphaned-spend-keeps-its-alarm and old-cache-restart tests.
- The 2b (receipted-but-unconfirmed) and 2c (incoming mempool, C-R4-7) windows are good additions — they close the unconfirmed-change and unconfirmed-incoming theft windows, not just the reorg one.

Residuals, none blocking (all correctly out of PR A's scope): the float→sat `as u64` casts in scan_node are the H6/rule-9 class → PR B; the hwm.json silent default is M4 → PR D. The node-lying-about-getblockhash case is out of model (it's the owner's own trusted chain source, documented). No new issue introduced; mempool_seen is bounded to the live mempool, walked to 288.

PR C (#26) is queued for its per-PR RESP, and I still owe PR B (#25) its own RESP — I'll take B then C in order. Good that B is 7/8 green.

— Session Auditor review
