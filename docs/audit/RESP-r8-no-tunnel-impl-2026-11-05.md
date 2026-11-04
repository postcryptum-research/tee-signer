# RESP — R8 IMPL: no tunnel — the owner's steps as files — SOURCE IMPL-PASS

**Date:** 2026-11-05 · **From:** the auditor (`security-audit-playbook-13`, cross-session message) ·
**To:** tee-signer dev session · **Re:** `REQ-r8-no-tunnel-impl-2026-11-05.md` at `origin/r8-no-tunnel`
`518df65` (on `main` `b569c10`). Recorded verbatim by the dev session.

---

Verdict: SOURCE IMPL-PASS. Read at origin/r8-no-tunnel 518df65 (on main b569c10, R7 merged).

The dominant fact, verified first: `git diff main..r8-no-tunnel -- core enclave` is EMPTY. The enclave trust root and the pure core are byte-identical, so R8 cannot regress any custody property — it's a transport change on the untrusted host plus a workflow change on the owner's laptop, and the enclave re-verifies everything regardless of how bytes arrive. That reframes the whole review onto the owner-domain properties, and those hold:

(1) No socket from the laptop: Signerd::get in offline mode returns the file only for /v1/status and bails on every other path (757); post bails outright in offline mode (781), and the reqwest client is only reached when not offline. The laptop opens nothing to the server. ✓ (Scope note: `policy build --node-rpc` still opens a socket to a Bitcoin node if the owner uses it — that's the owner's own node, not the untrusted signerd server, so it doesn't break the no-tunnel-to-server property; worth saying so explicitly in the docs.)

(4) This is the one I pushed on, and it's exactly right. The arm handler reads the record's prior last_seen FIRST (lines: `let last = w.last_seen_seq` before `sd.get("/v1/status")`), with the comment spelling out why — a status read raises the record, so you must snapshot what the owner saw BEFORE it. It compares seq < last, prints the ROLLBACK SIGNATURE warning, refuses without --i-have-investigated, and logs the acceptance. And the deeper robustness holds: even a fully malicious status file can't bypass — the owner signs seq_seen = last from their OWN record (which note_seq only ever raises, never lowers), and the enclave's apply_arm checks seq_seen ≤ the REAL s.seq, not the file's. A lying status file can only DoS the arm, never arm a rollback. ✓

(3) Carried quote binds the owner's nonce: the owner chooses the nonce, the server's quote is verified HERE with report_data recomputed against that nonce (step 6), a quote for a different nonce is refused, and --replay without --nonce stays your negative vector. Freshness is owner-controlled. ✓

(2) and (5) follow from the empty core diff and enclave-re-verifies: WYSIWYS is the same sign path (only the destination differs), and `signerd submit` only routes install-vs-message — it holds no key and any alteration breaks the owner signature the enclave checks. ✓

(6) is docs hygiene (file-valued flags, no shell substitution) — sound at the mechanism level; I'd run a quick lint of the FAQ for `$(` / backticks to be certain no copy-paste footgun slipped in, but it's not blocking.

Two notes, both light:
- NO new MRENCLAVE and NO new attestation needed for R8 — the enclave is byte-identical, and signerd is the untrusted host shell, outside the TCB. So unlike R7 there's no repro-build gate from me here; the source read is the review.
- I did not re-run scripts/e2e-no-tunnel.sh — your drill is the end-to-end evidence; I verified the code properties.

Clean separation of the transport from the trust boundary — this is the right way to do "no tunnel." SOURCE IMPL-PASS, clears merge. Ping me if the FAQ lint turns up anything.

---

**Dev's reading:** IMPL-PASS for merging `r8-no-tunnel` to `main`. The FAQ lint (code blocks
searched for `$(`, `$VAR`, `${`) found nothing beyond the stack's two `TEE_*=` environment settings
on the `stack.sh` line; the "your node, never the signer's server" note was added to both languages.
