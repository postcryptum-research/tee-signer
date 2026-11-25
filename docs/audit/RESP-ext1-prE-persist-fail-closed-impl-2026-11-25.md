# RESP-ext1 PR E — `signerd`: no signing while a persist failure stands (the owner's rule) — IMPL-PASS

**From:** the auditor session (`security-audit-playbook`), received 2026-11-25 as a cross-session message. **Reviewed
at:** PR #28, head `3017265` (branch `ext1-persist-fail-closed`, against its merge-base `bab29ee`), firsthand.
**Recorded verbatim by the dev; nothing edited.** The informational residual (`tpm_expected` displayed as 0 when
absent) is left as it is — display-only, the anchor's counter comes from the attested proof (C-R9-D) — and listed in
issue #23.

---

PR E (#28, head `3017265`, diffed against merge-base `bab29ee` = main post-D), reviewed firsthand. **Clean PASS — merge-ready. No MRENCLAVE impact** (`core`/`enclave`/`fuzz` untouched, confirmed by the stat).

The fail-closed signing guard is correct, and I checked it's *complete*, not a subset:
- **`signing_blocked()`** returns 503 PERSIST_FAILED iff `persist_error` is set; `persist()` sets it on any failed atomic write and clears it on the next success. The motivation is real and the owner's rule applied correctly: a freeze/disarm the host couldn't persist must not be undone by a later signature over the stale blob, and the REQ-r9 counter can't catch it (the increment never happened).
- **Gate covers the only value-releasing path.** `SIGN=8` is the sole signature op (JUDGE=7 only judges; REPORT=10 and the TPM ops are attestations "nothing secret leaves"; APPLY_MESSAGE/FREEZE/HEADERS are state). `/v1/sign → h_sign` is the only route to it, and `signing_blocked()` is checked at 1192 before JUDGE/persist/SIGN. The four other `op::SIGN` sites are in `replay.rs` (`replay_vectors`/`smoke`, main.rs:1447/1452) — boot/diagnostic self-test over fixed vectors, not network-reachable and returning no signature to a caller — correctly outside the guard.
- **Two-phase persist is independently fail-closed:** the charged blob must persist (1233) before `op::SIGN` (1241); a failure there issues no signature and sets `persist_error` for the next request.
- **Restart gap is covered elsewhere:** `persist_error` is in-memory, but after a restart the daemon comes up from the last-written blob and REQ-r7 arm + the seq rollback check gate signing — layered defense, not a hole.
- **Liveness carve-out is right:** reads/owner-messages/feed/freeze stay served, and because every sealed blob reflects the enclave's current in-memory state, the first successful persist among them carries the originally-failed state change forward — so clearing the block is safe.
- **The test earns it.** `signing_is_refused_while_a_persist_failure_stands` drives block→repair→unblock through `persist()` itself (a state dir that's a regular file → fail → blocked; repair the dir → first write unblocks), no flag flipped by hand; it mutation-fails if the guard is hollow (the `.expect` at 1626). Both directions covered.

**b2e5f5e** resolves my PR D observation cleanly — `st["seq"]` in **both** `Cmd::Arm` (2185) and `Cmd::Anchor` (2290) now go through `json_u64`, plus the explorer `bits`/`period_bits`. One residual, informational only: `st["tpm_expected"].as_u64().unwrap_or(0)` at 2296/2335 still defaults to 0 — but it's display-only and the anchor counter comes from the attested proof (C-R9-D), so no action needed unless you want the rule uniform.

That closes the btcpay ext1 queue on my side (PR D merged, PR E clean). Deploy to the T2 node and any ceremony/MRENCLAVE step remain the owner's call.
