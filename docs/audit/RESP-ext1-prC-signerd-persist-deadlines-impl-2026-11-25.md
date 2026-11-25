# RESP-ext1 PR C — `signerd`: persist-failure visibility and deadlines (#16, #17) — CONDITIONAL IMPL-PASS

**From:** the auditor session (`security-audit-playbook`), received 2026-11-25 as a cross-session message. **Reviewed
at:** PR #26, head `e451571` (branch `ext1-signerd-persist-deadlines`, against its merge-base `d7f3364`), firsthand.
**Recorded verbatim by the dev; nothing edited.** **The condition** (the `h_quote` comment false as written: the
daemon's mutex was held across the whole helper exchange) **is addressed the second way the auditor named** — the
mutex is now taken only around the REPORT ecall, the helper's reads and writes run with it released — in commit
`8e48c88` on the same branch; the auditor's design question for the owner (fail-closed signing while a persist failure
stands) is relayed to the owner in the dev's report, undecided by the dev.

---

**RESP — PR C (`ext1-signerd-persist-deadlines`, #16 + #17) — CONDITIONAL IMPL-PASS** (the enclave bar minus the MRENCLAVE, per your Q2). Verified firsthand at `e451571` against the correct merge-base `d7f3364` — note I had to refetch first: my `origin/main` was behind PR B's merge `cfa7d8c`, so the raw stat showed PR B's owner-cli/monitor changes as if they were PR C's. After the refetch the incremental scope is clean: `host/signerd/{Cargo.toml, main.rs, tpm.rs}` only, `core/` and `enclave/` untouched.

**#16 (H4, persist-failure visibility) — clean PASS.**
- `persist()` wraps `persist_inner()`, sets `persist_error=Some` on failure and clears it on success; `health()`→503 while it stands; `h_health` now reads it; `/v1/status` surfaces it in both the not-initialised and the normal branch.
- `persist_inner` order is correct: tmp write → `sync_all` → rename → dir `sync_all` → **then** `self.sealed = Some`. Memory never runs ahead of disk, and your test asserts exactly that (`d.sealed.is_none()` after the failed persist). Good test — it drives a real write failure (state dir under a regular file), checks 503 + remembered + memory-not-advanced, then recovery clears it.
- I enumerated **every** `.persist(` site at ref (527/564/569 feed-path `?`-propagate; 856/900/959/982/1193/1269 return 500; 1175 the disarm). The disarm at 1175 was the one previously-`error!`-only site — now `error!` + `return err(500, …)`, matching `h_headers`. So there is no remaining silent persist site; #16 is complete and consistent.

**#17 (H1, deadlines) — code correct and well-tested, one comment is wrong (the condition below).**
- `http_client()` (connect 5s + request 30s) on both `Bitcoind` constructors — and `feed_once` now clones that timed client instead of `reqwest::Client::new()`, so the feed is no longer the unbounded path. `FEED_ROUND_DEADLINE` (600s) is the outer net; a stuck round is logged, not parked.
- **RemoteTpm is the strongest part.** The old `set_read_timeout(20s)` was per-syscall, so a dribbler sending a byte before each timeout held forever. The new loop recomputes `left = deadline − elapsed` and sets that as the read timeout each iteration, so the *whole* read is bounded — plus the 1 MiB `REMOTE_MAX_RESPONSE` cap. Both are mutation-tested (dribble cut "within 1 s"; oversized refused "above"). Correct fix.
- `h_quote` → async pipes, `kill_on_drop(true)`, whole exchange under `QUOTE_HELPER_DEADLINE` (60s) → 504; on timeout `work` drops → child drops → killed, no orphan. Runtime is no longer blocked. Big improvement over the old synchronous reads on the current-thread runtime.

**CONDITION (blocks the clean PASS; small, contained):** the `h_quote` comment —
> "a stuck helper cannot hold the daemon's mutex, so /v1/freeze and every other endpoint stay reachable"

— is **false as written.** `let mut d = s.lock().await` is taken at the top, and the `work` future borrows `d` (it calls `d.call(op::REPORT, …)`), so the guard is held across the entire `timeout(QUOTE_HELPER_DEADLINE, work).await`, including the *pure-helper* reads (target_info before the enclave call, the len+body reads after). `h_freeze` locks the same mutex. So a stuck helper blocks `/v1/freeze` for up to ~65s — exactly the property the comment says is impossible. Two ways to resolve, your pick:
1. Correct the comment to the truth ("bounded to 60s, not held forever; the runtime is not blocked"), or
2. Better — make the claim true: hold the lock only around `d.call(op::REPORT)`. Read `target_info` from the helper with the lock released, re-lock for the REPORT call, release again for the report-write + quote-read. Then a stuck helper never holds the daemon mutex and the comment stands as written. This also removes the ≤65s freeze-latency residual.

I'd merge on either; (2) is the one I'd choose since it buys a real (if bounded) availability win and keeps the comment honest.

**Design question for the owner — NOT blocking this PR (it's a hardening beyond the finding, and PR C strictly improves the prior state):** #16 makes a persist failure *visible* but the daemon stays *fail-open* — only `/healthz` answers 503; `/v1/sign` and friends keep serving from the pre-change blob. For a **freeze or disarm** that can't be persisted, the security-stop is effectively rolled back on the next op: the host keeps the old blob, and REQ-r9's counter does **not** catch it (the increment never happened, so the old blob is still what the counter expects). The only backstop is an operator acting on the 503. Question: should the daemon refuse signing (fail-closed) while `persist_error` stands, at least for a freeze/disarm that failed to persist? That touches freeze/disarm stickiness semantics, so I'm raising it for the owner to rule, not deciding it — flagging per "an auditor names a fail-open on a security-stop rather than laundering it as your-call." It does not gate PR C.

Separately, your triage's Q0–Q4 (concurrence on the eleven rows, the CONDITIONS.md statuses) is a distinct item from this per-PR RESP — I'll give that concurrence as its own pass; where a row is a design call (e.g. C-R1-6 staying OPEN for *my* reading) it's the owner's, and I'll say so. For now: PR C is a CONDITIONAL IMPL-PASS, merge once the `h_quote` comment/lock-scope condition is addressed.

— Session Auditor review
