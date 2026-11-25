# RESP-ext1 PR B — SafeMath enforced in `signerd` and `owner-cli` (#15, #18) — IMPL-PASS

**From:** the auditor session (`security-audit-playbook`), received 2026-11-25 as a cross-session message. **Reviewed
at:** PR #25, head `d7f3364` (branch `ext1-safemath-host`, against its merge-base `a8c7313`), firsthand. **Recorded
verbatim by the dev; nothing edited.** Merge cleared on CI green per the per-PR protocol
(`RESP-ext1-external-review-triage-2026-11-25.md`, Q2). The non-blocking observation (the status `nonce` read as 0
when absent) is taken up in PR D.

---

REQ-ext1 PR B — `ext1-safemath-host` (#15 host SafeMath + #18 u32 heights) — **IMPL-PASS**. Reviewed firsthand against the merge-base (a8c7313..branch, not raw main — the RESP-file "removals" in a raw-main diff are just the stale-base artifact), full functions at the ref.

**Completeness is compiler-enforced — the strongest form of "SafeMath everywhere."** Both `host/signerd` and `owner/owner-cli` carry `arithmetic_side_effects = "deny"`, `cast_possible_truncation = "deny"`, `cast_sign_loss = "deny"` plus `[profile.release] overflow-checks = true`, and CI runs `clippy --all-targets -- -D warnings` on both (signerd under nosgx,tss). No raw `+/-/*` and no truncating/sign-losing `as` cast can survive compilation, so #18's H6 casts (main.rs:416, monitor.rs:448/759, the probe_top−start+1) are covered structurally, not site-by-site-by-hand. My job was then the semantics, and they hold:

- **btc_sat (the money conversion) is right.** `bitcoin::Amount::from_btc(btc)?.to_sat()` — the node's own rounding, and a negative/malformed/over-precise amount is an Err, never 0. Not a naive `(f64*1e8) as u64`. The call sites are `btc_sat(&u["amount"])?` / `btc_sat(&vout["value"])?` — fail-closed. `btc_sat_rounds_as_the_node_does_and_refuses_garbage` covers it.
- **json_u32 errors on both non-numeric and out-of-u32-range**, so every `json_u32(…)?` (node tip height, best_height's match) genuinely aborts the pass on a bad height rather than `unwrap_or(0) as u32`. That's the right direction — a silent tip=0 was the dangerous form.
- **next_nonce refuses at nonce-space exhaustion** (`checked_add(1).ok_or`) instead of wrapping to 0 — exactly the replay catastrophe you want refused.
- The height/confirmation semantics are correctly fail-closed: an unfitting tx height reads as *unconfirmed* (stays in the cap window), and `tip_h − h + 1` → `saturating_sub().saturating_add(1)` under-counts confirmations on an above-tip anomaly (keeps watching, never wraps to "deeply confirmed" and clears it). `period_start`'s saturating_sub provably can't underflow (`height % 2016 ≤ height`), honestly labelled as linter-form.
- Swept every other `saturating_sub`/`unwrap_or`: the `*80` Vec-capacity hint (0 = no prealloc, harmless), the rollback-warning `last.saturating_sub(seq)` (display-only, inside the already-detected rollback branch), `duration_since(UNIX_EPOCH)…unwrap_or(0)` (standard), `h.accepted…unwrap_or(0)` (0 = no progress = fail-closed). The replay.rs value subtraction is a test fixture (`.expect("fixture: the inputs cover the outputs and the fee")`) — a panic there is a test failure, fine.
- Rule-9 scope in CLAUDE.md is honest: host crates converted now; `core/tests`, `enclave/rcore` and core's `[lints]` entry ride the next core round by REQ, `core/src` under `#![deny]` until then. That matches my Q4 concurrence — and I'm still tracking the core `[lints]`/overflow-checks as a blocking item for that very next round (it's a TCB SafeMath-lint gap, so it may not drift).

**One non-blocking observation** (your call, not a condition): `next_nonce(st["nonce"].as_u64().unwrap_or(0))?` takes a missing/garbage nonce field as 0. It isn't exploitable — the enclave re-validates nonce monotonicity and `next_nonce(0)=1` — but it's the one spot that still reads a daemon field as 0 instead of erroring, against the "never 0, always an error" rule you applied to btc_sat/json_u32. If you want full consistency, a `json_u64(…)?` there would close it. Not needed for the PASS.

Clears for merge on CI-green per the per-PR protocol (Q2). Send C (`ext1-signerd-persist-deadlines`, #16/#17) when ready — I'll take the persist-failure visibility and the deadlines next.

— Session Auditor review
