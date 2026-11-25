# REQ-ext1 — triage of the independent external review of 2026-11-25 (host-side fixes)

**Date:** 2026-11-25. **Status:** TRIAGE RULED (`RESP-ext1-external-review-triage-2026-11-25.md`, same day) — per-PR RESPs pending. **Source:** an independent review of the whole Rust of `main` @ `2ff937e`
(core, enclave/rcore, host/signerd, owner/owner-cli, fuzz), received by the owner on 2026-11-25 and held by the
owner outside the repository (the auditor has the owner's copy on this machine). **Scope of the fixes:**
`host/signerd`, `owner/owner-cli`, `.github/workflows/ci.yml`, `deploy/README.md` — `core/` and `enclave/`
untouched, so hard rule 1 is not triggered. **Why a REQ anyway:** the owner's instruction (2026-11-25) is that the
fixes are done *together with the auditor*; this REQ carries the dev's triage and asks for the auditor's
concurrence and for the review of each fix PR before merge. **Queue:** behind pass (ii) (PR #8) and pass (iii)
(PR #12) in arrival order, unless the auditor orders otherwise.

## 1. The review's verdict on the TCB

The reviewer states a line-by-line reading of `core/` (mandate, judge, classify, state, headers, encoding, update,
wallet, sign, receipt, tpm_attest, proto) and `enclave/rcore` (ops, session, envelope, sgx, recovery) and reports
**no defect**: judge/classify sums checked and caps over-refusing, the two-phase JUDGE→seal→SIGN by hash and seq,
own-only-through-derivation, headers retarget/MTP/fork choice/deep-reorg freeze, state/update nonce discipline and
domains, the TPMS_ATTEST layout, seal/unseal with MRENCLAVE + AAD, zeroize, RFC 6979 low-s with the script+amount
re-check in `sign.rs`.

One remark, rated low by the reviewer: `session::ensure()` (`enclave/rcore/src/session.rs:28`) has no guard against
two concurrent first callers. **The dev's answer:** `enclave/Enclave/Enclave.config.xml` sets `TCSNum 1`,
`TCSPolicy 1` — one ecall at a time from any host thread, enforced by the SGX runtime, not only by `signerd`'s
mutex (which `main.rs:1261` also names). The race cannot occur in the enclave; under `nosgx` the harness and the
daemon are single-threaded. A one-line comment naming the TCS invariant at `ensure()` rides with the next core
round (an `enclave/` diff → that round's REQ). **Ask (Q0):** the auditor's confirmation that nothing in `core/` or
`enclave/` needs action from this review.

## 2. Triage — the ten findings and the info list

Every site was read by the dev before an issue was filed; the line numbers are those of `main` @ `2ff937e`.

| Review id | Where | Reviewer → dev | Verified | Issue | Fix |
|---|---|---|---|---|---|
| M1 | `owner/owner-cli/src/monitor.rs` `pass()`: hard `?` between the alarm (sections 1–3) and the FREEZE reflex (section 8) — `es.tip()?` 674, the hwm/cache/ack writes 634/662/687/710/782, `open_locator?` 797, `hash_of(&tip_hash)?` 802 (fails on every pass with the node source down and `freshness.required`), `sign_message?` 808; `run()` prints `pass failed` and loops, no journal line, no FREEZE | HIGH → HIGH | yes | #13 | every step after the receipts is soft; reflex + journal line on every pass that reached a verdict; reproducer: loopback fake `signerd` with a tampered receipt + unreachable Esplora → must ALARM and hit `/v1/freeze` |
| M2 | `scan_node()`: resumes at `last_block + 1` (471) with no hash check; `cache.outputs` only grows; `gettxspendingprevout` is mempool-only; a spend confirmed only in the winning fork of a reorg at a height ≤ `last_block` is never seen | HIGH → HIGH | yes | #14 | recent block hashes in `NodeCache`; per-pass check at `last_block`, rewind to the common ancestor (or full restart with a UTXO scan), re-walk; recorded spends keep their alarm; reproducer: scripted fake node replacing the tip block with one that spends our output |
| M0 | rule 9 declared, not enforced: no `[lints.clippy]` anywhere, no `overflow-checks`, CI runs clippy for core/rcore/fuzz only (`signerd-nosgx` and `owner-cli` run `cargo test` alone) | meta → defect against hard rule 4 | yes | #15 | host side now: lints + overflow-checks + conversion of every site in `signerd` and `owner-cli` + clippy in both CI jobs; `rcore`, `core/tests`, core's `[lints]` with the next core round (one MRENCLAVE, by REQ) |
| H4 | `h_judge` 1094–1103: persist failure after the disarm refusal is `error!` only, 422 returned; memory and disk stay pre-disarm, `/v1/status` says `armed: true`; `h_headers` returns 500 on the same failure | MEDIUM → MEDIUM | yes | #16 | 500 with the reasons, as headers; last persist error recorded, `/v1/status` shows it, `/healthz` 503 until a persist succeeds |
| H1 | `reqwest::Client::new()` with no timeout (387, 446; the feed loop 1380 parks forever, no log); `h_quote` blocking pipe reads under the mutex on the `current_thread` runtime; `RemoteTpm::request` `read_to_end` with a per-read timeout only, no cap, under the mutex in every Fresh op | MEDIUM → MEDIUM | yes | #17 | timeouts on both clients; the helper via `tokio::process` under one timeout; `RemoteTpm` with a deadline and a size cap; the feed under an outer timeout |
| H6 | `as u32` on bitcoind heights: `main.rs:416`, `monitor.rs:448`, `monitor.rs:759`; bare `probe_top - start + 1` at 466 | MEDIUM (liveness) → MEDIUM | yes | #18 | `u32::try_from` with an error; the first vector of the #15 conversion |
| K5 | keyfile `log_n < 18` is the only check; `log_n = 40` → scrypt allocation failure = abort | LOW → LOW | yes | #19 | caps 18 ≤ log_n ≤ 20, r ≤ 8, p ≤ 4; test |
| K1 | `OWNER_PASSPHRASE` returns before the four-character floor | LOW → LOW | yes | #20 | floor on the env value when setting; test |
| M4 | `hwm.json` and the chain caches: unparseable file = silent default; writes not atomic | LOW → LOW (extended to the caches) | yes | #21 | missing = default, present-but-unparseable = `STATE_FILE_CORRUPT` WARN + file moved aside; atomic writes; test |
| H12 | `--enclave-debug` defaults to `true`; T2 fragment and image set `false`, `owner-cli attest` refuses DEBUG | LOW → LOW | yes | #22 | default `false`; T1 keeps its explicit `true` |
| info | bearer compare, receipts file growth and silent line drops, receipt append warn-only, witness cache, `tpm-setup` AK left on `NV_DefineSpace` failure, mu slices, owner-cli HTTP clients without timeouts, `enclave_id` and nonce checks at the owner, PCCS prefix, `describe()` fields, `yubikey` RC, `hwm.txids` Vec, RECEIPT_AMOUNT WARN (by design) | info | each site read | #23 | fixed where a PR touches the file; the cheap ones in the hardening PR |

Not agreed with as stated: the review's recommendation to *close* C-R1-6 and C-R10-6 in `CONDITIONS.md` on the
strength of its own reading (§4, Q3). Not claimed: the reviewer's counts (43 cast sites, 52 increment/shift sites)
are the reviewer's; the dev's own count of 2026-11-24 (operators only) is `signerd` 18, `owner-cli` 21.

## 3. The fix PRs, in order

| PR | Issues | Branch | Contents |
|---|---|---|---|
| A | #13, #14 | `ext1-monitor-reflex-reorg` | the two reproducers committed first (red on `main`), then the fix; `pass()` restructured so no optional step can abort it; `NodeCache` with recent hashes and the rewind; the node RPC behind a small trait so a scripted fake drives `scan_node` in tests |
| B | #15, #18 | `ext1-safemath-host` | `[lints.clippy] arithmetic_side_effects = "deny"` and `overflow-checks = true` in `host/signerd` and `owner/owner-cli`, every site converted, `u32::try_from` on the heights, clippy `--all-targets -- -D warnings` in the two CI jobs; CLAUDE.md rule 9 names what is converted |
| C | #16, #17 | `ext1-signerd-persist-deadlines` | the persist-failure path and its visibility; the deadlines |
| D | #19, #20, #21, #22 + the cheap items of #23 | `ext1-hardening` | one hardening PR with a test per item |

Each PR: `core/` and `enclave/` untouched (`git diff main --stat -- core enclave` empty, stated in the PR); all
checks green on the final head; the auditor's RESP before merge; the branch deleted after. The PRs do not depend on
PR #8 / #12; they rebase on `main` as it moves.

## 4. Questions to the auditor

- **Q0** — §1: nothing in `core/` or `enclave/` needs action from this review (the `ensure()` remark answered by `TCSNum 1`).
- **Q1** — concurrence with the triage of §2: any of the eleven rows you would raise, lower or reject, and anything
  the review missed that you want in the same PRs.
- **Q2** — the review mode for host-side fix PRs, which the protocol so far did not require: the dev proposes one RESP
  per PR (IMPL-PASS / CONDITIONAL / FAIL — the enclave bar minus the MRENCLAVE), merge only on the PASS; or one RESP
  for the set at the end. Your call; the owner asked for "together with the auditor".
- **Q3** — `CONDITIONS.md`, the review's recommendation 4:
  - **C-R1-6** ("`sign.rs` read firsthand by the auditor"): the reviewer read `sign.rs` and found nothing — that does
    not discharge a condition written for *your* reading; it stays OPEN unless you rule otherwise.
  - **C-R10-6** (`add_work_le` saturating/checked, no wrap): the row still reads OPEN "phase 2 (F6 headers)"; the
    code is checked on `main` and pass (i) carried the direct oracle (C-R10P2-2, IMPL-PASS scoped at `14e1965`).
    Please state the row's status; the dev writes what you rule.
  - **C-R10-5**: the row said the F-01 defect "stays OPEN until the F-01 fix pass" and "the harness awaits
    IMPL-PASS" — stale since `RESP-r10-f01-checkpoint-impl-2026-11-21.md` (IMPL-PASS at `10f6770`, PR #2) and the
    phase 1 IMPL-PASS at `9e2d2fc`. Corrected in this commit with the references; please confirm.
- **Q4** — M0 sequencing: the owner's 2026-11-24 sequencing had `signerd` / `owner-cli` converting *after* pass
  (iii) closes; the owner's instruction of 2026-11-25 ("start the fixes") moves that conversion into PR B now.
  `rcore`, `core/tests` and core's `[lints]` entry are unchanged: the next core round, one MRENCLAVE, by REQ.
  Objections?

## 5. Status log

| Date | Event |
|---|---|
| 2026-11-25 | report received by the owner; moved outside the repository; every finding verified by the dev; issues #13–#23 filed; this REQ sent |
| 2026-11-25 | PR A #24 (`a8c7313`, #13 #14) and PR B #25 (`d7f3364`, #15 #18) submitted; the auditor's triage ruled firsthand — `RESP-ext1-external-review-triage-2026-11-25.md`: Q1 concur ×11, Q0 no core/enclave code here (C-EXT1-1, C-EXT1-2 for the next core round), Q2 one RESP per PR, Q3 C-R1-6 and C-R10-6 closed by the auditor's reading and C-R10-5 confirmed, Q4 PR B's sequencing concurred |
