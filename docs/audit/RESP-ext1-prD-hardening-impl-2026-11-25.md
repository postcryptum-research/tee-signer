# RESP-ext1 PR D — hardening (#19, #20, #21, #22; the cheap items of #23) — IMPL-PASS

**From:** the auditor session (`security-audit-playbook`), received 2026-11-25 as a cross-session message. **Reviewed
at:** PR #27, head `5edae7d` (branch `ext1-hardening`, against its merge-base `e451571`), firsthand. **Recorded
verbatim by the dev; nothing edited.** The non-blocking observation (the status `seq` and the explorer `bits` read as 0)
is taken up in PR E.

---

PR D (#27, `5edae7d` = `b3b269b` hardening + `5edae7d` nonce), reviewed firsthand at the ref, diffed against its merge-base `e451571b` (not current main). **Clean PASS — merge-ready. No MRENCLAVE impact (host-side only).** Every item is correct and break-tested both directions; I ran exhaustiveness greps across all sites, not just the diff:

- **`--enclave-debug` default true→false (#22)** — the crown item, and correct: this removes a fail-OPEN footgun (a production launch that forgot the flag silently ran a DEBUG enclave). Verified every launch path: T2 `Dockerfile.signerd-t2` ENV + `opt-add-…-t2` both explicit `false`; T1 compose fragment + `sgx-signerd-restart.sh` now explicit `--enclave-debug`/`true`; the base `Dockerfile.signerd` defaults false, so a T1 launch without its fragment fails to START on SGX1 (loud, fail-closed) rather than running insecure. Backstopped by `attest` rejecting a DEBUG quote. No path silently depends on the old default.
- **Constant-time bearer compare (#23)** — removes the `t == token` short-circuit timing oracle; `ct_eq` over equal length, the length-leak acknowledged and acceptable; `the_bearer_token_must_match_exactly` covers same-length-one-off / prefix / extension / wrong-scheme / no-header.
- **`check_keyfile_params` scrypt bounds [18–20]/[1–8]/[1–4] (#19)** — prevents the `log_n=40` → 2^40 alloc-abort DoS before scrypt runs; applied at BOTH read sites (`open_key` 506, `open_key_with` 519); `keygen`'s `kdf` at 193 uses hardcoded `(18,8,1)` so it's correctly unguarded; a real crafted `log_n=40` file is tested end-to-end.
- **`passphrase_floor` (#20)** — the `OWNER_PASSPHRASE` path no longer early-returns; an empty scripted passphrase is refused when *setting*, correctly skipped when *using* an existing key; tested from both sources.
- **`json_u64` nonce fix** — resolves my PR B observation: the daemon nonce is refused when missing/negative/fractional/string, never read as 0; applied at `nonce()` + the main.rs install-fallback; all cases tested.
- **Monitor `load_state`/`save_state` (#21)** — corruption is LOUD (`STATE_FILE_CORRUPT`) + evidence preserved (moved aside, timestamped) + atomic writes (tmp+rename); applied to all four state files; the hwm reset-on-corruption biases conservative (re-scan) and is never silent. Thorough test.
- **`http()` deadlines / tpm AK re-eviction** — fine; grep found no bare `reqwest` left in `owner/`.

**One non-blocking observation (not a PR D blocker, your call on timing).** Your own "never read a daemon field as 0" rule has a sibling site the PR didn't reach: `Cmd::Arm`, `owner/owner-cli/src/main.rs:2185`, `let seq = st["seq"].as_u64().unwrap_or(0);` (and the adjacent `boot_armed`/`boot_challenge`/`session_id` loose reads at 2186–2188). **It is NOT exploitable** — arm security rests on the owner-signed `seq_seen`, which comes from the *local* wallet record `last` (not from `st["seq"]`) and is verified by the enclave; the status `seq` only drives the display and the rollback *alarm*, and `unwrap_or(0)` biases fail-loud (`0 < last` fires ROLLBACK SIGNATURE when `last>0`; an empty `boot_challenge` dies at the 32-byte check). So this is pure rule-consistency + removing the first-arm (`last==0`) display ambiguity: routing `st["seq"]` through `json_u64` would make the rule uniform. Same character as the PR B nonce note you just closed — surface it whenever convenient, not before merge. (Lower-priority, pre-existing, out of PR D scope: the explorer `bits`/`period_bits` reads near main.rs:1919 also default to 0 — explorer-sourced, for the checkpoint record.)

Ready for PR E (#28, fail-closed signing) next.
