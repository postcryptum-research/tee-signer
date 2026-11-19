# RESP-r9a — IMPL-PASS: the Anchor pins the LIVE, attested counter (auditor, 2026-11-19, recorded verbatim)

Received from the auditor session (`security-audit-playbook-7f`) in answer to
`REQ-r9a-anchor-live-counter-2026-11-18.md` §7 on branch `r9a` @ `873a6378e3311fd31432ba44dd455ef632937123`
(the design: `RESP-r9a-anchor-live-counter-2026-11-18.md`, DESIGN-PASS, conditions C1–C6). Verbatim as sent.
Merged to `main` as a fast-forward the same day (`main` = that SHA).

---

r9a @ 873a6378e3311fd31432ba44dd455ef632937123: IMPL-PASS, no findings. All six RESP-r9a conditions and the seven IMPL-PASS criteria verified firsthand at the ref; the replay suite passes 5/5 on my box (cargo test --features nosgx,test-init --test replay → anchor_pins_the_live_counter_r9a + tpm_counter_freshness_r9 green). Cleared for the ceremony / new MRENCLAVE / new T2 wallet (owner-run).

What I checked, firsthand:
- C1 sealed-identity rooting: anchor_identity returns the SEALED ak_pk/nv_name on a bound state and requires message == sealed (else ANCHOR_TPM_MISMATCH); only an unbound state takes the message's identity (TOFU). certified_counter in anchor_live_counter is rooted on those sealed values, so a host handing a different TPM's identity + a valid proof from it is refused before the proof is even verified — the custody re-point the whole mechanism exists to stop. Vector 7 confirms it, and the sub-case "forged identity with the honest TPM's proof" still mismatches (identity before signature).
- C3 lower bound: live_counter < msg.counter → ANCHOR_COUNTER_BEHIND; expected := live_counter, not the message snapshot. Vector 3 fires it and asserts proof-consumed + state-unchanged.
- C4 (crown) no proof-less path: no proof → TPM_REQUIRED; apply_anchor is reached ONLY via anchor_live_counter's verified live value — exactly one caller, new signature, the old REQ-r9 §2.5 proof-less apply_anchor is gone (retirement confirmed). Vector 2 fires TPM_REQUIRED.
- C5 override intact: Anchor still open_full_stale; it uses certified_counter (no comparison to the stale blob's expected), not verify_nv_certify. The genuine owner re-pin of a live state still overrides a stale snapshot.
- C6 reasons: ANCHOR_TPM_MISMATCH and ANCHOR_COUNTER_BEHIND are distinct variants/codes (not collapsed into TPM_PARSE/STATE_STALE); hint_for_code carries the sanctioned recovery and signerd err()/owner_step surface it next to the code.
- The two-direction break-test (criterion 5): vector 7 refuses the forged identity AND vector 7b permits the honest same-identity re-pin (stale blob expects 505, TPM at 507, re-pin applies clean → expects 508, armed, a proven op then goes through). The guard is not over-tight. The final vector re-pins on a LIVE bound state (the 16:11 picture), clean.
- Vector 8 in both e2e scripts: two persists injected between tpm-certify and apply, then tpm_expected == live TPM counter asserted (software and real-TPM/PTT). I verified the enclave-level equivalent firsthand in the replay vectors; the e2e runs are yours.

One non-blocking observation (tidy-up, not a finding): tpm_set_last_fresh isn't updated on three refusal sub-paths of anchor_live_counter (TPM_REQUIRED, ANCHOR_TPM_MISMATCH, and the malformed-identity POLICY_INVALID) — so a status read right after one of those refusals can report a stale tpm_last_fresh from the previous op. It's a diagnostic flag only (reported in status, used in no decision; the refusal itself is authoritative), so nothing turns on it — but setting it false on those three paths would make the status honest. Your call whether to fold it in before the ceremony.

Forward boundary (not owed now): this is a source IMPL-PASS + firsthand test run. When you build the new T2 MRENCLAVE, a decorrelated repro of it is the deploy-content gate — same as my ca5c1a6 / c7c5d8ef repros; I'll do it against the built measure. Nothing on your side blocks on that until the image exists.

---

**Dev's note (2026-11-19).** The e2e runs the auditor leaves to the dev were green at the delivered SHA before the
pass (`scripts/e2e-local.sh` software transport, `scripts/e2e-tss-local.sh` on the laptop's Intel PTT; both assert
`tpm_expected == counter` after an anchor window with two persists). The non-blocking observation is taken up as a
separate small branch (`tpm_last_fresh := false` on every refusing path of `anchor_live_counter`, and on the
proof-less `TPM_REQUIRED` path of `open_full_fresh` for the same reason), sent to the auditor at its own SHA before
it merges — the ceremony signs whatever `main` measures once that is settled.
