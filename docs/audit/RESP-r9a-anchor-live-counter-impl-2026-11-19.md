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

---

## Addendum — the `tpm_last_fresh` tidy-up (two follow-up branches, both IMPL-PASS firsthand, 2026-11-19)

The non-blocking observation above was taken up in two enclave-only commits (`enclave/rcore`, core untouched),
each sent at its SHA and merged to `main` on the auditor's word. Status-only: no decision reads the flag; the
refusal itself is authoritative. Verbatim as sent.

**`r9a-last-fresh` @ `d5e3727ee4ee1e52163a25ca9360eccaa46633fa`:**

r9a-last-fresh @ d5e3727: IMPL-PASS, merge it. And my ruling on the open question: yes, flip ANCHOR_COUNTER_BEHIND → false too — one more small commit, same invariant.

The branch as written, verified firsthand (enclave-only, core untouched; replay 5/5 green on my box):
- The three paths you named now clear the flag (TPM_REQUIRED, the anchor_identity ANCHOR_TPM_MISMATCH, the malformed-identity POLICY_INVALID), with the `?` turned into a match so it's set before the early return. Correct.
- open_full_fresh's missing-deposit TPM_REQUIRED: KEEP it. It's the same gap on the Fresh path (every other refusal there already set false), not scope creep. Good catch.
- session.rs doc now states the semantics and that it's STATUS-only, no decision reads it — exactly right, and it's what makes this a tidy-up and not a security change.
- The replay assertions prime the flag true (a proven FREEZE whose blob is discarded) then assert the refusal clears it — they observe the actual flip, not a baseline false. Sound test design.

The ruling (your deliberately-left COUNTER_BEHIND=true):
Flip it to false. Reasoning: STATE_STALE is the exact analogue — proof verified cryptographically (certified_counter: nonce, Name, signature all pass), value then refused — and it already sets false. COUNTER_BEHIND is the same shape (proof verified, then the core's lower-bound refuses), so for the flag to mean one thing it should match. Your own new doc says "false after any refusal on the proof path"; leaving COUNTER_BEHIND true is the one refusal that contradicts it. And it costs nothing in signal: the operator already gets the precise ANCHOR_COUNTER_BEHIND reason + hint, which carries the "proof was fresh, the value went backward" nuance far better than a status bool could — so the flag doesn't need to encode it, and shouldn't, because that's where the inconsistency comes from. Net: tpm_last_fresh = "the last proof-gated op applied with a fresh proof; any refusal clears it," uniform.

Implementation: COUNTER_BEHIND is refused in the core (apply_anchor) after anchor_live_counter already set true, so the clean spot is apply_message's Anchor arm — clear the flag when apply_anchor returns Err. That also uniformly covers the other apply_anchor refusals (owner-sig, enclave_id, ArmSeqBehind), which today likewise keep it true after a verified proof; false is right for those too. Add a replay assertion that primes true then asserts COUNTER_BEHIND clears it, same pattern as the others.

Weight: zero security — status-only, the refusal is authoritative. So this is a consistency fix, not a blocker: the branch is already a strict improvement over main, and if you'd rather ship d5e3727 as-is and fold the COUNTER_BEHIND flip into the same ceremony build later, that's fine — tell me which and I'll note it. Either way the enclave change is cleared for the ceremony-signed build whenever the owner runs it.

**`r9a-last-fresh-2` @ `c54d9895fa03601be3d36eca3ede3f806e70f3a6`:**

r9a-last-fresh-2 @ c54d9895fa03601be3d36eca3ede3f806e70f3a6: IMPL-PASS, merge it. Verified firsthand at the ref.

- The Anchor arm is the clean spot I named: `anchor_live_counter(&s,&msg).and_then(|live| s.apply_anchor(...).inspect_err(|_| tpm_set_last_fresh(false)))`. anchor_live_counter sets the flag true only on certified_counter Ok (ops.rs:266) and false on every refusal inside it; apply_anchor's Err then clears it via inspect_err; an applied Anchor keeps the true. Net invariant: tpm_last_fresh = true iff the last proof-gated op APPLIED on a fresh proof — ANCHOR_COUNTER_BEHIND, owner-sig, challenge and seq all clear it now, uniform with STATE_STALE on the Fresh path. Exactly the ruling.
- inspect_err was the right call over map_err — side-effect only, returns the Result unchanged; clippy --all-targets -D warnings is clean on my box, and it's stable core, no new crate.
- Tests encode the flip where it's observable: vector 3 asserts true going in (the Unfreeze applied on a fresh proof), false right after ANCHOR_COUNTER_BEHIND, then re-primes with a proven FREEZE so the trailing proof-less TPM_REQUIRED still observes a clear; tpm_counter_freshness_r9's old "true after ARM_SEQ_BEHIND" became "false" — the assertion that used to encode the inconsistency now encodes the rule. Ran it: cargo fmt --check clean, clippy -D warnings clean, replay 5/5 green.
- Scope is enclave/rcore only (+21/-9), core untouched.

That closes the r9a flag thread end to end. On your word main measures d5e3727 + this for the ceremony build; the ceremony and the new T2 MRENCLAVE stay owner-run, and I repro the new MRENCLAVE on my box when the image is built (deploy-content gate).

---

**`main` for the ceremony build = `873a637` (REQ-r9a) + `d5e3727` + `c54d989`** (+ the docs commits). The new
MRENCLAVE is measured when the enclave is built on Hetzner in Docker (`PHASE=gendata`); the auditor's decorrelated
reproduction of that measure is the deploy-content gate before the image reaches `sgx-node-3`.
