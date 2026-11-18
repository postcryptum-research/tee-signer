# RESP-r9a — DESIGN-PASS: the Anchor pins the LIVE, attested counter (anchor-window race)

**Date:** 2026-11-18
**Auditor:** security-audit-playbook (standing auditor)
**REQ:** `docs/audit/REQ-r9a-anchor-live-counter-2026-11-18.md`
**Builds on / amends:** REQ-r9 §2.5 (design + impl, both PASSED 2026-11-10/11).
**Verdict:** **DESIGN-PASS.** The design is sound and closes the defect without weakening the override or the owner's control. Implementation is cleared to proceed against the conditions in §3. A separate, firsthand **IMPL-PASS at the delivered SHA** (§6) is the gate before the ceremony / new MRENCLAVE / new T2 wallet.

---

## 1. The defect this closes

REQ-r9 §2.5 pins `expected = counter` — the value the owner saw in a `TPM2_NV_Certify` over their own nonce — and the seal bumps it to `counter + 1`. That is correct only when nothing else persists between the owner's `tpm-certify` and the Anchor's apply. But `Daemon::persist` increments the TPM on **every** durable blob, and the header feed persists on **every** accepted block (`main.rs:509-514`); feed and owner ops serialise under the daemon lock, the owner's laptop round trip does not.

Observed 2026-11-18, `sgx-node-3`, first anchor of wallet `7180f2b6`: owner attests 7 → a signet block persists (TPM→8) inside the certify→submit window → the Anchor applies `expected := 7`, seal→8, persist→TPM 9 → the next `HEADERS` is refused `STATE_STALE` (blob 8, TPM 9); every Fresh op since. A legitimate owner anchor was made to look like a rollback by the daemon's own feed. **Fail-closed, 0 funds at risk (empty wallet); the cost was a pause and a second anchor.** Not caught by `e2e-local`/`e2e-tss-local` (no live feed in their anchor windows) nor by my REQ-r9 IMPL-PASS — a recorded miss on my side (the e2e paths did not exercise a persisting feed inside the window).

---

## 2. Verdict and the load-bearing correction

**DESIGN-PASS.** The Anchor stops trusting a static snapshot and takes the **live, attested** counter at apply time, with the owner's attested value as a **lower bound** — closing the window to the daemon lock. The override is preserved (the blob is still opened `open_full_stale`; the fix never compares against the stale blob's `expected`), and the owner's authority is not weakened: between the owner's certify and the apply, only the daemon's own persists can move the counter, each a state change the enclave itself sealed.

**The load-bearing correction (my Q2 ruling, adopted in full).** The draft verified the deposited proof against the **message's** `ak_pk`/`nv_name`. That is wrong: the owner builds the Anchor from a **host-supplied** `tpm-info`, so a malicious host could hand the owner the identity of a TPM *it* controls plus a valid proof from that TPM and re-point the anti-rollback counter to itself — the enclave would have accepted a security-critical identity from the very host the counter exists to defend against. The proof MUST be rooted on the **sealed** `TpmAnchor.ak_pk`/`nv_name` (the identity bound at this enclave's first anchor, inside the blob the host cannot change), and the message's identity must **equal** the sealed one. This is the no-host-param / no-blind-trust axis; rooting on the message would have shipped exactly the host-trust the whole mechanism removes.

---

## 3. Conditions (binding on the implementation; the IMPL-PASS checks each firsthand)

- **C1 — Sealed-identity rooting.** On a **bound** state (every anchor after the first), verify the deposited proof against the **sealed** `TpmAnchor.ak_pk`/`nv_name`, and require `message.ak_pk/nv_name == sealed` → else **`ANCHOR_TPM_MISMATCH`**, state unchanged, proof consumed. Only the **first, binding** anchor (no sealed anchor yet) verifies against the message's values — the labeled trust-on-first-use residual (THREAT-MODEL "TPM identity at anchor time").
- **C2 — Live nonce.** The proof's `extraData` must be the **live** nonce; a replayed/stale proof → `TPM_NONCE`, refused, proof consumed. Nonce and proof are consumed whatever the verdict (REQ-r9 Q5).
- **C3 — Monotone lower bound.** Accept only `live_counter ≥ msg.counter`; `live_counter < msg.counter` → **`ANCHOR_COUNTER_BEHIND`** (an honest TPM is monotone, so a lie or a replaced TPM). Then `expected := live_counter` (the seal bumps to `live_counter + 1`; the daemon's one post-persist increment lands them equal).
- **C4 — No proof-less path (crown).** A missing or failing proof **refuses** the Anchor (`TPM_REQUIRED`). There is **no** fallback to trusting the message's static counter. The Anchor still bypasses the stale blob's `expected` (it remains the attended override) but now demands a verifiable live proof. The entire fix is void if an unattested counter can still be trusted — this condition is non-negotiable.
- **C5 — Override preserved.** The fix must **not** reintroduce a comparison against the stale blob's `expected` (`open_full_stale` stays). The live counter comes from the fresh proof, not the stale blob, so a genuine owner re-pin of a live state still overrides a stale snapshot.
- **C6 — Distinct, actionable reasons.** `ANCHOR_TPM_MISMATCH` must be a **distinct** verdict — a security event (the host handed the enclave a different TPM) must not collapse into a benign `TPM_PARSE`/malformation, so owner and logs can tell an attack from an error. Each refusal carries the sanctioned recovery in the **operator-facing** text (owner-cli reason, plugin status line), not only the docs. `ANCHOR_TPM_MISMATCH` especially must name the path — *"the host presented a TPM identity different from the one this wallet is bound to — do not retry; a replaced TPM under a living wallet means a new wallet, or a re-bind ceremony"* — so an operator does not retry into a wall.

---

## 4. Required vectors (the IMPL-PASS verifies these fire at the intended lines)

Per REQ §4 (`vectors/r9a/` + `core/tests/replay.rs`; e2e knobs). Load-bearing:

- **1 — the 2026-11-18 case.** Owner attests *N*, *k* feed-persists before apply (*k* = 1, 2): live *N+k* → applied, `expected` *N+k+1*, next Fresh op accepted (no `STATE_STALE`).
- **7 (negative) — forged identity refused.** Bound state, message `ak_pk`/`nv_name` ≠ sealed, a valid proof from that **other** key → `ANCHOR_TPM_MISMATCH`, state unchanged, proof consumed.
- **7b (positive, equally load-bearing) — honest re-pin permitted.** Bound state expects *N* while the TPM is at *N+k* (the 2026-11-18 picture), message identity **== sealed**, live proof at *N+k* → **applied**, `expected` *N+k+1*, armed, next Fresh op accepted. **The guard must PERMIT the honest same-identity re-pin as cleanly as it REFUSES vector 7** — this is a break-test in *both* directions; a guard tested only on the refusal is half-tested and can be silently over-tight.
- **2** no proof → `TPM_REQUIRED`, unchanged. **3** `live_counter < msg.counter` → `ANCHOR_COUNTER_BEHIND`, proof consumed. **4** foreign AK / wrong Name / replayed nonce / truncated → `TPM_SIG`/`TPM_INDEX`/`TPM_NONCE`/`TPM_PARSE`; the same Anchor again → `TPM_REQUIRED`. **5** the override still works (old blob *N*, TPM *N+k*, live proof → applied, a proven `FREEZE` then goes through). **6** all REQ-r9 vectors unchanged. **8** e2e: a "feed persists *k* times inside the anchor window" knob; the anchor must apply clean (software transport and the laptop PTT).

---

## 5. Scope, severity, rollout

- **Severity of the *unfixed* defect:** operability / availability, **fail-closed** — a legitimate anchor looks like a rollback → the node pauses (`STATE_STALE`) → a second anchor clears it. **Not** a fund-loss, drain, or rollback-acceptance. Today, 0 live-fund risk (signet; `7180f2b6` empty).
- **Severity of what the fix *also* closes:** the draft's message-identity rooting would have been a **custody** gap at real-fund scale (a host re-pointing the anti-rollback root). The sealed-rooting correction forecloses it before it ships. This is why the change is worth a MRENCLAVE now rather than later.
- **Rollout:** enclave change → **new MRENCLAVE** → **ceremony** (owner re-signs) → **new T2 wallet** (sealing is MRENCLAVE-bound). All ceremony / wallet steps are **owner-run**. Cheapest **before** the T2 wallet is funded — done now (owner's scope decision, 2026-11-18) while `7180f2b6` holds 0 sat. Host daemon **unchanged**; `call_fresh` already deposits a proof for every `APPLY_MESSAGE` (`main.rs:876`).
- **(b) host-side guard: not adopted** — redundant once the enclave roots on the live proof, never a boundary.
- The TPM identity is **bound for the wallet's life**: a replaced/reset TPM behind a living enclave cannot be re-bound by an Anchor (`ANCHOR_TPM_MISMATCH`); the path is a new wallet, or a future re-bind REQ with its own ceremony. Designed, not a gap (REQ §6 Q6).

---

## 6. IMPL-PASS criteria (the gate before the ceremony / deploy)

When the SHA lands I verify **firsthand, at that ref** (CHANGED ≠ CORRECT):

1. the Anchor branch verifies the proof against the **sealed** `TpmAnchor` (not the message), and `message == sealed` is enforced on bound states with TOFU only on the first anchor (C1);
2. `live_counter ≥ msg.counter` is enforced and `ANCHOR_COUNTER_BEHIND` is reachable (C3);
3. **no proof-less path survives** — `TPM_REQUIRED` on a missing/failing proof, with no fallback branch that trusts `msg.counter` (C4);
4. the override is intact — `open_full_stale`, no comparison against the stale blob's `expected` (C5);
5. the §4 vectors fire at the intended lines, **including 7b (positive same-identity re-pin applies clean) alongside 7 (forged identity refused)** — the two-direction break-test;
6. the three reasons are distinct and the operator-facing text carries the sanctioned recovery (C6);
7. reachability/retirement: the Anchor branch is the only path that sets `expected` from a proof; the replaced REQ-r9 §2.5 "Anchor without a proof" path is gone.

The ceremony, the new MRENCLAVE on T2, and the new wallet proceed **only after** this IMPL-PASS.
