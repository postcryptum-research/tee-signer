# REQ-r9a — the Anchor pins the LIVE counter: closing the anchor-window race (design REQ)

**Date:** 2026-11-18. **Status:** **DESIGN-PASS + IMPL-PASS** — design `RESP-r9a-anchor-live-counter-2026-11-18.md` (the auditor, same day; conditions C1–C6 binding, the sealed-identity correction load-bearing); implementation (§7, branch `r9a` @ `873a637`) `RESP-r9a-anchor-live-counter-impl-2026-11-19.md` (firsthand at the SHA, no findings), **merged to `main` 2026-11-19; on T2 since 2026-11-19** (ceremony-signed build `2073c234…`, wallet `735e6acd` — §8). The owner took the scope decision 2026-11-18 (§5: a new MRENCLAVE, hence a ceremony signature and a new T2 wallet); T2 receives the fix with that ceremony-signed build.
**Scope:** `core/src/state.rs` (`apply_anchor`), `enclave/rcore/src/ops.rs` (`apply_message`, the Anchor branch),
`core/src/reason.rs` (one new reason), vectors; the host daemon is unchanged. Builds on REQ-r9 (design + impl, both
PASSED 2026-11-10/11) and amends its §2.5.

## 1. The problem, as it happened

REQ-r9 §2.5: the owner's `Anchor` pins `expected = counter` — the value the owner saw in a `TPM2_NV_Certify` over
their own nonce — and the seal bumps it to `counter + 1`; the daemon increments the TPM after persisting
(`Daemon::persist`, `host/signerd/src/main.rs:267-290`). That is correct whenever nothing else persists between the
owner's `tpm-certify` and the Anchor's apply. But `persist()` increments on **every** durable blob, and the header
feed persists on **every** accepted block (`main.rs:509-514`); feed and owner ops are serialised under the daemon
lock, the owner's laptop round trip is not.

2026-11-18, `sgx-node-3`, the first anchor of wallet `7180f2b6` (UTC): 16:10:57 `tpm-certify` attests 7 → 16:11:03
block 331423, 16:11:14 the feed persists → TPM 8 → 16:11:32 the Anchor applies, `expected := 7`, seal → 8, persist →
TPM 9 → 16:11:34 the feed's next `HEADERS` is refused `STATE_STALE` (blob 8, TPM 9); every Fresh op since. A
legitimate owner anchor was made to look like a rollback by the daemon's own feed. Fail-closed, 0 funds at risk
(the wallet was empty), the cost a pause and a second anchor. Not caught by `e2e-local` / `e2e-tss-local` (no live
feed during their anchors) nor by the IMPL-PASS (the auditor's own note, 2026-11-18). REQ-r9 §2 row 5 named the
effect ("spurious increment → `STATE_STALE` → owner's Anchor"), not that the daemon's feed is a source whose remedy
re-opens the same window.

Scope of the window: anchoring a **live** state (a wallet's first anchor; a re-pin while payouts run). From
`STATE_STALE` the re-anchor is race-free: the feed's refusal returns no `HeadersResponse`, so nothing persists or
increments but the anchor itself (`main.rs:517-519`; the counter sat at 9 through 40 min of refusals).

## 2. The change

The Anchor stops trusting a static snapshot and takes the **live, attested** counter at apply time, with the
owner's attested value as a lower bound.

1. **Enclave shell (`ops.rs`, `apply_message`, the `Message::Anchor` branch).** The blob is still opened with
   `open_full_stale` — the Anchor remains the attended override and must not compare against the stale blob's
   `expected`. New: it takes the deposited proof (`session::tpm_proof_take()`; none → `TPM_REQUIRED`), decodes it
   (`TPM_PARSE`), verifies it with `tpm_attest::verify_nv_certify` and the **live nonce** (`TPM_SIG` /
   `TPM_INDEX` / `TPM_NONCE` as today), and obtains `live_counter`. **Which identity the proof is verified
   against (auditor's correction, 2026-11-18):** when the state is already TPM-bound (every anchor after the
   first) the **sealed `TpmAnchor.ak_pk`/`nv_name`** — the identity bound at this enclave's first anchor, inside
   the blob the host cannot change — and the message's `ak_pk`/`nv_name` must **equal** the sealed ones, any
   difference → **`ANCHOR_TPM_MISMATCH`** (the owner builds the Anchor from a host-supplied `tpm-info`, so a host
   could otherwise hand the owner the identity of a TPM it owns plus a valid proof from it and re-point the
   anti-rollback counter to itself — caught, not trusted). Only the **first, binding anchor** (no sealed anchor
   yet) verifies against the message's values: trust-on-first-use, the labeled residual of THREAT-MODEL "TPM
   identity at anchor time". Nonce and proof are consumed whatever the verdict (REQ-r9 Q5).
2. **Core (`state.rs`, `apply_anchor(msg, boot_challenge, live_counter)`).** All existing checks (owner signature,
   enclave id, next nonce, this load's challenge, `seq_seen ≤ seq`, well-formed material). New:
   `live_counter < msg.counter` → refuse with a new reason **`ANCHOR_COUNTER_BEHIND`** (a counter only moves
   forward; a value below what the owner saw certified is a lying host or a replaced TPM). Then
   `TpmAnchor.expected = live_counter` (the seal bumps to `live_counter + 1`; the daemon increments once after
   the persist → equal). The owner's value binds the authorization to a minimum state — the fix does not weaken the
   owner's control: between the owner's certify and the apply only the daemon's own persists can move the counter,
   each a state change the enclave itself sealed.
3. **No fallback.** A missing or failing proof refuses the Anchor. REQ-r9 §2.5's "Anchor without a proof"
   (found by the rollback drill) is replaced: the Anchor still bypasses the stale blob's comparison, but demands a
   verifiable live proof. A host without a transport cannot run R9 at all; with one, `call_fresh` already deposits
   a proof for every `APPLY_MESSAGE` (`main.rs:876`), so the daemon is unchanged.
4. **Freshness table.** `APPLY_MESSAGE` stays `Fresh`; the Anchor branch verifies the deposit itself instead of
   via `open_full_fresh`. `freshness_table_is_complete` unchanged.
5. **Host.** Unchanged. The optional host-side guard (refuse an Anchor whose `counter` ≠ the live read under the
   lock, with a clear message) is **not** adopted: redundant once (a) lands, never a boundary (auditor 2026-11-18).
6. **owner-cli / operator-facing text.** Unchanged in behaviour; the printed prediction after `anchor` becomes
   "`tpm_expected` ≥ N+1". The refusal `ANCHOR_TPM_MISMATCH` must be surfaced with the sanctioned path in the
   message itself (owner-cli's reason text, the plugin page's status line), not only in the docs — so an operator
   who hits it does not retry into a wall: *"the host presented a TPM identity (key / counter Name) different from
   the one this wallet is bound to — do not retry; a replaced TPM under a living wallet means a new wallet, or a
   re-bind ceremony (REQ pending)"* (auditor's refinement, 2026-11-18).

## 3. Threat analysis (delta to REQ-r9 §2)

| Root in the VM does | Result |
|---|---|
| deposits the true live proof (counter ≥ the owner's) | applied; `expected` tracks the live counter — the race is closed to the daemon lock |
| deposits a proof with a counter below the owner's attested value | `ANCHOR_COUNTER_BEHIND` — impossible for an honest TPM (monotonic), so a lie or a replaced TPM |
| deposits a proof above the truth | cannot: the value is under the AK's signature (`TPM_SIG`) |
| replays an earlier proof | `extraData` ≠ the live nonce → `TPM_NONCE` |
| withholds the proof / the TPM | `TPM_REQUIRED` — the Anchor does not apply; the pause stays (REQ-r9 row 8) |
| hands the owner another TPM's identity through `tpm-info` and a valid proof from that TPM, on a **bound** state | `ANCHOR_TPM_MISMATCH` — the proof is verified against the sealed identity and the message must equal it (auditor 2026-11-18) |
| the same on the **first** anchor | the labeled trust-on-first-use residual, unchanged (THREAT-MODEL "TPM identity at anchor time"; hardening SHOULD: `TPM2_Certify` of our AK by the provider-certified key before pinning) |
| restores an old blob and restarts | unchanged: `STATE_STALE`; the override still needs the owner's signature over this load's challenge and the next nonce |
| substitutes the TPM before setup/anchor | unchanged residual (THREAT-MODEL "TPM identity at anchor time") |

## 4. Vectors (T0: `vectors/r9a/` + `core/tests/replay.rs`; e2e: `scripts/e2e-local.sh`, `scripts/e2e-tss-local.sh`)

1. owner attests *N*, *k* feed persists before the apply (*k* = 1, 2): live *N*+*k* → applied, `expected`
   *N*+*k*+1, the next Fresh op is accepted (no `STATE_STALE`) — the 2026-11-18 case.
2. Anchor with no deposited proof → `TPM_REQUIRED`, state unchanged.
3. deposited counter < owner's → `ANCHOR_COUNTER_BEHIND`, state unchanged, proof consumed.
4. foreign AK / wrong Name / replayed nonce / truncated attest → `TPM_SIG` / `TPM_INDEX` / `TPM_NONCE` /
   `TPM_PARSE`, Anchor refused, proof consumed; the same Anchor again → `TPM_REQUIRED`.
5. the override still works: old blob expects *N*, TPM at *N*+*k*, owner's Anchor with a live proof → applied,
   `expected` *N*+*k*+1, armed; a proven `FREEZE` then goes through.
6. all REQ-r9 vectors unchanged (replayed Anchor → `POLICY_NONCE`, `seq_seen` ahead → `ARM_SEQ_BEHIND`, …).
7. re-anchor on a bound state whose message `ak_pk`/`nv_name` ≠ the sealed ones (a valid proof from that other
   key) → `ANCHOR_TPM_MISMATCH`, state unchanged, proof consumed; the first anchor with message-carried identity →
   applied (TOFU, unchanged).
7b. **the positive case (auditor, 2026-11-18): a re-pin with the SAME identity applies clean** — a bound state that
   expects *N* while the TPM is at *N*+*k* (the 2026-11-18 picture), owner's Anchor with message identity ==
   sealed and a live proof at *N*+*k* → applied, `expected` *N*+*k*+1, armed; the next Fresh op accepted. This is
   exactly the 17:04Z re-anchor of `7180f2b6` ("already TPM-bound (expects 8); this anchor RE-PINS it"), and the
   guard must permit it as cleanly as it refuses vector 7.
8. e2e: the software transport gets a "feed persists *k* times inside the anchor window" knob; the anchor must
   apply clean. `e2e-tss-local`: the same against the laptop's PTT.

## 5. Consequences and rollout

- A new MRENCLAVE → the **ceremony** signs again (owner) → T2 redeploy as a new build → **a new wallet** on T2
  (sealing is MRENCLAVE-bound; FAQ "How do I move to a new enclave build"): the cheapest moment is **before the
  T2 wallet is funded** — `7180f2b6` holds 0 sat today. Owner cost: one init/quote/verify + mandate + anchor
  round (3× PIN + touch, one recovery passphrase), the retired record kept.
- **The TPM identity is bound for the wallet's life.** A replaced or reset TPM behind a living enclave cannot be
  re-bound by an Anchor (`ANCHOR_TPM_MISMATCH`); the path is a new wallet — or a later re-bind REQ with its own
  ceremony, if ever needed. `tpm-teardown` while a state is anchored stays forbidden (deploy/README). On Azure a
  re-placement loses the sealed state anyway (`STATE_UNSEALABLE` → new wallet → first anchor), so the constraint
  bites only an operator who recreates the objects under a living wallet.
- Until it lands: the worked example re-anchors on a repeat (race-free from `STATE_STALE`); no host-image change
  for a case (a) closes.
- Docs: DESIGN §2.5/§10 (R9 row), REQ-r9 §2 row 5 (done 2026-11-18), THREAT-MODEL row (done), FAQ EN/RU (done),
  deploy/README (done); this file gets the RESP and the impl addendum.

## 6. Questions for the auditor — answered 2026-11-18 (same day)

- Q1 reason name `ANCHOR_COUNTER_BEHIND` — **agreed**.
- Q2 the draft verified against the **message's** `ak_pk`/`nv_name` — **corrected by the auditor: SEALED.** A
  bound state verifies against the sealed `TpmAnchor` and requires message == sealed; the message's identity is
  trusted only at the first, binding anchor (§2.1, §3, vector 7, §5 consequence). Adopted in full.
- Q3 drop the proof-less Anchor (`TPM_REQUIRED` if none) — **agreed**, no proof-less fallback.
- Q4 the host-side guard (b) — **skip**, agreed.
- Q5 the mismatch reason's name `ANCHOR_TPM_MISMATCH` — **agreed, distinct**: a security-relevant verdict (the host
  handed the enclave a different TPM) must not collapse into a benign malformation; owner and logs must tell an
  attack from an error.
- Q6 the §5 consequence — the TPM identity is bound for the wallet's life — **agreed, designed, not a gap**:
  re-binding the anti-rollback root is a trust event that belongs behind a ceremony (the owner re-verifies the
  new TPM), never automatable; the only living-enclave case is an operator re-provisioning the NV objects under a
  living wallet, correctly refused. Refinement adopted in §2.6: the refusal text names the sanctioned path.
- The auditor's IMPL-PASS will check firsthand: the verification roots on the sealed `TpmAnchor` (not the
  message), the §4 break-tests fire at the intended lines, and no proof-less path survives.

## 7. Implementation (branch `r9a`, 2026-11-18) — for the auditor's IMPL-PASS

**Core (`core/`, no_std):**
- `src/tpm_attest.rs`: `certified_counter(attest, sig, ak_pk, nv_name, nonce) -> Result<u64, Reason>` — structure
  (`TPM_PARSE`), nonce (`TPM_NONCE`), index (`TPM_INDEX`), signature (`TPM_SIG`), **no value judgement**;
  `verify_nv_certify` = `certified_counter` + `counter == expected` (`STATE_STALE`). Every Fresh op is unchanged.
- `src/state.rs`: `State::anchor_identity(&self, msg)` — C1: a TPM-bound state answers the **sealed** `ak_pk`/`nv_name`
  and refuses a message naming anything else with `ANCHOR_TPM_MISMATCH`; an unbound state (first anchor) answers the
  message's (TOFU). `State::apply_anchor(&self, msg, boot_challenge, live_counter)` — the former checks (owner
  signature, enclave id, next nonce, this load's challenge, `seq_seen ≤ seq`), then `anchor_identity`, then C3:
  `live_counter < msg.counter → ANCHOR_COUNTER_BEHIND`; pins `TpmAnchor { ak_pk, nv_name, expected: live_counter }`
  (the seal bumps to `+1`). The message's `counter` is read **only** as the lower bound.
- `src/reason.rs`: `AnchorTpmMismatch` → `ANCHOR_TPM_MISMATCH`, `AnchorCounterBehind` → `ANCHOR_COUNTER_BEHIND`;
  `hint_for_code()` under `#[cfg(feature = "std")]` (host side only — the enclave carries no text) with the
  sanctioned recovery for `ANCHOR_TPM_MISMATCH`, `ANCHOR_COUNTER_BEHIND`, `STATE_STALE`, `TPM_REQUIRED`, `NOT_ARMED`.

**Enclave shell (`enclave/rcore/src/ops.rs`):**
- `apply_message`: the `Anchor` branch still opens the blob with `open_full_stale` (C5), then calls
  `anchor_live_counter(&state, &msg)`: `session::tpm_proof_take()` (none → `TPM_REQUIRED`, C4), `anchor_identity`
  (`ANCHOR_TPM_MISMATCH`, proof already consumed), a structural check of the identity (`POLICY_INVALID`), decode
  (`TPM_PARSE`), `certified_counter` against the sealed-or-first identity over the **live nonce** (C2;
  `TPM_NONCE`/`TPM_INDEX`/`TPM_SIG`), `tpm_set_last_fresh` accordingly → `apply_anchor(…, live)`. No branch reads
  `msg.counter` as a value; the REQ-r9 §2.5 proof-less path is gone. `FRESHNESS` table unchanged
  (`APPLY_MESSAGE` Fresh; comment updated).

**Host (untrusted):** `host/signerd`: the refusal JSON carries `hint` (first reason with one) and `signerd submit`/
status prints `CODE: hint` on REFUSED (C6). `owner/owner-cli`: the post-anchor prediction says "`tpm_expected`: at
least N+1". `btcpay` plugin: unchanged (it shows the daemon's `error`; the `hint` field is available to it).

**Vectors (RESP-r9a §4) — `enclave/rcore/tests/replay.rs`:**
- `anchor_pins_the_live_counter_r9a` (new): **2** proof-less first anchor → `TPM_REQUIRED`, nothing bound; **1**
  owner attests 500, two persists before the apply → applied, expects 503 == TPM, the next Fresh op accepted;
  **3** a deposit below the owner's value → `ANCHOR_COUNTER_BEHIND`, consumed (`TPM_REQUIRED` next), state
  unchanged; **4** foreign AK `TPM_SIG`, wrong Name `TPM_INDEX`, replayed nonce `TPM_NONCE`, truncated `TPM_PARSE`,
  then `TPM_REQUIRED`; **7** bound state + another TPM's identity with that TPM's valid proof →
  `ANCHOR_TPM_MISMATCH`, consumed, unchanged — and the same forged identity with the honest proof → the same
  mismatch; **5 + 7b** stale blob (expects 505, TPM 507) → `STATE_STALE`, a reload stays unarmed, the honest
  same-identity re-pin with a live proof → **applied**, expects 508 == TPM, armed, `tpm_last_fresh`, a proven
  `FREEZE` goes through; **1 again on a LIVE bound state** (k = 1, the 16:11 picture) → applied, 511 == TPM, the
  next owner op accepted.
- `tpm_counter_freshness_r9` (adapted): every Anchor now deposits (`anchor_call`); the first anchor and the
  stale-blob re-anchor are each tried proof-less first → `TPM_REQUIRED`; a malformed identity stays
  `POLICY_INVALID`; the captured old Anchor → `TPM_REQUIRED` without a proof, `POLICY_NONCE` with one.
- e2e: `scripts/e2e-local.sh` (software transport) and `scripts/e2e-tss-local.sh` (the laptop's Intel PTT) gained
  "the 2026-11-18 case": `freeze`+`unfreeze` between the owner's `tpm-certify` and `anchor` (two persists), then
  the anchor must leave `tpm_expected == TPM counter` (= attested + 2 + 1). Evidence 2026-11-18: e2e-local
  "blob expects 4 == TPM counter 4 ✓", e2e-tss "attested 57 + 2 persists in the window + 1 = expects 60 == TPM
  counter 60 ✓", handles identical before/after, teardown clean.

**Runs (2026-11-18, laptop):** `core`: fmt, clippy `-D warnings`, tests OK; `enclave/rcore` `--features nosgx,test-init`:
5/5 replay tests OK (incl. the two above), clippy OK; `host/signerd --features nosgx`: tests, clippy OK;
`owner/owner-cli`: 14 tests, clippy OK; `e2e-local: OK`; `e2e-tss-local: OK`.

**Not in this branch:** the enclave build on T1 (new MRENCLAVE), the ceremony signature, the T2 image and the new T2
wallet — owner-run, after the IMPL-PASS. The `vectors/r9a/` golden files are not produced: the R9/R9a scenarios
live in the replay test (as REQ-r9's did); say if you want them as files too.

## 8. Deployment 2026-11-19 — on T2 (owner-run; the facts recorded against the measure)

- **Build:** `main` `4dd6285` (= `873a637` + `d5e3727` + `c54d989` + docs). MRENCLAVE **`2073c234229af3986b9b5a8cd3abc844d1e808a97db14ffb46846a13257410cc`**, lfence 38638 — the rsync-tree build, a clean `git archive` build and the ceremony build agree; the auditor's decorrelated build on his own machine gave the same measurement (the deploy-content gate, PASS before anything was loaded on the node). Ceremony: `signature.hex` by the owner 13:38Z; `catsig` gates 1–4, 6, 7; MRSIGNER `56b25ccb4c1e446df1be4b308cd305b2d43e3f44745c10118bd7bad7bb2c0d41`, ProdID 1, SVN 1, DEBUG 0. T2 image: tarball sha256 `687752208c6ffa0c732039c1f09da838442553553539748864994acdc59a4822` (box id `f5ea8eb1f518`), node image id `df0b69fb2950`; in-image `enclave.signed.so` `f00c8593…`, `signerd` `4028c1d0…`, `dcap-quote-helper` `b603c4b6…`, `MANIFEST` `e86db1a9…` = the box's.
- **Wallet `735e6acd`** (T2-release, signet): xpub `tpubDChKbPA1vCvQQrykLPGSecRJGxAirLu4wYdvrkAL83HzTasa4No7ZTYYHv3fHnhje5XJE1H2pnqMvTX5XgF7yT2kKraWmMq6RcoF6gSCzxa`, enclave_id `fac66c626cf3ff0869f825d3c336b3d36b2acf8af6885a56d18bf21f9f0b8ffc`, identity `03683ec9f65b46b7d9f9851307a058fb41cee11cf643ab8558f8808b9f148f28f5`; quote over the owner's fresh nonce `3442e78c…`: 7/7 (pinned Intel root, DEBUG 0, MRENCLAVE/MRSIGNER above, card signature, report_data binding, TCB `SWHardeningNeeded` with the recorded INTEL-SA-00615 exception), quote sha256 `19281c71…`; `recovery-verify` OK offline; mandate `5559cf8a091016b9b54c4d58e5d1043fe96d85b4e3cb454fe891facb2c573e43` at nonce 0 (the 11-18 caps re-targeted; checkpoint signet 331553; `notAfterHeight` 500000); R7 drill `arm` applied (nonce 1); BTCPay store xpub + plugin token switched (`xpubMatches true`).
- **The REQ-r9a path, firsthand:** `tpm-info` counter 140 (AK/NV = the 11-17 `tpm-setup.json` objects) → owner nonce `c943d827…` → `tpm-certify` (TPMS_ATTEST 149 B, sig 64 B) → `owner-cli anchor` verified the proof (attested 140) and signed → `submit` → **applied: `tpm_bound true`, `tpm_expected 141`** (= the live counter + 1 by the seal), TPM read back 141, `tpm_last_fresh true`, nonce 2; daemon log since the submit: no refusal. **No `STATE_STALE`** — the 11-18 race (§2) does not reproduce on this build.
- **R9 drill:** restart 14:01:05Z → `boot_armed false`, `tpm_last_fresh false`, `best_height` 331559; block 331560 fed 14:18:47Z → `boot_armed true`, `tpm_expected 142`, `tpm_last_fresh true`: auto-arm without an owner. 15:03Z: armed, `best_height` 331566, `tpm_expected 148`, no refusals.
- **Retired:** `7180f2b6` (0 sat, never funded) → volume `retired-7180f2b6-20261119-135250/` (`state.sealed`, `token`), laptop record `wallet-7180f2b6-retired-2026-11-19.json`. Rollback, if ever: the previous image `c933b91baeff` is still on the node untagged (`docker tag` it back, `up`, restore the retired dir) — not needed.
- **Process defects (the dev's worked example; none in the enclave):** run 135128 halted in the read-only gate (the HTTP status is flat JSON, the CLI's `--out` file is wrapped — one shape read as the other); run 135250 halted after retiring the state and re-creating the sidecar, before `init`, on an assertion of `mrenclave` against the pre-init status (null until `init`). The resume script re-checked the exact interrupted picture read-only (sidecar on `df0b69fb2950`, uninitialised, retired dir present, no live `state.sealed`, nonce + pubs on the node) before `init`, asserted the measurement after `init`, and refused a later accidental re-run (`init-response-<stamp>.json` already present). Lessons 6–10 in deploy/README.
- Evidence (laptop, gitignored): `.local/signet-t2/r9a-deploy-20261119-135250{,-resume}.log`, `exchange/{quote,status,init-response,status-installed,status-armed,tpm-info,anchor-proof,status-anchored,tpm-info-anchored,status-r9-boot,status-r9-drill}-20261119-135250.json`. Reported to the auditor 2026-11-19 ~15:05Z (cross-session message, the identity card above).
