# REQ-r9 — the TPM counter as the enclave's freshness source (DESIGN) — 2026-11-10

**Round:** R9, design. **Asked of the auditor:** DESIGN-PASS before any `core/` or `enclave/` code
(hard rule 1). **Skeleton:** the auditor's pre-review of 2026-11-05, recorded verbatim in
`docs/studies/FRESHNESS-SOURCES-2026-11-05.md` §6; this REQ answers its three edges and four
questions and adds the sharp points found while writing it. **Owner decisions this rests on
(2026-11-05):** the cloud provider is an accepted residual (THREAT-MODEL V7); the control coin is not
pursued; R7 (owner arms every restart) stays the product on today's hardware; R9 is the next round.

## 1. The problem, as the attacker states it

"I am root in the VM. The enclave keeps its state in a sealed file I can copy and put back. R7 made
every restart wait for the owner's key, so I cannot spend, restore, restart and spend again while
the owner sleeps — unless the owner is willing to be woken for every reboot. The day the operator
wants unattended restarts, they must either build the opt-out enclave (then I replay the window's
budget at will) or give the enclave something that knows *now* from *then*." The study proved there
are exactly three such things: the owner's signature (R7), consensus work (the coin, dropped), or a
live hardware counter. R9 is the third: a TPM 2.0 monotonic counter the enclave can interrogate
through a signature it can verify, so that a restored old state is recognised as old without anyone
present.

## 2. The rule

**Anchor.** The sealed state carries an optional `TpmAnchor { ak_pk: P-256, nv_name: TPM2B_NAME,
expected: u64 }`. It is set attended — at `init`, or later by an owner-signed `Anchor` message
(§2.5) — after the owner has verified, **on the laptop**, that `ak_pk` is an attestation key of the
TPM they mean (vTPM: the endorsement chain to the provider's CA; physical TPM: the manufacturer's EK
certificate). The enclave never parses a certificate; its contract is "a P-256 signature from the
pinned AK over my nonce", the same contract as the owner key (R6b ruling). `nv_name` is the Name of an
NV index defined with `TPMA_NV_COUNTER`: the TPM itself enforces that the value only ever grows,
whoever holds the increment authorization. Without an anchor the enclave behaves exactly as R7
(`tpm_bound: false`); with one, every rule below applies (`tpm_bound: true`).

**Nonce.** Before a blob-reading ecall the host asks the enclave for a `tpm_nonce`: 32 bytes from
in-enclave `RDRAND`, held volatile, single-use, consumed by the next blob-reading ecall. The nonce
**must** be unpredictable per call, not derived from the session: with a predictable sequence an
attacker at counter *N* could pre-generate `certify(nonce_k)` for future *k*, spend (counter → *N*+1),
put the old blob back **without restarting** (the volatile session survives) and answer call *k* with
the pre-generated proof of *N* — a rollback inside one session. Random per-call nonces close it.

**Verify on every read.** Every ecall that reads the sealed blob — `JUDGE`, `SIGN`, `APPLY_MESSAGE`,
`HEADERS`, `INSTALL`, `UNFREEZE`, `ARM` and the rest — receives alongside the blob a *certify proof*:
the `TPMS_ATTEST` bytes of a `TPM2_NV_Certify` over the pinned index with the nonce as qualifying
data, and the `TPMT_SIGNATURE` over them. The enclave, in pure code (`signer-core`, bytes in →
verdict out): (1) verifies the ECDSA P-256 signature under `ak_pk` over SHA-256 of the attest bytes;
(2) reads the attest with a strict fixed-layout, bounds-checked reader and pins `magic ==
TPM_GENERATED (0xFF544347)`, `type == TPM_ST_ATTEST_NV (0x8014)`, `extraData == nonce`,
`attested.nv.indexName == nv_name`, `offset == 0`, `nvContents` = 8 bytes big-endian = *counter*;
(3) requires `counter == expected`. Anything else refuses the ecall: `TPM_SIG`, `TPM_PARSE`,
`TPM_NONCE`, `TPM_INDEX`, or **`STATE_STALE`** when only the value differs. No allocation, no
unbounded loop, no panic path.

**Bump on every write.** Every ecall that writes a new sealed blob stores `expected + 1` in it, and
the host must `TPM2_NV_Increment` the index before the next call. Order: seal first, increment
second. A crash between the two leaves the blob at *N*+1 and the counter at *N*: the next call is
`STATE_STALE` — the enclave does not know whether it sees a crash or a rollback and treats both the
same — and the owner resolves it (§2.5). The split the auditor named: the **`JUDGE`** seal charges the
window and bumps; **`SIGN`** is read-only against the charged state and only verifies (re-emitting
the same signature is the same transaction).

**Load.** The first blob-reading ecall after a load verifies like any other. If the proof is fresh
(`counter == expected`), the enclave sets its volatile `ARMED` itself: an **unattended restart with
the bound kept** — that is the whole point of R9. If it is stale or absent, the enclave stays
`NOT_ARMED` / refuses `STATE_STALE` until the owner acts. R7 is not removed, it is given a second
way to be satisfied.

### 2.5 The owner's override: `Anchor`

`Message::Anchor { enclave_id, nonce, boot_challenge, ak_pk, nv_name, counter, seq_seen }`,
domain `tee-signer/anchor/v1`, tag 9, signed by the owner key, consumed like `Arm`: `POLICY_SIG` /
`POLICY_NONCE` on a wrong key or nonce, `ARM_CHALLENGE` when `boot_challenge` is not this load's,
`ARM_SEQ_BEHIND` when `seq_seen > s.seq` (the rollback signature; owner-cli refuses to sign it
without `--i-have-investigated`, logged, exactly as `Arm`). On success the enclave sets the anchor
(`ak_pk`, `nv_name`, `expected := counter`), bumps once (the seal), and arms. It is the one path that
moves `expected` other than `+1`, and it needs the owner's key and presence: first anchoring at
deployment, a TPM that was lost or reset (vTPM migration), a crash between seal and increment, a
deliberate move to another TPM — and the attended fallback for every mismatch. Because the nonce is
the owner-message nonce, a captured old `Anchor` (naming a stale index or value) is refused after a
rollback, like every other owner message. `Arm` (tag 8) stays for `tpm_bound: false`.

### 2.6 Pure reads

`STATUS` and `REPORT` read the blob without a proof (the host must be able to report a stale or
unanchored state, and the quote nonce is already the owner's). Their output carries
`tpm: { bound, expected, last_verified_fresh: bool }` and the docs label them *possibly stale*; no
freshness decision is ever made from them. `REPORT` binds the card, not the counter.

## 3. Attacker scenarios against the rule

| # | Root in the VM does | Result |
|---|---|---|
| 1 | restores an old sealed blob (expected *N*) after the enclave sealed *N*+*k*, restarts | the TPM certifies *N*+*k* ≠ *N* → `STATE_STALE`; nothing signs; the owner sees it in `status` and decides |
| 2 | same, but presents a `certify` captured when the counter was *N* | `extraData` ≠ this call's nonce → `TPM_NONCE` |
| 3 | runs a software TPM, or another machine's TPM, that will certify *N* | signature not under `ak_pk` → `TPM_SIG` |
| 4 | decrements the counter | impossible: `TPMA_NV_COUNTER` indices only increment, for every authorization |
| 5 | increments the counter spuriously | the blob expects *N*, the TPM says *N*+1 → `STATE_STALE`; a denial of service against the operator's own payouts, resolved by the owner's `Anchor`; never a replay |
| 6 | copies the just-loaded fresh blob, spends, puts the copy back (the per-load trap) | the spend's `JUDGE` seal bumped to *N*+1; the copy expects *N* → stale at the next call. Per-write bumping is what makes the copy old |
| 7 | pre-generates proofs for future nonces | nonces are random per call (§2) |
| 8 | withholds the proof or the TPM | the enclave refuses every blob-reading ecall (`TPM_REQUIRED`); payouts pause like `FROZEN`; the status page says so; owner's `Anchor`/`Arm` when the TPM is back |
| 9 | crashes the host between seal and increment | indistinguishable from 1 by design → `STATE_STALE` → owner's `Anchor` (no loss, no brick: the recovery key also still works) |
| 10 | is the hypervisor / the cloud provider — *or anyone with control-plane rights over the VM's disks and vTPM state (VMGS): a subscription Contributor, a service principal* (wording widened 2026-11-17) | owns the vTPM or can restore its state together with the OS disk: a consistent rollback passes the comparison. **Out of scope by the owner's decision (V7)**; the bound reverts to the hot float, same as without a counter; R7's attended `arm` bounds this adversary better than R9's auto-arm |
| 11 *(added 2026-11-17; auditor: labeled residual, remedy a SHOULD — impl §10)* | substitutes the TPM **before** `tpm-setup`/`anchor` (a software TPM behind `/dev/tpmrm0`, another machine's TPM over the device path) | the owner pins the substitute's AK — trust-on-first-use. Scenario 3 only catches a substitution *after* the pin. The manual endorsement check of §2 reads a certificate through the same device path and does not bind *our* AK; on Azure Trusted Launch there is reportedly no EK certificate (Azure AK certificate at NV `0x01C101D0`, key `0x81000003`). Remedy: `TPM2_Certify` of our AK by the provider-certified key, verified on the laptop against the provider's root, before pinning — hardening, a SHOULD (auditor 2026-11-17: custody does not lean on the TPM identity, so it cannot be a software gate); THREAT-MODEL §5 row "TPM identity at anchor time" |
| 12 *(added 2026-11-17; auditor: correct, not an attack)* | the VM is re-placed on another physical host (deallocate/start, a security-type change, provider maintenance) | not an attack: the sealed blob is CPU-bound and refuses `STATE_UNSEALABLE`; the seed is gone with it, recovery = the recovery blob, new wallet (CONTINUITY §1, 2026-11-17) |

What R9 does not change: the mandate is still the shape bound; the window cap is still the ceiling
per window; the seed never leaves; a BTCPay admin still gets at most the window's unlisted budget.

## 4. What this is not

- **Not provider-proof.** The claim, time-stable wherever it is made: *"counter-backed bound holds
  against root inside the VM; against the cloud provider it reverts to the hot float, same as no
  counter."* The physical TPM on the operator's own FLC server removes the provider from the picture;
  Azure Trusted Launch gives a vTPM owned by the provider. The project's node `sgx-node-3` has **no**
  TPM today; the product claim is deployment-gated until a TPM is in front of the enclave.
- **Not a replacement for R7.** Additive only: R9 *adds* unattended restarts when the counter
  matches; it never subtracts the owner's ability to arm or anchor, and a lost TPM degrades to
  attended R7, never to "bricked".
- **Not a clock.** The counter orders the enclave's own writes; the block clock still runs windows.
- **Not the control coin.** No SPV, no serialization of payouts, no chain fees.
- **No X.509 in the TCB.** Endorsement chains are verified on the laptop; the enclave pins one P-256
  key and one Name.
- **The dev stand-in's liveness is not the product's.** Development runs against the owner's laptop
  TPM through a reverse ssh tunnel (laptop → server) and a two-operation agent on laptop loopback
  (`certify`, `increment`): the laptop must then be reachable at every seal, i.e. every payout. That
  is a protocol test bench (verify, counter logic, the vectors), not a deployment, and no product
  decision is taken from its pain. The product TPM is local to the server; the transport is a
  host-side swap, **but the sealed state must carry the production TPM's AK** — moving dev → product
  is an owner `Anchor` (or re-init), not a configuration change.

## 5. Changes (for the IMPL REQ; each a line here so the auditor can gate it)

`core/` (pure, `no_std`, no new crate — P-256 and SHA-256 are already in the TCB for owner signatures and receipts):
1. `tpm_attest.rs`: `verify_nv_certify(attest, sig, ak_pk, nv_name, nonce) -> Result<u64, Reason>` — the fixed-layout reader and the signature check; mutation-tested (truncated, overlong, wrong magic/type, wrong Name, foreign nonce, non-AK signature, offset ≠ 0, nvContents ≠ 8 bytes).
2. `State.tpm: Option<TpmAnchor>`; `expected` bumped in every state-producing path (one place: the seal helper, so no path can forget — the C-R7-4 lesson).
3. `Message::Anchor` (tag 9, domain `tee-signer/anchor/v1`), `apply_anchor` with the `Arm` checks plus the anchor set.
4. Reasons: `TPM_REQUIRED`, `TPM_SIG`, `TPM_PARSE`, `TPM_NONCE`, `TPM_INDEX`, `STATE_STALE`.
5. `proto`: ecall inputs gain the optional proof; `StatusResponse.tpm { bound, expected, last_verified_fresh }`.

`enclave/rcore`:
6. `TPM_NONCE` ecall (volatile, RDRAND, single-use); every blob-reading ecall verifies when `tpm_bound`; auto-arm on a fresh proof at the first read after load; `Anchor` routed like `Arm`.

`host/signerd` (untrusted):
7. `TpmTransport` trait `{ nonce → certify(nonce) → (attest, sig); increment(); read() }` with three implementations: `software` (T0 tests: a P-256 key and a counter in a file, including a *lying* variant for the vectors), `remote` (dev: HTTP to the laptop agent over the reverse tunnel), `tss` (product: `/dev/tpmrm0` through `tss-esapi` — later, when a TPM exists in front of a node).
8. The agent `tee-tpm-agent` (laptop, loopback only): creates its own AK under a fresh persistent handle and its own NV counter index — never the owner key's `0x81000100`, never the other projects' handles (`0x81000001/2/9`, `0x81010010/12`); prints the AK public key and the index Name for the owner's `anchor`.

`owner/owner-cli`:
9. `tpm-anchor-prepare` (laptop: verify the EK chain of the TPM in question with the system tooling, print `ak_pk` and `nv_name`), `anchor --key …` (the owner message; reads the live counter from the server's status file), `init --tpm-ak-file --tpm-nv-name-file --tpm-counter` (anchor at init). Docs: FAQ "unattended restarts with a TPM" (both languages), DESIGN §3/§6, THREAT-MODEL rows, POLICY reasons, CONTINUITY (TPM lost).

Vectors (`vectors/r9/`, T0): counter not advanced after a seal → `STATE_STALE`; old blob with a higher live counter → `STATE_STALE`; replayed proof → `TPM_NONCE`; foreign AK → `TPM_SIG`; wrong Name → `TPM_INDEX`; each parser mutation → `TPM_PARSE`; fresh proof after load → armed without the owner; `Anchor` with a stale nonce → `POLICY_NONCE`; `Anchor` with `seq_seen > seq` → `ARM_SEQ_BEHIND`.

## 6. Honest label after this round (what the docs will say)

"With a TPM in front of the enclave, a restart no longer waits for the owner: the enclave checks
the TPM's counter against the value it sealed last, and signs only if they agree. Root inside the
server cannot turn that counter back or forge the TPM's signature; it can only stop payouts. The
counter-backed bound holds against root inside the VM; against the cloud provider, who owns a
virtual TPM, it reverts to the hot float — the same as without a counter. On the operator's own
server with a physical TPM there is no provider. Today the project's node has no TPM; the feature is
developed against the owner's laptop TPM and labeled T0/T2-dev until a node with one exists."

## 7. Questions for the auditor

1. **Header-only seals.** Uniform bumping (every seal) is the simplest invariant, but a physical
   TPM's NV has finite endurance (vendors quote 10⁵–10⁶ writes); signet's 144 blocks/day plus payouts
   give ~10⁵ bumps in about two years. The standard remedy is a *hybrid* counter (`TPMA_NV_ORDERLY`:
   the count lives in RAM and reaches NV at orderly shutdown or at boundaries; an unorderly shutdown
   makes the counter jump **forward**, never back → a `STATE_STALE` the owner resolves once). I
   propose: uniform bumping **and** an orderly/hybrid index as the allocation default. Alternative
   for your ruling: `HEADERS` verifies but does not bump, with the argument that only budget-moving
   seals (`JUDGE`, owner messages) create states worth rolling back to — I prefer not to carry that
   argument; do you?
2. **`Anchor` vs `Arm`.** Two owner messages (tag 8 for `tpm_bound: false`, tag 9 for `true`), or
   fold: `Arm` with an optional anchor payload? I propose two: an `Arm` must never silently change
   the pinned TPM.
3. **Pure reads (§2.6).** `STATUS`/`REPORT` without a proof, labeled possibly-stale — acceptable?
   The alternative (a proof on `STATUS` too) makes the status page itself fail while the TPM is down,
   which is the moment the operator most needs it.
4. **Auto-arm on a fresh proof at load** as the defined behaviour in `tpm_bound` mode (R7's pause
   satisfied by the counter instead of the owner) — confirm this is the intended reading of your
   pre-review's "unattended restarts with the bound kept".
5. **Nonce transport.** One extra ecall per blob-reading call (`TPM_NONCE` → TPM → the call). Any
   objection to the enclave also accepting the nonce it issued for the *previous* call if that call
   never happened (host crash between nonce and call), to avoid a nonce leak that pauses payouts?
   My inclination: no — a nonce is consumed by issue, the host simply asks again.
6. **Dev stand-in scope.** The laptop agent exposes `increment` to the server over the tunnel. The
   auditor's pre-review already judged that a liveness DoS at worst; confirm nothing else is needed
   on the agent (e.g. it does not need to authenticate the server) for the dev bench.
