# Threat model

**Status:** draft for the first audit round (2026-11-03). Nothing here is enforced by code yet.

## 1. Assets

| Asset | Where it lives | Loss means |
|---|---|---|
| **A1 — the wallet seed** (BIP39 → BIP32 master) | inside the enclave, sealed at rest | total loss of the hot wallet, forever |
| **A2 — signing authority** (the ability to obtain a valid signature) | the enclave's ecall surface, reachable through `signerd` | loss bounded by the mandate |
| **A3 — the mandate** (policy + the owner's public key + nonce) | sealed state, installed by owner signature | an attacker who can change it owns A2 |
| **A4 — the owner key** | the merchant's separate device (YubiKey / TPM / Secure Enclave / phone) | attacker can rewrite the mandate (after the timelock) |
| **A5 — the recovery blob** (seed encrypted to the recovery key) and **the recovery key** | offline, merchant's custody | blob + key together = A1 |
| **A6 — budget/sequence state** (window usage, sequence, last header) | sealed state | rollback = one extra budget window |

## 2. Adversaries

| Id | Adversary | Capabilities | Tier that excludes them |
|---|---|---|---|
| **V1 — BTCPay admin** | the November 2026 attacker: valid admin credentials, full BTCPay UI/API, can upload plugins (= code execution inside the BTCPay process/container) | T1, T2 |
| **V2 — non-root host user / container escapee** | arbitrary code on the host as an unprivileged user; can talk to `signerd`; can read any file that user can read; **cannot** `ptrace` `signerd` (`kernel.yama.ptrace_scope ≥ 2`) | T1, T2 |
| **V3 — host root** | everything on the host: can read a *debug* enclave's memory through the SGX debug interface, can roll sealed state back, can replace binaries, can withhold or replay anything | **T2 only** |
| **V4 — the host's time and chain view** | V2 or V3 can set the host clock arbitrarily and feed any block headers they can obtain or mine | T1, T2 (windows run on PoW time) |
| **V5 — owner-key thief** | holds the owner device or extracted its key, not the recovery key | partially: the timelock + the owner's cancel; fully only by the owner rotating to the recovery key in time |
| **V6 — physical / Intel-level** | CPU vulnerabilities, microcode TCB, side channels, decapping | out of scope at every tier; stated, not mitigated |

The attack that motivates the project is **V1**. V1 is excluded at every TEE tier. V3 is the
classic SGX adversary and is excluded only at T2, and that is said on every label.

## 3. What each adversary can and cannot do

### V1 / V2 — application-level compromise (the November 2026 class)

Can: request any signature through the API, as many times as they like; read everything
BTCPay can read (invoices, the watch-only xpub, the policy as installed — it is public); freeze the
signer (harmless, fail-closed); submit a policy update with an **invalid** owner signature
(refused); submit a **replayed** owner-signed policy (refused: nonce); submit a replayed valid
*loosening* policy from the past (refused: nonce strictly increases).

Cannot: read the seed; sign to an unlisted destination above `unlisted.maxPerTx` or beyond
`unlisted.maxPerWindow`; sign to any destination above `limits.maxPerTx`; move more than
`limits.window.maxOutflow` per 144 blocks in total; sign a fee above the bounds; sign with any
sighash but `ALL`; make the enclave sign a *foreign* input; make change go to a key that is not
the wallet's; reset the window by moving the clock (windows are block-counted); change the
mandate.

**Bound:** the loss an application-level attacker can cause between the compromise and the owner's
freeze is ≤ `limits.window.maxOutflow` per 144 blocks, of which unlisted destinations get at most
`unlisted.maxPerWindow`; trusted destinations are the merchant's own cold storage, so outflow
there is not a loss. With a typical merchant mandate (unlisted: 0.01 BTC/tx, 0.05 BTC/day;
trusted: cold descriptor only) the attacker's take is 0.05 BTC/day instead of the whole wallet.

### V3 — host root

T1: can attach a debugger to the debug enclave (`EDBGRD`/`EDBGWR`) and so read the seed **and**
alter the mandate enforcement in memory — **T1 claims nothing against root, neither for the seed
nor for the policy** (auditor, RESP-prequestions Q1). What T1 does claim, and what the November
2026 incident needed: the seed is no longer a file or a database row the application can read,
and the application cannot sign outside the mandate.
T2: cannot read the seed or the state; can still: roll sealed state back (bound: one extra budget
window per rollback, and the receipt sequence exposes it); withhold headers (DoS: windows never
advance, so the current window's remaining budget is all that can ever be spent); withhold or
delay owner updates (DoS); replace `signerd` (changes nothing the enclave trusts); kill the service
(DoS). DoS is a loss of availability, never of funds — the merchant's funds sit in a watch-only
wallet that can be recovered from the recovery blob.

### V4 — clock and chain

The enclave has **no trusted time** (SGX1 has no trusted-time service; SGX2 platforms' is
deprecated). Therefore:
- **budget windows are measured in blocks** on a header chain the enclave verifies from an
  owner-pinned checkpoint (SHA256d, prev-hash linkage, target/retarget rule, cumulative work). To
  reset a window the attacker must present 144 blocks of valid proof-of-work. On mainnet that is
  the network's hash rate; on signet/testnet it is cheap, and the testnet label says so.
- **validity dates** (`validity.notAfter`, the timelock's activation height) are also in block
  height, not wall time.
- Host wall time is used for **nothing** that affects a signature. It may be logged.
- The header feed can be **withheld** (DoS) but not **forged**; a fork with less work than the
  known best is ignored; a reorg deeper than `limits.maxReorg` freezes the signer until the owner
  re-pins.

### V5 — owner-key thief

Can: submit a valid loosening policy. It becomes **pending** for `timelock` blocks (owner-chosen,
e.g. 144); `signerd` and the receipts announce it; the legitimate owner cancels it with the
recovery key or the owner key (either suffices to cancel — cancel is fail-closed), and rotates
the owner key to a new device with the recovery key. A tightening policy applies immediately —
a thief tightening the mandate is a DoS, not a theft.

Cannot: shorten the timelock without waiting the current timelock; apply a loosening change
before the timelock; sign transactions (the owner key never signs transactions).

### V6 — out of scope

Side channels against the enclave's secp256k1 (constant-time implementation is required and
stated; it is not a proof of side-channel freedom), microcode, physical attacks, Intel. Listed so
that no label implies otherwise.

## 4. Invariants the enclave enforces (the "backing question")

For every signature the enclave produces there is an enclave-enforced chain of facts tying it to
the mandate. "`signerd` checked it" or "BTCPay only sends valid PSBTs" is never backing.

| # | Invariant | Enforced by |
|---|---|---|
| I1 | Every signed input is the wallet's own: its `scriptPubKey` equals the one derived in-enclave from the sealed master key at the PSBT's claimed path, and the path is under the wallet's account | derivation in-enclave, match, refuse otherwise |
| I2 | Every input's amount is the one in the **full previous transaction** whose txid equals the outpoint's txid | `non_witness_utxo` required for every own input; txid recomputed in-enclave; `witness_utxo` alone is refused |
| I3 | An output is *own* only if its `scriptPubKey` equals an in-enclave derivation under the wallet's account on branch 0 or 1 at an index within the sealed bound | derivation + match; host `bip32_derivation` on outputs is a hint, never a decision |
| I4 | An output is *trusted* only if it matches an address or descriptor-derived address of the installed mandate within that descriptor's gap limit | derivation from the mandate's xpub in-enclave |
| I5 | Net outflow = Σ own inputs − Σ own outputs; it is ≤ `limits.maxPerTx` and, added to the current window's usage, ≤ `limits.window.maxOutflow`; per-class caps likewise | arithmetic in-enclave, checked overflow, state updated **before** the signature is released (sign-then-commit is refused by construction: commit, seal, then sign) |
| I6 | Fee = Σ all inputs − Σ all outputs ≤ `limits.maxFeeAbs` and ≤ `limits.maxFeeRate` × estimated vsize (upper-bound estimate) | arithmetic in-enclave |
| I7 | Only `SIGHASH_ALL`; transaction version 1 or 2; no unknown PSBT fields that change meaning; script types limited to those the mandate names | parser refuses the rest |
| I8 | Payjoin: foreign inputs are never signed, and the transaction is accepted only if net outflow ≤ 0 (the merchant receives) or the foreign-input case is explicitly allowed by the mandate with the same outflow rules | classification + rule |
| I9 | The mandate in force is the latest one whose owner signature verified against the sealed owner public key with nonce = previous + 1 and whose activation height has passed | signature verify in-enclave (P-256 ECDSA), sealed nonce |
| I10 | Budget windows advance only with verified headers; no header, no window | header chain verifier in-enclave |
| I11 | Every signature is preceded by sealing the updated state and followed by a receipt carrying a strictly increasing sequence number | state machine order |
| I12 | The seed is generated from in-enclave RDRAND and leaves the enclave only inside the recovery blob encrypted to the installed recovery public key at initialisation | no ecall returns it or a function of it except the blob, once |

## 5. Residual risks, stated

| Risk | Tier | Bound / mitigation | Status |
|---|---|---|---|
| Debug enclave readable by root | T1 | none — labeled | by design of the hardware |
| No attestation on T1 | T1 | label (auditor Q2): *"no remote attestation on this tier (EPID retired, DCAP needs newer hardware); enclave identity is trust-on-first-use pinned by MRENCLAVE sealing; you verify your wallet xpub at setup on your own device; this detects enclave code changes after setup but does not prove genuineness at first setup the way DCAP does."* Setup emits a signed **identity card** (MRENCLAVE ‖ xpub ‖ fingerprint ‖ identity pubkey) the owner stores; a swapped enclave cannot unseal the seed, so the xpub changes and the owner notices | labeled |
| State rollback | T1, T2 | with a **freshness witness** configured (`POLICY.md` `freshness.required`): a rolled-back enclave refuses to sign until the owner intervenes — loss becomes a liveness pause. Without one: ≤ one budget window per rollback, detectable via receipt sequence, owner alert (auditor Q3: acceptable, labeled, interim) | ruled 2026-11-03 |
| Header withholding / stale chain | all | DoS only; the current window's remaining budget is the cap | by design |
| Signet/testnet PoW is cheap | testnet | the block clock is only as strong as the chain's work; mainnet label differs | labeled |
| Owner device lost | all | recovery key rotates the owner; recovery blob restores funds elsewhere | design |
| Owner signs blind | all | a YubiKey has no display: what it signs is what `owner-cli` on the owner's machine shows (WYSIWYS rests on that machine). Residual carried from the perp gov-key ruling; a device with its own display (phone owner app, hardware wallet message signing) removes it | labeled |
| Freshness witness key compromised | all | the witness can only pause signing or hide a rollback; it cannot loosen the mandate or sign | labeled |
| Recovery key + blob stolen together | all | = seed theft; custody guidance | labeled |
| RBF counted twice toward the budget | all | conservative (over-counts); v2 may recognise replacements | labeled |
| secp256k1 side channels | T2 | constant-time library; no claim beyond that | labeled |
| Enclave bugs (parser, arithmetic) | all | pure-module tests + negative vectors + audit | the project's own job |
