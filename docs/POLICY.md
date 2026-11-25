# The mandate (policy) — field by field

**Status:** draft v1 for the first audit round (2026-11-03). The JSON below is the owner-side
representation; the enclave sees only the **canonical binary encoding** produced by `signer-core`
(`Mandate::to_canonical`), and the owner signs that encoding. Unknown fields are an error on both
sides (a misspelled cap must never become "unlimited"). Amounts are satoshis as unsigned integers;
heights are block heights; there are no wall-clock fields.

## 1. The one rule: the file is intent, the sealed state is law

Editing a mandate file changes nothing. The enclave enforces only the mandate that was installed by
an owner-signed `PolicyUpdate` with the next nonce (`DESIGN.md §6`). `owner-cli policy show`
prints, field by field, the installed mandate next to a file, marking every `DIFF` — the same habit
as TPM_sign's `permission show`.

## 2. Example — a merchant with daily sweeps to cold storage and small customer payouts

```json
{
  "version": 1,
  "network": "signet",
  "wallet": {
    "fingerprint": "d34db33f",
    "account": "84'/1'/0'",
    "scriptTypes": ["p2wpkh"]
  },
  "destinations": {
    "trusted": [
      { "label": "cold", "descriptor": "wpkh([aabbccdd/84'/1'/0']tpub.../0/*)", "gap": 20,
        "maxPerTx": 100000000, "maxPerWindow": 500000000 },
      { "label": "exchange-deposit", "address": "tb1q...",
        "maxPerTx": 20000000, "maxPerWindow": 50000000 }
    ],
    "unlisted": { "maxPerTx": 1000000, "maxPerWindow": 5000000 }
  },
  "limits": {
    "maxPerTx": 100000000,
    "window": { "blocks": 144, "maxOutflow": 500000000 },
    "maxFeeAbs": 100000,
    "maxFeeRate": 100,
    "maxInputs": 64,
    "maxOutputs": 32,
    "ownIndexGap": 100,
    "maxReorg": 6
  },
  "rules": {
    "sighash": "ALL",
    "payjoin": "inflow-only",
    "opReturn": "none",
    "rbf": true
  },
  "chain": { "checkpoint": { "hash": "0000...", "height": 250000 } },
  "freshness": { "required": true, "witnessPubKey": "04...", "maxTipLag": 6 },
  "validity": { "notAfterHeight": 300000 },
  "timelockBlocks": 144
}
```

## 3. Fields

### Top level

| Field | Required | Type | Meaning |
|---|---|---|---|
| `version` | yes | `1` | encoding version; anything else is refused |
| `network` | yes | `mainnet` \| `testnet4` \| `signet` \| `regtest` | selects chain parameters and the address encoding; must equal the network sealed at init |
| `wallet` | yes | object | the wallet this mandate governs; must equal the sealed wallet |
| `destinations` | yes | object | destination classes and their caps |
| `limits` | yes | object | transaction-wide bounds |
| `rules` | yes | object | structural rules |
| `chain` | yes | object | the header-chain checkpoint |
| `freshness` | yes | object | the freshness-witness precondition (`DESIGN.md §3`) |
| `validity` | yes | object | when the mandate stops working |
| `timelockBlocks` | yes | u32, 1 … 52 560 (≈ one year; REQ-r10-F02) | how long a loosening update waits before activation; a larger value is refused at install — it would make every later loosening and rotation unqueueable |

### `wallet`

| Field | Type | Meaning |
|---|---|---|
| `fingerprint` | 4 bytes hex | master fingerprint, as returned at init |
| `account` | path | account derivation; v1 accepts `84'/coin'/n'` only |
| `scriptTypes` | list | v1: `["p2wpkh"]`; `p2tr` is a later REQ. An input or own output of another type is refused |

### `destinations`

A **trusted** entry is matched by `address` (exact `scriptPubKey`) or by `descriptor` (v1: `wpkh(KEY/0/*)`
and `wpkh(KEY/1/*)`, `tr(KEY/…)` later; `KEY` an xpub with origin). Descriptor matching derives
indices `0..gap` from the descriptor's xpub in-enclave and compares scripts; `gap` ≤ 1000. **Cost:** a descriptor
entry is `2 × gap` key derivations per classification (both branches), and a signing classifies twice (judge, then
sign); at the bounds — 64 entries × `gap` 1000 — a signing took 12.2 s with 2 outputs and 18.1 s with 500 outputs on the
project's T2 node (2026-11-25, `deploy/README.md`) and the daemon answered nothing else meanwhile. Larger transactions
cost more — the upper figure is a 500-output transaction; the trusted-list size is the dominant lever, the transaction's
output count the secondary one. An `address` entry costs nothing; size `gap` and the list to what you need. Each
trusted entry has its own `maxPerTx` and `maxPerWindow`. A `trusted` output counts toward the entry's
caps **and** toward `limits.window.maxOutflow`.

`unlisted` is every output that is neither own nor trusted. `maxPerTx` bounds the **sum** of unlisted
outputs in one transaction; `maxPerWindow` their sum over the window. Set both to `0` to refuse
unlisted destinations entirely (a sweep-only wallet).

**The fee is inside the net outflow (auditor R5, load-bearing).** Net outflow = Σ own inputs −
Σ own outputs = Σ non-own outputs **+ fee**. Every class — trusted included — counts toward
`limits.window.maxOutflow`. So the amount an attacker can burn in fees per window is bounded by
`window.maxOutflow`, **not** by `maxFeeAbs` (which bounds one transaction only). Named residual,
bounded and detectable, V1-level: an attacker may (i) burn up to about `window.maxOutflow` per
window in fees while every payment lands in the merchant's own cold storage, and (ii) exhaust the
window budget so legitimate payouts wait for the next window. The optional `limits.maxFeePerWindow`
caps the fee burn below the outflow budget.

### `limits`

| Field | Meaning |
|---|---|
| `maxPerTx` | upper bound on **net outflow** (Σ own inputs − Σ own outputs) of one transaction, any class |
| `window.blocks` | window length; v1 fixes the semantic as *fixed windows starting at `window.start_height`*, rolled forward by whole windows when `best_height − start ≥ blocks` |
| `window.maxOutflow` | upper bound on the sum of net outflows in a window |
| `maxFeeAbs` | fee = Σ all inputs − Σ all outputs, absolute bound **per transaction** |
| `maxFeePerWindow` | optional; sum of fees over the window. Absent = bounded only by `window.maxOutflow` (fee ∈ net outflow, see `destinations`) |
| `maxFeeRate` | sat/vB against a **lower-bound** vsize computed in-enclave from the input/output types (own P2WPKH exact, foreign inputs at P2TR key-path size, shortest DER signatures). Lower bound is the conservative direction: the computed rate is never below the real one, so the check can only refuse more. Liveness note (auditor): a fair fee on a transaction larger than the estimate can be over-refused; set `maxFeeRate` with that in mind, `maxFeeAbs` is the hard backstop |
| `maxInputs`, `maxOutputs` | sizes the fixed enclave heap; refuse above |
| `ownIndexGap` | an own output may use an index up to `own_index_bound + gap` on its branch; using it raises the bound |
| `maxReorg` | a reorg deeper than this freezes the signer until the owner re-pins the checkpoint |

### `rules`

| Field | Values | Meaning |
|---|---|---|
| `sighash` | `ALL` | v1 accepts only `ALL`; a PSBT `sighash_type` of anything else, or absent-with-default on a non-ALL flag, is refused |
| `payjoin` | `none` \| `inflow-only` \| `outflow-allowed` | `none`: any foreign input refuses. `inflow-only`: foreign inputs allowed only when net outflow ≤ 0 (the merchant receives; the usual payjoin receiver case). `outflow-allowed`: foreign inputs allowed and net outflow judged by the same caps as a normal spend |
| `opReturn` | `none` \| `zero-value` | whether a zero-value `OP_RETURN` output is tolerated (it counts as unlisted with amount 0 and does not count toward caps). Explicit rule (auditor R4c): an `OP_RETURN` with non-zero value, or any `OP_RETURN` under `none`, refuses |
| `rbf` | bool | whether `nSequence < 0xfffffffe` is accepted; a replacement is a new transaction and is charged again (conservative) |

### `chain`

`checkpoint.{hash, height, time, bits, periodStartTime, periodBits}`: the header the enclave starts from,
with what the verifier needs to continue from it. An update may only move the checkpoint **forward** to a
header the enclave has already verified, or re-pin after a freeze. **Same height with different content is
not forward** (fuzz finding F-2026-11-20-01). At install, while the chain is not frozen, a changed checkpoint
is accepted only if **every** field is pinned by the enclave's own header record: `hash`/`height` a verified
recent header, `time` and `bits` that header's, `periodStartTime`/`periodBits` the enclave's current-period
values — which it knows exactly only for a header of the **current retarget period**, so a header of an
earlier period is refused (`POLICY_INVALID`) rather than trusted on the owner's word. While the chain is
**frozen** by a reorg deeper than `maxReorg` there is no local header to validate against: a re-pin applies
**at once** (forward or same-height — the block-height timelock cannot run while frozen), is
**checkpoint-only** (any other field changed in the same update is refused), and the owner's signature is the
root of trust for that recovery (`THREAT-MODEL.md`, V5 ∧ frozen). **While frozen, any policy update that does not
re-pin the checkpoint is refused `CHAIN_REORG`** (REQ-r10-O01): a tightening would be a no-op and a loosening would
park in `pending` for ever, since the block height cannot advance while the chain is frozen. A pending update queued
before the freeze must be cancelled first (`Cancel`, owner or recovery key); then the re-pin.

### `freshness`

| Field | Meaning |
|---|---|
| `required` | `true`: every signature needs a witness token whose tip is within `maxTipLag` blocks of the enclave's best header and whose `last_seen_seq ≤` the enclave's sequence; a rolled-back enclave therefore pauses instead of overspending. `false`: no token needed; rollback is bounded and detected only (labeled) |
| `witnessPubKey` | P-256 public key of the owner's monitor; must be present when `required` |
| `maxTipLag` | how stale a token's tip may be, in blocks (1–144). **This number is the rollback residual** (auditor R13): within `maxTipLag` blocks of the rolled-back point, a token with `last_seen_seq ≤` the rolled-back sequence and a tip still within the lag passes both checks once. Set it as small as the witness cadence allows; the exposure per network (mainnet ≈ 10 min/block; signet/testnet cheaper PoW, faster) is shown at `GET /v1/status` |

### `validity`

`notAfterHeight`: after this height every signing request is refused until a new mandate is
installed. Pick it like a certificate expiry (e.g. +1 year of blocks ≈ 52 560). There is no
`notBefore`: an update activates by nonce and timelock.

## 4. What is NOT in the mandate, deliberately

- No wall-clock times. The enclave has none.
- No "approved invoice" or "approved payout" lists from BTCPay. BTCPay is the compromised party in
  the threat model; nothing it asserts can loosen a rule. Customer payouts are what the `unlisted`
  caps are for.
- No per-transaction owner approval. That would be a hardware wallet, and merchants already have
  those; the point here is unattended signing inside a bound.

## 5. Tightening vs loosening (what applies at once, what waits the timelock)

An update is **tightening** iff every one of these holds; otherwise it is loosening and waits
`timelockBlocks` of the *installed* mandate.

**The classifier fails toward loosening (auditor R6, load-bearing).** It runs field by field on
the **canonical decoded** mandate, never on JSON. A field that is unknown, absent on either side,
of a different shape, or not *provably* tightening by the table below makes the **whole** update
loosening. There is no default of "tightening"; the only way to apply at once is for every field
to be provably in the restrictive direction.

| Field | tightening direction |
|---|---|
| `destinations.trusted` | entries removed, or an entry's `maxPerTx` / `maxPerWindow` / `gap` lowered; **no entry added or changed in address/descriptor** |
| `destinations.unlisted.*` | lowered |
| `limits.maxPerTx`, `window.maxOutflow`, `maxFeeAbs`, `maxFeeRate`, `maxInputs`, `maxOutputs`, `ownIndexGap`, `maxReorg` | lowered |
| `limits.maxFeePerWindow` | lowered, or absent → present |
| `limits.window.blocks` | raised (a longer window with the same budget is tighter) |
| `rules.payjoin` | moved toward `none`; `rules.opReturn` toward `none`; `rules.rbf` to `false` |
| `chain.checkpoint` | unchanged, or moved **strictly forward** — same height with different content is not forward and is loosening (F-2026-11-20-01); a re-pin while the chain is frozen bypasses this table and applies at once, checkpoint-only (see `chain` above) |
| `freshness.required` | `false → true`; `freshness.maxTipLag` lowered; **`witnessPubKey` changed = loosening** (a new witness could hide a rollback) |
| `validity.notAfterHeight` | lowered |
| `timelockBlocks` | raised |
| `network`, `wallet` | unchanged (a change is refused outright) |

Nonce, owner rotation and recovery: `DESIGN.md §6–7`.

## 6. Refusal reasons (machine-readable, stable identifiers)

`PSBT_PARSE`, `UNKNOWN_FIELD`, `INPUT_NO_PREVTX`, `INPUT_PREVTX_MISMATCH`, `INPUT_NOT_OWN`,
`INPUT_FOREIGN_FORBIDDEN`, `INPUT_SCRIPT_TYPE`, `OUTPUT_SCRIPT_TYPE`, `CHANGE_INDEX_BEYOND_GAP`,
`SIGHASH`, `TX_VERSION`, `RBF_FORBIDDEN`, `OPRETURN_FORBIDDEN`, `CAP_TX`, `CAP_WINDOW`,
`CAP_UNLISTED_TX`, `CAP_UNLISTED_WINDOW`, `CAP_TRUSTED_TX(label)`, `CAP_TRUSTED_WINDOW(label)`,
`FEE_ABS`, `FEE_RATE`, `TOO_MANY_INPUTS`, `TOO_MANY_OUTPUTS`, `OVERFLOW`, `MANDATE_EXPIRED`,
`FROZEN`, `CHAIN_STALE`, `CHAIN_REORG`, `FRESHNESS_MISSING`, `FRESHNESS_SIG`, `FRESHNESS_TIP`,
`FRESHNESS_SEQ_BEHIND` (rollback suspected — needs owner re-arm), `POLICY_SIG`, `POLICY_NONCE`, `POLICY_NETWORK`,
`POLICY_WALLET`, `POLICY_PENDING`, `STATE_UNSEALABLE`, `SEQ_BEHIND_SESSION`, and from R7 `NOT_ARMED` (this enclave
load has not been approved by the owner: no judging or signing until `Arm`), `ARM_CHALLENGE` (an `Arm` over
another load's challenge — a replay), `ARM_SEQ_BEHIND` (the owner saw a higher sequence than the enclave
remembers: the state was rolled back), and from R9 (IMPL-PASS 2026-11-10) `TPM_REQUIRED` (the state
is TPM-bound and no counter proof was presented for this call), `TPM_PARSE` (the proof is not a well-formed
NV attestation), `TPM_NONCE` (the proof is not over the nonce this enclave issued for this call — a replay),
`TPM_INDEX` (another counter index than the pinned one), `TPM_SIG` (not signed by the pinned attestation key),
`STATE_STALE` (the TPM certifies a counter other than the one this blob expects: a rollback, a crash between
seal and increment, or a spurious increment — the owner's `Anchor` resolves it), and from R9a (IMPL-PASS 2026-11-19; on T2 since 2026-11-19, ceremony-signed build `2073c234…`)
`ANCHOR_TPM_MISMATCH` (an `Anchor` on a TPM-bound state names another attestation key or counter index than the
sealed ones: the host handed the owner the identity of a TPM it controls — the TPM identity is bound for the
wallet's life; a replaced TPM under a living wallet means a new wallet or a re-bind ceremony, never a retry),
`ANCHOR_COUNTER_BEHIND` (the host's live counter proof is below the value the owner saw certified — a lying host
or a replaced TPM), and from R11 `STATE_INVALID` (the sealed state opened but its mandate fails its own bounds —
impossible under the seal, so a corrupted state file or a test build; refused at the one door every op passes,
before any gate reads a bound and before a counter proof is consumed) and `POLICY_TOO_EXPENSIVE` (the
trusted-destination scan would exceed its derivation bound of 128 000 — `MAX_TRUSTED × MAX_BRANCHES × MAX_GAP`, the
validated worst case — unreachable for a mandate that passed `validate`). Every one of them has at least one refusal
vector in `vectors/`, in the `rcore` replay test or in `core/tests`.
