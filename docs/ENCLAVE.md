# The enclave shell (R2) — seal envelope, ecall surface, two-phase signing, build gates

**Status:** design supplement for round R2 (2026-11-03), written under the DESIGN-PASS of
`audit/RESP-design-2026-11-03.md`; ruled with the R2 IMPL REQ at its commit.

## 1. Shape

```
host (signerd, untrusted)                      enclave (signer-enclave)
  sealed blob on disk  ──(bytes in)──▶  ┌─────────────────────────────────────────┐
  PSBT / messages / headers             │ C: edger8r glue only (Enclave.c)        │
                                        │ Rust FFI crate `rcore` (staticlib):     │
  ◀──(sealed blob out, results)──       │   unseal → core → reseal, randomness,   │
                                        │   BIP39, recovery blob, identity key    │
  writes blob (fsync, rename) BEFORE    │ `signer-core`: forbid(unsafe), pure     │
  acting on any result                  └─────────────────────────────────────────┘
```

**Stateless ecalls.** Every ecall takes the sealed blob in and returns a new sealed blob out; the
enclave keeps no persistent state between ecalls. Consequences: nothing inside the enclave races
(concurrency is the host's serialization, and a concurrent call on a stale blob simply produces a
sibling blob the host must not persist — `signerd` holds one mutex around every ecall and persists
in order); a host rollback is "present an older blob", which is exactly what the freshness witness
and the receipt sequence are for; and the enclave can be restarted at will.

## 2. Seal envelope

```
Envelope v1 (canonical encoding, then sgx_seal_data, MRENCLAVE policy on T1):
  version        u16  = 1
  network        u8
  seed           [32]   BIP39 entropy (256 bits) from sgx_read_rand — the only copy
  identity_sk    [32]   secp256k1 secret for receipts and the identity card; from sgx_read_rand,
                        NEVER derived from the seed (C-R1-2)
  state          bytes  signer_core::state::State::encode()
  last_judged    Option<{ txid[32], seq u64 }>   the record the two-phase sign checks (§4)
AAD = "tee-signer/envelope/v1" ‖ MRENCLAVE-policy marker
```

`sgx_seal_data` with `SGX_KEYPOLICY_MRENCLAVE` on T1: a different enclave cannot open the blob,
which is what pins the identity card. T2 (MRSIGNER + ISVSVN with an explicit upgrade path) is a
later REQ. The account xpriv is derived from the seed at every ecall that needs it and dropped
before return; nothing derived from the seed is cached across ecalls.

## 3. Ecall surface (`enclave/Enclave.edl`)

| ecall | in | out | effect |
|---|---|---|---|
| `init` | network, owner_pk, recovery_pk | keys-only sealed blob, xpub (78 B), fingerprint, identity_pk (33 B), identity card + its signature, recovery blob | generates seed and identity key, binds owner and recovery keys; the recovery blob is produced here and **nowhere else** (I12). No mandate yet: the mandate names the fingerprint, which exists only now |
| `install` | keys-only sealed blob, mandate bytes, owner sig (as `PolicyUpdate` nonce 0 for this enclave id) | full sealed blob | verifies the signature against the **bound** owner, `validate`, network and wallet (fingerprint, `84'/coin'/0'`, P2WPKH) against the derived ones, `State::new_at_init`. A keys-only blob can only ever become a full one under a mandate the bound owner signed |
| `status` | sealed blob | public status (tier, measurement, network, xpub, nonce, seq, frozen, armed, best height, window usage, mandate hash, pending hash + activation, chain labels) | none |
| `policy` | sealed blob | installed mandate bytes + sig, pending mandate bytes + sig + activation | none |
| `apply_message` | sealed blob, message bytes | sealed blob | `State::apply_message` |
| `freeze` | sealed blob | sealed blob | `State::freeze` (unauthenticated) |
| `headers` | sealed blob, N × 80-byte headers | sealed blob, accepted count | header verifier (§6) |
| `judge` | sealed blob, PSBT, optional witness token | sealed blob (charged), summary, or refusal (+ sealed blob if disarmed) | `classify` + `judge`; records `last_judged` |
| `sign` | **charged** sealed blob, PSBT | signed PSBT, receipt + identity signature | signs only if `last_judged.txid == txid(PSBT)` and `last_judged.seq == state.seq` (§4) |

Test-only ops `TEST_INIT` (known seed and identity key, a ready state) and `TEST_RESET_SESSION`
(forget the volatile session mark) exist behind the `rcore` feature `test-init` so the vector
runner can replay `vectors/r1` through the real ecalls with the known test wallet and prove the
fork refusal; the release build refuses the feature and asserts the symbols are absent (same bar
as `hollow-test`, C-R9). All operations go through **one** ecall, `ecall_call(op, in, out)`, with
canonical request and response bytes defined once in `signer_core::proto` for both sides.

## 4. Two-phase signing — the ordering the enclave enforces

`judge` charges the state (window usage, index bounds, `seq`), records `last_judged = {txid,
seq}`, and returns the **charged** blob. `sign` takes a blob and a PSBT and signs **only** if the
blob's `last_judged` names this PSBT's txid and the blob's `seq`. So:

- no signature can exist unless the host first obtained — and therefore can persist — the charged
  blob (`signerd` persists it before calling `sign`; a crash between the two leaves a charged
  budget and no signature, the conservative failure of `DESIGN.md §4`);
- re-signing the same PSBT with the same charged blob is idempotent (RFC6979 gives the same
  signature; nothing is charged twice);
- a different PSBT against the same blob refuses — and "different" means **different bytes**:
  `last_judged` carries `SHA-256(PSBT bytes)`, not only the txid, so a PSBT with the same
  transaction but altered hints (which could change which inputs are classified as own) is a new
  request and needs a new `judge`;
- the hollow-test `commit_before_sign` (core) plus this rule (shell) together close I11.

## 4a. The seq-fork — what stateless ecalls cost on SGX1, stated (auditor objection, R2)

Because the enclave keeps no persistent high-water mark, a host that holds a sealed blob can feed
**two** `judge` calls the **same** base blob: `judge(base@N, A) → blobA@N+1` and `judge(base@N, B)
→ blobB@N+1`, then `sign(blobA, A)` and `sign(blobB, B)` — two signed transactions, each charged
against the same base window, each under the caps, together over them. `last_judged` does not
stop it (each blob matches its own transaction), and the freshness witness does not stop it (both
judges run at seq N and one token with `last_seen_seq ≤ N` serves both). This is the SGX1
no-monotonic-counter limit of Q3 in its sharpest form.

- **Reachability, in two layers (auditor).** With an **honest** `signerd` V1 cannot fork: V1
  (BTCPay admin, plugin RCE) only ever sees the HTTP API, never a blob; `signerd` runs as its own
  user, keeps the blob at mode `0600`, and serializes every ecall behind one mutex — that mutex
  prevents an *accidental* fork under concurrent requests and nothing more. `signerd` is untrusted
  in this design ("transport and storage only"), so **no security claim rests on it**: a
  compromised signerd user (V2) or root (V3) can fork, and what still catches that is the two
  mechanisms below.
- **In-enclave session high-water mark — prevents the fork within one enclave lifetime.** `rcore`
  keeps, in enclave memory for the life of the loaded enclave, the highest `seq` it has produced
  and refuses any input blob below it (`SEQ_BEHIND_SESSION`). Because the blob is MRENCLAVE-sealed,
  an attacker can only replay a *real* past blob, never forge one at a higher seq, so the
  second-judge-from-base is refused outright. A host restart resets the volatile mark and is the
  only way across it — and every load draws a random **`session_id`** that goes into `status` and
  into every receipt. A bare session change is **not** an alarm (a crash-restart is legitimate);
  the alarm is seq duplication across sessions, or a chain spend without a receipt (below).
- **Detection is the monitor's, and the chain is the ground truth.** A host that forks blobs will
  also withhold receipts, so receipt forwarding is a convenience, not detection. The owner's
  monitor (R4 spec) watches the wallet's UTXOs on-chain (it has the xpub) and alarms on **any spend
  with no matching receipt** — that is the primary detection; receipts are keyed by `(session_id,
  seq)` and additionally alarm on seq regression and **seq duplication** (within or across
  sessions); a session change with seq continuity across it is logged as a benign restart. The
  witness token carries the tip, so a fork across a block boundary is visible too.
- **The bound, stated.** Until detection: k forked transactions at the same seq, each within the
  per-transaction caps and each charged against the same base window — k × the remaining window
  budget, amplified by detection latency. `freshness.required` **detects** this through the monitor;
  it does not prevent it. Prevention needs a monotonic counter SGX1 does not have; a counter
  service or an external anchor on T2 is a later REQ.

## 5. Randomness and the recovery blob

`sgx_read_rand` (RDRAND inside the enclave) is the only source: the seed, the identity key, the
recovery blob's ephemeral scalar, and the secp256k1 context randomization at every enclave entry
(C-R10c). Recovery blob: ephemeral P-256 scalar → ECDH with `recovery_pk` → HKDF-SHA256(salt =
"tee-signer/recovery/v1", info = fingerprint ‖ xpub) → AES-256-GCM, nonce `0^12` (the key is used
exactly once by construction: fresh ephemeral ⇒ fresh key), AAD = fingerprint ‖ xpub, plaintext =
the 24-word mnemonic's entropy (32 bytes). Output = ephemeral pubkey (65) ‖ ciphertext ‖ tag. The
ephemeral scalar and the seed copies are zeroized before return.

**Identity card** = canonical `{MRENCLAVE[32], network, xpub[78], fingerprint[4], identity_pk[33],
tier}` signed by the identity key over `domain_digest("tee-signer/identity/v1", card)`. MRENCLAVE
is read from the enclave's own report (`sgx_create_report` with a null target).

## 6. Header verifier (pulled from R4 into R2: nothing signs without a chain view)

`signer_core::headers`: a header is accepted if it links to the best (or to a recent header, a
fork), its hash ≤ its target, its target is the one the network rules require at that height
(mainnet / signet: retarget every 2016 blocks from the period's first timestamp, clamped ×4 / ÷4,
capped at the pow limit; regtest: pow limit; testnet4: as mainnet plus the 20-minute
min-difficulty rule and the walk-back to the last non-min-difficulty header), and its timestamp is
greater than the median of the previous 11 (a header-validity rule consuming only header
timestamps; **no policy decision — window, timelock, validity, freshness — consults any time**;
all of those are heights). Forks are chosen by cumulative work (the `bitcoin` crate's `Work`);
a reorg deeper than `maxReorg` freezes (`CHAIN_REORG`). The checkpoint's target and the period's
first timestamp are part of the mandate's checkpoint (`chain.checkpoint` gains `bits` and
`periodStartTime`) so the verifier never needs headers before the checkpoint. There is no
future-time rule (no clock). Signet's cheap PoW and regtest's absent PoW are labeled at `status`.

## 7. Build gates (`enclave/Makefile`, each a hard failure)

1. `objdump -d enclave.so | grep -c '\bcpuid\b'` == 0 (C-R10a).
2. `nm enclave.so` has no symbol from `hollow-test` or `test-init` in a release build (C-R9,
   `RELEASE=1` refuses the features and asserts).
3. `cargo build --locked --release` for `rcore`; no `--allow-multiple-definition`; no TEXTREL
   (`readelf -d enclave.so | grep -c TEXTREL` == 0).
4. `sgx_sign` with `DisableDebug=1` in the config for release; on T1 the launch is debug by
   hardware necessity and `status.tier = "T1-debug"`.
5. Reproducibility (C-R1-3): two builds in the pinned container compare equal on MRENCLAVE and
   every SIGSTRUCT field except `header.date` and its signature (`sgx_sign dump`), never on the
   `.so` hash.
