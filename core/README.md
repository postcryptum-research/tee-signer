# signer-core — the trusted core

`no_std` + `alloc`, pure, host-testable. The same bytes run inside the SGX enclave and in `cargo
test`. No I/O, no clock, no randomness, no global mutable state: bytes in, verdicts and signatures
out. Design of record: `../docs/DESIGN.md`, `../docs/POLICY.md`, `../docs/THREAT-MODEL.md`.

## The flow the enclave drives

```
bytes (PSBT, mandate, state, messages)        ── all untrusted host input ──
   │
   ├─ state::State::decode(sealed bytes)                 strict; failure ⇒ STATE_UNSEALABLE
   ├─ state.activate_pending(); state.roll_window()      heights only, no clock
   ├─ classify::classify(psbt, account, mandate, bound)  I1–I4, I7: own / foreign / trusted / unlisted
   ├─ judge::judge(state, classified, witness)           I5–I9: caps, fee, window, freshness
   │      └─ Accept { state', summary }   ⇒ seal state' FIRST (commit → seal → sign)
   ├─ sign::sign_own_inputs(psbt, account_xpriv, classified)   BIP143, RFC6979, SIGHASH_ALL
   └─ receipt::Receipt::from_summary(..).digest() → sign::sign_digest_secp(identity_sk, ..)
```

Owner / recovery / witness messages: `update::Message::decode` → `state.apply_message(msg)`
(policy update with the fail-toward-loosening classifier, cancel, unfreeze, rearm, rotate owner,
recover). Freeze is `state.freeze()` — unauthenticated, fail-closed.

## Modules

| Module | Holds |
|---|---|
| `encoding` | the strict canonical codec: LE integers, `0/1` bools, bounded length prefixes, no trailing bytes |
| `reason` | the stable refusal identifiers of `POLICY.md §6` |
| `mandate` | `Mandate` types, codec, `validate`, `hash`, `compare` (tightening / loosening) |
| `wallet` | `Account` (fingerprint + account xpub), own-path parsing from origins, derivation, trusted matching |
| `classify` | PSBT → `Classified` (every input needs `non_witness_utxo`; own only through a verified hint) |
| `judge` | the policy engine; charges the state on accept; disarms on a suspected rollback |
| `state` | the sealed policy state (secrets live beside it in the enclave shell), transitions |
| `sign` | BIP143 signatures for own P2WPKH inputs, P2WPKH finalisation, compact secp256k1 for receipts |
| `receipt` | the receipt and its domain-separated digest |
| `update` | message types, codec, domain-separated digests, P-256 verification |

## Tests and vectors

```sh
cargo test                            # unit + vectors + transitions
cargo test --features hollow-test     # + the mutation suite: each guard removed ⇒ its vector goes green
cargo clippy --all-targets -- -D warnings
TEE_VECTORS_OUT=../vectors/r1 cargo test --test vectors   # (re)write the JSON vectors
```

`tests/vectors.rs` is the R1 bar (`docs/audit/RESP-design-2026-11-03.md` R12): accept vectors
that sign, finalise and leave a verified receipt; refuse vectors naming their reasons, with boundary
pairs (cap / cap + 1, gap − 1 / gap, lag / lag + 1); the fee-overpayment trap, the change-to-foreign
trap, the rollback detection with disarm; u64 overflow vectors. `tests/transitions.rs` covers the
update protocol and the window; its `hollow` module (feature-gated, refused by release builds)
proves I2, I3, I5/I11 and the window caps are load-bearing by removing each guard.

Every vector is also written as JSON (`../vectors/r1/*.json`, format in `../vectors/README.md`) so
the enclave-side runner (R2) replays the same bytes through the real ecalls.

## Rules this crate is written under

- `#![forbid(unsafe_code)]`, `#![deny(clippy::arithmetic_side_effects)]`: every add/mul/sub on
  amounts and heights is checked or saturating; overflow is a refusal (`OVERFLOW`).
- Host hints are pointers to a derivation the enclave performs; a hint that does not reproduce the
  script refuses the transaction. A missing hint on an own output makes it count as unlisted.
- The vsize used by the fee-rate check is a **lower bound** (own P2WPKH exact, foreign inputs at
  P2TR key-path size, shortest DER signature): a smaller vsize means a higher computed rate, so the
  estimate can only cause more refusals, never fewer.
- `hollow-test` and `std` are never enabled for the enclave build; the build asserts it.
