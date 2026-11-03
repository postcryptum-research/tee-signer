# vectors/ — golden vectors

`r1/` is written by `core/tests/vectors.rs` (`TEE_VECTORS_OUT=vectors/r1 cargo test --test vectors`)
and is the R1 bar; the enclave-side runner (R2) replays every file through the real ecalls and must
reproduce the verdict byte for byte. Keys are throwaway signet test keys (`core/tests/common/mod.rs`,
seeds `[0x01; 32]` wallet, `[0x02; 32]` cold descriptor, `[0x77; 32]` foreign); nothing here has ever
held value and nothing here is a mainnet key.

## File format

```json
{
  "name": "refuse-change-to-foreign-key",
  "expect": "accept" | "refuse",
  "reasons": ["OUTPUT_SCRIPT_TYPE"],        // stable identifiers, POLICY.md §6; order-insensitive
  "disarms": false,                          // refusal that also disarms the signer (rollback suspected)
  "network": "signet",
  "account_xpub": "tpub...",                 // the wallet's account key (m/84'/1'/0')
  "fingerprint": "hex4",                     // master fingerprint
  "mandate_hex": "...",                      // canonical Mandate bytes (state.mandate)
  "state_hex": "...",                        // canonical State bytes (seal payload, no secrets)
  "psbt_hex": "...",                         // the PSBT exactly as the host would submit it
  "witness_hex": "..." | null                // canonical WitnessToken message, if any
}
```

A runner: decode state → `classify` with the account derived from `account_xpub` → `judge` with the
witness → compare `expect`/`reasons`/`disarms`. For `accept`, additionally sign with the test
wallet's account xpriv and verify every own input's signature.

## Naming

`accept-*` and `refuse-*`; boundary pairs share a stem (`...-at-cap-boundary` / `...-plus-one`).
The mutation (hollow-test) proofs are not vectors: they are the `hollow` module of
`core/tests/transitions.rs` and run only with `--features hollow-test`.
