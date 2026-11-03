# core/PROVENANCE.md — every crate inside the enclave TCB

One line per crate that reaches the enclave through `signer-core` (measured with
`cargo tree -e normal --no-default-features`, 2026-11-03). Changing a line is a REQ
(`CLAUDE.md` rule 6, `CONDITIONS.md` C-R10b). Direct dependencies are exact (`=`) in `Cargo.toml`;
`Cargo.lock` is committed; builds are `--locked`.

## Direct

| Crate | Version | Source | Why it is in the TCB | Features (enclave build) |
|---|---|---|---|---|
| `bitcoin` | =0.32.102 | crates.io (rust-bitcoin) | PSBT (BIP174) parse, transaction model, BIP32 derivation, BIP143 sighash, script types | none (`default-features = false`) |
| `secp256k1` | =0.29.1 | crates.io (rust-bitcoin) | ECDSA signing (RFC6979, low-s), pubkey derivation, receipt signatures | `alloc`, `lowmemory`; context randomization wired in R2 (C-R10c) |
| `sha2` | =0.10.9 | crates.io (RustCrypto) | SHA-256 for canonical hashes and domain-separated digests | `force-soft` — and the build asserts no `cpuid` (C-R10a) |
| `p256` | =0.13.2 | crates.io (RustCrypto) | verify owner / recovery / witness P-256 ECDSA signatures | `ecdsa`, `arithmetic` |

## Transitive (as locked)

| Crate | Version | Pulled by | Role |
|---|---|---|---|
| `secp256k1-sys` | 0.10.1 | secp256k1 | libsecp256k1 C sources, built by `cc` with `USE_EXTERNAL_DEFAULT_CALLBACKS`, `-Dprintf(...)=`, `lowmemory` tables |
| `bitcoin_hashes` | 0.14.101 | bitcoin | SHA256d, HASH160, tagged hashes |
| `bitcoin-io`, `bitcoin-units`, `base58ck`, `bech32`, `hex-conservative`, `hex_lit` | as locked | bitcoin | encoding helpers |
| `ecdsa` | 0.16.9 | p256 | ECDSA verify (and sign, unused in the enclave) |
| `elliptic-curve`, `primeorder`, `crypto-bigint`, `ff`, `group`, `sec1`, `base16ct`, `der`, `const-oid`, `subtle`, `zeroize` | as locked | p256 / ecdsa | curve arithmetic and SEC1 parsing |
| `rfc6979`, `hmac` | 0.4.0 / 0.12.1 | ecdsa | deterministic nonces for the signing side of `ecdsa` (not used in the enclave; linked only if reachable, `--gc-sections`) |
| `digest`, `block-buffer`, `crypto-common`, `generic-array`, `typenum`, `signature`, `rand_core` | as locked | sha2 / p256 | traits and buffers; `rand_core` without `getrandom` |
| `cpufeatures` | 0.2.17 | sha2 | **inert** under `force-soft`; its `cpuid` path must not be linked — the objdump assertion is the gate |
| `cfg-if`, `arrayvec` | as locked | misc | build-time cfg, fixed-capacity vectors |

Not in the enclave: `hex`, `serde`, `serde_json` (dev-dependencies), anything behind `std` or
`hollow-test`. **R2 additions (each a REQ line):** `hmac` + `pbkdf2` (BIP39), `hkdf` + `aes-gcm`
(recovery blob).

## Cost note (RESP-r1 D-11, C-R1-1)

Trusted-descriptor matching (`wallet::matches_trusted`) derives up to `branches × gap` child keys
per output that is neither own nor an exact-address match — the dominant per-transaction EC cost
(≤ `branches × gap × candidates` scalar multiplications; `gap ≤ 1000`). Own-output and own-input
classification cost one derivation per hinted path. R2 measures this on T1 hardware and sizes
`maxOutputs × gap` to the enclave's time and heap budget.
