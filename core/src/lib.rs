//! signer-core — the trusted core of tee-signer.
//!
//! Everything here runs inside the SGX enclave *and*, byte for byte the same, on the host under
//! test. The crate is `no_std` + `alloc`: no I/O, no clock, no randomness, no global mutable state.
//! Inputs are bytes from the untrusted host; outputs are verdicts, canonical bytes and signatures.
//!
//! Module map (design of record: `docs/DESIGN.md`, `docs/POLICY.md`, `docs/THREAT-MODEL.md`):
//! - `bip39`    — entropy → mnemonic → seed (the enclave's key derivation; the tests' too)
//! - `encoding` — strict canonical binary encoding (the only wire format the enclave accepts)
//! - `reason`   — stable refusal identifiers (`POLICY.md §6`)
//! - `mandate`  — the mandate: types, canonical encode/decode, validation, tightening classifier
//! - `wallet`   — in-enclave BIP32 derivation and script matching
//! - `classify` — PSBT → classified inputs/outputs (own / trusted / unlisted / foreign / op_return)
//! - `headers`  — the header-chain verifier: the enclave's only clock
//! - `judge`    — the policy engine: classified transaction + mandate + state → verdict
//! - `state`    — the sealed state (windows, bounds, sequence) and how a verdict charges it
//! - `sign`     — BIP143 signatures for own inputs with the account key
//! - `receipt`  — the signed receipt a signature leaves behind
//! - `update`   — owner / recovery / witness messages and their verification
//! - `proto`    — the ecall wire protocol shared by the enclave and the daemon
//! - `tpm_attest` — REQ-r9: the TPM counter freshness proof (`TPM2_NV_Certify`) verifier

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::arithmetic_side_effects)]

extern crate alloc;

pub mod bip39;
pub mod classify;
pub mod encoding;
pub mod headers;
pub mod judge;
pub mod mandate;
pub mod proto;
pub mod reason;
pub mod receipt;
pub mod sign;
pub mod state;
pub mod tpm_attest;
pub mod update;
pub mod wallet;

/// The one hash this crate uses for canonical digests: SHA-256, software path only.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// Domain-separated digest: `SHA-256(domain ‖ 0x00 ‖ payload)`. Every signed message in this
/// crate goes through a distinct domain string so no signature can be replayed as another kind.
pub fn domain_digest(domain: &str, payload: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(domain.as_bytes());
    h.update([0u8]);
    h.update(payload);
    h.finalize().into()
}
