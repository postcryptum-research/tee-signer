//! tee-signer fuzz harness (REQ-r10 / RESP-r10, 2026-11-20). Host-side `std` test code, OUTSIDE the
//! TCB: it links `signer-core` with its `std` feature exactly as the vector suite does and never
//! changes it. Nothing built from this crate ships or is measured.
//!
//! - `fixtures` — the vector suite's own fixtures (`core/tests/common/mod.rs`), included by path so
//!   a fuzzer-found input is directly comparable to a vector (auditor's choice, RESP-r10 Q3).
//! - `seeds`    — the honest objects every oracle is calibrated on (signed messages, receipt, card,
//!   TPM attest, mandates, state), deterministic from the fixture keys.
//! - `targets`  — one body per fuzz target, `fn(&[u8])`; called by the libFuzzer binaries in
//!   `fuzz_targets/` and by the stable replay test in `tests/replay.rs` (the CI gate).
//!
//! Every assertion in `targets` is an oracle from REQ-r10 §1–§2 or a condition of RESP-r10
//! (C-R10-1 … C-R10-6); the panic message names it.

// `deny`, not `forbid`: the one `unsafe` of the harness is the C ABI of the real ecall (`dispatch::raw_call`,
// `rcore_call` as the bridge calls it), allowed on that function alone.
#![deny(unsafe_code)]

pub mod dispatch;
#[path = "../../core/tests/common/mod.rs"]
#[allow(dead_code, clippy::all)]
pub mod fixtures;
pub mod gen;
pub mod policy;
pub mod seeds;
pub mod structured;
pub mod targets;
