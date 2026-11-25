//! rcore — the enclave's FFI crate (`docs/ENCLAVE.md`).
//!
//! The only crate in the TCB that contains `unsafe`: the SDK calls (sealing, randomness, the
//! self-report), the allocator over `sgx_tstdc`, and the C-callable dispatcher. Everything that
//! decides anything lives in `signer-core`, which stays `forbid(unsafe_code)`.
//!
//! One exported symbol, `rcore_call(op, in, out)`, is the whole ecall surface (`proto::op`).
//! Every ecall takes the sealed blob in and gives it back out; the enclave keeps nothing between
//! calls except the volatile session mark (`session`), which exists to refuse a replayed blob.

#![no_std]
#![deny(missing_docs)]
// Hard rule 9 (SafeMath) — the same three lints the Cargo table carries, visible at the source (R11, C-EXT1-1)
#![deny(clippy::arithmetic_side_effects, clippy::cast_possible_truncation, clippy::cast_sign_loss)]

extern crate alloc;

mod allocator;
mod envelope;
mod ops;
pub mod recovery;
mod session;
mod sgx;

use alloc::vec::Vec;

use signer_core::proto::Response;

/// Status codes returned by `rcore_call` (the response bytes carry the detail).
pub mod status {
    /// Success: `out` holds a canonical `Response`.
    pub const OK: i32 = 0;
    /// `out_cap` too small for the response (the host retries with a larger buffer).
    pub const OUT_TOO_SMALL: i32 = -1;
    /// Null pointer or bad length.
    pub const BAD_ARGS: i32 = -2;
}

/// The one ecall. `op` is a `proto::op` code, `in` the request's canonical bytes; the canonical
/// `Response` is written to `out` and its length to `out_len`.
///
/// # Safety
/// Called by the edger8r-generated bridge, which has already copied `in` into enclave memory and
/// allocated `out` inside the enclave; the pointers and lengths are what the bridge checked.
#[no_mangle]
pub unsafe extern "C" fn rcore_call(
    op: u32,
    in_ptr: *const u8,
    in_len: usize,
    out_ptr: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if (in_ptr.is_null() && in_len != 0) || out_ptr.is_null() || out_len.is_null() {
        return status::BAD_ARGS;
    }
    let input: &[u8] = if in_len == 0 { &[] } else { core::slice::from_raw_parts(in_ptr, in_len) };
    let response: Response = ops::dispatch(op, input);
    let bytes: Vec<u8> = response.encode();
    if bytes.len() > out_cap {
        *out_len = bytes.len();
        return status::OUT_TOO_SMALL;
    }
    core::ptr::copy_nonoverlapping(bytes.as_ptr(), out_ptr, bytes.len());
    *out_len = bytes.len();
    status::OK
}

/// Panic = abort = `SGX_ERROR_ENCLAVE_CRASHED` at the host. Nothing is charged on this path.
/// Absent under `nosgx` (the host test binary's `std` provides the handler) and under `test`.
#[cfg(all(not(feature = "nosgx"), not(test)))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sgx::abort()
}

/// The sysroot's `alloc` rlib keeps a `.data.DW.ref.rust_eh_personality` reference that survives
/// `--gc-sections`; with `panic = "abort"` the personality routine can never be called. The lab
/// resolved it with fat LTO, which cargo does not apply to a crate that also builds an rlib; this
/// definition is the explicit form of the same fact. Aborts if ever reached.
#[cfg(all(not(feature = "nosgx"), not(test)))]
#[no_mangle]
pub extern "C" fn rust_eh_personality() -> ! {
    sgx::abort()
}
