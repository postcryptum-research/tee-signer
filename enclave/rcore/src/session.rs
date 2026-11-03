//! The volatile session: a random id drawn at first use and the highest sequence this enclave
//! load has produced. Lives in enclave memory only; a restart resets both (`docs/ENCLAVE.md §4a`).

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

static INIT: AtomicBool = AtomicBool::new(false);
static SESSION_LO: AtomicU64 = AtomicU64::new(0);
static SESSION_HI: AtomicU64 = AtomicU64::new(0);
static HWM: AtomicU64 = AtomicU64::new(0);

fn ensure() {
    if INIT.load(Ordering::Acquire) {
        return;
    }
    let mut b = [0u8; 16];
    crate::sgx::read_rand(&mut b);
    SESSION_LO.store(u64::from_le_bytes(b[..8].try_into().unwrap_or([0; 8])), Ordering::Relaxed);
    SESSION_HI.store(u64::from_le_bytes(b[8..].try_into().unwrap_or([0; 8])), Ordering::Relaxed);
    INIT.store(true, Ordering::Release);
}

/// The per-load session id.
pub fn id() -> [u8; 16] {
    ensure();
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&SESSION_LO.load(Ordering::Relaxed).to_le_bytes());
    out[8..].copy_from_slice(&SESSION_HI.load(Ordering::Relaxed).to_le_bytes());
    out
}

/// Refuse an input state whose sequence is below what this session already produced.
pub fn check_seq(seq: u64) -> bool {
    ensure();
    seq >= HWM.load(Ordering::Acquire)
}

/// Record a sequence this session produced (monotonic).
pub fn raise(seq: u64) {
    ensure();
    HWM.fetch_max(seq, Ordering::AcqRel);
}

/// Test builds only: forget the session (simulates an enclave reload).
#[cfg(feature = "test-init")]
pub fn reset() {
    INIT.store(false, Ordering::Release);
    HWM.store(0, Ordering::Release);
}
