//! The volatile session: a random id and a random **boot challenge** drawn at first use, the
//! highest sequence this enclave load has produced, and whether the owner has **armed** this
//! load (REQ-r7). All of it lives in enclave memory only; a restart resets all of it
//! (`docs/ENCLAVE.md §4a`). None of it is ever sealed: a sealed "armed" would roll back and
//! forward with the blob, which is exactly what the boot-arm exists to refuse (C-R7-0, C-R7-2).

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

static INIT: AtomicBool = AtomicBool::new(false);
static SESSION_LO: AtomicU64 = AtomicU64::new(0);
static SESSION_HI: AtomicU64 = AtomicU64::new(0);
static CHALLENGE: [AtomicU64; 4] = [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];
static HWM: AtomicU64 = AtomicU64::new(0);
#[cfg(not(feature = "auto-arm"))]
static ARMED: AtomicBool = AtomicBool::new(false);

fn ensure() {
    if INIT.load(Ordering::Acquire) {
        return;
    }
    // C-R7-1: in-enclave randomness (`sgx_read_rand`), never an OCALL to the host — a host-sourced
    // challenge could be replayed together with an old `Arm`.
    let mut b = [0u8; 48];
    crate::sgx::read_rand(&mut b);
    SESSION_LO.store(u64::from_le_bytes(b[..8].try_into().unwrap_or([0; 8])), Ordering::Relaxed);
    SESSION_HI.store(u64::from_le_bytes(b[8..16].try_into().unwrap_or([0; 8])), Ordering::Relaxed);
    for (i, c) in CHALLENGE.iter().enumerate() {
        let off = 16 + 8 * i;
        c.store(u64::from_le_bytes(b[off..off + 8].try_into().unwrap_or([0; 8])), Ordering::Relaxed);
    }
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

/// The per-load boot challenge the owner's `Arm` must carry (REQ-r7).
pub fn challenge() -> [u8; 32] {
    ensure();
    let mut out = [0u8; 32];
    for (i, c) in CHALLENGE.iter().enumerate() {
        out[8 * i..8 * i + 8].copy_from_slice(&c.load(Ordering::Relaxed).to_le_bytes());
    }
    out
}

/// Whether the owner has approved this load. False after every load until a valid `Arm`
/// (pause build); the `auto-arm` build compiles the pause out and is always armed (C-R7-8).
#[cfg(not(feature = "auto-arm"))]
pub fn armed() -> bool {
    ensure();
    ARMED.load(Ordering::Acquire)
}
#[cfg(feature = "auto-arm")]
pub const fn armed() -> bool {
    true
}

/// Record the owner's approval of this load (after `State::apply_arm` accepted the message).
#[cfg(not(feature = "auto-arm"))]
pub fn arm() {
    ensure();
    ARMED.store(true, Ordering::Release);
}
#[cfg(feature = "auto-arm")]
pub fn arm() {}

/// Refuse an input state whose sequence is below what this session already produced.
pub fn check_seq(seq: u64) -> bool {
    ensure();
    seq >= HWM.load(Ordering::Acquire)
}

/// Record a sequence this session produced or armed on (monotonic). Every blob-reading ecall
/// that accepts a blob ratchets here, `Arm` included (C-R7-3): an armed process can never be
/// handed a blob older than the one it was armed on.
pub fn raise(seq: u64) {
    ensure();
    HWM.fetch_max(seq, Ordering::AcqRel);
}

/// Test builds only: forget the session (simulates an enclave reload: new id, new challenge,
/// unarmed, HWM 0).
#[cfg(feature = "test-init")]
pub fn reset() {
    INIT.store(false, Ordering::Release);
    HWM.store(0, Ordering::Release);
    #[cfg(not(feature = "auto-arm"))]
    ARMED.store(false, Ordering::Release);
}
