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

// REQ-r9: the TPM counter proof of the NEXT blob-reading ecall — a single live nonce (random,
// consumed on issue of the next one and on use), the proof bytes the host deposited for it, and
// whether the last verified proof was fresh. Volatile like everything here.
static TPM_NONCE: [AtomicU64; 4] = [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];
static TPM_NONCE_LIVE: AtomicBool = AtomicBool::new(false);
/// Proof storage: `MAX_ATTEST_LEN` (512) + 64 bytes of signature, as 72 little-endian words.
static TPM_PROOF: [AtomicU64; 72] = [const { AtomicU64::new(0) }; 72];
static TPM_PROOF_LEN: AtomicU64 = AtomicU64::new(0);
static TPM_PROOF_PRESENT: AtomicBool = AtomicBool::new(false);
static TPM_LAST_FRESH: AtomicBool = AtomicBool::new(false);

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

/// REQ-r9: issue the nonce for the next blob-reading call. Random, in-enclave, single-use: a new
/// nonce forgets the previous one and any proof deposited for it (exactly one live nonce, C-R9 Q5).
pub fn tpm_nonce_issue() -> [u8; 32] {
    ensure();
    let mut b = [0u8; 32];
    crate::sgx::read_rand(&mut b);
    for (i, w) in TPM_NONCE.iter().enumerate() {
        w.store(u64::from_le_bytes(b[8 * i..8 * i + 8].try_into().unwrap_or([0; 8])), Ordering::Relaxed);
    }
    TPM_PROOF_PRESENT.store(false, Ordering::Release);
    TPM_NONCE_LIVE.store(true, Ordering::Release);
    b
}

fn tpm_nonce_value() -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, w) in TPM_NONCE.iter().enumerate() {
        out[8 * i..8 * i + 8].copy_from_slice(&w.load(Ordering::Relaxed).to_le_bytes());
    }
    out
}

/// REQ-r9: deposit the proof bytes (attest ‖ sig, unverified) for the live nonce. `false` when no
/// nonce is live or the proof is too long.
pub fn tpm_proof_store(bytes: &[u8]) -> bool {
    ensure();
    if !TPM_NONCE_LIVE.load(Ordering::Acquire) || bytes.len() > 72 * 8 {
        return false;
    }
    for (i, w) in TPM_PROOF.iter().enumerate() {
        let mut chunk = [0u8; 8];
        let start = 8 * i;
        if start < bytes.len() {
            let end = core::cmp::min(start + 8, bytes.len());
            chunk[..end - start].copy_from_slice(&bytes[start..end]);
        }
        w.store(u64::from_le_bytes(chunk), Ordering::Relaxed);
    }
    TPM_PROOF_LEN.store(bytes.len() as u64, Ordering::Relaxed);
    TPM_PROOF_PRESENT.store(true, Ordering::Release);
    true
}

/// REQ-r9: take the live nonce and the deposited proof for THIS call, consuming both (single-use
/// whatever the verdict). `None` when either is missing.
pub fn tpm_proof_take() -> Option<([u8; 32], alloc::vec::Vec<u8>)> {
    ensure();
    let live = TPM_NONCE_LIVE.swap(false, Ordering::AcqRel);
    let present = TPM_PROOF_PRESENT.swap(false, Ordering::AcqRel);
    if !live || !present {
        return None;
    }
    let nonce = tpm_nonce_value();
    let len = TPM_PROOF_LEN.load(Ordering::Relaxed) as usize;
    let mut out = alloc::vec::Vec::with_capacity(len);
    for w in TPM_PROOF.iter() {
        out.extend_from_slice(&w.load(Ordering::Relaxed).to_le_bytes());
    }
    out.truncate(len);
    Some((nonce, out))
}

/// REQ-r9: record the verdict of the last proof (for `STATUS`).
pub fn tpm_set_last_fresh(fresh: bool) {
    TPM_LAST_FRESH.store(fresh, Ordering::Release);
}

/// REQ-r9: whether the last verified proof in this load was fresh.
pub fn tpm_last_fresh() -> bool {
    TPM_LAST_FRESH.load(Ordering::Acquire)
}

/// Test builds only: forget the session (simulates an enclave reload: new id, new challenge,
/// unarmed, HWM 0).
#[cfg(feature = "test-init")]
pub fn reset() {
    INIT.store(false, Ordering::Release);
    HWM.store(0, Ordering::Release);
    #[cfg(not(feature = "auto-arm"))]
    ARMED.store(false, Ordering::Release);
    TPM_NONCE_LIVE.store(false, Ordering::Release);
    TPM_PROOF_PRESENT.store(false, Ordering::Release);
    TPM_LAST_FRESH.store(false, Ordering::Release);
}
