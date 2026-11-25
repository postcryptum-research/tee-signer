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
/// The most a deposited proof may be: the 72 words (`MAX_ATTEST_LEN` 512 + the 64-byte signature).
const TPM_PROOF_MAX: usize = 576;
static TPM_PROOF_LEN: AtomicU64 = AtomicU64::new(0);
static TPM_PROOF_PRESENT: AtomicBool = AtomicBool::new(false);
static TPM_LAST_FRESH: AtomicBool = AtomicBool::new(false);

/// A little-endian word from exactly eight bytes; the callers hand it `chunks_exact(8)` pieces, so the
/// fallback is unreachable (and a zero word would be a wrong session id or challenge, which the owner's
/// `Arm` would then fail against — never silently accepted).
fn word(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().unwrap_or([0; 8]))
}

/// Draw the session id and the boot challenge once per load.
///
/// Two concurrent first callers cannot happen: `Enclave.config.xml` sets `TCSNum 1`, `TCSPolicy 1` — the
/// SGX runtime admits one ecall at a time from any host thread (and under `nosgx` the harness and the daemon
/// are single-threaded, `signerd` serialising its ecalls under one mutex besides); the enclave Makefile's
/// gate 8 and CI refuse a config that says otherwise (C-R11-2). If `TCSNum` is ever raised above 1, this
/// function must first become a proper once-init (an `AtomicBool` compare-exchange or a `Once`): the race
/// it would otherwise have is a torn session id / challenge, which the owner's `Arm` would then fail against.
fn ensure() {
    if INIT.load(Ordering::Acquire) {
        return;
    }
    // C-R7-1: in-enclave randomness (`sgx_read_rand`), never an OCALL to the host — a host-sourced
    // challenge could be replayed together with an old `Arm`.
    let mut b = [0u8; 48];
    crate::sgx::read_rand(&mut b);
    let mut words = b.chunks_exact(8);
    SESSION_LO.store(words.next().map_or(0, word), Ordering::Relaxed);
    SESSION_HI.store(words.next().map_or(0, word), Ordering::Relaxed);
    for (c, w) in CHALLENGE.iter().zip(words) {
        c.store(word(w), Ordering::Relaxed);
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
    for (w, c) in out.chunks_exact_mut(8).zip(CHALLENGE.iter()) {
        w.copy_from_slice(&c.load(Ordering::Relaxed).to_le_bytes());
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
    for (w, chunk) in TPM_NONCE.iter().zip(b.chunks_exact(8)) {
        w.store(word(chunk), Ordering::Relaxed);
    }
    TPM_PROOF_PRESENT.store(false, Ordering::Release);
    TPM_NONCE_LIVE.store(true, Ordering::Release);
    b
}

fn tpm_nonce_value() -> [u8; 32] {
    let mut out = [0u8; 32];
    for (chunk, w) in out.chunks_exact_mut(8).zip(TPM_NONCE.iter()) {
        chunk.copy_from_slice(&w.load(Ordering::Relaxed).to_le_bytes());
    }
    out
}

/// REQ-r9: deposit the proof bytes (attest ‖ sig, unverified) for the live nonce. `false` when no
/// nonce is live or the proof is too long.
pub fn tpm_proof_store(bytes: &[u8]) -> bool {
    ensure();
    if !TPM_NONCE_LIVE.load(Ordering::Acquire) || bytes.len() > TPM_PROOF_MAX {
        return false;
    }
    // the proof as 72 words, the last one zero-padded; words beyond the proof are zero (the length is kept)
    let mut chunks = bytes.chunks(8);
    for w in TPM_PROOF.iter() {
        let mut word_bytes = [0u8; 8];
        if let Some(c) = chunks.next() {
            word_bytes[..c.len()].copy_from_slice(c);
        }
        w.store(u64::from_le_bytes(word_bytes), Ordering::Relaxed);
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
    let len = usize::try_from(TPM_PROOF_LEN.load(Ordering::Relaxed)).ok()?;
    let mut out = alloc::vec::Vec::with_capacity(len);
    for w in TPM_PROOF.iter() {
        out.extend_from_slice(&w.load(Ordering::Relaxed).to_le_bytes());
    }
    out.truncate(len);
    Some((nonce, out))
}

/// REQ-r9: record the verdict of the last proof-gated call (for `STATUS`): true only when that call
/// applied on a verified fresh proof; false after any refusal of it — a missing or failing proof, a
/// stale counter, or a core refusal behind a verified proof alike.
pub fn tpm_set_last_fresh(fresh: bool) {
    TPM_LAST_FRESH.store(fresh, Ordering::Release);
}

/// REQ-r9: whether the last proof-gated call in this load applied on a fresh proof. Reported by
/// `STATUS` only; no decision reads it — the refusal itself is authoritative.
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
