//! REQ-r9 — the TPM counter as the enclave's freshness source: the pure verifier of a
//! `TPM2_NV_Certify` proof over the pinned counter index and the enclave's own nonce.
//!
//! Bytes in, verdict out. The enclave pins one P-256 attestation key and one NV index Name in its
//! sealed state (the owner verified the TPM's endorsement on their machine — no X.509 here) and
//! demands, before reading a blob, a fresh attestation that the counter's live value equals the
//! value the blob expects. A rolled-back blob expects a smaller value than the TPM will ever
//! certify again → `STATE_STALE`. The reader is a strict fixed-layout walk over the
//! `TPMS_ATTEST` marshaling (TPM 2.0 Part 2 §10.12.8/§10.12.3): every field bounds-checked, every
//! pinned field compared, no allocation, no unbounded loop, no arithmetic that can wrap, no panic
//! path (C-R9-A).

use crate::reason::Reason;
use crate::update::verify_p256;

/// `TPM_GENERATED_VALUE`: the first four bytes of every TPM-made attestation.
pub const TPM_GENERATED: u32 = 0xFF54_4347;
/// `TPM_ST_ATTEST_NV`.
pub const ST_ATTEST_NV: u16 = 0x8014;
/// `TPM_ALG_SHA256`, the name algorithm the pinned index must use.
pub const ALG_SHA256: u16 = 0x000B;
/// A `TPM2B_NAME` for a SHA-256 Name: algorithm id (2) ‖ digest (32).
pub const NV_NAME_LEN: usize = 34;
/// Largest attestation this reader accepts (an NV attest is ~190 bytes; 512 leaves room for a
/// long qualified-signer Name without accepting arbitrary input).
pub const MAX_ATTEST_LEN: usize = 512;

/// What the sealed state pins (REQ-r9 §2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TpmAnchor {
    /// The TPM's attestation key, SEC1 uncompressed P-256.
    pub ak_pk: [u8; 65],
    /// The Name of the counter index (`TPMA_NV_COUNTER`), SHA-256 Name.
    pub nv_name: [u8; NV_NAME_LEN],
    /// The counter value this blob expects the TPM to certify.
    pub expected: u64,
}

impl TpmAnchor {
    /// Structural check at anchoring: a valid P-256 point and a SHA-256 Name.
    pub fn well_formed(&self) -> bool {
        crate::update::parse_p256_pubkey(&self.ak_pk).is_some()
            && self.nv_name[0] == (ALG_SHA256 >> 8) as u8
            && self.nv_name[1] == (ALG_SHA256 & 0xFF) as u8
    }
}

/// A bounds-checked big-endian cursor. Every read returns `None` past the end.
struct Be<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Be<'a> {
    fn new(b: &'a [u8]) -> Self {
        Be { b, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.b.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }
    fn u16(&mut self) -> Option<u16> {
        let s = self.take(2)?;
        Some(u16::from_be_bytes([s[0], s[1]]))
    }
    fn u32(&mut self) -> Option<u32> {
        let s = self.take(4)?;
        Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn u64(&mut self) -> Option<u64> {
        let s = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Some(u64::from_be_bytes(a))
    }
    /// `TPM2B_*`: a u16 length then that many bytes, the length capped at `max`.
    fn tpm2b(&mut self, max: usize) -> Option<&'a [u8]> {
        let n = usize::from(self.u16()?);
        if n > max {
            return None;
        }
        self.take(n)
    }
    fn at_end(&self) -> bool {
        self.pos == self.b.len()
    }
}

/// The fields of an NV attestation this verifier cares about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NvAttest {
    /// `extraData` — must be the enclave's nonce.
    pub extra: [u8; 32],
    /// `attested.nv.indexName`.
    pub index_name: [u8; NV_NAME_LEN],
    /// The counter the TPM certified (8 bytes big-endian at offset 0).
    pub counter: u64,
}

/// Parse a `TPMS_ATTEST` of type `TPM_ST_ATTEST_NV`. Anything unexpected → `TPM_PARSE`, except
/// the two pinned fields that get their own reasons downstream (returned raw here).
pub fn parse_nv_attest(attest: &[u8]) -> Result<NvAttest, Reason> {
    if attest.len() > MAX_ATTEST_LEN {
        return Err(Reason::TpmParse);
    }
    let mut r = Be::new(attest);
    let p = || Reason::TpmParse;
    if r.u32().ok_or_else(p)? != TPM_GENERATED {
        return Err(p());
    }
    if r.u16().ok_or_else(p)? != ST_ATTEST_NV {
        return Err(p());
    }
    // qualifiedSigner: TPM2B_NAME (any name algorithm; the signature binds the key, not this field)
    let _signer = r.tpm2b(68).ok_or_else(p)?;
    // extraData: TPM2B_DATA — the enclave's nonce, exactly 32 bytes
    let extra_b = r.tpm2b(64).ok_or_else(p)?;
    if extra_b.len() != 32 {
        return Err(Reason::TpmNonce);
    }
    let mut extra = [0u8; 32];
    extra.copy_from_slice(extra_b);
    // clockInfo: clock u64, resetCount u32, restartCount u32, safe u8 — read, not trusted
    r.u64().ok_or_else(p)?;
    r.u32().ok_or_else(p)?;
    r.u32().ok_or_else(p)?;
    let safe = r.u8().ok_or_else(p)?;
    if safe > 1 {
        return Err(p());
    }
    // firmwareVersion u64
    r.u64().ok_or_else(p)?;
    // attested = TPMS_NV_CERTIFY_INFO { indexName TPM2B_NAME, offset u16, nvContents TPM2B_MAX_NV_BUFFER }
    let name_b = r.tpm2b(68).ok_or_else(p)?;
    if name_b.len() != NV_NAME_LEN {
        return Err(Reason::TpmIndex);
    }
    let mut index_name = [0u8; NV_NAME_LEN];
    index_name.copy_from_slice(name_b);
    if r.u16().ok_or_else(p)? != 0 {
        return Err(p());
    }
    let contents = r.tpm2b(64).ok_or_else(p)?;
    if contents.len() != 8 {
        return Err(p());
    }
    let mut c = [0u8; 8];
    c.copy_from_slice(contents);
    let counter = u64::from_be_bytes(c);
    if !r.at_end() {
        return Err(p());
    }
    Ok(NvAttest {
        extra,
        index_name,
        counter,
    })
}

/// Verify a certify proof against the anchor and the nonce the enclave issued for this call.
/// Returns the certified counter when it equals the expected one. The order of checks gives each
/// mutation its own reason: structure (`TPM_PARSE`), nonce (`TPM_NONCE`), index (`TPM_INDEX`),
/// signature (`TPM_SIG`), value (`STATE_STALE`).
pub fn verify_nv_certify(
    attest: &[u8],
    sig: &[u8; 64],
    anchor: &TpmAnchor,
    nonce: &[u8; 32],
) -> Result<u64, Reason> {
    let a = parse_nv_attest(attest)?;
    if a.extra != *nonce {
        return Err(Reason::TpmNonce);
    }
    if a.index_name != anchor.nv_name {
        return Err(Reason::TpmIndex);
    }
    // The TPM signs SHA-256(attest) with the AK (TPM_ALG_ECDSA / SHA-256); the host hands the
    // signature as raw r ‖ s with s normalized low (a TPM may emit a high s; both halves of the
    // pair verify the same message).
    if !verify_p256(&anchor.ak_pk, &crate::sha256(attest), sig) {
        return Err(Reason::TpmSig);
    }
    if a.counter != anchor.expected {
        return Err(Reason::StateStale);
    }
    Ok(a.counter)
}

/// Build the canonical `TPMS_ATTEST` bytes an honest TPM would produce for these fields — used by
/// the software stand-in and the tests (never by the enclave).
pub fn build_nv_attest(
    signer_name: &[u8],
    nonce: &[u8; 32],
    index_name: &[u8; NV_NAME_LEN],
    counter: u64,
) -> alloc::vec::Vec<u8> {
    let mut v = alloc::vec::Vec::with_capacity(200);
    v.extend_from_slice(&TPM_GENERATED.to_be_bytes());
    v.extend_from_slice(&ST_ATTEST_NV.to_be_bytes());
    v.extend_from_slice(&(signer_name.len() as u16).to_be_bytes());
    v.extend_from_slice(signer_name);
    v.extend_from_slice(&32u16.to_be_bytes());
    v.extend_from_slice(nonce);
    v.extend_from_slice(&0u64.to_be_bytes()); // clock
    v.extend_from_slice(&0u32.to_be_bytes()); // resetCount
    v.extend_from_slice(&0u32.to_be_bytes()); // restartCount
    v.push(1); // safe
    v.extend_from_slice(&0u64.to_be_bytes()); // firmwareVersion
    v.extend_from_slice(&(NV_NAME_LEN as u16).to_be_bytes());
    v.extend_from_slice(index_name);
    v.extend_from_slice(&0u16.to_be_bytes()); // offset
    v.extend_from_slice(&8u16.to_be_bytes());
    v.extend_from_slice(&counter.to_be_bytes());
    v
}
