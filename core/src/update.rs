//! Owner, recovery and witness messages: canonical encoding, domain-separated digests and P-256
//! ECDSA verification. The state transitions they cause live in `state`.
//!
//! Every message carries the `enclave_id` it is for and (owner/recovery messages) the next nonce,
//! and is signed over `domain_digest(DOMAIN, payload)`. One domain per message kind, so a
//! signature over one kind can never verify as another.

use alloc::vec::Vec;

use p256::ecdsa::signature::hazmat::PrehashVerifier;

use crate::encoding::{Dec, DecodeError, Enc};

/// Domain strings. Changing one is a wire-format change.
pub mod domain {
    /// `PolicyUpdate`.
    pub const POLICY: &str = "tee-signer/policy/v1";
    /// `Cancel`.
    pub const CANCEL: &str = "tee-signer/cancel/v1";
    /// `Unfreeze`.
    pub const UNFREEZE: &str = "tee-signer/unfreeze/v1";
    /// `Rearm`.
    pub const REARM: &str = "tee-signer/rearm/v1";
    /// `RotateOwner`.
    pub const ROTATE_OWNER: &str = "tee-signer/rotate-owner/v1";
    /// `Recover`.
    pub const RECOVER: &str = "tee-signer/recover/v1";
    /// `WitnessToken`.
    pub const WITNESS: &str = "tee-signer/witness/v1";
}

/// Parse a SEC1 uncompressed P-256 public key. `None` if not a valid point.
pub fn parse_p256_pubkey(bytes: &[u8; 65]) -> Option<p256::ecdsa::VerifyingKey> {
    if bytes[0] != 0x04 {
        return None;
    }
    p256::ecdsa::VerifyingKey::from_sec1_bytes(bytes).ok()
}

/// Verify a raw `r ‖ s` (64 bytes) P-256 ECDSA signature over a 32-byte digest.
pub fn verify_p256(pk: &[u8; 65], digest: &[u8; 32], sig: &[u8; 64]) -> bool {
    let Some(vk) = parse_p256_pubkey(pk) else { return false };
    let Ok(sig) = p256::ecdsa::Signature::from_slice(sig) else { return false };
    vk.verify_prehash(digest, &sig).is_ok()
}

/// Max canonical mandate length accepted inside a `PolicyUpdate` (generous; the decoder's own
/// bounds are far tighter in practice).
pub const MAX_MANDATE_BYTES: usize = 64 * 1024;

/// A signed message from the owner or the recovery key, or a witness token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    /// Install a new mandate (owner).
    PolicyUpdate {
        /// Target enclave.
        enclave_id: [u8; 32],
        /// `installed nonce + 1`.
        nonce: u64,
        /// Canonical mandate bytes.
        mandate: Vec<u8>,
        /// Owner signature.
        sig: [u8; 64],
    },
    /// Clear a pending loosening update (owner or recovery).
    Cancel {
        /// Target enclave.
        enclave_id: [u8; 32],
        /// Next nonce.
        nonce: u64,
        /// Signature.
        sig: [u8; 64],
    },
    /// Lift a freeze (owner).
    Unfreeze {
        /// Target enclave.
        enclave_id: [u8; 32],
        /// Next nonce.
        nonce: u64,
        /// Signature.
        sig: [u8; 64],
    },
    /// Re-arm after a `FRESHNESS_SEQ_BEHIND` (owner). `seq` is the sequence the owner asserts as
    /// current; the enclave adopts `max(own, seq)` so a replayed Rearm can never lower it.
    Rearm {
        /// Target enclave.
        enclave_id: [u8; 32],
        /// Next nonce.
        nonce: u64,
        /// Asserted sequence.
        seq: u64,
        /// Signature.
        sig: [u8; 64],
    },
    /// Rotate the owner key (owner; loosening, timelocked).
    RotateOwner {
        /// Target enclave.
        enclave_id: [u8; 32],
        /// Next nonce.
        nonce: u64,
        /// New owner key.
        new_owner_pk: [u8; 65],
        /// Signature by the current owner.
        sig: [u8; 64],
    },
    /// Hand the owner role to a new key (recovery key; immediate).
    Recover {
        /// Target enclave.
        enclave_id: [u8; 32],
        /// Next nonce.
        nonce: u64,
        /// New owner key.
        new_owner_pk: [u8; 65],
        /// Signature by the recovery key.
        sig: [u8; 64],
    },
    /// Freshness witness token.
    WitnessToken {
        /// Target enclave.
        enclave_id: [u8; 32],
        /// Chain tip the witness saw.
        tip_hash: [u8; 32],
        /// Its height.
        tip_height: u32,
        /// Highest receipt sequence the witness has seen from this enclave.
        last_seen_seq: u64,
        /// Issue counter (monitoring only; the two checks are tip and seq).
        issued: u64,
        /// Witness signature.
        sig: [u8; 64],
    },
}

const TAG_POLICY: u8 = 1;
const TAG_CANCEL: u8 = 2;
const TAG_UNFREEZE: u8 = 3;
const TAG_REARM: u8 = 4;
const TAG_ROTATE_OWNER: u8 = 5;
const TAG_RECOVER: u8 = 6;
const TAG_WITNESS: u8 = 7;

impl Message {
    /// The bytes that are signed (everything but the signature), and the domain.
    pub fn payload(&self) -> (&'static str, Vec<u8>) {
        let mut e = Enc::new();
        match self {
            Message::PolicyUpdate { enclave_id, nonce, mandate, .. } => {
                e.fixed(enclave_id).u64(*nonce).bytes(mandate);
                (domain::POLICY, e.finish())
            }
            Message::Cancel { enclave_id, nonce, .. } => {
                e.fixed(enclave_id).u64(*nonce);
                (domain::CANCEL, e.finish())
            }
            Message::Unfreeze { enclave_id, nonce, .. } => {
                e.fixed(enclave_id).u64(*nonce);
                (domain::UNFREEZE, e.finish())
            }
            Message::Rearm { enclave_id, nonce, seq, .. } => {
                e.fixed(enclave_id).u64(*nonce).u64(*seq);
                (domain::REARM, e.finish())
            }
            Message::RotateOwner { enclave_id, nonce, new_owner_pk, .. } => {
                e.fixed(enclave_id).u64(*nonce).fixed(new_owner_pk);
                (domain::ROTATE_OWNER, e.finish())
            }
            Message::Recover { enclave_id, nonce, new_owner_pk, .. } => {
                e.fixed(enclave_id).u64(*nonce).fixed(new_owner_pk);
                (domain::RECOVER, e.finish())
            }
            Message::WitnessToken { enclave_id, tip_hash, tip_height, last_seen_seq, issued, .. } => {
                e.fixed(enclave_id).fixed(tip_hash).u32(*tip_height).u64(*last_seen_seq).u64(*issued);
                (domain::WITNESS, e.finish())
            }
        }
    }

    /// The digest the signer signs.
    pub fn digest(&self) -> [u8; 32] {
        let (d, p) = self.payload();
        crate::domain_digest(d, &p)
    }

    /// The carried signature.
    pub fn sig(&self) -> &[u8; 64] {
        match self {
            Message::PolicyUpdate { sig, .. }
            | Message::Cancel { sig, .. }
            | Message::Unfreeze { sig, .. }
            | Message::Rearm { sig, .. }
            | Message::RotateOwner { sig, .. }
            | Message::Recover { sig, .. }
            | Message::WitnessToken { sig, .. } => sig,
        }
    }

    /// The enclave this message is addressed to.
    pub fn enclave_id(&self) -> &[u8; 32] {
        match self {
            Message::PolicyUpdate { enclave_id, .. }
            | Message::Cancel { enclave_id, .. }
            | Message::Unfreeze { enclave_id, .. }
            | Message::Rearm { enclave_id, .. }
            | Message::RotateOwner { enclave_id, .. }
            | Message::Recover { enclave_id, .. }
            | Message::WitnessToken { enclave_id, .. } => enclave_id,
        }
    }

    /// Verify the signature with `pk`.
    pub fn verify(&self, pk: &[u8; 65]) -> bool {
        verify_p256(pk, &self.digest(), self.sig())
    }

    /// Canonical wire encoding (tag, fields, signature).
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::new();
        match self {
            Message::PolicyUpdate { enclave_id, nonce, mandate, sig } => {
                e.u8(TAG_POLICY).fixed(enclave_id).u64(*nonce).bytes(mandate).fixed(sig);
            }
            Message::Cancel { enclave_id, nonce, sig } => {
                e.u8(TAG_CANCEL).fixed(enclave_id).u64(*nonce).fixed(sig);
            }
            Message::Unfreeze { enclave_id, nonce, sig } => {
                e.u8(TAG_UNFREEZE).fixed(enclave_id).u64(*nonce).fixed(sig);
            }
            Message::Rearm { enclave_id, nonce, seq, sig } => {
                e.u8(TAG_REARM).fixed(enclave_id).u64(*nonce).u64(*seq).fixed(sig);
            }
            Message::RotateOwner { enclave_id, nonce, new_owner_pk, sig } => {
                e.u8(TAG_ROTATE_OWNER).fixed(enclave_id).u64(*nonce).fixed(new_owner_pk).fixed(sig);
            }
            Message::Recover { enclave_id, nonce, new_owner_pk, sig } => {
                e.u8(TAG_RECOVER).fixed(enclave_id).u64(*nonce).fixed(new_owner_pk).fixed(sig);
            }
            Message::WitnessToken { enclave_id, tip_hash, tip_height, last_seen_seq, issued, sig } => {
                e.u8(TAG_WITNESS)
                    .fixed(enclave_id)
                    .fixed(tip_hash)
                    .u32(*tip_height)
                    .u64(*last_seen_seq)
                    .u64(*issued)
                    .fixed(sig);
            }
        }
        e.finish()
    }

    /// Strict decode.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut d = Dec::new(bytes);
        let m = match d.u8()? {
            TAG_POLICY => Message::PolicyUpdate {
                enclave_id: d.fixed()?,
                nonce: d.u64()?,
                mandate: d.bytes(MAX_MANDATE_BYTES)?,
                sig: d.fixed()?,
            },
            TAG_CANCEL => Message::Cancel { enclave_id: d.fixed()?, nonce: d.u64()?, sig: d.fixed()? },
            TAG_UNFREEZE => {
                Message::Unfreeze { enclave_id: d.fixed()?, nonce: d.u64()?, sig: d.fixed()? }
            }
            TAG_REARM => Message::Rearm {
                enclave_id: d.fixed()?,
                nonce: d.u64()?,
                seq: d.u64()?,
                sig: d.fixed()?,
            },
            TAG_ROTATE_OWNER => Message::RotateOwner {
                enclave_id: d.fixed()?,
                nonce: d.u64()?,
                new_owner_pk: d.fixed()?,
                sig: d.fixed()?,
            },
            TAG_RECOVER => Message::Recover {
                enclave_id: d.fixed()?,
                nonce: d.u64()?,
                new_owner_pk: d.fixed()?,
                sig: d.fixed()?,
            },
            TAG_WITNESS => Message::WitnessToken {
                enclave_id: d.fixed()?,
                tip_hash: d.fixed()?,
                tip_height: d.u32()?,
                last_seen_seq: d.u64()?,
                issued: d.u64()?,
                sig: d.fixed()?,
            },
            _ => return Err(DecodeError),
        };
        d.finish()?;
        Ok(m)
    }
}
