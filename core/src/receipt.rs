//! The receipt every signature leaves behind (`docs/DESIGN.md §4`), signed by the enclave
//! identity key. The owner's monitor verifies the chain of receipts and watches `seq`.

use alloc::string::String;
use alloc::vec::Vec;

use crate::encoding::{Dec, DecodeError, Enc};
use crate::judge::Summary;

/// Receipt encoding version.
pub const RECEIPT_VERSION: u16 = 1;
/// Signature domain.
pub const DOMAIN: &str = "tee-signer/receipt/v1";

/// A receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    /// Enclave id.
    pub enclave_id: [u8; 32],
    /// Sequence number.
    pub seq: u64,
    /// Txid of the unsigned transaction.
    pub txid: [u8; 32],
    /// Net outflow.
    pub net_outflow: u64,
    /// Σ unlisted.
    pub unlisted: u64,
    /// Σ per trusted label.
    pub trusted: Vec<(String, u64)>,
    /// Fee.
    pub fee: u64,
    /// Height at judgement.
    pub height: u32,
    /// Installed mandate hash.
    pub mandate_hash: [u8; 32],
    /// Pending mandate hash.
    pub pending_hash: Option<[u8; 32]>,
    /// Owner nonce.
    pub nonce: u64,
}

impl Receipt {
    /// Build from a judge summary.
    pub fn from_summary(enclave_id: [u8; 32], s: &Summary) -> Self {
        Receipt {
            enclave_id,
            seq: s.seq,
            txid: s.txid,
            net_outflow: s.net_outflow,
            unlisted: s.unlisted,
            trusted: s.trusted.clone(),
            fee: s.fee,
            height: s.height,
            mandate_hash: s.mandate_hash,
            pending_hash: s.pending_hash,
            nonce: s.nonce,
        }
    }

    /// Canonical bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::new();
        e.u16(RECEIPT_VERSION)
            .fixed(&self.enclave_id)
            .u64(self.seq)
            .fixed(&self.txid)
            .u64(self.net_outflow)
            .u64(self.unlisted)
            .list(&self.trusted, |e, (l, v)| {
                e.str(l).u64(*v);
            })
            .u64(self.fee)
            .u32(self.height)
            .fixed(&self.mandate_hash)
            .option(self.pending_hash.as_ref(), |e, h| {
                e.fixed(h);
            })
            .u64(self.nonce);
        e.finish()
    }

    /// Strict decode.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut d = Dec::new(bytes);
        if d.u16()? != RECEIPT_VERSION {
            return Err(DecodeError);
        }
        let r = Receipt {
            enclave_id: d.fixed()?,
            seq: d.u64()?,
            txid: d.fixed()?,
            net_outflow: d.u64()?,
            unlisted: d.u64()?,
            trusted: d.list(crate::mandate::bounds::MAX_TRUSTED, |d| {
                Ok((d.str(crate::mandate::bounds::MAX_LABEL)?, d.u64()?))
            })?,
            fee: d.u64()?,
            height: d.u32()?,
            mandate_hash: d.fixed()?,
            pending_hash: d.option(|d| d.fixed())?,
            nonce: d.u64()?,
        };
        d.finish()?;
        Ok(r)
    }

    /// The digest the identity key signs.
    pub fn digest(&self) -> [u8; 32] {
        crate::domain_digest(DOMAIN, &self.encode())
    }
}
