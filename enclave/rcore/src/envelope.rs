//! The seal envelope (`docs/ENCLAVE.md §2`): the secrets beside the core state, canonical bytes,
//! sealed under the MRENCLAVE policy with a fixed AAD.

use alloc::vec::Vec;

use signer_core::encoding::{Dec, DecodeError, Enc};
use signer_core::state::State;
use zeroize::Zeroize;

/// Envelope version.
pub const VERSION: u16 = 1;
/// Sealing AAD.
pub const AAD: &[u8] = b"tee-signer/envelope/v1";

/// The two-phase sign record: what `JUDGE` charged for, what `SIGN` may sign.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LastJudged {
    /// SHA-256 of the exact PSBT bytes judged (hints included — a different PSBT with the same
    /// txid is a different request).
    pub psbt_hash: [u8; 32],
    /// Txid of the unsigned transaction.
    pub txid: [u8; 32],
    /// The state's sequence after the charge.
    pub seq: u64,
    /// The receipt (canonical, unsigned) the judge produced.
    pub receipt: Vec<u8>,
}

/// What the sealed blob contains. `state` is `None` between `INIT` and `INSTALL`.
pub struct Envelope {
    /// Network byte.
    pub network: u8,
    /// BIP39 entropy (32 bytes). The only copy.
    pub seed: [u8; 32],
    /// Identity secret key (secp256k1), never seed-derived.
    pub identity_sk: [u8; 32],
    /// Owner key bound at `INIT`.
    pub owner_pk: [u8; 65],
    /// Recovery key bound at `INIT`.
    pub recovery_pk: [u8; 65],
    /// Core state, once a mandate is installed.
    pub state: Option<State>,
    /// Two-phase sign record.
    pub last_judged: Option<LastJudged>,
}

impl Drop for Envelope {
    fn drop(&mut self) {
        self.seed.zeroize();
        self.identity_sk.zeroize();
    }
}

impl Envelope {
    /// Canonical plaintext.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::new();
        e.u16(VERSION)
            .u8(self.network)
            .fixed(&self.seed)
            .fixed(&self.identity_sk)
            .fixed(&self.owner_pk)
            .fixed(&self.recovery_pk)
            .option(self.state.as_ref(), |e, s| {
                e.bytes(&s.encode());
            })
            .option(self.last_judged.as_ref(), |e, l| {
                e.fixed(&l.psbt_hash).fixed(&l.txid).u64(l.seq).bytes(&l.receipt);
            });
        e.finish()
    }

    /// Strict decode of the plaintext.
    pub fn decode(b: &[u8]) -> Result<Self, DecodeError> {
        let mut d = Dec::new(b);
        if d.u16()? != VERSION {
            return Err(DecodeError);
        }
        let network = d.u8()?;
        let seed = d.fixed()?;
        let identity_sk = d.fixed()?;
        let owner_pk = d.fixed()?;
        let recovery_pk = d.fixed()?;
        let state = d.option(|d| State::decode(&d.bytes(signer_core::proto::limits::MAX_SEALED)?))?;
        let last_judged = d.option(|d| {
            Ok(LastJudged {
                psbt_hash: d.fixed()?,
                txid: d.fixed()?,
                seq: d.u64()?,
                receipt: d.bytes(signer_core::proto::limits::MAX_SMALL)?,
            })
        })?;
        d.finish()?;
        Ok(Envelope { network, seed, identity_sk, owner_pk, recovery_pk, state, last_judged })
    }

    /// Seal: canonical plaintext → sealed bytes. The plaintext copy is zeroized.
    pub fn seal(&self) -> Option<Vec<u8>> {
        let mut plain = self.encode();
        let out = crate::sgx::seal(AAD, &plain);
        plain.zeroize();
        out
    }

    /// Unseal untrusted host bytes: MAC verified by the SDK, AAD checked, then strict decode.
    pub fn unseal(sealed: &[u8]) -> Option<Envelope> {
        let (aad, mut plain) = crate::sgx::unseal(sealed)?;
        if aad != AAD {
            plain.zeroize();
            return None;
        }
        let env = Envelope::decode(&plain).ok();
        plain.zeroize();
        env
    }
}
