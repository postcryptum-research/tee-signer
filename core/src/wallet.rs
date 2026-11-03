//! In-enclave BIP32 derivation and script matching (invariants I1, I3, I4).
//!
//! Everything a PSBT says about keys and paths is a *hint*: the enclave derives the key itself
//! from its own account key and compares the resulting script to the one in the transaction.
//! A hint that does not reproduce the script is a refusal, never a fallback.

use alloc::vec::Vec;

use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpub};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{CompressedPublicKey, ScriptBuf};

use crate::mandate::{AccountPath, Matcher};

/// The wallet's account-level public key with its origin. Built by the enclave from the sealed
/// master key at load; built by tests from an xpub.
#[derive(Clone, Debug)]
pub struct Account {
    /// Master fingerprint.
    pub fingerprint: [u8; 4],
    /// Account path (hardened components).
    pub path: AccountPath,
    /// Account-level xpub.
    pub xpub: Xpub,
}

/// A fully specified own key: branch and index under the account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnPath {
    /// 0 = receive, 1 = change.
    pub branch: u32,
    /// Child index (non-hardened).
    pub index: u32,
}

impl Account {
    /// The derivation path of the account itself, `m/purpose'/coin'/account'`.
    pub fn account_derivation_path(&self) -> Option<DerivationPath> {
        let p = ChildNumber::from_hardened_idx(self.path.purpose).ok()?;
        let c = ChildNumber::from_hardened_idx(self.path.coin).ok()?;
        let a = ChildNumber::from_hardened_idx(self.path.account).ok()?;
        Some(DerivationPath::from(alloc::vec![p, c, a]))
    }

    /// Interpret a PSBT origin `(fingerprint, path)` as one of our own paths. `None` if it is not
    /// ours: different fingerprint, not under the account, wrong depth, hardened leaf, branch > 1.
    pub fn own_path_from_origin(&self, fp: &Fingerprint, path: &DerivationPath) -> Option<OwnPath> {
        if fp.as_bytes() != &self.fingerprint {
            return None;
        }
        let v: Vec<ChildNumber> = path.to_u32_vec().into_iter().map(ChildNumber::from).collect();
        if v.len() != 5 {
            return None;
        }
        let want = [
            ChildNumber::from_hardened_idx(self.path.purpose).ok()?,
            ChildNumber::from_hardened_idx(self.path.coin).ok()?,
            ChildNumber::from_hardened_idx(self.path.account).ok()?,
        ];
        if v[0] != want[0] || v[1] != want[1] || v[2] != want[2] {
            return None;
        }
        let branch = match v[3] {
            ChildNumber::Normal { index } if index <= 1 => index,
            _ => return None,
        };
        let index = match v[4] {
            ChildNumber::Normal { index } => index,
            _ => return None,
        };
        Some(OwnPath { branch, index })
    }

    /// Derive the compressed public key at `branch/index`.
    pub fn pubkey_at<C: bitcoin::secp256k1::Verification>(
        &self,
        secp: &Secp256k1<C>,
        p: OwnPath,
    ) -> Option<CompressedPublicKey> {
        let b = ChildNumber::from_normal_idx(p.branch).ok()?;
        let i = ChildNumber::from_normal_idx(p.index).ok()?;
        let child = self.xpub.derive_pub(secp, &[b, i]).ok()?;
        Some(child.to_pub())
    }

    /// The P2WPKH script of the key at `branch/index`.
    pub fn p2wpkh_at<C: bitcoin::secp256k1::Verification>(
        &self,
        secp: &Secp256k1<C>,
        p: OwnPath,
    ) -> Option<ScriptBuf> {
        let pk = self.pubkey_at(secp, p)?;
        Some(ScriptBuf::new_p2wpkh(&pk.wpubkey_hash()))
    }
}

/// Does `script` belong to the trusted destination described by `matcher`? Derives every
/// candidate for a descriptor (bounded by its gap and branches) and compares scripts.
pub fn matches_trusted<C: bitcoin::secp256k1::Verification>(
    secp: &Secp256k1<C>,
    matcher: &Matcher,
    script: &bitcoin::Script,
) -> bool {
    match matcher {
        Matcher::Address { script_pubkey } => script.as_bytes() == script_pubkey.as_slice(),
        Matcher::Descriptor { xpub, branches, gap } => {
            let Ok(x) = Xpub::decode(xpub) else { return false };
            // Only P2WPKH candidates are compared; a non-P2WPKH script can never match, so skip
            // the derivation entirely.
            if !script.is_p2wpkh() {
                return false;
            }
            for b in branches {
                let Ok(bn) = ChildNumber::from_normal_idx(*b) else { return false };
                let Ok(branch_key) = x.derive_pub(secp, &[bn]) else { return false };
                for i in 0..*gap {
                    let Ok(cn) = ChildNumber::from_normal_idx(i) else { return false };
                    let Ok(k) = branch_key.derive_pub(secp, &[cn]) else { return false };
                    let s = ScriptBuf::new_p2wpkh(&k.to_pub().wpubkey_hash());
                    if s.as_script() == script {
                        return true;
                    }
                }
            }
            false
        }
    }
}
