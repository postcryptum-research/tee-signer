//! In-enclave BIP32 derivation and script matching (invariants I1, I3, I4).
//!
//! Everything a PSBT says about keys and paths is a *hint*: the enclave derives the key itself
//! from its own account key and compares the resulting script to the one in the transaction.
//! A hint that does not reproduce the script is a refusal, never a fallback.

use alloc::vec::Vec;

use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpub};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{CompressedPublicKey, ScriptBuf};

use crate::mandate::{bounds, AccountPath, Matcher, TrustedDest};
use crate::reason::Reason;

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
    pub fn p2wpkh_at<C: bitcoin::secp256k1::Verification>(&self, secp: &Secp256k1<C>, p: OwnPath) -> Option<ScriptBuf> {
        let pk = self.pubkey_at(secp, p)?;
        Some(ScriptBuf::new_p2wpkh(&pk.wpubkey_hash()))
    }
}

/// Does `script` belong to the trusted destination described by `matcher`? Derives every
/// candidate for a descriptor (bounded by its gap and branches) and compares scripts. Since R11 the
/// production path is `match_trusted_outputs` (one pass over all outputs); this per-output walk is the
/// reference the tests hold it against.
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

/// R11 (C-EXT1-4): the derivation bound of one trusted-destination scan — the validated worst case
/// `bounds::MAX_TRUSTED × bounds::MAX_BRANCHES × bounds::MAX_GAP` = 64 × 2 × 1000 candidate keys. A mandate
/// that passed `validate` can never need more, so for a valid mandate the refusal is unreachable; the counter
/// makes the bound explicit in the code and testable (`core/tests/trusted_scan.rs`). The per-branch key
/// derivations (at most `MAX_TRUSTED × MAX_BRANCHES` = 128) are not counted: the count is the candidates.
pub const DERIVATION_CAP: u32 = 128_000;

/// What one trusted-destination scan found: the destination index per output (in the order the scripts were
/// given; `None` = unlisted) and how many candidate keys it derived.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedMatches {
    /// Per output, the first trusted destination (list order) whose matcher matched it.
    pub dest: Vec<Option<usize>>,
    /// Candidate keys derived (`Σ branches × gap` over the descriptors that were scanned).
    pub derivations: u32,
}

/// R11 (C-EXT1-4): every output against every trusted destination in ONE pass — a descriptor's candidate keys
/// are derived once and each compared against every output still unmatched, so the cost is
/// `Σ_trusted(branches × gap)` derivations whatever the number of outputs (the per-output `matches_trusted`
/// costs `outputs × Σ`). The result is the one the per-output walk gives: an output takes the FIRST destination
/// in list order whose matcher matches it, and an output already matched is never re-matched. `matches_trusted`
/// stays as the reference the tests compare this against. The derivations are counted as they happen and the
/// scan refuses `PolicyTooExpensive` the moment the count would pass `cap` — during the scan, not at its end
/// (production passes `DERIVATION_CAP`; the tests pass small caps).
pub fn match_trusted_outputs<C: bitcoin::secp256k1::Verification>(
    secp: &Secp256k1<C>,
    trusted: &[TrustedDest],
    scripts: &[&bitcoin::Script],
    cap: u32,
) -> Result<TrustedMatches, Reason> {
    let mut dest: Vec<Option<usize>> = alloc::vec![None; scripts.len()];
    let mut derivations: u32 = 0;
    for (di, d) in trusted.iter().enumerate() {
        match &d.matcher {
            Matcher::Address { script_pubkey } => {
                for (slot, s) in dest.iter_mut().zip(scripts) {
                    if slot.is_none() && s.as_bytes() == script_pubkey.as_slice() {
                        *slot = Some(di);
                    }
                }
            }
            Matcher::Descriptor { xpub, branches, gap } => {
                // only a P2WPKH output can match a wpkh descriptor: with none left unmatched there is nothing
                // to derive (the per-output walk skips the derivation for a non-P2WPKH script the same way)
                if !dest.iter().zip(scripts).any(|(slot, s)| slot.is_none() && s.is_p2wpkh()) {
                    continue;
                }
                let Ok(x) = Xpub::decode(xpub) else { continue };
                for b in branches {
                    let Ok(bn) = ChildNumber::from_normal_idx(*b) else { break };
                    let Ok(branch_key) = x.derive_pub(secp, &[bn]) else { break };
                    for i in 0..*gap {
                        let Ok(cn) = ChildNumber::from_normal_idx(i) else { break };
                        derivations = derivations.checked_add(1).ok_or(Reason::PolicyTooExpensive)?;
                        if derivations > cap {
                            return Err(Reason::PolicyTooExpensive);
                        }
                        let Ok(k) = branch_key.derive_pub(secp, &[cn]) else { break };
                        let s = ScriptBuf::new_p2wpkh(&k.to_pub().wpubkey_hash());
                        for (slot, o) in dest.iter_mut().zip(scripts) {
                            if slot.is_none() && s.as_script() == *o {
                                *slot = Some(di);
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(TrustedMatches { dest, derivations })
}

/// `DERIVATION_CAP` is the validated worst case and nothing else (the test `cap_is_the_bounds_product` holds it).
pub fn derivation_cap_from_bounds() -> Option<u32> {
    u32::try_from(bounds::MAX_TRUSTED)
        .ok()?
        .checked_mul(u32::try_from(bounds::MAX_BRANCHES).ok()?)?
        .checked_mul(bounds::MAX_GAP)
}
