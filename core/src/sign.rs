//! Signatures: BIP143 for the wallet's own P2WPKH inputs with the account private key, and
//! compact secp256k1 ECDSA for receipts with the enclave identity key.
//!
//! Signing happens only after `judge` returned `Accept` and the enclave sealed the charged state
//! (`docs/DESIGN.md §4`). This module never looks at the mandate: by the time it runs, the
//! decision is made and recorded.

use bitcoin::bip32::{ChildNumber, Xpriv};
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey, Signing, Verification};
use bitcoin::hashes::Hash;
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{Psbt, Witness};

use crate::classify::{Classified, InputClass};
use crate::reason::{Reason, Refusal};

/// Sign every own input of `psbt` (as classified) with keys derived from the account-level
/// `xpriv`. Returns the number of inputs signed. The PSBT must be the same bytes that were
/// classified; the classification's `Own` paths are the only keys ever opened.
pub fn sign_own_inputs<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    psbt: &mut Psbt,
    account_xpriv: &Xpriv,
    c: &Classified,
) -> Result<usize, Refusal> {
    if psbt.inputs.len() != c.inputs.len() {
        return Err(Reason::PsbtParse.into());
    }
    let tx = psbt.unsigned_tx.clone();
    let mut cache = SighashCache::new(&tx);
    let mut signed = 0usize;
    for (i, class) in c.inputs.iter().enumerate() {
        let InputClass::Own { path, amount, .. } = class else { continue };
        let b = ChildNumber::from_normal_idx(path.branch).map_err(|_| Refusal::one(Reason::InputNotOwn))?;
        let n = ChildNumber::from_normal_idx(path.index).map_err(|_| Refusal::one(Reason::InputNotOwn))?;
        let child = account_xpriv.derive_priv(secp, &[b, n]).map_err(|_| Refusal::one(Reason::InputNotOwn))?;
        let sk = child.private_key;
        let pk = bitcoin::CompressedPublicKey(sk.public_key(secp));
        let spk = bitcoin::ScriptBuf::new_p2wpkh(&pk.wpubkey_hash());
        // re-check against the previous output: the classification proved this, but signing a
        // script the key does not control would be a silent no-op worth refusing loudly
        let prev = psbt.inputs[i].non_witness_utxo.as_ref().ok_or_else(|| Refusal::one(Reason::InputNoPrevTx))?;
        let prevout = prev
            .output
            .get(tx.input[i].previous_output.vout as usize)
            .ok_or_else(|| Refusal::one(Reason::InputPrevTxMismatch))?;
        if prevout.script_pubkey != spk || prevout.value.to_sat() != *amount {
            return Err(Reason::InputNotOwn.into());
        }
        let sighash = cache
            .p2wpkh_signature_hash(i, &spk, bitcoin::Amount::from_sat(*amount), EcdsaSighashType::All)
            .map_err(|_| Refusal::one(Reason::PsbtParse))?;
        let msg = Message::from_digest(sighash.to_byte_array());
        let signature = secp.sign_ecdsa(&msg, &sk); // RFC6979, low-s normalised by the library
        let sig = bitcoin::ecdsa::Signature { signature, sighash_type: EcdsaSighashType::All };
        psbt.inputs[i].partial_sigs.insert(bitcoin::PublicKey::new(pk.0), sig);
        signed = signed.saturating_add(1);
    }
    Ok(signed)
}

/// Finalize the own P2WPKH inputs that carry exactly one partial signature. Convenience for the
/// host; the enclave does not need it. Returns the number finalized.
pub fn finalize_own_inputs(psbt: &mut Psbt, c: &Classified) -> usize {
    let mut n = 0usize;
    for (i, class) in c.inputs.iter().enumerate() {
        if !matches!(class, InputClass::Own { .. }) {
            continue;
        }
        let Some(input) = psbt.inputs.get_mut(i) else { continue };
        if input.partial_sigs.len() != 1 {
            continue;
        }
        let (pk, sig) = input.partial_sigs.iter().next().map(|(k, v)| (*k, *v)).expect("len 1");
        let Ok(cpk) = bitcoin::CompressedPublicKey::try_from(pk) else { continue };
        input.final_script_witness = Some(Witness::p2wpkh(&sig, &cpk.0));
        input.partial_sigs.clear();
        input.sighash_type = None;
        input.bip32_derivation.clear();
        n = n.saturating_add(1);
    }
    n
}

/// Compact (64-byte `r ‖ s`) secp256k1 ECDSA signature over a 32-byte digest, for receipts.
pub fn sign_digest_secp<C: Signing>(secp: &Secp256k1<C>, sk: &SecretKey, digest: &[u8; 32]) -> [u8; 64] {
    let msg = Message::from_digest(*digest);
    secp.sign_ecdsa(&msg, sk).serialize_compact()
}

/// Verify a compact secp256k1 ECDSA signature with a 33-byte compressed public key.
pub fn verify_digest_secp<C: Verification>(
    secp: &Secp256k1<C>,
    pk: &[u8; 33],
    digest: &[u8; 32],
    sig: &[u8; 64],
) -> bool {
    let Ok(pk) = bitcoin::secp256k1::PublicKey::from_slice(pk) else { return false };
    let Ok(sig) = bitcoin::secp256k1::ecdsa::Signature::from_compact(sig) else { return false };
    let msg = Message::from_digest(*digest);
    secp.verify_ecdsa(&msg, &sig, &pk).is_ok()
}
