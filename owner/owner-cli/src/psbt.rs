//! PSBT helpers for the owner's manual sends and the end-to-end test: build (previous transaction
//! from an Esplora API, origin hints for the enclave), finalize P2WPKH, broadcast. BTCPay does
//! all of this itself in R3; these exist so a merchant can move coins without BTCPay and so the
//! R2 signet run has a path.

use std::str::FromStr;

use anyhow::{anyhow, bail, Result};
use bitcoin::absolute::LockTime;
use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpub};
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::transaction::Version;
use bitcoin::{Address, Amount, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use signer_core::mandate::Network;

fn child(xpub: &Xpub, branch: u32, index: u32) -> Result<bitcoin::CompressedPublicKey> {
    let secp = Secp256k1::new();
    Ok(xpub.derive_pub(&secp, &[ChildNumber::from_normal_idx(branch)?, ChildNumber::from_normal_idx(index)?])?.to_pub())
}

pub fn address(xpub: &str, net: Network, branch: u32, index: u32) -> Result<String> {
    let x = Xpub::from_str(xpub)?;
    let pk = child(&x, branch, index)?;
    Ok(Address::p2wpkh(&pk, net.to_bitcoin()).to_string())
}

fn origin(fp: &str, coin: u32, branch: u32, index: u32) -> Result<(Fingerprint, DerivationPath)> {
    let f = <[u8; 4]>::try_from(hex::decode(fp)?.as_slice()).map_err(|_| anyhow!("fingerprint"))?;
    Ok((
        Fingerprint::from(f),
        DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(84)?,
            ChildNumber::from_hardened_idx(coin)?,
            ChildNumber::from_hardened_idx(0)?,
            ChildNumber::from_normal_idx(branch)?,
            ChildNumber::from_normal_idx(index)?,
        ]),
    ))
}

#[allow(clippy::too_many_arguments)]
pub fn build(
    xpub: &str,
    fp: &str,
    net: Network,
    esplora: &str,
    utxo: &str,
    branch: u32,
    index: u32,
    to: &str,
    amount: u64,
    fee: u64,
    change_index: u32,
) -> Result<String> {
    let x = Xpub::from_str(xpub)?;
    let (txid_s, vout_s) = utxo.split_once(':').ok_or_else(|| anyhow!("--utxo txid:vout"))?;
    let txid = Txid::from_str(txid_s)?;
    let vout: u32 = vout_s.parse()?;
    let hex_tx = reqwest::blocking::get(format!("{}/tx/{txid}/hex", esplora.trim_end_matches('/')))?.error_for_status()?.text()?;
    let prev: Transaction = deserialize(&hex::decode(hex_tx.trim())?)?;
    if prev.compute_txid() != txid {
        bail!("esplora returned a different transaction");
    }
    let prevout = prev.output.get(vout as usize).ok_or_else(|| anyhow!("vout out of range"))?;
    let own_pk = child(&x, branch, index)?;
    let own_spk = ScriptBuf::new_p2wpkh(&own_pk.wpubkey_hash());
    if prevout.script_pubkey != own_spk {
        bail!("that output is not the wallet's address at {branch}/{index}");
    }
    let in_amount = prevout.value.to_sat();
    let change = in_amount.checked_sub(amount).and_then(|v| v.checked_sub(fee)).ok_or_else(|| anyhow!("amount + fee exceed the coin"))?;
    let dest = Address::from_str(to)?.require_network(net.to_bitcoin())?;
    let mut outputs = vec![TxOut { value: Amount::from_sat(amount), script_pubkey: dest.script_pubkey() }];
    let change_pk = child(&x, 1, change_index)?;
    if change >= 546 {
        outputs.push(TxOut { value: Amount::from_sat(change), script_pubkey: ScriptBuf::new_p2wpkh(&change_pk.wpubkey_hash()) });
    }
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn { previous_output: OutPoint { txid, vout }, script_sig: ScriptBuf::new(), sequence: Sequence::ENABLE_RBF_NO_LOCKTIME, witness: Witness::new() }],
        output: outputs,
    };
    let mut psbt = Psbt::from_unsigned_tx(tx)?;
    psbt.inputs[0].non_witness_utxo = Some(prev);
    psbt.inputs[0].bip32_derivation.insert(own_pk.0, origin(fp, net.coin_type(), branch, index)?);
    if change >= 546 {
        psbt.outputs[1].bip32_derivation.insert(change_pk.0, origin(fp, net.coin_type(), 1, change_index)?);
    }
    use base64::Engine;
    Ok(base64::engine::general_purpose::STANDARD.encode(psbt.serialize()))
}

fn parse_psbt(s: &str) -> Result<Psbt> {
    if let Ok(b) = hex::decode(s.trim()) {
        if let Ok(p) = Psbt::deserialize(&b) {
            return Ok(p);
        }
    }
    use base64::Engine;
    let b = base64::engine::general_purpose::STANDARD.decode(s.trim())?;
    Ok(Psbt::deserialize(&b)?)
}

pub fn finalize(s: &str) -> Result<String> {
    let mut psbt = parse_psbt(s)?;
    for input in psbt.inputs.iter_mut() {
        if input.final_script_witness.is_some() {
            continue;
        }
        if input.partial_sigs.len() != 1 {
            bail!("an input has {} partial signatures; expected 1", input.partial_sigs.len());
        }
        let (pk, sig) = input.partial_sigs.iter().next().map(|(k, v)| (*k, *v)).unwrap();
        let cpk = bitcoin::CompressedPublicKey::try_from(pk)?;
        input.final_script_witness = Some(Witness::p2wpkh(&sig, &cpk.0));
        input.partial_sigs.clear();
        input.sighash_type = None;
        input.bip32_derivation.clear();
    }
    let tx = psbt.extract_tx()?;
    Ok(hex::encode(serialize(&tx)))
}

pub fn broadcast(esplora: &str, tx_hex: &str) -> Result<String> {
    let r = reqwest::blocking::Client::new().post(format!("{}/tx", esplora.trim_end_matches('/'))).body(tx_hex.trim().to_string()).send()?;
    let status = r.status();
    let text = r.text()?;
    if !status.is_success() {
        bail!("broadcast: {status} {text}");
    }
    Ok(text)
}
