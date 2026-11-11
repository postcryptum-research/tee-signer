//! PSBT → classified transaction (invariants I1–I4, I7, I8 structure).
//!
//! Every input and output is classified by *what the enclave can derive or match itself*:
//! - an input is **own** only if the PSBT's origin hint names our fingerprint and account, and the
//!   key the enclave derives at that path reproduces the previous output's script (I1);
//! - every input — own or foreign — must carry the **full previous transaction** whose txid is
//!   the outpoint's, and amounts come from it (I2);
//! - an output is **own** only if its origin hint names our fingerprint and account, the index is
//!   within the sealed bound plus the mandate's gap, and the derived script matches (I3);
//! - an output is **trusted** only if it matches a mandate destination (I4);
//! - everything else is **unlisted**, except a zero-value `OP_RETURN` under `opReturn = zero-value`.
//!
//! Host hints (`bip32_derivation`) are pointers to a derivation to verify, never decisions: a hint
//! that does not reproduce the script refuses the transaction. A missing hint on an own output
//! makes it count as unlisted (charged to the budget) — the safe direction.

use alloc::vec::Vec;

use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Psbt, Transaction};

use crate::mandate::{Mandate, OpReturnRule, ScriptType};
use crate::reason::{Reason, Refusal};
use crate::wallet::{matches_trusted, Account, OwnPath};

/// An input after classification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InputClass {
    /// The wallet's own; the enclave will sign it.
    Own {
        /// Branch/index under the account.
        path: OwnPath,
        /// Amount from the verified previous transaction.
        amount: u64,
        /// Script type.
        script_type: ScriptType,
    },
    /// Someone else's (payjoin). Never signed.
    Foreign {
        /// Amount from the verified previous transaction.
        amount: u64,
    },
}

/// An output after classification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutputClass {
    /// To one of the wallet's own keys (change or self-send).
    Own {
        /// Branch/index.
        path: OwnPath,
        /// Amount.
        amount: u64,
    },
    /// To a trusted destination of the mandate.
    Trusted {
        /// Index into `mandate.destinations.trusted`.
        dest: usize,
        /// Amount.
        amount: u64,
    },
    /// Anything else.
    Unlisted {
        /// Amount.
        amount: u64,
    },
    /// A zero-value OP_RETURN tolerated by the mandate.
    OpReturn,
}

/// The classified transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Classified {
    /// Inputs, in transaction order.
    pub inputs: Vec<InputClass>,
    /// Outputs, in transaction order.
    pub outputs: Vec<OutputClass>,
    /// Transaction version.
    pub version: i32,
    /// Any input signals RBF.
    pub rbf: bool,
    /// Lower bound on the final vsize (conservative for the fee-rate check: a smaller vsize means
    /// a higher computed rate, i.e. more refusals, never fewer).
    pub vsize_lower_bound: u64,
    /// Txid of the unsigned transaction.
    pub txid: [u8; 32],
}

/// Byte sizes used for the vsize lower bound.
mod size {
    /// Outpoint 36 + empty scriptSig varint 1 + sequence 4.
    pub const INPUT_BASE: u64 = 41;
    /// Witness for a P2WPKH input: count 1, sig push 1 + 70 (shortest low-s DER), key push 1 + 33.
    pub const WITNESS_P2WPKH: u64 = 106;
    /// Witness for a foreign input, lower bound: P2TR key path, count 1 + push 1 + 64.
    pub const WITNESS_FOREIGN_LB: u64 = 66;
    /// Version 4 + locktime 4.
    pub const TX_FIXED: u64 = 8;
    /// Segwit marker and flag.
    pub const MARKER_FLAG: u64 = 2;
}

fn varint_len(n: u64) -> u64 {
    match n {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

#[cfg(feature = "hollow-test")]
/// Guard knobs for the hollow-test suite only (I2, I3). Absent from every non-test build.
#[derive(Clone, Copy, Debug)]
pub struct ClassifyGuards {
    /// I2: require `non_witness_utxo` and recompute its txid.
    pub require_prevtx: bool,
    /// I3: verify that the derived script reproduces an own output's script.
    pub verify_own_output_script: bool,
}

#[cfg(feature = "hollow-test")]
impl Default for ClassifyGuards {
    fn default() -> Self {
        ClassifyGuards { require_prevtx: true, verify_own_output_script: true }
    }
}

#[cfg(feature = "hollow-test")]
/// Classify with explicit guard knobs (hollow-test suite only).
pub fn classify_with_guards<C: bitcoin::secp256k1::Verification>(
    secp: &Secp256k1<C>,
    psbt_bytes: &[u8],
    account: &Account,
    mandate: &Mandate,
    own_index_bound: [u32; 2],
    g: ClassifyGuards,
) -> Result<Classified, Refusal> {
    let psbt = Psbt::deserialize(psbt_bytes).map_err(|_| Refusal::one(Reason::PsbtParse))?;
    classify_inner(secp, &psbt, account, mandate, own_index_bound, g)
}

/// Decode and classify. `own_index_bound` is the sealed `[receive, change]` bound.
pub fn classify<C: bitcoin::secp256k1::Verification>(
    secp: &Secp256k1<C>,
    psbt_bytes: &[u8],
    account: &Account,
    mandate: &Mandate,
    own_index_bound: [u32; 2],
) -> Result<Classified, Refusal> {
    let psbt = Psbt::deserialize(psbt_bytes).map_err(|_| Refusal::one(Reason::PsbtParse))?;
    classify_psbt(secp, &psbt, account, mandate, own_index_bound)
}

/// Classify an already-decoded PSBT.
pub fn classify_psbt<C: bitcoin::secp256k1::Verification>(
    secp: &Secp256k1<C>,
    psbt: &Psbt,
    account: &Account,
    mandate: &Mandate,
    own_index_bound: [u32; 2],
) -> Result<Classified, Refusal> {
    classify_inner(
        secp,
        psbt,
        account,
        mandate,
        own_index_bound,
        #[cfg(feature = "hollow-test")]
        ClassifyGuards::default(),
    )
}

fn classify_inner<C: bitcoin::secp256k1::Verification>(
    secp: &Secp256k1<C>,
    psbt: &Psbt,
    account: &Account,
    mandate: &Mandate,
    own_index_bound: [u32; 2],
    #[cfg(feature = "hollow-test")] g: ClassifyGuards,
) -> Result<Classified, Refusal> {
    #[cfg(feature = "hollow-test")]
    let (require_prevtx, verify_own_output_script) = (g.require_prevtx, g.verify_own_output_script);
    #[cfg(not(feature = "hollow-test"))]
    let (require_prevtx, verify_own_output_script) = (true, true);
    let tx: &Transaction = &psbt.unsigned_tx;
    let limits = &mandate.limits;

    // --- structure and bounds first, before any derivation work ---
    if psbt.version != 0 {
        return Err(Reason::PsbtParse.into());
    }
    if !psbt.unknown.is_empty() || !psbt.proprietary.is_empty() {
        return Err(Reason::UnknownField.into());
    }
    if tx.input.len() != psbt.inputs.len() || tx.output.len() != psbt.outputs.len() {
        return Err(Reason::PsbtParse.into());
    }
    if tx.input.is_empty() || tx.output.is_empty() {
        return Err(Reason::PsbtParse.into());
    }
    if tx.input.len() > limits.max_inputs as usize {
        return Err(Reason::TooManyInputs.into());
    }
    if tx.output.len() > limits.max_outputs as usize {
        return Err(Reason::TooManyOutputs.into());
    }
    // duplicate outpoints make the transaction invalid; refuse rather than double-count
    for (i, a) in tx.input.iter().enumerate() {
        if tx.input.iter().skip(i.saturating_add(1)).any(|b| b.previous_output == a.previous_output) {
            return Err(Reason::PsbtParse.into());
        }
    }
    let version = tx.version.0;
    let rbf = tx.input.iter().any(|i| i.sequence.is_rbf());

    let mut base: u64 = size::TX_FIXED
        .saturating_add(varint_len(tx.input.len() as u64))
        .saturating_add(varint_len(tx.output.len() as u64));
    let mut witness: u64 = size::MARKER_FLAG;

    // --- inputs ---
    let mut inputs = Vec::with_capacity(tx.input.len());
    for (i, txin) in tx.input.iter().enumerate() {
        let pin = &psbt.inputs[i];
        if !pin.unknown.is_empty() || !pin.proprietary.is_empty() {
            return Err(Reason::UnknownField.into());
        }
        // sighash: absent (defaults to ALL at signing) or exactly ALL
        if let Some(sh) = pin.sighash_type {
            if sh.to_u32() != 1 {
                return Err(Reason::Sighash.into());
            }
        }
        // I2: full previous transaction, txid recomputed and matched
        let prevout: bitcoin::TxOut = if require_prevtx {
            let prev = pin.non_witness_utxo.as_ref().ok_or_else(|| Refusal::one(Reason::InputNoPrevTx))?;
            if prev.compute_txid() != txin.previous_output.txid {
                return Err(Reason::InputPrevTxMismatch.into());
            }
            let p = prev
                .output
                .get(txin.previous_output.vout as usize)
                .ok_or_else(|| Refusal::one(Reason::InputPrevTxMismatch))?
                .clone();
            // if a witness_utxo is also present it must agree; a disagreeing pair is a lie somewhere
            if let Some(w) = &pin.witness_utxo {
                if *w != p {
                    return Err(Reason::InputPrevTxMismatch.into());
                }
            }
            p
        } else {
            // hollow-test only: the I2 guard removed — amounts taken from the host's witness_utxo
            pin.witness_utxo.clone().ok_or_else(|| Refusal::one(Reason::InputNoPrevTx))?
        };
        let amount = prevout.value.to_sat();
        base = base.saturating_add(size::INPUT_BASE);

        // I1: own only through a hint that the derivation reproduces
        let mut own: Option<OwnPath> = None;
        for (hint_pk, (fp, path)) in &pin.bip32_derivation {
            if let Some(p) = account.own_path_from_origin(fp, path) {
                let derived = account.pubkey_at(secp, p).ok_or_else(|| Refusal::one(Reason::InputNotOwn))?;
                if derived.0 != *hint_pk {
                    return Err(Reason::InputNotOwn.into());
                }
                let script = account.p2wpkh_at(secp, p).ok_or_else(|| Refusal::one(Reason::InputNotOwn))?;
                if script.as_script() != prevout.script_pubkey.as_script() {
                    return Err(Reason::InputNotOwn.into());
                }
                own = Some(p);
            }
        }
        match own {
            Some(path) => {
                if !prevout.script_pubkey.is_p2wpkh() {
                    return Err(Reason::InputScriptType.into());
                }
                if !mandate.wallet.script_types.contains(&ScriptType::P2wpkh) {
                    return Err(Reason::InputScriptType.into());
                }
                witness = witness.saturating_add(size::WITNESS_P2WPKH);
                inputs.push(InputClass::Own { path, amount, script_type: ScriptType::P2wpkh });
            }
            None => {
                witness = witness.saturating_add(size::WITNESS_FOREIGN_LB);
                inputs.push(InputClass::Foreign { amount });
            }
        }
    }

    // --- outputs ---
    let mut outputs = Vec::with_capacity(tx.output.len());
    for (i, txout) in tx.output.iter().enumerate() {
        let pout = &psbt.outputs[i];
        if !pout.unknown.is_empty() || !pout.proprietary.is_empty() {
            return Err(Reason::UnknownField.into());
        }
        let spk = &txout.script_pubkey;
        let amount = txout.value.to_sat();
        base = base.saturating_add(8).saturating_add(varint_len(spk.len() as u64)).saturating_add(spk.len() as u64);

        if spk.is_op_return() {
            if mandate.rules.op_return != OpReturnRule::ZeroValue || amount != 0 {
                return Err(Reason::OpReturnForbidden.into());
            }
            outputs.push(OutputClass::OpReturn);
            continue;
        }

        // I3: own through a verified hint, within bound + gap
        let mut own: Option<OwnPath> = None;
        for (hint_pk, (fp, path)) in &pout.bip32_derivation {
            if let Some(p) = account.own_path_from_origin(fp, path) {
                if p.branch > 1 {
                    continue;
                }
                let derived = account.pubkey_at(secp, p).ok_or_else(|| Refusal::one(Reason::OutputScriptType))?;
                if derived.0 != *hint_pk {
                    // a hint naming our path with someone else's key: not ours, and not honest
                    return Err(Reason::OutputScriptType.into());
                }
                let script = account.p2wpkh_at(secp, p).ok_or_else(|| Refusal::one(Reason::OutputScriptType))?;
                if verify_own_output_script && script.as_script() != spk.as_script() {
                    return Err(Reason::OutputScriptType.into());
                }
                let bound = own_index_bound[p.branch as usize];
                let limit = bound.saturating_add(limits.own_index_gap);
                if p.index >= limit {
                    return Err(Reason::ChangeIndexBeyondGap.into());
                }
                own = Some(p);
            }
        }
        if let Some(path) = own {
            outputs.push(OutputClass::Own { path, amount });
            continue;
        }
        // I4: trusted by match
        let mut trusted: Option<usize> = None;
        for (di, d) in mandate.destinations.trusted.iter().enumerate() {
            if matches_trusted(secp, &d.matcher, spk.as_script()) {
                trusted = Some(di);
                break;
            }
        }
        match trusted {
            Some(dest) => outputs.push(OutputClass::Trusted { dest, amount }),
            None => outputs.push(OutputClass::Unlisted { amount }),
        }
    }

    let weight = base.saturating_mul(4).saturating_add(witness);
    let vsize_lower_bound = weight.saturating_add(3).checked_div(4).unwrap_or(u64::MAX);
    let txid: [u8; 32] = *tx.compute_txid().as_ref();

    Ok(Classified { inputs, outputs, version, rbf, vsize_lower_bound, txid })
}
