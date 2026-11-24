//! Phase 2, pass (ii): `classify` (F7) and `judge` (F8). A scripted PSBT generator over the vector fixtures
//! builds honest transactions and, on request, one host-asserted lie; the classify target checks the
//! enclave's verdict against the harness's own reading of the rules (I1–I4) and that no host-asserted field
//! can turn a refusal into an acceptance or change a counted amount; the judge target checks the accept
//! invariants (§1.4), the window charge and C-R10-4 (`disarms` exactly on the verified seq-behind token).
//! Every assertion names its oracle.

use std::collections::BTreeMap;

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use signer_core::classify::{classify, Classified, InputClass, OutputClass};
use signer_core::judge::{judge, Verdict};
use signer_core::mandate::{Mandate, OpReturnRule, PayjoinRule};
use signer_core::reason::{Reason, Refusal};
use signer_core::update::Message;
use signer_core::wallet::OwnPath;

use crate::fixtures::{self, foreign_spk, Wallet, ENCLAVE_ID};
use crate::seeds::honest;

const H: u32 = 250_010; // the honest fixture state's best height (seeds.rs)
const GAP: u32 = 100; // base mandate own_index_gap
const COLD_GAP: u32 = 20; // the cold descriptor's gap in the base mandate

fn secp() -> &'static Secp256k1<All> {
    static S: std::sync::OnceLock<Secp256k1<All>> = std::sync::OnceLock::new();
    S.get_or_init(Secp256k1::new)
}

fn code(r: &Refusal) -> &'static str {
    r.0.first().map(|x| x.code()).unwrap_or("")
}

// ------------------------------------------------------------------------------------------------
// the scripted PSBT
// ------------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InKind {
    OwnHinted,
    OwnUnhinted,
    Foreign,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutKind {
    Own,
    Cold,       // the trusted descriptor, within its gap
    ColdBeyond, // the cold wallet beyond the descriptor's gap: unlisted
    Unlisted,
    OpReturn,
}
#[derive(Clone, Copy, Debug)]
struct InSpec {
    kind: InKind,
    index: u32,
    amount: u64,
}
#[derive(Clone, Copy, Debug)]
struct OutSpec {
    kind: OutKind,
    index: u32,
    amount: u64,
}
/// One host-asserted lie (classify mode 1), applied to input/output `target`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lie {
    None,
    NoPrevtxWitnessUtxoOnly, // I2: no full previous tx, a witness_utxo that claims the amount
    DisagreeingWitnessUtxo,  // I2: the pair lies somewhere
    SwappedPrevtx,           // I2: a previous tx that is not the outpoint's
    HintOtherIndexKey,       // I1: our path named with another index's key
    HintOnForeign,           // I1: a foreign input dressed as ours
    OutHintForeignKey,       // I3: our path with someone else's key on an output
    OutIndexBeyondGap,       // I3: an own output beyond bound + gap
    SighashNone,             // sighash other than ALL
    DuplicateOutpoint,       // the same outpoint twice
    UnknownField,            // a proprietary/unknown PSBT field
    OutScriptNotOurs,        // I3: our key and path in the hint, someone else's script in the output
}

struct Spec {
    ins: Vec<InSpec>,
    outs: Vec<OutSpec>,
    version: i32,
    rbf: bool,
    lie: Lie,
    target: usize,
}

fn amount_of(lo: u8, hi: u8) -> u64 {
    match (lo, hi) {
        (0xff, 0xff) => u64::MAX - 1_000, // the overflow corner (judge sums)
        (0xfe, 0xff) => u64::MAX / 2 + 1, // two of these overflow a sum
        _ => 1_000 + u64::from(u16::from_le_bytes([lo, hi])) * 1_000,
    }
}

/// Parse `[n_in, n_out, version, flags, lie, target] ‖ n_in×[kind, index, amt_lo, amt_hi] ‖ n_out×[kind, index, amt_lo, amt_hi]`.
fn parse_spec(data: &[u8]) -> Option<Spec> {
    if data.len() < 6 {
        return None;
    }
    let n_in = 1 + usize::from(data[0] % 4);
    let n_out = 1 + usize::from(data[1] % 4);
    let version = match data[2] % 4 {
        0 => 1,
        1 | 2 => 2,
        _ => 3,
    };
    let rbf = data[3] & 1 != 0;
    let lie = match data[4] % 12 {
        0 => Lie::None,
        1 => Lie::NoPrevtxWitnessUtxoOnly,
        2 => Lie::DisagreeingWitnessUtxo,
        3 => Lie::SwappedPrevtx,
        4 => Lie::HintOtherIndexKey,
        5 => Lie::HintOnForeign,
        6 => Lie::OutHintForeignKey,
        7 => Lie::OutIndexBeyondGap,
        8 => Lie::SighashNone,
        9 => Lie::DuplicateOutpoint,
        10 => Lie::UnknownField,
        _ => Lie::OutScriptNotOurs,
    };
    let target = usize::from(data[5]);
    let body = &data[6..];
    if body.len() < 4 * (n_in + n_out) {
        return None;
    }
    let mut ins = Vec::new();
    for i in 0..n_in {
        let r = &body[4 * i..4 * i + 4];
        let kind = match r[0] % 3 {
            0 => InKind::OwnHinted,
            1 => InKind::OwnUnhinted,
            _ => InKind::Foreign,
        };
        ins.push(InSpec { kind, index: u32::from(r[1]), amount: amount_of(r[2], r[3]) });
    }
    let mut outs = Vec::new();
    for i in 0..n_out {
        let r = &body[4 * (n_in + i)..4 * (n_in + i) + 4];
        let kind = match r[0] % 5 {
            0 => OutKind::Own,
            1 => OutKind::Cold,
            2 => OutKind::ColdBeyond,
            3 => OutKind::Unlisted,
            _ => OutKind::OpReturn,
        };
        outs.push(OutSpec { kind, index: u32::from(r[1]), amount: amount_of(r[2], r[3]) });
    }
    Some(Spec { ins, outs, version, rbf, lie, target })
}

struct Fixtures {
    w: Wallet,
    cold: Wallet,
    foreign: Wallet,
}
fn fx() -> &'static Fixtures {
    static F: std::sync::OnceLock<Fixtures> = std::sync::OnceLock::new();
    F.get_or_init(|| Fixtures {
        w: fixtures::wallet(0x01),
        cold: fixtures::wallet(0x02),
        foreign: fixtures::wallet(0x77),
    })
}

fn out_spk(f: &Fixtures, o: &OutSpec) -> ScriptBuf {
    match o.kind {
        OutKind::Own => f.w.spk(o.index % 2, o.index / 2), // branch 0/1, index = idx/2
        OutKind::Cold => f.cold.spk(0, o.index % COLD_GAP),
        OutKind::ColdBeyond => f.cold.spk(0, COLD_GAP + o.index % 10),
        OutKind::Unlisted => foreign_spk(o.index),
        OutKind::OpReturn => ScriptBuf::new_op_return([0x42u8; 4]),
    }
}
fn own_out_path(o: &OutSpec) -> OwnPath {
    OwnPath { branch: o.index % 2, index: o.index / 2 }
}

/// Build the PSBT the spec describes, honest except for the one lie.
fn build(spec: &Spec) -> Psbt {
    let f = fx();
    let mut prevs = Vec::new();
    let mut txins: Vec<TxIn> = Vec::new();
    for (i, s) in spec.ins.iter().enumerate() {
        let spk = match s.kind {
            InKind::Foreign => f.foreign.spk(0, s.index),
            _ => f.w.spk(0, s.index),
        };
        let prev = fixtures::funding_tx(&[(spk, s.amount)], 1000 + i as u32);
        let mut outpoint = OutPoint { txid: prev.compute_txid(), vout: 0 };
        if spec.lie == Lie::DuplicateOutpoint && i == spec.target % spec.ins.len() && i > 0 {
            outpoint = txins[0].previous_output; // the same outpoint as input 0
        }
        txins.push(TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: if spec.rbf { Sequence::ENABLE_RBF_NO_LOCKTIME } else { Sequence::MAX },
            witness: Witness::new(),
        });
        prevs.push(prev);
    }
    let tx = Transaction {
        version: Version(spec.version),
        lock_time: LockTime::ZERO,
        input: txins,
        output: spec
            .outs
            .iter()
            .map(|o| TxOut {
                value: Amount::from_sat(if o.kind == OutKind::OpReturn { 0 } else { o.amount }),
                script_pubkey: out_spk(f, o),
            })
            .collect(),
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).expect("unsigned tx");
    for (i, s) in spec.ins.iter().enumerate() {
        psbt.inputs[i].non_witness_utxo = Some(prevs[i].clone());
        if s.kind == InKind::OwnHinted {
            psbt.inputs[i].bip32_derivation.insert(f.w.pubkey(0, s.index), f.w.origin(0, s.index));
        }
    }
    for (i, o) in spec.outs.iter().enumerate() {
        if o.kind == OutKind::Own {
            let p = own_out_path(o);
            psbt.outputs[i].bip32_derivation.insert(f.w.pubkey(p.branch, p.index), f.w.origin(p.branch, p.index));
        }
    }
    // the lie
    let ti = spec.target % spec.ins.len();
    let to = spec.target % spec.outs.len();
    match spec.lie {
        Lie::None | Lie::DuplicateOutpoint => {}
        Lie::NoPrevtxWitnessUtxoOnly => {
            let prev = psbt.inputs[ti].non_witness_utxo.take().expect("set above");
            let mut lying = prev.output[0].clone();
            lying.value = Amount::from_sat(lying.value.to_sat().saturating_mul(3).max(1));
            psbt.inputs[ti].witness_utxo = Some(lying);
        }
        Lie::DisagreeingWitnessUtxo => {
            let prev = psbt.inputs[ti].non_witness_utxo.clone().expect("set above");
            let mut lying = prev.output[0].clone();
            lying.value = Amount::from_sat(lying.value.to_sat().saturating_add(1));
            psbt.inputs[ti].witness_utxo = Some(lying);
        }
        Lie::SwappedPrevtx => {
            let spk = psbt.inputs[ti].non_witness_utxo.as_ref().expect("set above").output[0].script_pubkey.clone();
            psbt.inputs[ti].non_witness_utxo = Some(fixtures::funding_tx(&[(spk, spec.ins[ti].amount)], 7777));
        }
        Lie::HintOtherIndexKey => {
            let s = spec.ins[ti];
            psbt.inputs[ti].bip32_derivation.clear();
            psbt.inputs[ti].bip32_derivation.insert(f.w.pubkey(0, s.index.wrapping_add(1)), f.w.origin(0, s.index));
        }
        Lie::HintOnForeign => {
            let s = spec.ins[ti];
            psbt.inputs[ti].bip32_derivation.clear();
            psbt.inputs[ti].bip32_derivation.insert(f.w.pubkey(0, s.index), f.w.origin(0, s.index));
        }
        Lie::OutHintForeignKey => {
            let o = spec.outs[to];
            let p = own_out_path(&o);
            psbt.outputs[to].bip32_derivation.clear();
            psbt.outputs[to].bip32_derivation.insert(f.foreign.pubkey(0, 1), f.w.origin(p.branch, p.index));
        }
        Lie::OutIndexBeyondGap => {
            // rebuild the output as our own key at index GAP + k: a correct hint, a script that is ours, too far
            let o = spec.outs[to];
            let idx = GAP + o.index % 50;
            let branch = o.index % 2;
            psbt.unsigned_tx.output[to].script_pubkey = f.w.spk(branch, idx);
            psbt.outputs[to].bip32_derivation.clear();
            psbt.outputs[to].bip32_derivation.insert(f.w.pubkey(branch, idx), f.w.origin(branch, idx));
        }
        Lie::SighashNone => {
            psbt.inputs[ti].sighash_type =
                Some(bitcoin::psbt::PsbtSighashType::from(bitcoin::sighash::EcdsaSighashType::None));
        }
        Lie::UnknownField => {
            psbt.inputs[ti].unknown.insert(bitcoin::psbt::raw::Key { type_value: 0xf0, key: vec![0x01] }, vec![0x02]);
        }
        Lie::OutScriptNotOurs => {
            // an honest-looking hint (our key, our path) on an output paying someone else
            let o = spec.outs[to];
            let p = own_out_path(&o);
            psbt.unsigned_tx.output[to].script_pubkey = foreign_spk(7);
            psbt.outputs[to].bip32_derivation.clear();
            psbt.outputs[to]
                .bip32_derivation
                .insert(f.w.pubkey(p.branch, p.index % GAP), f.w.origin(p.branch, p.index % GAP));
        }
    }
    psbt
}

/// For the seed writer: the serialized PSBT a scripted spec builds (`[n_in, n_out, version, flags, lie, target] ‖ records`).
pub fn seed_psbt(spec_bytes: &[u8]) -> Option<Vec<u8>> {
    parse_spec(spec_bytes).map(|s| build(&s).serialize())
}

/// The harness's reading of the classifier's rules for an honest build (`Lie::None`).
fn expected_honest(spec: &Spec, m: &Mandate) -> Result<(Vec<InputClass>, Vec<OutputClass>), Reason> {
    if spec.outs.iter().any(|o| o.kind == OutKind::OpReturn) && m.rules.op_return == OpReturnRule::None {
        // op_return outputs come after all inputs are read; inputs have no refusal in an honest build
        return Err(Reason::OpReturnForbidden);
    }
    let mut ins = Vec::new();
    for s in &spec.ins {
        ins.push(match s.kind {
            InKind::OwnHinted => InputClass::Own {
                path: OwnPath { branch: 0, index: s.index },
                amount: s.amount,
                script_type: signer_core::mandate::ScriptType::P2wpkh,
            },
            _ => InputClass::Foreign { amount: s.amount },
        });
    }
    let mut outs = Vec::new();
    for o in &spec.outs {
        outs.push(match o.kind {
            OutKind::Own => {
                let p = own_out_path(o);
                if p.index >= GAP {
                    return Err(Reason::ChangeIndexBeyondGap);
                }
                OutputClass::Own { path: p, amount: o.amount }
            }
            OutKind::Cold => OutputClass::Trusted { dest: 0, amount: o.amount },
            OutKind::ColdBeyond | OutKind::Unlisted => OutputClass::Unlisted { amount: o.amount },
            OutKind::OpReturn => OutputClass::OpReturn,
        });
    }
    Ok((ins, outs))
}

/// The refusal the single lie must produce — or `None` when the lie does not bite on this spec (the
/// target input is not ours for an input lie, …), in which case the honest reading applies.
fn expected_lie(spec: &Spec) -> Option<Reason> {
    let ti = spec.target % spec.ins.len();
    let to = spec.target % spec.outs.len();
    let own_in = spec.ins[ti].kind == InKind::OwnHinted;
    match spec.lie {
        Lie::None => None,
        Lie::NoPrevtxWitnessUtxoOnly => Some(Reason::InputNoPrevTx),
        Lie::DisagreeingWitnessUtxo => Some(Reason::InputPrevTxMismatch),
        Lie::SwappedPrevtx => Some(Reason::InputPrevTxMismatch),
        Lie::HintOtherIndexKey => Some(Reason::InputNotOwn),
        Lie::HintOnForeign => {
            if spec.ins[ti].kind == InKind::Foreign {
                Some(Reason::InputNotOwn)
            } else if own_in {
                None
            } else {
                Some(Reason::InputNotOwn)
            }
        }
        Lie::OutHintForeignKey => {
            if spec.outs[to].kind == OutKind::OpReturn {
                None
            } else {
                Some(Reason::OutputScriptType)
            }
        }
        Lie::OutIndexBeyondGap => {
            if spec.outs[to].kind == OutKind::OpReturn {
                None
            } else {
                Some(Reason::ChangeIndexBeyondGap)
            }
        }
        Lie::SighashNone => Some(Reason::Sighash),
        Lie::DuplicateOutpoint => {
            if spec.ins.len() > 1 && ti > 0 {
                Some(Reason::PsbtParse)
            } else {
                None
            }
        }
        Lie::UnknownField => Some(Reason::UnknownField),
        Lie::OutScriptNotOurs => {
            if spec.outs[to].kind == OutKind::OpReturn {
                None
            } else {
                Some(Reason::OutputScriptType)
            }
        }
    }
}

fn mandate_for_classify(knob: u8) -> Mandate {
    let h = honest();
    let mut m = h.mandate.clone();
    if knob & 1 != 0 {
        m.rules.op_return = OpReturnRule::ZeroValue;
    }
    m
}

/// `mode ‖ …`: 0 raw PSBT bytes; 1 the scripted build, exact expectations; 2 the differential "the host never
/// decides": an honest build that classifies, then every lie in turn — never a different acceptance.
pub fn classify_target(data: &[u8]) {
    let Some((&mode, rest)) = data.split_first() else { return };
    let f = fx();
    let bound = [0u32, 0];
    match mode % 3 {
        0 => {
            let m = mandate_for_classify(0);
            if let Ok(c) = classify(secp(), rest, &f.w.account, &m, bound) {
                let psbt = Psbt::deserialize(rest).expect("F7: classified bytes do not deserialize");
                check_classified_against_psbt(&psbt, &c, bound);
            }
        }
        1 => {
            let Some((&knob, rest)) = rest.split_first() else { return };
            let Some(spec) = parse_spec(rest) else { return };
            let m = mandate_for_classify(knob);
            let psbt = build(&spec);
            let bytes = psbt.serialize();
            let r = classify(secp(), &bytes, &f.w.account, &m, bound);
            match (expected_lie(&spec), expected_honest(&spec, &m)) {
                (Some(want), _) => match &r {
                    Err(e) => {
                        // the lie's refusal, unless an earlier-checked honest refusal of the same build wins
                        let honest_err = expected_honest(&spec, &m).err();
                        let ok = code(e) == want.code() || honest_err.as_ref().is_some_and(|h| code(e) == h.code());
                        assert!(
                            ok,
                            "F7: lie {:?} on target {} refused as {}, expected {} (or the build's own {:?})",
                            spec.lie,
                            spec.target,
                            code(e),
                            want.code(),
                            honest_err.map(|h| h.code())
                        );
                    }
                    Ok(_) => panic!("F7: the host's lie {:?} was ACCEPTED (spec {:?})", spec.lie, spec.ins),
                },
                (None, Err(want)) => match &r {
                    Err(e) => assert_eq!(code(e), want.code(), "F7: honest build refused with another reason"),
                    Ok(_) => panic!("F7: an honest build the rules refuse ({}) was accepted", want.code()),
                },
                (None, Ok((ins, outs))) => {
                    let c = r.unwrap_or_else(|e| panic!("F7: an honest build was refused: {}", code(&e)));
                    assert_eq!(c.inputs, ins, "F7: input classes differ from the harness's reading");
                    assert_eq!(c.outputs, outs, "F7: output classes differ from the harness's reading");
                    assert_eq!(c.version, spec.version);
                    assert_eq!(c.rbf, spec.rbf);
                    assert_eq!(
                        c.txid,
                        psbt.unsigned_tx.compute_txid().to_byte_array(),
                        "F7: txid is not the unsigned tx's"
                    );
                    check_classified_against_psbt(&psbt, &c, bound);
                }
            }
        }
        _ => {
            let Some(spec0) = parse_spec(rest) else { return };
            let spec = Spec { lie: Lie::None, ..spec0 };
            let m = mandate_for_classify(0);
            let honest_psbt = build(&spec);
            let Ok(c0) = classify(secp(), &honest_psbt.serialize(), &f.w.account, &m, bound) else { return };
            // every lie: refused, or (for the hint lies that may not bite) a classification that signs no more
            for lie in [
                Lie::NoPrevtxWitnessUtxoOnly,
                Lie::DisagreeingWitnessUtxo,
                Lie::SwappedPrevtx,
                Lie::HintOtherIndexKey,
                Lie::HintOnForeign,
                Lie::OutHintForeignKey,
                Lie::OutIndexBeyondGap,
                Lie::SighashNone,
                Lie::UnknownField,
                Lie::OutScriptNotOurs,
            ] {
                for target in 0..spec.ins.len().max(spec.outs.len()) {
                    let lied = build(&Spec {
                        lie,
                        target,
                        ..Spec {
                            ins: spec.ins.clone(),
                            outs: spec.outs.clone(),
                            version: spec.version,
                            rbf: spec.rbf,
                            lie,
                            target,
                        }
                    });
                    match classify(secp(), &lied.serialize(), &f.w.account, &m, bound) {
                        Err(_) => {}
                        Ok(c1) => {
                            // the host never decides: the only acceptable Ok is the SAME classification (the lie did
                            // not bite on this target); never a different own set or amount
                            assert_eq!(c1, c0, "I1–I3: a host-asserted field ({lie:?} on {target}) changed the classification instead of refusing");
                        }
                    }
                }
            }
            // adding a witness_utxo that AGREES with the previous tx is allowed and changes nothing
            let mut agree = honest_psbt.clone();
            for i in 0..agree.inputs.len() {
                let p = agree.inputs[i].non_witness_utxo.as_ref().unwrap().output[0].clone();
                agree.inputs[i].witness_utxo = Some(p);
            }
            let c2 = classify(secp(), &agree.serialize(), &f.w.account, &m, bound)
                .expect("F7: an agreeing witness_utxo was refused");
            assert_eq!(c2, c0, "F7: an agreeing witness_utxo changed the classification");
            // dropping an own input's hint: the input is no longer ours (less is signed), never more
            if let Some(i) = spec.ins.iter().position(|s| s.kind == InKind::OwnHinted) {
                let mut unhinted = honest_psbt.clone();
                unhinted.inputs[i].bip32_derivation.clear();
                if let Ok(c3) = classify(secp(), &unhinted.serialize(), &f.w.account, &m, bound) {
                    assert!(
                        matches!(c3.inputs[i], InputClass::Foreign { .. }),
                        "I1: an input without a hint classified as ours"
                    );
                }
            }
        }
    }
}

/// What any `Ok` classification must satisfy against the PSBT it came from (I2, I3, the bound).
fn check_classified_against_psbt(psbt: &Psbt, c: &Classified, bound: [u32; 2]) {
    let f = fx();
    assert_eq!(c.inputs.len(), psbt.unsigned_tx.input.len(), "F7: input count");
    assert_eq!(c.outputs.len(), psbt.unsigned_tx.output.len(), "F7: output count");
    for (i, ic) in c.inputs.iter().enumerate() {
        let txin = &psbt.unsigned_tx.input[i];
        let prev =
            psbt.inputs[i].non_witness_utxo.as_ref().expect("I2: an accepted input without its previous transaction");
        assert_eq!(prev.compute_txid(), txin.previous_output.txid, "I2: previous tx is not the outpoint's");
        let prevout = &prev.output[txin.previous_output.vout as usize];
        match ic {
            InputClass::Own { path, amount, .. } => {
                assert_eq!(*amount, prevout.value.to_sat(), "I2: the counted amount is not the previous output's");
                let derived = f.w.account.p2wpkh_at(secp(), *path).expect("derivable");
                assert_eq!(derived, prevout.script_pubkey, "I1: an own input whose script is not the derived one");
            }
            InputClass::Foreign { amount } => {
                assert_eq!(*amount, prevout.value.to_sat(), "I2: a foreign amount not the previous output's")
            }
        }
    }
    for (i, oc) in c.outputs.iter().enumerate() {
        let txout = &psbt.unsigned_tx.output[i];
        match oc {
            OutputClass::Own { path, amount } => {
                assert_eq!(*amount, txout.value.to_sat());
                let derived = f.w.account.p2wpkh_at(secp(), *path).expect("derivable");
                assert_eq!(derived, txout.script_pubkey, "I3: an own output whose script is not the derived one");
                assert!(path.index < bound[path.branch as usize] + GAP, "I3: an own output beyond bound + gap");
            }
            OutputClass::Trusted { amount, .. } | OutputClass::Unlisted { amount } => {
                assert_eq!(*amount, txout.value.to_sat())
            }
            OutputClass::OpReturn => assert_eq!(txout.value.to_sat(), 0, "an OP_RETURN with value classified"),
        }
    }
    assert!(c.vsize_lower_bound >= 60, "F7: vsize lower bound implausibly small");
}

// ------------------------------------------------------------------------------------------------
// judge — F8
// ------------------------------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum WitnessKind {
    None,
    Fresh,        // tip = best, last_seen_seq <= seq
    SeqBehind,    // verified, last_seen_seq > seq  → the one disarm case
    Unverified,   // signed by a stranger, high seq → must NOT disarm
    LaggingTip,   // tip too far behind
    UnknownTip,   // a tip hash the enclave never saw
    OtherEnclave, // enclave_id of another enclave
    FutureTip,    // tip_height above best
}

struct JudgeSpec {
    frozen: bool,
    unarmed: bool,
    chain_frozen: bool,
    expired: bool,
    freshness: bool,
    witness: WitnessKind,
    seq: u64,
    fill: u8,
    best_delta: u8,
    payjoin: PayjoinRule,
    rbf_allowed: bool,
    fee_window: bool,
    scale: u8,
}

fn parse_judge(data: &[u8]) -> Option<(JudgeSpec, Spec)> {
    if data.len() < 8 {
        return None;
    }
    let f = data[0];
    let js = JudgeSpec {
        frozen: f & 1 != 0,
        unarmed: f & 2 != 0,
        chain_frozen: f & 4 != 0,
        expired: f & 8 != 0,
        freshness: f & 16 != 0,
        rbf_allowed: f & 32 == 0,
        fee_window: f & 64 != 0,
        witness: match data[1] % 8 {
            0 => WitnessKind::None,
            1 => WitnessKind::Fresh,
            2 => WitnessKind::SeqBehind,
            3 => WitnessKind::Unverified,
            4 => WitnessKind::LaggingTip,
            5 => WitnessKind::UnknownTip,
            6 => WitnessKind::OtherEnclave,
            _ => WitnessKind::FutureTip,
        },
        seq: u64::from(data[2]),
        fill: data[3],
        best_delta: data[4],
        payjoin: match data[5] % 3 {
            0 => PayjoinRule::None,
            1 => PayjoinRule::InflowOnly,
            _ => PayjoinRule::OutflowAllowed,
        },
        scale: data[6],
    };
    let mut spec = parse_spec(&data[7..])?;
    spec.lie = Lie::None; // the judge target feeds honest classifications; lies are classify's business
    Some((js, spec))
}

/// `[flags, witness, seq, fill, best_delta, payjoin, scale] ‖ PSBT spec`. The state is the honest fixture's with the
/// knobs applied; the PSBT is the scripted honest build, classified by the enclave first (a refusal there ends the
/// case); then `judge` against the harness's own reading of §1.4 and C-R10-4.
pub fn judge_target(data: &[u8]) {
    let Some((js, spec)) = parse_judge(data) else { return };
    let h = honest();
    let f = fx();
    let keys = fixtures::keys();
    // the mandate: knobs on top of the honest one
    let mut m = h.mandate.clone();
    m.rules.payjoin = js.payjoin;
    m.rules.rbf = js.rbf_allowed;
    if js.fee_window {
        m.limits.max_fee_per_window = Some(m.limits.max_fee_abs.saturating_mul(2));
    }
    if js.freshness {
        m.freshness.required = true;
        m.freshness.witness_pk = Some(keys.witness.pk);
    }
    // caps scaled down to make them reachable: scale 0 keeps the fixture's, otherwise caps shrink
    let sc = u64::from(js.scale % 8) + 1;
    m.limits.max_per_tx = (m.limits.max_per_tx / sc).max(1);
    m.destinations.unlisted.max_per_tx = (m.destinations.unlisted.max_per_tx / sc).max(1);
    m.destinations.unlisted.max_per_window = (m.destinations.unlisted.max_per_window / sc).max(1);
    m.limits.window_max_outflow = (m.limits.window_max_outflow / sc).max(1);
    m.limits.max_fee_abs = (m.limits.max_fee_abs / sc).max(1);
    for t in &mut m.destinations.trusted {
        t.max_per_tx = (t.max_per_tx / sc).max(1);
        t.max_per_window = (t.max_per_window / sc).max(1);
    }
    assert!(m.validate().is_ok(), "harness: the knobbed mandate must stay valid");
    let mut s = fixtures::init_state(m.clone(), &keys, H);
    s.frozen = js.frozen;
    s.armed = !js.unarmed;
    s.seq = js.seq;
    fixtures::set_best(&mut s, H + u32::from(js.best_delta));
    s.chain.frozen = js.chain_frozen;
    if js.expired {
        s.mandate.not_after_height = s.chain.best.unwrap().height - 1;
    }
    let best = s.chain.best.unwrap();
    // window fill: a fraction of each cap already spent this window
    let frac = |cap: u64| cap / 256 * u64::from(js.fill);
    s.window.outflow = frac(m.limits.window_max_outflow);
    s.window.unlisted = frac(m.destinations.unlisted.max_per_window);
    s.window.fees = frac(m.limits.max_fee_per_window.unwrap_or(0));
    s.window.start_height = best.height.saturating_sub(10); // inside the current window (no roll)
                                                            // the witness token
    let token = |tip_height: u32, tip_hash: [u8; 32], last_seen_seq: u64, signer: &fixtures::P256Key, eid: [u8; 32]| {
        let mut t =
            Message::WitnessToken { enclave_id: eid, tip_hash, tip_height, last_seen_seq, issued: 1, sig: [0; 64] };
        signer.sign(&mut t);
        t
    };
    let lag_too_far = m.freshness.max_tip_lag + 1 + u32::from(js.fill % 4);
    let witness: Option<Message> = match js.witness {
        WitnessKind::None => None,
        WitnessKind::Fresh => Some(token(
            best.height,
            best.hash,
            js.seq.saturating_sub(u64::from(js.fill % 3)),
            &keys.witness,
            ENCLAVE_ID,
        )),
        WitnessKind::SeqBehind => {
            Some(token(best.height, best.hash, js.seq + 1 + u64::from(js.fill % 5), &keys.witness, ENCLAVE_ID))
        }
        WitnessKind::Unverified => {
            Some(token(best.height, best.hash, js.seq + 1 + u64::from(js.fill % 5), &h.ak, ENCLAVE_ID))
        }
        WitnessKind::LaggingTip => {
            let th = best.height.saturating_sub(lag_too_far);
            Some(token(th, fixtures::header_hash(th), js.seq, &keys.witness, ENCLAVE_ID))
        }
        WitnessKind::UnknownTip => Some(token(best.height, [0x5a; 32], js.seq, &keys.witness, ENCLAVE_ID)),
        WitnessKind::OtherEnclave => Some(token(best.height, best.hash, js.seq, &keys.witness, [0x5c; 32])),
        WitnessKind::FutureTip => Some(token(best.height + 1, [0x5b; 32], js.seq, &keys.witness, ENCLAVE_ID)),
    };
    // the transaction, classified by the enclave
    let psbt = build(&spec);
    let Ok(c) = classify(secp(), &psbt.serialize(), &f.w.account, &s.mandate, s.own_index_bound) else { return };
    let v = judge(&s, &c, witness.as_ref());
    // determinism / idempotence
    assert_eq!(judge(&s, &c, witness.as_ref()), v, "F8: judge is not a pure function of its inputs");

    // --- the harness's reading ---
    // liveness, in the enclave's order
    let liveness: Option<(Reason, bool)> = if s.frozen {
        Some((Reason::Frozen, false))
    } else if !s.armed {
        Some((Reason::FreshnessSeqBehind, false))
    } else if s.chain.frozen {
        Some((Reason::ChainReorg, false))
    } else if best.height > s.mandate.not_after_height {
        Some((Reason::MandateExpired, false))
    } else if m.freshness.required {
        match (js.witness, &witness) {
            (WitnessKind::None, _) => Some((Reason::FreshnessMissing, false)),
            (WitnessKind::OtherEnclave | WitnessKind::Unverified, _) => Some((Reason::FreshnessSig, false)),
            (WitnessKind::FutureTip | WitnessKind::LaggingTip | WitnessKind::UnknownTip, _) => {
                Some((Reason::FreshnessTip, false))
            }
            (WitnessKind::SeqBehind, _) => Some((Reason::FreshnessSeqBehind, true)),
            (WitnessKind::Fresh, _) => None,
        }
    } else {
        None
    };
    if let Some((want, disarms)) = liveness {
        match &v {
            Verdict::Refuse { refusal, disarm } => {
                assert_eq!(code(refusal), want.code(), "F8: liveness refusal differs");
                assert_eq!(
                    disarm.is_some(),
                    disarms,
                    "C-R10-4: disarm fired on the wrong refusal class ({})",
                    code(refusal)
                );
                if let Some(d) = disarm {
                    assert!(!d.armed, "C-R10-4: the disarmed state is still armed");
                }
            }
            Verdict::Accept { .. } => panic!("F8: accepted although {} must refuse", want.code()),
        }
        return;
    }
    // the sums, checked, in the enclave's order; an overflow is the single reason OVERFLOW
    let mut own_in = 0u64;
    let mut all_in = 0u64;
    let mut own_out = 0u64;
    let mut all_out = 0u64;
    let mut unlisted = 0u64;
    let mut trusted: BTreeMap<String, u64> = BTreeMap::new();
    let mut overflow = false;
    let mut add = |a: &mut u64, b: u64| match a.checked_add(b) {
        Some(x) => *a = x,
        None => overflow = true,
    };
    let foreign_present = c.inputs.iter().any(|i| matches!(i, InputClass::Foreign { .. }));
    let own_present = c.inputs.iter().any(|i| matches!(i, InputClass::Own { .. }));
    for i in &c.inputs {
        match i {
            InputClass::Own { amount, .. } => {
                add(&mut own_in, *amount);
                add(&mut all_in, *amount);
            }
            InputClass::Foreign { amount } => add(&mut all_in, *amount),
        }
    }
    for o in &c.outputs {
        match o {
            OutputClass::Own { amount, .. } => {
                add(&mut own_out, *amount);
                add(&mut all_out, *amount);
            }
            OutputClass::Trusted { dest, amount } => {
                add(&mut all_out, *amount);
                let label = m.destinations.trusted[*dest].label.clone();
                let e = trusted.entry(label).or_insert(0);
                add(e, *amount);
            }
            OutputClass::Unlisted { amount } => {
                add(&mut all_out, *amount);
                add(&mut unlisted, *amount);
            }
            OutputClass::OpReturn => {}
        }
    }
    if overflow {
        match &v {
            Verdict::Refuse { refusal, disarm } => {
                assert_eq!(code(refusal), Reason::Overflow.code(), "F8: a wrapping sum was not refused OVERFLOW");
                assert!(disarm.is_none(), "C-R10-4: disarm on OVERFLOW");
            }
            Verdict::Accept { .. } => panic!("C-R10-6/F8: a wrapping sum was accepted"),
        }
        return;
    }
    if all_out > all_in {
        match &v {
            Verdict::Refuse { refusal, disarm } => {
                assert_eq!(
                    code(refusal),
                    Reason::PsbtParse.code(),
                    "F8: outputs above inputs not refused as PSBT_PARSE"
                );
                assert!(disarm.is_none());
            }
            Verdict::Accept { .. } => panic!("F8: outputs above inputs accepted"),
        }
        return;
    }
    let fee = all_in - all_out;
    let net_outflow = own_in.saturating_sub(own_out);
    let inflow = own_out > own_in;
    let l = &m.limits;
    let mut want: Vec<&'static str> = Vec::new();
    if c.version != 1 && c.version != 2 {
        want.push("TX_VERSION");
    }
    if c.rbf && !m.rules.rbf {
        want.push("RBF_FORBIDDEN");
    }
    if foreign_present && m.rules.payjoin == PayjoinRule::None {
        want.push("INPUT_FOREIGN_FORBIDDEN");
    }
    if !own_present {
        want.push("INPUT_NOT_OWN");
    }
    if foreign_present && m.rules.payjoin == PayjoinRule::InflowOnly && !inflow && net_outflow > 0 {
        want.push("INPUT_FOREIGN_FORBIDDEN");
    }
    if net_outflow > l.max_per_tx {
        want.push("CAP_TX");
    }
    if unlisted > m.destinations.unlisted.max_per_tx {
        want.push("CAP_UNLISTED_TX");
    }
    for (label, v_) in &trusted {
        if let Some(d) = m.destinations.trusted.iter().find(|d| &d.label == label) {
            if *v_ > d.max_per_tx {
                want.push("CAP_TRUSTED_TX");
            }
        }
    }
    if fee > l.max_fee_abs {
        want.push("FEE_ABS");
    }
    if let Some(max_fee) = l.max_fee_rate.checked_mul(c.vsize_lower_bound) {
        if fee > max_fee {
            want.push("FEE_RATE");
        }
    }
    let w = &s.window;
    let w_outflow = w.outflow.checked_add(net_outflow);
    let w_unlisted = w.unlisted.checked_add(unlisted);
    let w_fees = w.fees.checked_add(fee);
    let (Some(w_outflow), Some(w_unlisted), Some(w_fees)) = (w_outflow, w_unlisted, w_fees) else {
        assert!(
            matches!(&v, Verdict::Refuse { refusal, .. } if code(refusal) == Reason::Overflow.code()),
            "F8: a wrapping window sum not refused OVERFLOW"
        );
        return;
    };
    if w_outflow > l.window_max_outflow {
        want.push("CAP_WINDOW");
    }
    if w_unlisted > m.destinations.unlisted.max_per_window {
        want.push("CAP_UNLISTED_WINDOW");
    }
    if let Some(cap) = l.max_fee_per_window {
        if w_fees > cap {
            want.push("FEE_WINDOW");
        }
    }
    for (label, v_) in &trusted {
        let already = w.trusted.iter().find(|(l_, _)| l_ == label).map(|(_, a)| *a).unwrap_or(0);
        if let Some(d) = m.destinations.trusted.iter().find(|d| &d.label == label) {
            if already + *v_ > d.max_per_window {
                want.push("CAP_TRUSTED_WINDOW");
            }
        }
    }
    want.sort_unstable();
    match &v {
        Verdict::Refuse { refusal, disarm } => {
            assert!(disarm.is_none(), "C-R10-4: a cap/structure refusal disarmed the signer");
            let mut got: Vec<&str> = refusal.0.iter().map(|r| r.code()).collect();
            got.sort_unstable();
            assert_eq!(got, want, "F8: the refusal set differs from the harness's reading (fee {fee}, net {net_outflow}, unlisted {unlisted})");
        }
        Verdict::Accept { state, summary } => {
            assert!(
                want.is_empty(),
                "F8: ACCEPTED although the rules refuse: {want:?} (fee {fee}, net {net_outflow}, unlisted {unlisted})"
            );
            // the charge: exactly the amounts, never a decrease; seq + 1; the bound raised
            assert_eq!(state.window.outflow, w_outflow, "F8: window outflow charge");
            assert_eq!(state.window.unlisted, w_unlisted, "F8: window unlisted charge");
            assert_eq!(state.window.fees, w_fees, "F8: window fee charge");
            for (label, v_) in &trusted {
                let before = w.trusted.iter().find(|(l_, _)| l_ == label).map(|(_, a)| *a).unwrap_or(0);
                let after = state.window.trusted.iter().find(|(l_, _)| l_ == label).map(|(_, a)| *a).unwrap_or(0);
                assert_eq!(after, before + *v_, "F8: trusted window charge for {label}");
            }
            assert_eq!(state.seq, s.seq + 1, "F8: seq did not advance by exactly one");
            assert_eq!(summary.seq, state.seq);
            assert_eq!(
                (summary.net_outflow, summary.unlisted, summary.fee),
                (net_outflow, unlisted, fee),
                "F8: summary amounts"
            );
            assert_eq!(summary.txid, c.txid);
            assert_eq!(summary.height, best.height);
            let mut bound = s.own_index_bound;
            for i in &c.inputs {
                if let InputClass::Own { path, .. } = i {
                    bound[path.branch as usize] = bound[path.branch as usize].max(path.index + 1);
                }
            }
            for o in &c.outputs {
                if let OutputClass::Own { path, .. } = o {
                    bound[path.branch as usize] = bound[path.branch as usize].max(path.index + 1);
                }
            }
            assert_eq!(state.own_index_bound, bound, "F8: the own-index bound after a spend");
            assert!(state.armed && !state.frozen, "F8: an accepted spend changed the liveness flags");
            assert_eq!(state.mandate, s.mandate, "F8: an accepted spend changed the mandate");
            // judging the same transaction again from the charged state: the window has less room, never more
            if let Verdict::Accept { state: s2, .. } = judge(state, &c, witness.as_ref()) {
                assert!(
                    s2.window.outflow >= state.window.outflow && s2.seq == state.seq + 1,
                    "F8: the window charge went backwards"
                );
            }
        }
    }
}
