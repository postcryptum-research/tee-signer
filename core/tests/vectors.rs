//! The vector suite: every vector is a (state, PSBT, witness) triple with an expected verdict.
//! Both directions are exercised (accept vectors sign and finalize; refuse vectors name their
//! reasons). With `TEE_VECTORS_OUT=<dir>` the suite also writes each vector as JSON for the
//! auditor and for the enclave-side runner.

mod common;

use bitcoin::hashes::Hash;
use bitcoin::psbt::PsbtSighashType;
use bitcoin::secp256k1::SecretKey;
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{Amount, Psbt, ScriptBuf, TxOut};
use common::*;
use signer_core::classify::classify;
use signer_core::judge::{judge, Verdict};
use signer_core::mandate::*;
use signer_core::receipt::Receipt;
use signer_core::sign::{finalize_own_inputs, sign_digest_secp, sign_own_inputs, verify_digest_secp};
use signer_core::state::State;
use signer_core::update::Message;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Expect {
    Accept,
    Refuse(Vec<&'static str>),
}

struct Vector {
    name: &'static str,
    state: State,
    psbt: Psbt,
    witness: Option<Message>,
    expect: Expect,
    /// expected `disarm` on refusal
    disarms: bool,
}

struct Fx {
    w: Wallet,
    cold: Wallet,
    keys: Keys,
}

fn fx() -> Fx {
    Fx { w: wallet(0x01), cold: wallet(0x02), keys: keys() }
}

const H: u32 = 250_100; // best height for most vectors (checkpoint 250_000)

fn state_with(f: &Fx, m: Mandate) -> State {
    init_state(m, &f.keys, H)
}

fn simple_payout(f: &Fx, unlisted_amount: u64, fee: u64) -> Psbt {
    // in: own(0,5) 2_000_000 ; out: foreign unlisted ; change own(1,0)
    let in_amt = 2_000_000u64;
    let change = in_amt - unlisted_amount - fee;
    build_psbt(
        &f.w,
        &[In::Own { branch: 0, index: 5, amount: in_amt, hint: true }],
        &[
            Out { spk: foreign_spk(1), amount: unlisted_amount, hint: None },
            Out { spk: f.w.spk(1, 0), amount: change, hint: Some((1, 0)) },
        ],
        2,
        false,
    )
    .psbt
}

fn witness_token(_f: &Fx, tip_height: u32, last_seen_seq: u64, signer: &P256Key) -> Message {
    let mut m = Message::WitnessToken {
        enclave_id: ENCLAVE_ID,
        tip_hash: header_hash(tip_height),
        tip_height,
        last_seen_seq,
        issued: 1,
        sig: [0; 64],
    };
    signer.sign(&mut m);
    m
}

fn vectors() -> Vec<Vector> {
    let f = fx();
    let base = base_mandate(&f.w, &f.cold);
    let mut v: Vec<Vector> = Vec::new();
    let mut push = |name, state, psbt, witness, expect, disarms| {
        v.push(Vector { name, state, psbt, witness, expect, disarms });
    };
    let refuse = |codes: &[&'static str]| Expect::Refuse(codes.to_vec());

    // ---------------- accept ----------------
    push("accept-payout-unlisted-within-cap", state_with(&f, base.clone()), simple_payout(&f, 900_000, 2_000), None, Expect::Accept, false);
    push("accept-unlisted-at-cap-boundary", state_with(&f, base.clone()), simple_payout(&f, 1_000_000, 2_000), None, Expect::Accept, false);
    {
        // sweep two coins to the cold descriptor; net outflow exactly maxPerTx (1 BTC)
        let psbt = build_psbt(
            &f.w,
            &[In::Own { branch: 0, index: 1, amount: 50_000_000, hint: true }, In::Own { branch: 0, index: 2, amount: 50_000_000, hint: true }],
            &[Out { spk: f.cold.spk(0, 3), amount: 99_990_000, hint: None }],
            2,
            true,
        )
        .psbt;
        push("accept-sweep-to-trusted-descriptor-net-at-cap", state_with(&f, base.clone()), psbt, None, Expect::Accept, false);
    }
    {
        let psbt = build_psbt(
            &f.w,
            &[In::Own { branch: 0, index: 0, amount: 10_000, hint: true }],
            &[Out { spk: f.w.spk(0, 50), amount: 9_000, hint: Some((0, 50)) }],
            2,
            false,
        )
        .psbt;
        push("accept-self-transfer-to-own-receive-index", state_with(&f, base.clone()), psbt, None, Expect::Accept, false);
    }
    {
        let mut m = base.clone();
        m.rules.payjoin = PayjoinRule::InflowOnly;
        let psbt = build_psbt(
            &f.w,
            &[In::Foreign { spk: foreign_spk(9), amount: 100_000 }, In::Own { branch: 0, index: 3, amount: 20_000, hint: true }],
            &[Out { spk: f.w.spk(0, 4), amount: 119_000, hint: Some((0, 4)) }],
            2,
            false,
        )
        .psbt;
        push("accept-payjoin-inflow-only-receiving", state_with(&f, m), psbt, None, Expect::Accept, false);
    }
    {
        let mut m = base.clone();
        m.rules.op_return = OpReturnRule::ZeroValue;
        let mut psbt = simple_payout(&f, 900_000, 2_000);
        psbt.unsigned_tx.output.push(TxOut { value: Amount::ZERO, script_pubkey: ScriptBuf::new_op_return([1u8, 2, 3]) });
        psbt.outputs.push(Default::default());
        push("accept-opreturn-zero-value-when-allowed", state_with(&f, m), psbt, None, Expect::Accept, false);
    }
    {
        let mut m = base.clone();
        m.freshness = Freshness { required: true, witness_pk: Some(f.keys.witness.pk), max_tip_lag: 6 };
        let s = state_with(&f, m);
        let tok = witness_token(&f, H, 0, &f.keys.witness);
        push("accept-witness-token-fresh", s.clone(), simple_payout(&f, 900_000, 2_000), Some(tok), Expect::Accept, false);
        let tok = witness_token(&f, H - 6, 0, &f.keys.witness);
        push("accept-witness-token-at-max-tip-lag", s, simple_payout(&f, 900_000, 2_000), Some(tok), Expect::Accept, false);
    }
    {
        // change at index bound+gap-1 is the last accepted index
        let psbt = build_psbt(
            &f.w,
            &[In::Own { branch: 0, index: 5, amount: 2_000_000, hint: true }],
            &[Out { spk: foreign_spk(1), amount: 900_000, hint: None }, Out { spk: f.w.spk(1, 99), amount: 1_098_000, hint: Some((1, 99)) }],
            2,
            false,
        )
        .psbt;
        push("accept-change-index-at-gap-boundary", state_with(&f, base.clone()), psbt, None, Expect::Accept, false);
    }

    // ---------------- refuse: caps and fees ----------------
    {
        let psbt = build_psbt(
            &f.w,
            &[In::Own { branch: 0, index: 1, amount: 200_000_000, hint: true }],
            &[Out { spk: f.cold.spk(0, 3), amount: 100_000_001, hint: None }, Out { spk: f.w.spk(1, 0), amount: 99_998_999, hint: Some((1, 0)) }],
            2,
            false,
        )
        .psbt;
        push("refuse-cap-tx-and-trusted-tx-plus-one", state_with(&f, base.clone()), psbt, None, refuse(&["CAP_TX", "CAP_TRUSTED_TX"]), false);
    }
    push("refuse-cap-unlisted-tx-plus-one", state_with(&f, base.clone()), simple_payout(&f, 1_000_001, 2_000), None, refuse(&["CAP_UNLISTED_TX"]), false);
    {
        let mut s = state_with(&f, base.clone());
        s.window.outflow = 5 * BTC - 1_000;
        push("refuse-cap-window", s, simple_payout(&f, 900_000, 2_000), None, refuse(&["CAP_WINDOW"]), false);
    }
    {
        let mut s = state_with(&f, base.clone());
        s.window.unlisted = 4_999_000;
        push("refuse-cap-unlisted-window", s, simple_payout(&f, 2_000, 1_000), None, refuse(&["CAP_UNLISTED_WINDOW"]), false);
    }
    {
        let mut s = state_with(&f, base.clone());
        s.window.trusted = vec![("cold".into(), 5 * BTC - 1_000)];
        let psbt = build_psbt(
            &f.w,
            &[In::Own { branch: 0, index: 1, amount: 10_000, hint: true }],
            &[Out { spk: f.cold.spk(0, 0), amount: 2_000, hint: None }, Out { spk: f.w.spk(1, 0), amount: 7_000, hint: Some((1, 0)) }],
            2,
            false,
        )
        .psbt;
        push("refuse-cap-trusted-window", s, psbt, None, refuse(&["CAP_TRUSTED_WINDOW"]), false);
    }
    push("refuse-fee-abs-plus-one", state_with(&f, base.clone()), simple_payout(&f, 900_000, 100_001), None, refuse(&["FEE_ABS", "FEE_RATE"]), false);
    push("refuse-fee-rate", state_with(&f, base.clone()), simple_payout(&f, 900_000, 50_000), None, refuse(&["FEE_RATE"]), false);
    {
        let mut m = base.clone();
        m.limits.max_fee_per_window = Some(10_000);
        let mut s = state_with(&f, m);
        s.window.fees = 9_000;
        push("refuse-fee-window", s, simple_payout(&f, 900_000, 2_000), None, refuse(&["FEE_WINDOW"]), false);
    }
    {
        // C-R5b: trusted-only destination, the FEE pushes the window over — fee ∈ net outflow
        // (fee rate cap lifted in this vector so the window cap is the only thing that fires)
        let mut m = base.clone();
        m.limits.max_fee_rate = 1_000;
        let mut s = state_with(&f, m);
        s.window.outflow = 5 * BTC - 50_000;
        let psbt = build_psbt(
            &f.w,
            &[In::Own { branch: 0, index: 1, amount: 150_000, hint: true }],
            &[Out { spk: f.cold.spk(0, 0), amount: 100_000, hint: None }],
            2,
            false,
        )
        .psbt;
        push("refuse-trusted-at-max-fee-fee-counts-toward-window", s, psbt, None, refuse(&["CAP_WINDOW"]), false);
    }
    {
        let mut m = base.clone();
        m.limits.max_inputs = 2;
        m.limits.max_outputs = 2;
        let psbt3 = build_psbt(
            &f.w,
            &[
                In::Own { branch: 0, index: 1, amount: 10_000, hint: true },
                In::Own { branch: 0, index: 2, amount: 10_000, hint: true },
                In::Own { branch: 0, index: 3, amount: 10_000, hint: true },
            ],
            &[Out { spk: foreign_spk(1), amount: 29_000, hint: None }],
            2,
            false,
        )
        .psbt;
        push("refuse-too-many-inputs", state_with(&f, m.clone()), psbt3, None, refuse(&["TOO_MANY_INPUTS"]), false);
        let psbt = build_psbt(
            &f.w,
            &[In::Own { branch: 0, index: 1, amount: 30_000, hint: true }],
            &[
                Out { spk: foreign_spk(1), amount: 9_000, hint: None },
                Out { spk: foreign_spk(2), amount: 9_000, hint: None },
                Out { spk: foreign_spk(3), amount: 9_000, hint: None },
            ],
            2,
            false,
        )
        .psbt;
        push("refuse-too-many-outputs", state_with(&f, m), psbt, None, refuse(&["TOO_MANY_OUTPUTS"]), false);
    }
    {
        // C-R12e: Σ inputs near u64::MAX ⇒ OVERFLOW, never wrap
        let psbt = build_psbt(
            &f.w,
            &[In::Own { branch: 0, index: 1, amount: u64::MAX, hint: true }, In::Own { branch: 0, index: 2, amount: 1, hint: true }],
            &[Out { spk: foreign_spk(1), amount: 1, hint: None }],
            2,
            false,
        )
        .psbt;
        push("refuse-overflow-sum-inputs", state_with(&f, base.clone()), psbt, None, refuse(&["OVERFLOW"]), false);
        let psbt = build_psbt(
            &f.w,
            &[In::Own { branch: 0, index: 1, amount: 10, hint: true }],
            &[Out { spk: foreign_spk(1), amount: u64::MAX, hint: None }, Out { spk: foreign_spk(2), amount: 1, hint: None }],
            2,
            false,
        )
        .psbt;
        push("refuse-overflow-sum-outputs", state_with(&f, base.clone()), psbt, None, refuse(&["OVERFLOW"]), false);
    }

    // ---------------- refuse: PSBT traps (I1–I3) ----------------
    {
        // the fee-overpayment trap: only a witness_utxo, which lies about the amount
        let mut psbt = simple_payout(&f, 900_000, 2_000);
        psbt.inputs[0].non_witness_utxo = None;
        psbt.inputs[0].witness_utxo = Some(TxOut { value: Amount::from_sat(2_000_000), script_pubkey: f.w.spk(0, 5) });
        push("refuse-input-no-prevtx-witness-utxo-only", state_with(&f, base.clone()), psbt, None, refuse(&["INPUT_NO_PREVTX"]), false);
    }
    {
        let mut psbt = simple_payout(&f, 900_000, 2_000);
        let other = funding_tx(&[(f.w.spk(0, 5), 2_000_000)], 9999);
        psbt.inputs[0].non_witness_utxo = Some(other);
        push("refuse-input-prevtx-txid-mismatch", state_with(&f, base.clone()), psbt, None, refuse(&["INPUT_PREVTX_MISMATCH"]), false);
    }
    {
        // non_witness_utxo correct, but a witness_utxo that disagrees with it
        let mut psbt = simple_payout(&f, 900_000, 2_000);
        psbt.inputs[0].witness_utxo = Some(TxOut { value: Amount::from_sat(1), script_pubkey: f.w.spk(0, 5) });
        push("refuse-input-witness-utxo-disagrees-with-prevtx", state_with(&f, base.clone()), psbt, None, refuse(&["INPUT_PREVTX_MISMATCH"]), false);
    }
    {
        // hint names our path 0/5 but carries a foreign key
        let mut psbt = simple_payout(&f, 900_000, 2_000);
        psbt.inputs[0].bip32_derivation.clear();
        psbt.inputs[0].bip32_derivation.insert(wallet(0x77).pubkey(0, 5), f.w.origin(0, 5));
        push("refuse-input-hint-path-with-foreign-key", state_with(&f, base.clone()), psbt, None, refuse(&["INPUT_NOT_OWN"]), false);
    }
    {
        // hint names path 0/6 (our key 6) while the coin is at 0/5: derivation does not reproduce
        let mut psbt = simple_payout(&f, 900_000, 2_000);
        psbt.inputs[0].bip32_derivation.clear();
        psbt.inputs[0].bip32_derivation.insert(f.w.pubkey(0, 6), f.w.origin(0, 6));
        push("refuse-input-hint-wrong-index", state_with(&f, base.clone()), psbt, None, refuse(&["INPUT_NOT_OWN"]), false);
    }
    {
        // I3: the classic trap — output hint claims our change path, script is a foreign key
        let mut psbt = simple_payout(&f, 900_000, 2_000);
        psbt.unsigned_tx.output[1].script_pubkey = foreign_spk(5);
        push("refuse-change-to-foreign-key", state_with(&f, base.clone()), psbt, None, refuse(&["OUTPUT_SCRIPT_TYPE"]), false);
    }
    {
        // change hint beyond bound + gap (bound 0, gap 100, index 100)
        let psbt = build_psbt(
            &f.w,
            &[In::Own { branch: 0, index: 5, amount: 2_000_000, hint: true }],
            &[Out { spk: foreign_spk(1), amount: 900_000, hint: None }, Out { spk: f.w.spk(1, 100), amount: 1_098_000, hint: Some((1, 100)) }],
            2,
            false,
        )
        .psbt;
        push("refuse-change-index-beyond-gap", state_with(&f, base.clone()), psbt, None, refuse(&["CHANGE_INDEX_BEYOND_GAP"]), false);
    }
    {
        // our own change without a hint: counted as unlisted (safe direction) — here it blows the unlisted cap
        let mut psbt = simple_payout(&f, 900_000, 2_000);
        psbt.outputs[1].bip32_derivation.clear();
        push("refuse-own-change-without-hint-counts-as-unlisted", state_with(&f, base.clone()), psbt, None, refuse(&["CAP_UNLISTED_TX"]), false);
    }

    // ---------------- refuse: structure ----------------
    {
        let mut psbt = simple_payout(&f, 900_000, 2_000);
        psbt.inputs[0].sighash_type = Some(PsbtSighashType::from(EcdsaSighashType::None));
        push("refuse-sighash-none", state_with(&f, base.clone()), psbt, None, refuse(&["SIGHASH"]), false);
        let mut psbt = simple_payout(&f, 900_000, 2_000);
        psbt.inputs[0].sighash_type = Some(PsbtSighashType::from(EcdsaSighashType::AllPlusAnyoneCanPay));
        push("refuse-sighash-anyonecanpay", state_with(&f, base.clone()), psbt, None, refuse(&["SIGHASH"]), false);
    }
    {
        let psbt = build_psbt(
            &f.w,
            &[In::Own { branch: 0, index: 5, amount: 2_000_000, hint: true }],
            &[Out { spk: foreign_spk(1), amount: 900_000, hint: None }, Out { spk: f.w.spk(1, 0), amount: 1_098_000, hint: Some((1, 0)) }],
            3,
            false,
        )
        .psbt;
        push("refuse-tx-version-3", state_with(&f, base.clone()), psbt, None, refuse(&["TX_VERSION"]), false);
    }
    {
        let mut m = base.clone();
        m.rules.rbf = false;
        let psbt = build_psbt(
            &f.w,
            &[In::Own { branch: 0, index: 5, amount: 2_000_000, hint: true }],
            &[Out { spk: foreign_spk(1), amount: 900_000, hint: None }, Out { spk: f.w.spk(1, 0), amount: 1_098_000, hint: Some((1, 0)) }],
            2,
            true,
        )
        .psbt;
        push("refuse-rbf-forbidden", state_with(&f, m), psbt, None, refuse(&["RBF_FORBIDDEN"]), false);
    }
    {
        let mut psbt = simple_payout(&f, 900_000, 2_000);
        psbt.unsigned_tx.output.push(TxOut { value: Amount::ZERO, script_pubkey: ScriptBuf::new_op_return([1u8]) });
        psbt.outputs.push(Default::default());
        push("refuse-opreturn-under-none", state_with(&f, base.clone()), psbt, None, refuse(&["OPRETURN_FORBIDDEN"]), false);
        let mut m = base.clone();
        m.rules.op_return = OpReturnRule::ZeroValue;
        let mut psbt = simple_payout(&f, 900_000, 2_000);
        psbt.unsigned_tx.output[0].value = Amount::from_sat(899_999);
        psbt.unsigned_tx.output.push(TxOut { value: Amount::from_sat(1), script_pubkey: ScriptBuf::new_op_return([1u8]) });
        psbt.outputs.push(Default::default());
        push("refuse-opreturn-nonzero-value", state_with(&f, m), psbt, None, refuse(&["OPRETURN_FORBIDDEN"]), false);
    }
    {
        let psbt = build_psbt(
            &f.w,
            &[In::Foreign { spk: foreign_spk(9), amount: 100_000 }, In::Own { branch: 0, index: 3, amount: 20_000, hint: true }],
            &[Out { spk: f.w.spk(0, 4), amount: 119_000, hint: Some((0, 4)) }],
            2,
            false,
        )
        .psbt;
        push("refuse-foreign-input-under-payjoin-none", state_with(&f, base.clone()), psbt, None, refuse(&["INPUT_FOREIGN_FORBIDDEN"]), false);
        let mut m = base.clone();
        m.rules.payjoin = PayjoinRule::InflowOnly;
        let psbt = build_psbt(
            &f.w,
            &[In::Foreign { spk: foreign_spk(9), amount: 1_000 }, In::Own { branch: 0, index: 3, amount: 200_000, hint: true }],
            &[Out { spk: foreign_spk(1), amount: 150_000, hint: None }, Out { spk: f.w.spk(1, 0), amount: 50_000, hint: Some((1, 0)) }],
            2,
            false,
        )
        .psbt;
        push("refuse-payjoin-inflow-only-with-outflow", state_with(&f, m), psbt, None, refuse(&["INPUT_FOREIGN_FORBIDDEN"]), false);
    }
    {
        let mut psbt = simple_payout(&f, 900_000, 2_000);
        psbt.inputs[0].bip32_derivation.clear();
        push("refuse-own-coin-without-hint-nothing-to-sign", state_with(&f, base.clone()), psbt, None, refuse(&["INPUT_FOREIGN_FORBIDDEN", "INPUT_NOT_OWN"]), false);
    }
    {
        let mut psbt = simple_payout(&f, 900_000, 2_000);
        psbt.inputs[0].unknown.insert(bitcoin::psbt::raw::Key { type_value: 0xf0, key: vec![1] }, vec![2]);
        push("refuse-unknown-field", state_with(&f, base.clone()), psbt, None, refuse(&["UNKNOWN_FIELD"]), false);
    }
    {
        let mut psbt = simple_payout(&f, 900_000, 2_000);
        let dup = psbt.unsigned_tx.input[0].clone();
        psbt.unsigned_tx.input.push(dup);
        psbt.inputs.push(psbt.inputs[0].clone());
        push("refuse-duplicate-outpoint", state_with(&f, base.clone()), psbt, None, refuse(&["PSBT_PARSE"]), false);
    }

    // ---------------- refuse: liveness and freshness ----------------
    {
        let mut s = state_with(&f, base.clone());
        set_best(&mut s, 300_001);
        push("refuse-mandate-expired", s, simple_payout(&f, 900_000, 2_000), None, refuse(&["MANDATE_EXPIRED"]), false);
        let mut s = state_with(&f, base.clone());
        s.freeze();
        push("refuse-frozen", s, simple_payout(&f, 900_000, 2_000), None, refuse(&["FROZEN"]), false);
        let mut s = state_with(&f, base.clone());
        s.chain.best = None;
        push("refuse-chain-stale", s, simple_payout(&f, 900_000, 2_000), None, refuse(&["CHAIN_STALE"]), false);
    }
    {
        let mut m = base.clone();
        m.freshness = Freshness { required: true, witness_pk: Some(f.keys.witness.pk), max_tip_lag: 6 };
        let s = state_with(&f, m);
        push("refuse-freshness-missing", s.clone(), simple_payout(&f, 900_000, 2_000), None, refuse(&["FRESHNESS_MISSING"]), false);
        let tok = witness_token(&f, H, 0, &f.keys.owner);
        push("refuse-freshness-sig-wrong-key", s.clone(), simple_payout(&f, 900_000, 2_000), Some(tok), refuse(&["FRESHNESS_SIG"]), false);
        let tok = witness_token(&f, H - 7, 0, &f.keys.witness);
        push("refuse-freshness-tip-lag-plus-one", s.clone(), simple_payout(&f, 900_000, 2_000), Some(tok), refuse(&["FRESHNESS_TIP"]), false);
        let mut tok = witness_token(&f, H, 0, &f.keys.witness);
        if let Message::WitnessToken { tip_hash, .. } = &mut tok {
            *tip_hash = [0xab; 32];
        }
        f.keys.witness.sign(&mut tok);
        push("refuse-freshness-tip-unknown-hash", s.clone(), simple_payout(&f, 900_000, 2_000), Some(tok), refuse(&["FRESHNESS_TIP"]), false);
        let tok = witness_token(&f, H + 1, 0, &f.keys.witness);
        push("refuse-freshness-tip-ahead-of-best", s.clone(), simple_payout(&f, 900_000, 2_000), Some(tok), refuse(&["FRESHNESS_TIP"]), false);
        // the rollback detection: witness has seen seq 5, this (rolled-back) state remembers 3
        let mut s3 = s.clone();
        s3.seq = 3;
        let tok = witness_token(&f, H, 5, &f.keys.witness);
        push("refuse-freshness-seq-behind-disarms", s3, simple_payout(&f, 900_000, 2_000), Some(tok), refuse(&["FRESHNESS_SEQ_BEHIND"]), true);
        let mut sd = s.clone();
        sd.armed = false;
        let tok = witness_token(&f, H, 0, &f.keys.witness);
        push("refuse-disarmed-until-rearm", sd, simple_payout(&f, 900_000, 2_000), Some(tok), refuse(&["FRESHNESS_SEQ_BEHIND"]), false);
    }
    v
}

fn codes(r: &signer_core::reason::Refusal) -> Vec<&'static str> {
    r.0.iter().map(|x| x.code()).collect()
}

fn run(v: &Vector) -> Result<(), String> {
    let f = fx();
    let secp = secp();
    let bytes = v.psbt.serialize();
    let classified = classify(&secp, &bytes, &f.w.account, &v.state.mandate, v.state.own_index_bound);
    let verdict = match classified {
        Err(r) => Verdict::Refuse { refusal: r, disarm: None },
        Ok(c) => judge(&v.state, &c, v.witness.as_ref()),
    };
    match (&v.expect, &verdict) {
        (Expect::Accept, Verdict::Accept { state, summary }) => {
            // sign, verify each own input's signature, finalize, extract
            let c = classify(&secp, &bytes, &f.w.account, &v.state.mandate, v.state.own_index_bound).unwrap();
            let mut psbt = v.psbt.clone();
            let n = sign_own_inputs(&secp, &mut psbt, &f.w.account_xpriv, &c).map_err(|e| format!("sign: {e:?}"))?;
            let own_count = c.inputs.iter().filter(|i| matches!(i, signer_core::classify::InputClass::Own { .. })).count();
            if n != own_count {
                return Err(format!("signed {n} of {own_count} own inputs"));
            }
            let tx = psbt.unsigned_tx.clone();
            let mut cache = SighashCache::new(&tx);
            for (i, class) in c.inputs.iter().enumerate() {
                if let signer_core::classify::InputClass::Own { path, amount, .. } = class {
                    let (pk, sig) = psbt.inputs[i].partial_sigs.iter().next().expect("partial sig");
                    let spk = f.w.spk(path.branch, path.index);
                    let sh = cache.p2wpkh_signature_hash(i, &spk, Amount::from_sat(*amount), EcdsaSighashType::All).unwrap();
                    let msg = bitcoin::secp256k1::Message::from_digest(sh.to_byte_array());
                    secp.verify_ecdsa(&msg, &sig.signature, &pk.inner).map_err(|e| format!("input {i}: {e}"))?;
                    if sig.sighash_type != EcdsaSighashType::All {
                        return Err("sighash".into());
                    }
                }
            }
            let fin = finalize_own_inputs(&mut psbt, &c);
            if fin != own_count {
                return Err(format!("finalized {fin}"));
            }
            if c.inputs.iter().all(|i| matches!(i, signer_core::classify::InputClass::Own { .. })) {
                let final_tx = psbt.extract_tx_unchecked_fee_rate();
                if final_tx.input.iter().any(|i| i.witness.is_empty()) {
                    return Err("empty witness after finalize".into());
                }
            }
            // state charged before signing: seq advanced, window charged
            if state.seq != v.state.seq + 1 {
                return Err("seq not advanced".into());
            }
            if summary.seq != state.seq {
                return Err("summary seq".into());
            }
            // receipt round trip + identity signature
            let identity = SecretKey::from_slice(&[0x55; 32]).unwrap();
            let identity_pk = identity.public_key(&secp).serialize();
            let r = Receipt::from_summary(v.state.enclave_id, summary);
            let enc = r.encode();
            let back = Receipt::decode(&enc).map_err(|_| "receipt decode")?;
            if back != r {
                return Err("receipt round trip".into());
            }
            let sig = sign_digest_secp(&secp, &identity, &r.digest());
            if !verify_digest_secp(&secp, &identity_pk, &r.digest(), &sig) {
                return Err("receipt sig".into());
            }
            // state round trip through the sealed encoding
            let st = State::decode(&state.encode()).map_err(|_| "state decode")?;
            if &st != state {
                return Err("state round trip".into());
            }
            Ok(())
        }
        (Expect::Refuse(want), Verdict::Refuse { refusal, disarm }) => {
            let got = codes(refusal);
            let mut got_sorted = got.clone();
            got_sorted.sort();
            let mut want_sorted = want.clone();
            want_sorted.sort();
            if got_sorted != want_sorted {
                return Err(format!("reasons: got {got:?}, want {want:?}"));
            }
            if disarm.is_some() != v.disarms {
                return Err(format!("disarm: got {}, want {}", disarm.is_some(), v.disarms));
            }
            if let Some(d) = disarm {
                if d.armed {
                    return Err("disarmed state still armed".into());
                }
            }
            Ok(())
        }
        (Expect::Accept, Verdict::Refuse { refusal, .. }) => Err(format!("expected accept, got {:?}", codes(refusal))),
        (Expect::Refuse(want), Verdict::Accept { .. }) => Err(format!("expected refuse {want:?}, got accept")),
    }
}

#[test]
fn all_vectors() {
    let vs = vectors();
    let mut failures = Vec::new();
    for v in &vs {
        if let Err(e) = run(v) {
            failures.push(format!("{}: {}", v.name, e));
        }
    }
    assert!(failures.is_empty(), "vector failures:\n{}", failures.join("\n"));
    // every refusal identifier reachable in R1 has at least one vector
    let mut covered: Vec<&str> = Vec::new();
    for v in &vs {
        if let Expect::Refuse(c) = &v.expect {
            covered.extend(c.iter().copied());
        }
    }
    covered.sort();
    covered.dedup();
    let required_r1 = [
        "CAP_TRUSTED_TX", "CAP_TRUSTED_WINDOW", "CAP_TX", "CAP_UNLISTED_TX", "CAP_UNLISTED_WINDOW", "CAP_WINDOW",
        "CHAIN_STALE", "CHANGE_INDEX_BEYOND_GAP", "FEE_ABS", "FEE_RATE", "FEE_WINDOW", "FRESHNESS_MISSING",
        "FRESHNESS_SEQ_BEHIND", "FRESHNESS_SIG", "FRESHNESS_TIP", "FROZEN", "INPUT_FOREIGN_FORBIDDEN",
        "INPUT_NOT_OWN", "INPUT_NO_PREVTX", "INPUT_PREVTX_MISMATCH", "MANDATE_EXPIRED", "OPRETURN_FORBIDDEN",
        "OUTPUT_SCRIPT_TYPE", "OVERFLOW", "PSBT_PARSE", "RBF_FORBIDDEN", "SIGHASH", "TOO_MANY_INPUTS",
        "TOO_MANY_OUTPUTS", "TX_VERSION", "UNKNOWN_FIELD",
    ];
    for r in required_r1 {
        assert!(covered.contains(&r), "no refusal vector for {r}");
    }
    let accepts = vs.iter().filter(|v| v.expect == Expect::Accept).count();
    assert!(accepts >= 8, "too few accept vectors: {accepts}");
    dump(&vs);
}

#[derive(serde::Serialize)]
struct Dump<'a> {
    name: &'a str,
    expect: String,
    reasons: Vec<&'a str>,
    disarms: bool,
    network: &'static str,
    account_xpub: String,
    fingerprint: String,
    mandate_hex: String,
    state_hex: String,
    psbt_hex: String,
    witness_hex: Option<String>,
}

fn dump(vs: &[Vector]) {
    let Ok(dir) = std::env::var("TEE_VECTORS_OUT") else { return };
    std::fs::create_dir_all(&dir).unwrap();
    let f = fx();
    for v in vs {
        let (expect, reasons) = match &v.expect {
            Expect::Accept => ("accept".to_string(), vec![]),
            Expect::Refuse(r) => ("refuse".to_string(), r.clone()),
        };
        let d = Dump {
            name: v.name,
            expect,
            reasons,
            disarms: v.disarms,
            network: "signet",
            account_xpub: f.w.account.xpub.to_string(),
            fingerprint: hex::encode(f.w.account.fingerprint),
            mandate_hex: hex::encode(v.state.mandate.encode()),
            state_hex: hex::encode(v.state.encode()),
            psbt_hex: hex::encode(v.psbt.serialize()),
            witness_hex: v.witness.as_ref().map(|m| hex::encode(m.encode())),
        };
        let path = format!("{dir}/{}.json", v.name);
        std::fs::write(path, serde_json::to_string_pretty(&d).unwrap()).unwrap();
    }
}
