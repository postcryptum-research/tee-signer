//! State transitions: mandate updates (tightening at once, loosening timelocked, the classifier
//! failing toward loosening), cancel / unfreeze / rearm / rotate / recover, window rolling,
//! and the hollow-test mutations (each guard removed ⇒ its vector goes green).

mod common;

use common::*;
use signer_core::classify::classify;
use signer_core::judge::{judge, Verdict};
use signer_core::mandate::*;
use signer_core::reason::Reason;
use signer_core::state::State;
use signer_core::update::Message;

const H: u32 = 250_100;

fn fx() -> (Wallet, Wallet, Keys) {
    (wallet(0x01), wallet(0x02), keys())
}

fn update(keys: &Keys, signer: &P256Key, m: &Mandate, nonce: u64) -> Message {
    let _ = keys;
    let mut msg = Message::PolicyUpdate { enclave_id: ENCLAVE_ID, nonce, mandate: m.encode(), sig: [0; 64] };
    signer.sign(&mut msg);
    msg
}

fn first_reason(r: &signer_core::reason::Refusal) -> &'static str {
    r.0[0].code()
}

#[test]
fn mandate_codec_and_validate() {
    let (w, cold, _) = fx();
    let m = base_mandate(&w, &cold);
    assert_eq!(m.validate(), Ok(()));
    let bytes = m.encode();
    let back = Mandate::decode(&bytes).unwrap();
    assert_eq!(back, m);
    assert_eq!(back.hash(), m.hash());
    // trailing byte refused
    let mut t = bytes.clone();
    t.push(0);
    assert!(Mandate::decode(&t).is_err());
    // validation failures
    let mut bad = m.clone();
    bad.timelock_blocks = 0;
    assert_eq!(bad.validate(), Err(Invalid::Timelock));
    let mut bad = m.clone();
    bad.limits.own_index_gap = 101;
    assert_eq!(bad.validate(), Err(Invalid::Limits));
    let mut bad = m.clone();
    bad.freshness.required = true;
    assert_eq!(bad.validate(), Err(Invalid::Freshness));
    let mut bad = m.clone();
    bad.destinations.trusted.push(bad.destinations.trusted[0].clone());
    assert_eq!(bad.validate(), Err(Invalid::Label));
    let mut bad = m.clone();
    bad.destinations.trusted[0].matcher = Matcher::Address { script_pubkey: vec![0x51] };
    assert_eq!(bad.validate(), Err(Invalid::AddressScript));
    let mut bad = m.clone();
    bad.wallet.account.coin = 0;
    assert_eq!(bad.validate(), Err(Invalid::AccountPath));
    let mut bad = m.clone();
    bad.not_after_height = bad.checkpoint.height;
    assert_eq!(bad.validate(), Err(Invalid::Validity));
}

#[test]
fn tightening_applies_at_once_and_loosening_waits() {
    let (w, cold, k) = fx();
    let base = base_mandate(&w, &cold);
    let s0 = init_state(base.clone(), &k, H);

    // tightening: lower the unlisted cap
    let mut t = base.clone();
    t.destinations.unlisted.max_per_tx = 500_000;
    assert_eq!(compare(&base, &t), Ok(Change::Tightening));
    let s1 = s0.apply_message(&update(&k, &k.owner, &t, 1)).unwrap();
    assert_eq!(s1.mandate, t);
    assert_eq!(s1.nonce, 1);
    assert!(s1.pending.is_none());

    // loosening: raise it back
    let mut l = t.clone();
    l.destinations.unlisted.max_per_tx = 2_000_000;
    assert_eq!(compare(&t, &l), Ok(Change::Loosening));
    let s2 = s1.apply_message(&update(&k, &k.owner, &l, 2)).unwrap();
    assert_eq!(s2.mandate, t, "installed mandate unchanged while pending");
    let p = s2.pending.as_ref().unwrap();
    assert_eq!(p.activation_height, H + 144);
    assert_eq!(p.mandate, l);

    // a second update while pending is refused
    let mut l2 = l.clone();
    l2.limits.max_per_tx = 2 * BTC;
    let e = s2.apply_message(&update(&k, &k.owner, &l2, 3)).unwrap_err();
    assert_eq!(first_reason(&e), "POLICY_PENDING");

    // the pending mandate activates once the chain reaches the activation height
    let mut s3 = s2.clone();
    set_best(&mut s3, H + 143);
    s3.activate_pending();
    assert_eq!(s3.mandate, t);
    set_best(&mut s3, H + 144);
    s3.activate_pending();
    assert_eq!(s3.mandate, l);
    assert!(s3.pending.is_none());
}

#[test]
fn classifier_fails_toward_loosening() {
    let (w, cold, _) = fx();
    let base = base_mandate(&w, &cold);
    type Case = (&'static str, Box<dyn Fn(&mut Mandate)>, Change);
    let cases: Vec<Case> = vec![
        ("identical", Box::new(|_| {}), Change::Tightening),
        ("remove trusted", Box::new(|m| m.destinations.trusted.clear()), Change::Tightening),
        ("add trusted", Box::new(|m| {
            m.destinations.trusted.push(TrustedDest {
                label: "exch".into(),
                matcher: Matcher::Address { script_pubkey: foreign_spk(1).to_bytes() },
                max_per_tx: 1,
                max_per_window: 1,
            })
        }), Change::Loosening),
        ("trusted matcher gap lowered", Box::new(|m| {
            if let Matcher::Descriptor { gap, .. } = &mut m.destinations.trusted[0].matcher { *gap = 5 }
        }), Change::Tightening),
        ("trusted matcher gap raised", Box::new(|m| {
            if let Matcher::Descriptor { gap, .. } = &mut m.destinations.trusted[0].matcher { *gap = 50 }
        }), Change::Loosening),
        ("trusted matcher branch added", Box::new(|m| {
            if let Matcher::Descriptor { branches, .. } = &mut m.destinations.trusted[0].matcher { branches.push(1) }
        }), Change::Loosening),
        ("trusted matcher key changed", Box::new(|m| {
            m.destinations.trusted[0].matcher = Matcher::Descriptor { xpub: wallet(0x03).xpub_bytes(), branches: vec![0], gap: 20 }
        }), Change::Loosening),
        ("trusted cap lowered", Box::new(|m| m.destinations.trusted[0].max_per_tx = 1), Change::Tightening),
        ("trusted cap raised", Box::new(|m| m.destinations.trusted[0].max_per_window = 10 * BTC), Change::Loosening),
        ("window longer", Box::new(|m| m.limits.window_blocks = 288), Change::Tightening),
        ("window shorter", Box::new(|m| m.limits.window_blocks = 72), Change::Loosening),
        ("fee per window added", Box::new(|m| m.limits.max_fee_per_window = Some(1)), Change::Tightening),
        ("fee rate raised", Box::new(|m| m.limits.max_fee_rate = 101), Change::Loosening),
        ("payjoin toward none", Box::new(|m| m.rules.payjoin = PayjoinRule::None), Change::Tightening),
        ("payjoin opened", Box::new(|m| m.rules.payjoin = PayjoinRule::OutflowAllowed), Change::Loosening),
        ("rbf off", Box::new(|m| m.rules.rbf = false), Change::Tightening),
        ("opreturn allowed", Box::new(|m| m.rules.op_return = OpReturnRule::ZeroValue), Change::Loosening),
        ("checkpoint forward", Box::new(|m| { m.checkpoint.height = 250_050; m.checkpoint.hash = header_hash(250_050) }), Change::Tightening),
        ("checkpoint backward", Box::new(|m| { m.checkpoint.height = 249_999; m.checkpoint.hash = header_hash(249_999) }), Change::Loosening),
        ("freshness enabled (a precondition added)", Box::new(|m| { m.freshness.required = true; m.freshness.witness_pk = Some(p256_key(0xc3).pk) }), Change::Tightening),
        ("tip lag lowered", Box::new(|m| m.freshness.max_tip_lag = 1), Change::Tightening),
        ("validity shortened", Box::new(|m| m.not_after_height = 260_000), Change::Tightening),
        ("validity extended", Box::new(|m| m.not_after_height = 400_000), Change::Loosening),
        ("timelock raised", Box::new(|m| m.timelock_blocks = 1000), Change::Tightening),
        ("timelock lowered", Box::new(|m| m.timelock_blocks = 1), Change::Loosening),
        ("tighten one loosen another", Box::new(|m| { m.limits.max_per_tx = 1; m.limits.max_fee_abs = 1_000_000 }), Change::Loosening),
    ];
    for (name, f, want) in cases {
        let mut m = base.clone();
        f(&mut m);
        assert_eq!(compare(&base, &m), Ok(want), "{name}");
    }
    // witness key set when required: adding a key is tightening only together with required
    let mut with_key = base.clone();
    with_key.freshness.required = true;
    with_key.freshness.witness_pk = Some(p256_key(0xc3).pk);
    let mut other_key = with_key.clone();
    other_key.freshness.witness_pk = Some(p256_key(0xd4).pk);
    assert_eq!(compare(&with_key, &other_key), Ok(Change::Loosening), "witness key change is loosening");
    let mut dropped = with_key.clone();
    dropped.freshness.required = false;
    assert_eq!(compare(&with_key, &dropped), Ok(Change::Loosening));
    // immutables
    let mut net = base.clone();
    net.network = Network::Mainnet;
    assert_eq!(compare(&base, &net), Err(Immutable::Network));
    let mut wal = base.clone();
    wal.wallet.fingerprint = [9; 4];
    assert_eq!(compare(&base, &wal), Err(Immutable::Wallet));
}

#[test]
fn update_refusals() {
    let (w, cold, k) = fx();
    let base = base_mandate(&w, &cold);
    let s0 = init_state(base.clone(), &k, H);
    let mut t = base.clone();
    t.destinations.unlisted.max_per_tx = 500_000;
    // wrong signer
    let e = s0.apply_message(&update(&k, &k.recovery, &t, 1)).unwrap_err();
    assert_eq!(first_reason(&e), "POLICY_SIG");
    // wrong nonce
    let e = s0.apply_message(&update(&k, &k.owner, &t, 2)).unwrap_err();
    assert_eq!(first_reason(&e), "POLICY_NONCE");
    // replay of an accepted nonce
    let s1 = s0.apply_message(&update(&k, &k.owner, &t, 1)).unwrap();
    let e = s1.apply_message(&update(&k, &k.owner, &t, 1)).unwrap_err();
    assert_eq!(first_reason(&e), "POLICY_NONCE");
    // wrong enclave id
    let mut msg = update(&k, &k.owner, &t, 2);
    if let Message::PolicyUpdate { enclave_id, .. } = &mut msg {
        *enclave_id = [0; 32];
    }
    k.owner.sign(&mut msg);
    let e = s1.apply_message(&msg).unwrap_err();
    assert_eq!(first_reason(&e), "POLICY_SIG");
    // network and wallet immutable
    let mut net = base.clone();
    net.network = Network::Mainnet;
    net.wallet.account.coin = 0;
    let e = s1.apply_message(&update(&k, &k.owner, &net, 2)).unwrap_err();
    assert_eq!(first_reason(&e), "POLICY_NETWORK");
    let mut wal = base.clone();
    wal.wallet.fingerprint = [9; 4];
    let e = s1.apply_message(&update(&k, &k.owner, &wal, 2)).unwrap_err();
    assert_eq!(first_reason(&e), "POLICY_WALLET");
    // invalid mandate
    let mut inv = base.clone();
    inv.timelock_blocks = 0;
    let e = s1.apply_message(&update(&k, &k.owner, &inv, 2)).unwrap_err();
    assert_eq!(first_reason(&e), "POLICY_INVALID");
    // checkpoint ahead of the verified chain, or not a header this enclave verified
    let mut ahead = base.clone();
    ahead.checkpoint.height = H + 1;
    ahead.checkpoint.hash = header_hash(H + 1);
    let e = s1.apply_message(&update(&k, &k.owner, &ahead, 2)).unwrap_err();
    assert_eq!(first_reason(&e), "POLICY_INVALID");
    let mut unknown = base.clone();
    unknown.checkpoint.height = H - 1;
    unknown.checkpoint.hash = [0xcd; 32];
    let e = s1.apply_message(&update(&k, &k.owner, &unknown, 2)).unwrap_err();
    assert_eq!(first_reason(&e), "POLICY_INVALID");
    // a verified recent header is accepted as the new checkpoint (and the chain view is kept)
    let mut known = base.clone();
    known.checkpoint.height = H - 3;
    known.checkpoint.hash = header_hash(H - 3);
    known.destinations.unlisted.max_per_tx = 400_000; // tightening; the checkpoint moves forward (250_000 → H-3)
    let s_known = s1.apply_message(&update(&k, &k.owner, &known, 2)).unwrap();
    assert!(s_known.pending.is_none(), "forward checkpoint to a verified header + tightening applies at once");
    assert_eq!(s_known.mandate.checkpoint.height, H - 3);
    assert_eq!(s_known.chain.best.unwrap().height, H, "the chain view is kept, not reset");
    // non-canonical bytes
    let mut bytes = t.encode();
    bytes.push(0);
    let mut msg = Message::PolicyUpdate { enclave_id: ENCLAVE_ID, nonce: 2, mandate: bytes, sig: [0; 64] };
    k.owner.sign(&mut msg);
    let e = s1.apply_message(&msg).unwrap_err();
    assert_eq!(first_reason(&e), "POLICY_INVALID");
    // message codec round trip
    let msg = update(&k, &k.owner, &t, 2);
    assert_eq!(Message::decode(&msg.encode()).unwrap(), msg);
}

#[test]
fn cancel_unfreeze_rearm_rotate_recover() {
    let (w, cold, k) = fx();
    let base = base_mandate(&w, &cold);
    let s0 = init_state(base.clone(), &k, H);
    let mut l = base.clone();
    l.limits.max_per_tx = 2 * BTC;
    let s1 = s0.apply_message(&update(&k, &k.owner, &l, 1)).unwrap();
    assert!(s1.pending.is_some());

    // cancel by the recovery key
    let mut c = Message::Cancel { enclave_id: ENCLAVE_ID, nonce: 2, sig: [0; 64] };
    k.recovery.sign(&mut c);
    let s2 = s1.apply_message(&c).unwrap();
    assert!(s2.pending.is_none());
    // cancel by a stranger
    let mut c = Message::Cancel { enclave_id: ENCLAVE_ID, nonce: 3, sig: [0; 64] };
    k.witness.sign(&mut c);
    assert_eq!(first_reason(&s2.apply_message(&c).unwrap_err()), "POLICY_SIG");

    // freeze is unauthenticated; unfreeze needs the owner
    let mut s3 = s2.clone();
    s3.freeze();
    assert!(s3.frozen);
    let mut u = Message::Unfreeze { enclave_id: ENCLAVE_ID, nonce: 3, sig: [0; 64] };
    k.recovery.sign(&mut u);
    assert_eq!(first_reason(&s3.apply_message(&u).unwrap_err()), "POLICY_SIG");
    k.owner.sign(&mut u);
    let s4 = s3.apply_message(&u).unwrap();
    assert!(!s4.frozen);

    // rearm raises seq, never lowers it
    let mut s5 = s4.clone();
    s5.armed = false;
    s5.seq = 10;
    let mut r = Message::Rearm { enclave_id: ENCLAVE_ID, nonce: 4, seq: 7, sig: [0; 64] };
    k.owner.sign(&mut r);
    let s6 = s5.apply_message(&r).unwrap();
    assert!(s6.armed);
    assert_eq!(s6.seq, 10);
    let mut r = Message::Rearm { enclave_id: ENCLAVE_ID, nonce: 5, seq: 12, sig: [0; 64] };
    k.owner.sign(&mut r);
    let s7 = s6.apply_message(&r).unwrap();
    assert_eq!(s7.seq, 12);
    // replayed rearm (same nonce) refused
    assert_eq!(first_reason(&s7.apply_message(&r).unwrap_err()), "POLICY_NONCE");

    // rotate owner: timelocked
    let new_owner = p256_key(0xe5);
    let mut ro = Message::RotateOwner { enclave_id: ENCLAVE_ID, nonce: 6, new_owner_pk: new_owner.pk, sig: [0; 64] };
    k.owner.sign(&mut ro);
    let s8 = s7.apply_message(&ro).unwrap();
    assert_eq!(s8.owner_pk, k.owner.pk);
    assert_eq!(s8.pending_owner.as_ref().unwrap().activation_height, H + 144);
    let mut s9 = s8.clone();
    set_best(&mut s9, H + 144);
    s9.activate_pending();
    assert_eq!(s9.owner_pk, new_owner.pk);
    // the old owner can no longer update
    let mut t = base.clone();
    t.limits.max_per_tx = 1;
    assert_eq!(first_reason(&s9.apply_message(&update(&k, &k.owner, &t, 7)).unwrap_err()), "POLICY_SIG");
    let s10 = s9.apply_message(&update(&k, &new_owner, &t, 7)).unwrap();
    assert_eq!(s10.mandate.limits.max_per_tx, 1);
    // rotate to the recovery key is refused
    let mut ro = Message::RotateOwner { enclave_id: ENCLAVE_ID, nonce: 8, new_owner_pk: k.recovery.pk, sig: [0; 64] };
    new_owner.sign(&mut ro);
    assert_eq!(first_reason(&s10.apply_message(&ro).unwrap_err()), "POLICY_INVALID");

    // recover: immediate, voids anything pending
    let mut l = s10.mandate.clone();
    l.limits.max_per_tx = 3 * BTC;
    let s11 = s10.apply_message(&update(&k, &new_owner, &l, 8)).unwrap();
    assert!(s11.pending.is_some());
    let fresh = p256_key(0xf6);
    let mut rc = Message::Recover { enclave_id: ENCLAVE_ID, nonce: 9, new_owner_pk: fresh.pk, sig: [0; 64] };
    new_owner.sign(&mut rc);
    assert_eq!(first_reason(&s11.apply_message(&rc).unwrap_err()), "POLICY_SIG", "owner cannot recover");
    k.recovery.sign(&mut rc);
    let s12 = s11.apply_message(&rc).unwrap();
    assert_eq!(s12.owner_pk, fresh.pk);
    assert!(s12.pending.is_none());
    // state round trip through sealing encoding
    assert_eq!(State::decode(&s12.encode()).unwrap(), s12);
}

#[test]
fn window_rolls_forward_only_by_whole_windows() {
    let (w, cold, k) = fx();
    let base = base_mandate(&w, &cold); // window 144 from checkpoint 250_000
    let mut s = init_state(base, &k, 250_000);
    s.window.outflow = 123;
    set_best(&mut s, 250_143);
    s.roll_window();
    assert_eq!(s.window.start_height, 250_000);
    assert_eq!(s.window.outflow, 123, "same window keeps usage");
    set_best(&mut s, 250_144);
    s.roll_window();
    assert_eq!(s.window.start_height, 250_144);
    assert_eq!(s.window.outflow, 0, "new window resets usage");
    s.window.outflow = 7;
    set_best(&mut s, 250_144 + 3 * 144 + 10);
    s.roll_window();
    assert_eq!(s.window.start_height, 250_144 + 3 * 144);
    assert_eq!(s.window.outflow, 0);
    // chain view behind the window start never moves it back
    set_best(&mut s, 250_000);
    s.roll_window();
    assert_eq!(s.window.start_height, 250_144 + 3 * 144);
}

#[test]
fn judge_charges_before_signing_second_spend_hits_window() {
    let (w, cold, k) = fx();
    let mut base = base_mandate(&w, &cold);
    base.limits.window_max_outflow = 1_500_000;
    let s0 = init_state(base, &k, H);
    let secp = secp();
    let psbt = build_psbt(
        &w,
        &[In::Own { branch: 0, index: 5, amount: 2_000_000, hint: true }],
        &[Out { spk: foreign_spk(1), amount: 900_000, hint: None }, Out { spk: w.spk(1, 0), amount: 1_098_000, hint: Some((1, 0)) }],
        2,
        false,
    )
    .psbt;
    let bytes = psbt.serialize();
    let c = classify(&secp, &bytes, &w.account, &s0.mandate, s0.own_index_bound).unwrap();
    let Verdict::Accept { state: s1, .. } = judge(&s0, &c, None) else { panic!("first accept") };
    assert_eq!(s1.window.outflow, 902_000);
    assert_eq!(s1.own_index_bound, [6, 1]);
    // the same transaction again against the charged state: over the window
    let Verdict::Refuse { refusal, .. } = judge(&s1, &c, None) else { panic!("second must refuse") };
    assert_eq!(refusal.0, vec![Reason::CapWindow]);
}

#[cfg(feature = "hollow-test")]
mod hollow {
    //! Remove a guard ⇒ its vector goes green. Each of these is a proof that the guard is load-bearing.
    use super::*;
    use bitcoin::{Amount, TxOut};
    use signer_core::classify::{classify_with_guards, ClassifyGuards};
    use signer_core::judge::{judge_with_guards, Guards};

    #[test]
    fn i2_without_prevtx_requirement_the_lying_witness_utxo_signs() {
        let (w, cold, k) = fx();
        let s = init_state(base_mandate(&w, &cold), &k, H);
        let secp = secp();
        // the coin is really 2_000_000; the host claims 1_000_000 so the 1_000_000 it pockets looks like change math
        let mut psbt = build_psbt(
            &w,
            &[In::Own { branch: 0, index: 5, amount: 2_000_000, hint: true }],
            &[Out { spk: foreign_spk(1), amount: 900_000, hint: None }, Out { spk: w.spk(1, 0), amount: 98_000, hint: Some((1, 0)) }],
            2,
            false,
        )
        .psbt;
        psbt.inputs[0].non_witness_utxo = None;
        psbt.inputs[0].witness_utxo = Some(TxOut { value: Amount::from_sat(1_000_000), script_pubkey: w.spk(0, 5) });
        let bytes = psbt.serialize();
        assert!(classify(&secp, &bytes, &w.account, &s.mandate, s.own_index_bound).is_err(), "guard on: refused");
        let g = ClassifyGuards { require_prevtx: false, ..Default::default() };
        let c = classify_with_guards(&secp, &bytes, &w.account, &s.mandate, s.own_index_bound, g).unwrap();
        assert!(matches!(judge(&s, &c, None), Verdict::Accept { .. }), "guard off: the lie signs (fee 1_002_000 hidden)");
    }

    #[test]
    fn i3_without_script_verification_change_to_foreign_key_signs() {
        let (w, cold, k) = fx();
        let s = init_state(base_mandate(&w, &cold), &k, H);
        let secp = secp();
        let mut psbt = build_psbt(
            &w,
            &[In::Own { branch: 0, index: 5, amount: 2_000_000, hint: true }],
            &[Out { spk: foreign_spk(1), amount: 900_000, hint: None }, Out { spk: w.spk(1, 0), amount: 1_098_000, hint: Some((1, 0)) }],
            2,
            false,
        )
        .psbt;
        psbt.unsigned_tx.output[1].script_pubkey = foreign_spk(5); // hint still claims our change path
        let bytes = psbt.serialize();
        assert!(classify(&secp, &bytes, &w.account, &s.mandate, s.own_index_bound).is_err(), "guard on: refused");
        let g = ClassifyGuards { verify_own_output_script: false, ..Default::default() };
        let c = classify_with_guards(&secp, &bytes, &w.account, &s.mandate, s.own_index_bound, g).unwrap();
        assert!(matches!(judge(&s, &c, None), Verdict::Accept { .. }), "guard off: 1_098_000 to a foreign key signs as 'change'");
    }

    #[test]
    fn i5_i11_without_commit_the_window_never_fills() {
        let (w, cold, k) = fx();
        let mut base = base_mandate(&w, &cold);
        base.limits.window_max_outflow = 1_500_000;
        let s0 = init_state(base, &k, H);
        let secp = secp();
        let psbt = build_psbt(
            &w,
            &[In::Own { branch: 0, index: 5, amount: 2_000_000, hint: true }],
            &[Out { spk: foreign_spk(1), amount: 900_000, hint: None }, Out { spk: w.spk(1, 0), amount: 1_098_000, hint: Some((1, 0)) }],
            2,
            false,
        )
        .psbt;
        let c = classify(&secp, &psbt.serialize(), &w.account, &s0.mandate, s0.own_index_bound).unwrap();
        let g = Guards { commit_before_sign: false, ..Default::default() };
        let Verdict::Accept { state: s1, .. } = judge_with_guards(&s0, &c, None, g) else { panic!() };
        assert_eq!(s1.window.outflow, 0, "guard off: nothing charged");
        assert!(matches!(judge_with_guards(&s1, &c, None, g), Verdict::Accept { .. }), "guard off: signs again past the window");
    }

    #[test]
    fn window_caps_guard_is_load_bearing() {
        let (w, cold, k) = fx();
        let mut s = init_state(base_mandate(&w, &cold), &k, H);
        s.window.outflow = 5 * BTC - 1_000;
        let secp = secp();
        let psbt = build_psbt(
            &w,
            &[In::Own { branch: 0, index: 5, amount: 2_000_000, hint: true }],
            &[Out { spk: foreign_spk(1), amount: 900_000, hint: None }, Out { spk: w.spk(1, 0), amount: 1_098_000, hint: Some((1, 0)) }],
            2,
            false,
        )
        .psbt;
        let c = classify(&secp, &psbt.serialize(), &w.account, &s.mandate, s.own_index_bound).unwrap();
        assert!(matches!(judge(&s, &c, None), Verdict::Refuse { .. }));
        let g = Guards { window_caps: false, ..Default::default() };
        assert!(matches!(judge_with_guards(&s, &c, None, g), Verdict::Accept { .. }));
    }
}
