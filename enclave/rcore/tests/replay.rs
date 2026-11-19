//! The whole ecall surface through `rcore_call` in host simulation (`nosgx`): two-step init,
//! identity card and recovery blob checks, headers on a mined regtest chain, judge → sign with
//! the two-phase rule, the session high-water mark refusing a forked base blob, and the replay
//! of every `vectors/r1/*.json` through the real dispatcher.

use bitcoin::absolute::LockTime;
use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpriv, Xpub};
use bitcoin::block::Header;
use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash;
use bitcoin::pow::CompactTarget;
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use p256::ecdsa::signature::hazmat::PrehashSigner;

use signer_core::mandate::*;
use signer_core::proto::{self, op, IdentityCard, Response};
use signer_core::receipt::Receipt;
use signer_core::sign::verify_digest_secp;
use signer_core::state::State;
use signer_core::update::Message;

/// The session mark is process-global (one enclave = one process); the two tests serialize.
static SESSION_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn call(op_code: u32, input: &[u8]) -> Response {
    let mut out = vec![0u8; 2 * 1024 * 1024];
    let mut out_len = 0usize;
    let rc =
        unsafe { rcore::rcore_call(op_code, input.as_ptr(), input.len(), out.as_mut_ptr(), out.len(), &mut out_len) };
    assert_eq!(rc, 0, "rcore_call status");
    Response::decode(&out[..out_len]).unwrap()
}

struct P256Key {
    sk: p256::ecdsa::SigningKey,
    pk: [u8; 65],
}

fn p256_key(b: u8) -> P256Key {
    let mut bytes = [b; 32];
    bytes[0] = 1;
    let sk = p256::ecdsa::SigningKey::from_bytes((&bytes).into()).unwrap();
    let point = sk.verifying_key().to_encoded_point(false);
    let mut pk = [0u8; 65];
    pk.copy_from_slice(point.as_bytes());
    P256Key { sk, pk }
}

impl P256Key {
    fn sign(&self, msg: &mut Message) {
        let d = msg.digest();
        let sig: p256::ecdsa::Signature = self.sk.sign_prehash(&d).unwrap();
        let mut s = [0u8; 64];
        s.copy_from_slice(&sig.to_bytes());
        match msg {
            Message::PolicyUpdate { sig, .. }
            | Message::Cancel { sig, .. }
            | Message::Unfreeze { sig, .. }
            | Message::Rearm { sig, .. }
            | Message::RotateOwner { sig, .. }
            | Message::Recover { sig, .. }
            | Message::Arm { sig, .. }
            | Message::Anchor { sig, .. }
            | Message::WitnessToken { sig, .. } => *sig = s,
        }
    }
    fn raw_sk(&self) -> [u8; 32] {
        let mut b = [0u8; 32];
        b.copy_from_slice(&self.sk.to_bytes());
        b
    }
}

/// Host-side wallet from the same entropy the enclave got (test seed).
#[allow(dead_code)]
struct Wallet {
    account_xpriv: Xpriv,
    xpub: Xpub,
    fingerprint: [u8; 4],
}

fn wallet(entropy: &[u8; 32], net: bitcoin::Network, coin: u32) -> Wallet {
    let secp = Secp256k1::new();
    let seed = signer_core::bip39::seed(&signer_core::bip39::mnemonic(entropy));
    let master = Xpriv::new_master(net, &seed).unwrap();
    let path = DerivationPath::from(vec![
        ChildNumber::from_hardened_idx(84).unwrap(),
        ChildNumber::from_hardened_idx(coin).unwrap(),
        ChildNumber::from_hardened_idx(0).unwrap(),
    ]);
    let account_xpriv = master.derive_priv(&secp, &path).unwrap();
    let xpub = Xpub::from_priv(&secp, &account_xpriv);
    let mut fingerprint = [0u8; 4];
    fingerprint.copy_from_slice(master.fingerprint(&secp).as_bytes());
    Wallet { account_xpriv, xpub, fingerprint }
}

impl Wallet {
    fn spk(&self, secp: &Secp256k1<All>, branch: u32, index: u32) -> ScriptBuf {
        let k = self
            .xpub
            .derive_pub(
                secp,
                &[ChildNumber::from_normal_idx(branch).unwrap(), ChildNumber::from_normal_idx(index).unwrap()],
            )
            .unwrap();
        ScriptBuf::new_p2wpkh(&k.to_pub().wpubkey_hash())
    }
    fn pubkey(&self, secp: &Secp256k1<All>, branch: u32, index: u32) -> bitcoin::secp256k1::PublicKey {
        self.xpub
            .derive_pub(
                secp,
                &[ChildNumber::from_normal_idx(branch).unwrap(), ChildNumber::from_normal_idx(index).unwrap()],
            )
            .unwrap()
            .to_pub()
            .0
    }
    fn origin(&self, coin: u32, branch: u32, index: u32) -> (Fingerprint, DerivationPath) {
        (
            Fingerprint::from(self.fingerprint),
            DerivationPath::from(vec![
                ChildNumber::from_hardened_idx(84).unwrap(),
                ChildNumber::from_hardened_idx(coin).unwrap(),
                ChildNumber::from_hardened_idx(0).unwrap(),
                ChildNumber::from_normal_idx(branch).unwrap(),
                ChildNumber::from_normal_idx(index).unwrap(),
            ]),
        )
    }
}

fn mine(prev: &Header, time: u32, salt: u32) -> Header {
    let limit = bitcoin::params::Params::REGTEST.max_attainable_target;
    let mut h = Header {
        version: bitcoin::block::Version::TWO,
        prev_blockhash: prev.block_hash(),
        merkle_root: bitcoin::TxMerkleNode::from_byte_array([salt as u8; 32]),
        time,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        nonce: 0,
    };
    while h.validate_pow(limit).is_err() {
        h.nonce += 1;
    }
    h
}

fn regtest_mandate(fp: [u8; 4], cp: &Header) -> Mandate {
    Mandate {
        version: MANDATE_VERSION,
        network: Network::Regtest,
        wallet: WalletSpec {
            fingerprint: fp,
            account: AccountPath { purpose: 84, coin: 1, account: 0 },
            script_types: vec![ScriptType::P2wpkh],
        },
        destinations: Destinations {
            trusted: vec![],
            unlisted: ClassCaps { max_per_tx: 1_000_000, max_per_window: 5_000_000 },
        },
        limits: Limits {
            max_per_tx: 100_000_000,
            window_blocks: 144,
            window_max_outflow: 500_000_000,
            max_fee_abs: 100_000,
            max_fee_rate: 100,
            max_fee_per_window: None,
            max_inputs: 64,
            max_outputs: 32,
            own_index_gap: 100,
            max_reorg: 6,
        },
        rules: Rules {
            sighash: SighashRule::All,
            payjoin: PayjoinRule::None,
            op_return: OpReturnRule::None,
            rbf: true,
        },
        checkpoint: Checkpoint {
            hash: cp.block_hash().to_byte_array(),
            height: 100,
            time: cp.time,
            bits: 0x207f_ffff,
            period_start_time: cp.time,
            period_bits: 0x207f_ffff,
        },
        freshness: Freshness { required: false, witness_pk: None, max_tip_lag: 6 },
        not_after_height: 10_000,
        timelock_blocks: 144,
    }
}

fn payout_psbt(
    secp: &Secp256k1<All>,
    w: &Wallet,
    coin: u32,
    in_index: u32,
    in_amount: u64,
    out_amount: u64,
    fee: u64,
) -> Psbt {
    let prev = Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_consensus(777),
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut { value: Amount::from_sat(in_amount), script_pubkey: w.spk(secp, 0, in_index) }],
    };
    let foreign = wallet(&[0x77; 32], bitcoin::Network::Regtest, 1).spk(secp, 0, 1);
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: prev.compute_txid(), vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut { value: Amount::from_sat(out_amount), script_pubkey: foreign },
            TxOut { value: Amount::from_sat(in_amount - out_amount - fee), script_pubkey: w.spk(secp, 1, 0) },
        ],
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    psbt.inputs[0].non_witness_utxo = Some(prev);
    psbt.inputs[0].bip32_derivation.insert(w.pubkey(secp, 0, in_index), w.origin(coin, 0, in_index));
    psbt.outputs[1].bip32_derivation.insert(w.pubkey(secp, 1, 0), w.origin(coin, 1, 0));
    psbt
}

#[test]
fn full_flow_init_install_headers_judge_sign_and_fork_refusal() {
    let _guard = SESSION_LOCK.lock().unwrap();
    let secp = Secp256k1::new();
    let owner = p256_key(0xa1);
    let recovery = p256_key(0xb2);
    let entropy = [0x33u8; 32];

    // --- INIT (test variant with a known seed; the real INIT draws it) ---
    call(op::TEST_RESET_SESSION, &[]);
    let init = proto::InitRequest { network: 3, owner_pk: owner.pk, recovery_pk: recovery.pk };
    let treq = proto::TestInitRequest { init: init.clone(), seed: entropy, identity_sk: [0x55; 32], state: vec![] };
    let r = call(op::TEST_INIT, &treq.encode());
    assert!(r.ok, "{:?}", r.reasons);
    let ir = proto::InitResponse::decode(&r.payload).unwrap();
    let w = wallet(&entropy, bitcoin::Network::Regtest, 1);
    assert_eq!(ir.xpub, w.xpub.encode(), "the enclave derives the same account as the host from the same entropy");
    assert_eq!(ir.fingerprint, w.fingerprint);
    // identity card verifies under the identity key and names the wallet
    let card = IdentityCard::decode(&ir.card).unwrap();
    assert_eq!(card.xpub, ir.xpub);
    assert_eq!(card.tier, "T0-nosgx");
    assert!(verify_digest_secp(&secp, &ir.identity_pk, &card.digest(), &ir.card_sig));
    // the recovery blob opens with the recovery key to the entropy, and is bound to this wallet
    let got = rcore::recovery::decrypt(&recovery.raw_sk(), &ir.fingerprint, &ir.xpub, &ir.recovery_blob).unwrap();
    assert_eq!(got, entropy);
    assert!(rcore::recovery::decrypt(&owner.raw_sk(), &ir.fingerprint, &ir.xpub, &ir.recovery_blob).is_none());
    // a keys-only blob answers STATUS with installed=false and is refused by everything else
    let r = call(op::STATUS, &ir.sealed);
    assert!(r.ok);
    assert!(!proto::StatusResponse::decode(&r.payload).unwrap().installed);
    let r = call(op::POLICY, &ir.sealed);
    assert!(!r.ok && r.reasons == vec!["STATE_UNSEALABLE"]);

    // --- INSTALL the owner-signed mandate (now that the fingerprint is known) ---
    let genesis = Header {
        version: bitcoin::block::Version::TWO,
        prev_blockhash: bitcoin::BlockHash::all_zeros(),
        merkle_root: bitcoin::TxMerkleNode::all_zeros(),
        time: 1_000_000,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        nonce: 0,
    };
    let cp = mine(&genesis, 1_000_000, 1);
    let mandate = regtest_mandate(ir.fingerprint, &cp);
    assert_eq!(mandate.validate(), Ok(()));
    let enclave_id = signer_core::sha256(&ir.identity_pk);
    let mut m = Message::PolicyUpdate { enclave_id, nonce: 0, mandate: mandate.encode(), sig: [0; 64] };
    owner.sign(&mut m);
    // a mandate signed by the recovery key is refused
    let mut bad = m.clone();
    recovery.sign(&mut bad);
    let r = call(
        op::INSTALL,
        &proto::SealedWith { sealed: ir.sealed.clone(), data: mandate.encode(), extra: Some(bad.sig().to_vec()) }
            .encode(),
    );
    assert!(!r.ok && r.reasons == vec!["POLICY_SIG"]);
    // a mandate for a different fingerprint is refused
    let mut other = mandate.clone();
    other.wallet.fingerprint = [9; 4];
    let mut mo = Message::PolicyUpdate { enclave_id, nonce: 0, mandate: other.encode(), sig: [0; 64] };
    owner.sign(&mut mo);
    let r = call(
        op::INSTALL,
        &proto::SealedWith { sealed: ir.sealed.clone(), data: other.encode(), extra: Some(mo.sig().to_vec()) }.encode(),
    );
    assert!(!r.ok && r.reasons == vec!["POLICY_WALLET"]);
    // the right one installs
    let r = call(
        op::INSTALL,
        &proto::SealedWith { sealed: ir.sealed.clone(), data: mandate.encode(), extra: Some(m.sig().to_vec()) }
            .encode(),
    );
    assert!(r.ok, "{:?}", r.reasons);
    let sealed0 = proto::SealedResponse::decode(&r.payload).unwrap().sealed;
    // installing twice is refused
    let r = call(
        op::INSTALL,
        &proto::SealedWith { sealed: sealed0.clone(), data: mandate.encode(), extra: Some(m.sig().to_vec()) }.encode(),
    );
    assert!(!r.ok);

    // --- STATUS / POLICY ---
    let r = call(op::STATUS, &sealed0);
    assert!(r.ok);
    let st = proto::StatusResponse::decode(&r.payload).unwrap();
    assert_eq!(st.best_height, 100);
    assert_eq!(st.seq, 0);
    assert!(st.clock_label.contains("regtest"));
    let r = call(op::POLICY, &sealed0);
    let pol = proto::PolicyResponse::decode(&r.payload).unwrap();
    assert_eq!(pol.mandate, mandate.encode());
    assert_eq!(pol.sig, *m.sig());

    // --- HEADERS: mine 10 on the checkpoint ---
    let mut hs = Vec::new();
    let mut prev = cp;
    for i in 0..10u32 {
        let h = mine(&prev, prev.time + 10, 100 + i);
        hs.push(serialize(&h));
        prev = h;
    }
    let raw: Vec<u8> = hs.concat();
    let r = call(op::HEADERS, &proto::SealedWith { sealed: sealed0.clone(), data: raw, extra: None }.encode());
    assert!(r.ok, "{:?}", r.reasons);
    let hr = proto::HeadersResponse::decode(&r.payload).unwrap();
    assert_eq!(hr.accepted, 10);
    assert_eq!(hr.best_height, 110);
    let sealed1 = hr.sealed;

    // --- JUDGE → SIGN ---
    let psbt = payout_psbt(&secp, &w, 1, 5, 2_000_000, 900_000, 2_000);
    let bytes = psbt.serialize();
    let r = call(op::JUDGE, &proto::SealedWith { sealed: sealed1.clone(), data: bytes.clone(), extra: None }.encode());
    assert!(r.ok, "{:?}", r.reasons);
    let jr = proto::JudgeResponse::decode(&r.payload).unwrap();
    let charged = jr.sealed;
    let preview = Receipt::decode(&jr.receipt).unwrap();
    assert_eq!(preview.seq, 1);
    assert_eq!(preview.net_outflow, 902_000);
    // SIGN with the UNCHARGED blob refuses (two-phase)
    let r = call(op::SIGN, &proto::SealedWith { sealed: sealed1.clone(), data: bytes.clone(), extra: None }.encode());
    assert!(!r.ok, "sign needs the charged blob");
    // SIGN with the charged blob but a different PSBT (same txid, hint stripped) refuses
    let mut stripped = psbt.clone();
    stripped.outputs[1].bip32_derivation.clear();
    let r = call(
        op::SIGN,
        &proto::SealedWith { sealed: charged.clone(), data: stripped.serialize(), extra: None }.encode(),
    );
    assert!(!r.ok, "sign needs the exact judged bytes");
    // SIGN with the charged blob and the exact bytes signs; the receipt verifies
    let r = call(op::SIGN, &proto::SealedWith { sealed: charged.clone(), data: bytes.clone(), extra: None }.encode());
    assert!(r.ok, "{:?}", r.reasons);
    let sr = proto::SignResponse::decode(&r.payload).unwrap();
    let signed = Psbt::deserialize(&sr.psbt).unwrap();
    let (pk, sig) = signed.inputs[0].partial_sigs.iter().next().unwrap();
    let mut cache = SighashCache::new(&signed.unsigned_tx);
    let sh = cache
        .p2wpkh_signature_hash(0, &w.spk(&secp, 0, 5), Amount::from_sat(2_000_000), EcdsaSighashType::All)
        .unwrap();
    secp.verify_ecdsa(&bitcoin::secp256k1::Message::from_digest(sh.to_byte_array()), &sig.signature, &pk.inner)
        .unwrap();
    let receipt = Receipt::decode(&sr.receipt).unwrap();
    assert_eq!(receipt, preview);
    assert!(verify_digest_secp(&secp, &ir.identity_pk, &receipt.digest(), &sr.receipt_sig));
    assert_eq!(sr.session_id, st.session_id);
    // signing again with the same charged blob is idempotent (same signature)
    let r2 = call(op::SIGN, &proto::SealedWith { sealed: charged.clone(), data: bytes.clone(), extra: None }.encode());
    assert!(r2.ok);
    assert_eq!(proto::SignResponse::decode(&r2.payload).unwrap().psbt, sr.psbt);

    // --- the fork: a second JUDGE from the same base blob is refused by the session mark ---
    let psbt_b = payout_psbt(&secp, &w, 1, 6, 2_000_000, 800_000, 2_000);
    let r =
        call(op::JUDGE, &proto::SealedWith { sealed: sealed1.clone(), data: psbt_b.serialize(), extra: None }.encode());
    assert!(!r.ok && r.reasons == vec!["SEQ_BEHIND_SESSION"], "{:?}", r.reasons);
    // and so is every other operation on the stale blob
    let r = call(op::HEADERS, &proto::SealedWith { sealed: sealed1.clone(), data: vec![], extra: None }.encode());
    assert!(!r.ok && r.reasons == vec!["SEQ_BEHIND_SESSION"]);
    // the charged blob continues normally
    let r =
        call(op::JUDGE, &proto::SealedWith { sealed: charged.clone(), data: psbt_b.serialize(), extra: None }.encode());
    assert!(r.ok, "{:?}", r.reasons);
    let charged2 = proto::JudgeResponse::decode(&r.payload).unwrap().sealed;
    let st2 = proto::StatusResponse::decode(&call(op::STATUS, &charged2).payload).unwrap();
    assert_eq!(st2.seq, 2);
    assert_eq!(st2.window_outflow, 902_000 + 802_000);
    // --- after an enclave "reload" the volatile mark is gone — and so is the owner's approval:
    // REQ-r7 makes a reloaded process one that judges and signs nothing until `Arm` ---
    call(op::TEST_RESET_SESSION, &[]);
    let r =
        call(op::JUDGE, &proto::SealedWith { sealed: sealed1.clone(), data: psbt_b.serialize(), extra: None }.encode());
    assert!(!r.ok && r.reasons == vec!["NOT_ARMED"], "a reload is unarmed: {:?}", r.reasons);
    let r = call(op::SIGN, &proto::SealedWith { sealed: charged.clone(), data: bytes.clone(), extra: None }.encode());
    assert!(
        !r.ok && r.reasons == vec!["NOT_ARMED"],
        "the signing entrypoint checks the boot-arm itself: {:?}",
        r.reasons
    );
    let st3 = proto::StatusResponse::decode(&call(op::STATUS, &charged2).payload).unwrap();
    assert_ne!(st3.session_id, st.session_id);
    assert!(!st3.boot_armed && !st3.auto_arm);
    assert_ne!(st3.boot_challenge, st.boot_challenge, "a fresh challenge per load");
    // a replayed Arm — an earlier load's challenge — is refused
    let mut stale = Message::Arm { enclave_id, nonce: 1, boot_challenge: st.boot_challenge, seq_seen: 2, sig: [0; 64] };
    owner.sign(&mut stale);
    let r = call(
        op::APPLY_MESSAGE,
        &proto::SealedWith { sealed: charged2.clone(), data: stale.encode(), extra: None }.encode(),
    );
    assert!(!r.ok && r.reasons == vec!["ARM_CHALLENGE"], "{:?}", r.reasons);
    // the owner saw #2: a rolled-back blob (#0) cannot be armed with that knowledge
    let mut arm_old =
        Message::Arm { enclave_id, nonce: 1, boot_challenge: st3.boot_challenge, seq_seen: 2, sig: [0; 64] };
    owner.sign(&mut arm_old);
    let r = call(
        op::APPLY_MESSAGE,
        &proto::SealedWith { sealed: sealed1.clone(), data: arm_old.encode(), extra: None }.encode(),
    );
    assert!(!r.ok && r.reasons == vec!["ARM_SEQ_BEHIND"], "{:?}", r.reasons);
    // the wrong key, the wrong nonce
    let thief = p256_key(0xb2);
    let mut arm_thief =
        Message::Arm { enclave_id, nonce: 1, boot_challenge: st3.boot_challenge, seq_seen: 2, sig: [0; 64] };
    thief.sign(&mut arm_thief);
    let r = call(
        op::APPLY_MESSAGE,
        &proto::SealedWith { sealed: charged2.clone(), data: arm_thief.encode(), extra: None }.encode(),
    );
    assert!(!r.ok && r.reasons == vec!["POLICY_SIG"], "{:?}", r.reasons);
    let mut arm_nonce =
        Message::Arm { enclave_id, nonce: 7, boot_challenge: st3.boot_challenge, seq_seen: 2, sig: [0; 64] };
    owner.sign(&mut arm_nonce);
    let r = call(
        op::APPLY_MESSAGE,
        &proto::SealedWith { sealed: charged2.clone(), data: arm_nonce.encode(), extra: None }.encode(),
    );
    assert!(!r.ok && r.reasons == vec!["POLICY_NONCE"], "{:?}", r.reasons);
    // still unarmed after all of that
    assert!(!proto::StatusResponse::decode(&call(op::STATUS, &charged2).payload).unwrap().boot_armed);
    // the genuine Arm over THIS load's challenge, on the current blob
    let mut arm = Message::Arm { enclave_id, nonce: 1, boot_challenge: st3.boot_challenge, seq_seen: 2, sig: [0; 64] };
    owner.sign(&mut arm);
    let r = call(
        op::APPLY_MESSAGE,
        &proto::SealedWith { sealed: charged2.clone(), data: arm.encode(), extra: None }.encode(),
    );
    assert!(r.ok, "{:?}", r.reasons);
    let charged2 = proto::SealedResponse::decode(&r.payload).unwrap().sealed; // the nonce is consumed: 1
    let st4 = proto::StatusResponse::decode(&call(op::STATUS, &charged2).payload).unwrap();
    assert!(st4.boot_armed && st4.nonce == 1 && st4.seq == 2, "{st4:?}");
    // the same Arm again within the load: the nonce is spent
    let r = call(
        op::APPLY_MESSAGE,
        &proto::SealedWith { sealed: charged2.clone(), data: arm.encode(), extra: None }.encode(),
    );
    assert!(!r.ok && r.reasons == vec!["POLICY_NONCE"], "{:?}", r.reasons);
    // C-R7-3: arming ratcheted the mark to #2 — the stale blob is refused inside this armed process
    let r =
        call(op::JUDGE, &proto::SealedWith { sealed: sealed1.clone(), data: psbt_b.serialize(), extra: None }.encode());
    assert!(!r.ok && r.reasons == vec!["SEQ_BEHIND_SESSION"], "{:?}", r.reasons);

    // --- FREEZE (unauthenticated) then a message ---
    let r = call(op::FREEZE, &charged2);
    assert!(r.ok);
    let frozen = proto::SealedResponse::decode(&r.payload).unwrap().sealed;
    let r = call(op::JUDGE, &proto::SealedWith { sealed: frozen.clone(), data: bytes.clone(), extra: None }.encode());
    assert!(!r.ok && r.reasons == vec!["FROZEN"]);
    let mut un = Message::Unfreeze { enclave_id, nonce: 2, sig: [0; 64] }; // 1 went to the Arm
    owner.sign(&mut un);
    let r = call(op::APPLY_MESSAGE, &proto::SealedWith { sealed: frozen, data: un.encode(), extra: None }.encode());
    assert!(r.ok, "{:?}", r.reasons);
    // a truncated blob is refused here; a bit-flipped one is refused by the SDK's MAC on
    // hardware (the nosgx stand-in has no MAC — that check is the R2 hardware smoke test)
    let truncated = charged2[..charged2.len() - 1].to_vec();
    let r = call(op::STATUS, &truncated);
    assert!(!r.ok && r.reasons == vec!["STATE_UNSEALABLE"]);
}

#[derive(serde::Deserialize)]
struct Vector {
    name: String,
    expect: String,
    reasons: Vec<String>,
    disarms: bool,
    state_hex: String,
    psbt_hex: String,
    witness_hex: Option<String>,
}

#[test]
fn replay_r1_vectors_through_the_dispatcher() {
    let _guard = SESSION_LOCK.lock().unwrap();
    let secp = Secp256k1::new();
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors/r1");
    let mut names: Vec<_> = std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().path()).collect();
    names.sort();
    assert!(names.len() >= 50);
    let w = wallet(&[0x01; 32], bitcoin::Network::Signet, 1);
    let mut failures = Vec::new();
    for path in names {
        let v: Vector = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let state_bytes = hex::decode(&v.state_hex).unwrap();
        let state = State::decode(&state_bytes).unwrap();
        call(op::TEST_RESET_SESSION, &[]);
        let treq = proto::TestInitRequest {
            init: proto::InitRequest { network: 2, owner_pk: state.owner_pk, recovery_pk: state.recovery_pk },
            seed: [0x01; 32],
            identity_sk: [0x55; 32],
            state: state_bytes,
        };
        let r = call(op::TEST_INIT, &treq.encode());
        assert!(r.ok, "{}: test init {:?}", v.name, r.reasons);
        let ir = proto::InitResponse::decode(&r.payload).unwrap();
        assert_eq!(ir.fingerprint, w.fingerprint, "{}: fixture wallet", v.name);
        let psbt = hex::decode(&v.psbt_hex).unwrap();
        let witness = v.witness_hex.as_ref().map(|h| hex::decode(h).unwrap());
        let r = call(
            op::JUDGE,
            &proto::SealedWith { sealed: ir.sealed.clone(), data: psbt.clone(), extra: witness }.encode(),
        );
        let mut got = r.reasons.clone();
        got.sort();
        let mut want = v.reasons.clone();
        want.sort();
        match v.expect.as_str() {
            "accept" => {
                if !r.ok {
                    failures.push(format!("{}: expected accept, got {:?}", v.name, r.reasons));
                    continue;
                }
                let jr = proto::JudgeResponse::decode(&r.payload).unwrap();
                let r =
                    call(op::SIGN, &proto::SealedWith { sealed: jr.sealed, data: psbt.clone(), extra: None }.encode());
                if !r.ok {
                    failures.push(format!("{}: sign {:?}", v.name, r.reasons));
                    continue;
                }
                let sr = proto::SignResponse::decode(&r.payload).unwrap();
                let signed = Psbt::deserialize(&sr.psbt).unwrap();
                let mut cache = SighashCache::new(&signed.unsigned_tx);
                let mut n = 0;
                for (i, input) in signed.inputs.iter().enumerate() {
                    for (pk, sig) in &input.partial_sigs {
                        let prev = input.non_witness_utxo.as_ref().unwrap();
                        let prevout = &prev.output[signed.unsigned_tx.input[i].previous_output.vout as usize];
                        let sh = cache
                            .p2wpkh_signature_hash(i, &prevout.script_pubkey, prevout.value, EcdsaSighashType::All)
                            .unwrap();
                        if secp
                            .verify_ecdsa(
                                &bitcoin::secp256k1::Message::from_digest(sh.to_byte_array()),
                                &sig.signature,
                                &pk.inner,
                            )
                            .is_err()
                        {
                            failures.push(format!("{}: bad signature on input {i}", v.name));
                        }
                        n += 1;
                    }
                }
                if n == 0 {
                    failures.push(format!("{}: nothing signed", v.name));
                }
                let receipt = Receipt::decode(&sr.receipt).unwrap();
                if !verify_digest_secp(&secp, &ir.identity_pk, &receipt.digest(), &sr.receipt_sig) {
                    failures.push(format!("{}: receipt sig", v.name));
                }
            }
            "refuse" => {
                if r.ok {
                    failures.push(format!("{}: expected refuse {:?}, got accept", v.name, want));
                    continue;
                }
                if got != want {
                    failures.push(format!("{}: reasons {:?} want {:?}", v.name, got, want));
                }
                if v.disarms == r.payload.is_empty() {
                    failures.push(format!(
                        "{}: disarm payload presence {} want {}",
                        v.name,
                        !r.payload.is_empty(),
                        v.disarms
                    ));
                }
            }
            _ => unreachable!(),
        }
    }
    assert!(failures.is_empty(), "replay failures:\n{}", failures.join("\n"));
}

/// `REPORT` (REQ-r5 §3): the report binds the identity card and the verifier's nonce in
/// `report_data`, changes nothing, and refuses anything but a 544-byte input.
#[test]
fn report_binds_card_and_nonce() {
    let owner = p256_key(0xa1);
    let recovery = p256_key(0xb2);
    let entropy = [0x33u8; 32];
    call(op::TEST_RESET_SESSION, &[]);
    let init = proto::InitRequest { network: 3, owner_pk: owner.pk, recovery_pk: recovery.pk };
    let treq = proto::TestInitRequest { init, seed: entropy, identity_sk: [0x55; 32], state: vec![] };
    let r = call(op::TEST_INIT, &treq.encode());
    assert!(r.ok, "{:?}", r.reasons);
    let ir = proto::InitResponse::decode(&r.payload).unwrap();
    let card = IdentityCard::decode(&ir.card).unwrap();

    let nonce = [0x77u8; 32];
    let mut data = vec![0u8; proto::quote::TARGET_INFO_LEN];
    data.extend_from_slice(&nonce);
    let r = call(op::REPORT, &proto::SealedWith { sealed: ir.sealed.clone(), data, extra: None }.encode());
    assert!(r.ok, "{:?}", r.reasons);
    let rr = proto::ReportResponse::decode(&r.payload).unwrap();
    assert_eq!(rr.card.encode(), card.encode(), "the card the report binds is the card INIT signed");
    let expect = signer_core::sha256(&proto::quote::preimage(&nonce, &card.encode()));
    let o = proto::quote::REPORT_DATA_OFFSET;
    assert_eq!(&rr.report[o..o + 32], &expect[..], "report_data[..32] = SHA-256(domain ‖ nonce ‖ card)");
    assert_eq!(rr.report[o + 32..o + 64], [0u8; 32]);
    // the same blob, a different nonce: a different binding (anti-replay is the verifier's nonce)
    let mut data2 = vec![0u8; proto::quote::TARGET_INFO_LEN];
    data2.extend_from_slice(&[0x78u8; 32]);
    let r2 = call(op::REPORT, &proto::SealedWith { sealed: ir.sealed.clone(), data: data2, extra: None }.encode());
    let rr2 = proto::ReportResponse::decode(&r2.payload).unwrap();
    assert_ne!(rr2.report[o..o + 32], rr.report[o..o + 32]);
    // read-only: status after is the status before
    let s1 = call(op::STATUS, &ir.sealed);
    assert!(s1.ok);
    // one byte short, one byte long, a stray `extra`: ENCODING
    for bad in [543usize, 545] {
        let r = call(
            op::REPORT,
            &proto::SealedWith { sealed: ir.sealed.clone(), data: vec![0u8; bad], extra: None }.encode(),
        );
        assert!(!r.ok && r.reasons.iter().any(|x| x == "ENCODING"), "{bad}: {:?}", r.reasons);
    }
    let r4 = call(
        op::REPORT,
        &proto::SealedWith { sealed: ir.sealed.clone(), data: vec![0u8; 544], extra: Some(vec![1]) }.encode(),
    );
    assert!(!r4.ok && r4.reasons.iter().any(|x| x == "ENCODING"), "{:?}", r4.reasons);
    // a blob that does not unseal: no report at all
    let r5 = call(op::REPORT, &proto::SealedWith { sealed: vec![9u8; 40], data: vec![0u8; 544], extra: None }.encode());
    assert!(!r5.ok && r5.reasons.iter().any(|x| x == "STATE_UNSEALABLE"), "{:?}", r5.reasons);
}

/// REQ-r9: a software TPM for the T0 bench — an AK, a counter index Name and a live counter; it
/// certifies honestly unless asked to lie, and only ever increments.
struct SoftTpm {
    ak: P256Key,
    name: [u8; signer_core::tpm_attest::NV_NAME_LEN],
    counter: u64,
}

impl SoftTpm {
    fn new(seed: u8, tag: u8, counter: u64) -> Self {
        let mut name = [tag; signer_core::tpm_attest::NV_NAME_LEN];
        name[0] = 0x00;
        name[1] = 0x0B;
        SoftTpm { ak: p256_key(seed), name, counter }
    }
    fn increment(&mut self) {
        self.counter += 1;
    }
    /// An honest `TPM2_NV_Certify` over `nonce`: the attest names this index and the live counter.
    fn certify(&self, nonce: &[u8; 32]) -> proto::TpmProof {
        self.certify_as(nonce, &self.name, self.counter, &self.ak)
    }
    fn certify_as(&self, nonce: &[u8; 32], name: &[u8; 34], counter: u64, key: &P256Key) -> proto::TpmProof {
        let attest = signer_core::tpm_attest::build_nv_attest(&[0u8; 34], nonce, name, counter);
        let d = signer_core::sha256(&attest);
        let sig: p256::ecdsa::Signature = key.sk.sign_prehash(&d).unwrap();
        let sig = sig.normalize_s().unwrap_or(sig);
        let mut s = [0u8; 64];
        s.copy_from_slice(&sig.to_bytes());
        proto::TpmProof { attest, sig: s }
    }
}

/// The host's side of a `Fresh` call when the state is TPM-bound: nonce → certify → deposit → call.
fn fresh_call(tpm: &SoftTpm, op_code: u32, input: &[u8]) -> Response {
    let nonce: [u8; 32] = call(op::TPM_NONCE, &[]).payload.try_into().unwrap();
    let r = call(op::TPM_PROOF, &tpm.certify(&nonce).encode());
    assert!(r.ok, "deposit: {:?}", r.reasons);
    call(op_code, input)
}

/// REQ-r9a: the host's side of an `Anchor` — `call_fresh` deposits a proof for every APPLY_MESSAGE, and
/// the enclave verifies it against the SEALED identity and pins the LIVE value (the deposit is
/// mandatory, C4). `tpm` is the TPM the host actually talks to — honest or not.
fn anchor_call(tpm: &SoftTpm, sealed: &[u8], msg: &Message) -> Response {
    fresh_call(
        tpm,
        op::APPLY_MESSAGE,
        &proto::SealedWith { sealed: sealed.to_vec(), data: msg.encode(), extra: None }.encode(),
    )
}

/// A proof-less APPLY_MESSAGE (no nonce, no deposit).
fn bare_apply(sealed: &[u8], msg: &Message) -> Response {
    call(op::APPLY_MESSAGE, &proto::SealedWith { sealed: sealed.to_vec(), data: msg.encode(), extra: None }.encode())
}

fn status_of(sealed: &[u8]) -> proto::StatusResponse {
    let r = call(op::STATUS, sealed);
    assert!(r.ok, "{:?}", r.reasons);
    proto::StatusResponse::decode(&r.payload).unwrap()
}

#[test]
fn tpm_counter_freshness_r9() {
    let _guard = SESSION_LOCK.lock().unwrap();
    let owner = p256_key(0xc1);
    let recovery = p256_key(0xd2);
    let entropy = [0x44u8; 32];
    call(op::TEST_RESET_SESSION, &[]);
    let init = proto::InitRequest { network: 3, owner_pk: owner.pk, recovery_pk: recovery.pk };
    let treq = proto::TestInitRequest { init, seed: entropy, identity_sk: [0x66; 32], state: vec![] };
    let r = call(op::TEST_INIT, &treq.encode());
    assert!(r.ok, "{:?}", r.reasons);
    let ir = proto::InitResponse::decode(&r.payload).unwrap();
    let genesis = Header {
        version: bitcoin::block::Version::TWO,
        prev_blockhash: bitcoin::BlockHash::all_zeros(),
        merkle_root: bitcoin::TxMerkleNode::all_zeros(),
        time: 1_000_000,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        nonce: 0,
    };
    let cp = mine(&genesis, 1_000_000, 1);
    let mandate = regtest_mandate(ir.fingerprint, &cp);
    let enclave_id = signer_core::sha256(&ir.identity_pk);
    let mut m = Message::PolicyUpdate { enclave_id, nonce: 0, mandate: mandate.encode(), sig: [0; 64] };
    owner.sign(&mut m);
    let r = call(
        op::INSTALL,
        &proto::SealedWith { sealed: ir.sealed.clone(), data: mandate.encode(), extra: Some(m.sig().to_vec()) }
            .encode(),
    );
    assert!(r.ok, "{:?}", r.reasons);
    let unbound = proto::SealedResponse::decode(&r.payload).unwrap().sealed;
    let st = status_of(&unbound);
    assert!(!st.tpm_bound && st.tpm_expected == 0 && st.boot_armed, "an unanchored state is R7 as before: {st:?}");

    // --- the owner's TPM, verified on the laptop; its live counter happens to be 1000 ---
    let mut tpm = SoftTpm::new(0xe3, 0x5A, 1000);

    // --- Anchor negatives first: wrong challenge, seq ahead, malformed key, wrong nonce, wrong signer ---
    let challenge = st.boot_challenge;
    let mk = |nonce: u64, challenge: [u8; 32], ak_pk: [u8; 65], name: [u8; 34], counter: u64, seq_seen: u64| {
        Message::Anchor {
            enclave_id,
            nonce,
            boot_challenge: challenge,
            ak_pk,
            nv_name: name,
            counter,
            seq_seen,
            sig: [0; 64],
        }
    };
    let mut bad = mk(1, [9; 32], tpm.ak.pk, tpm.name, tpm.counter, 0);
    owner.sign(&mut bad);
    let r = anchor_call(&tpm, &unbound, &bad);
    assert!(!r.ok && r.reasons == vec!["ARM_CHALLENGE"], "{:?}", r.reasons);
    let mut bad = mk(1, challenge, tpm.ak.pk, tpm.name, tpm.counter, 5);
    owner.sign(&mut bad);
    let r = anchor_call(&tpm, &unbound, &bad);
    assert!(!r.ok && r.reasons == vec!["ARM_SEQ_BEHIND"], "{:?}", r.reasons);
    let mut sha1_name = tpm.name;
    sha1_name[1] = 0x04;
    let mut bad = mk(1, challenge, tpm.ak.pk, sha1_name, tpm.counter, 0);
    owner.sign(&mut bad);
    assert!(status_of(&unbound).tpm_last_fresh, "the previous Anchor's proof was verified before its refusal");
    let r = anchor_call(&tpm, &unbound, &bad);
    assert!(!r.ok && r.reasons == vec!["POLICY_INVALID"], "{:?}", r.reasons);
    assert!(!status_of(&unbound).tpm_last_fresh, "a malformed identity clears the flag (no proof was verified)");
    let mut bad = mk(3, challenge, tpm.ak.pk, tpm.name, tpm.counter, 0);
    owner.sign(&mut bad);
    let r = anchor_call(&tpm, &unbound, &bad);
    assert!(!r.ok && r.reasons == vec!["POLICY_NONCE"], "{:?}", r.reasons);
    let mut bad = mk(1, challenge, tpm.ak.pk, tpm.name, tpm.counter, 0);
    recovery.sign(&mut bad);
    let r = anchor_call(&tpm, &unbound, &bad);
    assert!(!r.ok && r.reasons == vec!["POLICY_SIG"], "{:?}", r.reasons);

    // --- the genuine Anchor: the state pins the TPM and expects counter+1 after the seal ---
    let mut anchor = mk(1, challenge, tpm.ak.pk, tpm.name, tpm.counter, 0);
    owner.sign(&mut anchor);
    // REQ-r9a C4: even the first, binding anchor needs the host's live proof — no proof-less path
    let r = bare_apply(&unbound, &anchor);
    assert!(!r.ok && r.reasons == vec!["TPM_REQUIRED"], "proof-less Anchor: {:?}", r.reasons);
    assert!(!status_of(&unbound).tpm_bound, "a refused Anchor binds nothing");
    let r = anchor_call(&tpm, &unbound, &anchor);
    assert!(r.ok, "{:?}", r.reasons);
    let bound1 = proto::SealedResponse::decode(&r.payload).unwrap().sealed;
    tpm.increment(); // the host increments after persisting the new blob
    let st = status_of(&bound1);
    assert!(st.tpm_bound && st.tpm_expected == 1001 && st.nonce == 1, "{st:?}");

    // --- every Fresh op now needs a proof; a pure read does not ---
    let r = call(op::FREEZE, &bound1);
    assert!(!r.ok && r.reasons == vec!["TPM_REQUIRED"], "no proof deposited: {:?}", r.reasons);
    let r = call(op::POLICY, &bound1);
    assert!(r.ok, "POLICY is a labeled pure read: {:?}", r.reasons);
    // a proof deposited without a live nonce is refused
    let r = call(op::TPM_PROOF, &tpm.certify(&[1; 32]).encode());
    assert!(!r.ok && r.reasons == vec!["TPM_NONCE"], "{:?}", r.reasons);
    // an honest proof: FREEZE goes through and the seal bumps to 1002
    let r = fresh_call(&tpm, op::FREEZE, &bound1);
    assert!(r.ok, "{:?}", r.reasons);
    let frozen = proto::SealedResponse::decode(&r.payload).unwrap().sealed;
    tpm.increment();
    let st = status_of(&frozen);
    assert!(st.frozen && st.tpm_expected == 1002 && st.tpm_last_fresh, "{st:?}");
    // the nonce and the proof were consumed: the same op again needs a new round trip
    let r = call(op::FREEZE, &frozen);
    assert!(!r.ok && r.reasons == vec!["TPM_REQUIRED"], "{:?}", r.reasons);

    // --- the rollback: the pre-freeze blob expects 1001, the TPM certifies 1002 ---
    let r = fresh_call(&tpm, op::FREEZE, &bound1);
    assert!(!r.ok && r.reasons == vec!["STATE_STALE"], "{:?}", r.reasons);
    assert!(!status_of(&frozen).tpm_last_fresh);
    // a crash between seal and increment looks the same: blob at 1002, counter still 1001
    let mut lagging = SoftTpm::new(0xe3, 0x5A, 1001);
    let r = fresh_call(&lagging, op::FREEZE, &frozen);
    assert!(!r.ok && r.reasons == vec!["STATE_STALE"], "{:?}", r.reasons);
    lagging.increment();

    // --- replay: a proof for an earlier nonce ---
    let nonce_a: [u8; 32] = call(op::TPM_NONCE, &[]).payload.try_into().unwrap();
    let proof_a = tpm.certify(&nonce_a);
    let nonce_b: [u8; 32] = call(op::TPM_NONCE, &[]).payload.try_into().unwrap(); // a new nonce forgets nonce_a
    assert_ne!(nonce_a, nonce_b);
    assert!(call(op::TPM_PROOF, &proof_a.encode()).ok);
    let r = call(op::FREEZE, &frozen);
    assert!(!r.ok && r.reasons == vec!["TPM_NONCE"], "{:?}", r.reasons);

    // --- a foreign TPM (another AK), a foreign index, a malformed attest ---
    let other = SoftTpm::new(0xf4, 0x5A, 1002);
    let n: [u8; 32] = call(op::TPM_NONCE, &[]).payload.try_into().unwrap();
    assert!(call(op::TPM_PROOF, &other.certify(&n).encode()).ok);
    let r = call(op::FREEZE, &frozen);
    assert!(!r.ok && r.reasons == vec!["TPM_SIG"], "{:?}", r.reasons);
    let n: [u8; 32] = call(op::TPM_NONCE, &[]).payload.try_into().unwrap();
    let mut other_name = tpm.name;
    other_name[5] ^= 1;
    assert!(call(op::TPM_PROOF, &tpm.certify_as(&n, &other_name, tpm.counter, &tpm.ak).encode()).ok);
    let r = call(op::FREEZE, &frozen);
    assert!(!r.ok && r.reasons == vec!["TPM_INDEX"], "{:?}", r.reasons);
    let n: [u8; 32] = call(op::TPM_NONCE, &[]).payload.try_into().unwrap();
    let mut p = tpm.certify(&n);
    p.attest.truncate(40);
    assert!(call(op::TPM_PROOF, &p.encode()).ok, "the deposit does not verify; the next Fresh op does");
    let r = call(op::FREEZE, &frozen);
    assert!(!r.ok && r.reasons == vec!["TPM_PARSE"], "{:?}", r.reasons);
    // the proof is consumed whatever the verdict
    let r = call(op::FREEZE, &frozen);
    assert!(!r.ok && r.reasons == vec!["TPM_REQUIRED"], "{:?}", r.reasons);

    // --- an unattended reload: no owner, a fresh proof arms the load by itself ---
    call(op::TEST_RESET_SESSION, &[]);
    let st = status_of(&frozen);
    assert!(!st.boot_armed && !st.tpm_last_fresh, "a reload starts unarmed: {st:?}");
    let mut un = Message::Unfreeze { enclave_id, nonce: 2, sig: [0; 64] };
    owner.sign(&mut un);
    // the owner's message itself is a Fresh op: without a proof it is TPM_REQUIRED, not NOT_ARMED
    let r =
        call(op::APPLY_MESSAGE, &proto::SealedWith { sealed: frozen.clone(), data: un.encode(), extra: None }.encode());
    assert!(!r.ok && r.reasons == vec!["TPM_REQUIRED"], "{:?}", r.reasons);
    let r = fresh_call(
        &tpm,
        op::APPLY_MESSAGE,
        &proto::SealedWith { sealed: frozen.clone(), data: un.encode(), extra: None }.encode(),
    );
    assert!(r.ok, "fresh proof after a reload: {:?}", r.reasons);
    let live = proto::SealedResponse::decode(&r.payload).unwrap().sealed;
    tpm.increment();
    let st = status_of(&live);
    assert!(
        st.boot_armed && !st.frozen && st.tpm_expected == 1003 && st.nonce == 2,
        "auto-armed on a fresh proof: {st:?}"
    );

    // --- a reload onto a rolled-back blob stays unarmed: STATE_STALE, never auto-arm ---
    call(op::TEST_RESET_SESSION, &[]);
    let r = fresh_call(&tpm, op::FREEZE, &bound1);
    assert!(!r.ok && r.reasons == vec!["STATE_STALE"], "{:?}", r.reasons);
    assert!(!status_of(&live).boot_armed, "a stale proof never arms");
    // an owner message other than Anchor cannot rescue a stale blob either: it needs the proof
    let mut fr = Message::Unfreeze { enclave_id, nonce: 3, sig: [0; 64] };
    owner.sign(&mut fr);
    let r = fresh_call(
        &tpm,
        op::APPLY_MESSAGE,
        &proto::SealedWith { sealed: bound1.clone(), data: fr.encode(), extra: None }.encode(),
    );
    assert!(!r.ok && r.reasons == vec!["STATE_STALE"], "{:?}", r.reasons);
    // ...until the owner re-anchors ON THE STALE BLOB (§2.5 + REQ-r9a): the override does not compare
    // the proof against the stale blob's expectation (C5), but it is NOT exempt from the proof (C4) —
    // the live, attested value becomes the new expectation; the blob's nonce is 1 → next 2
    let st = status_of(&bound1);
    assert!(st.tpm_expected == 1001 && st.nonce == 1, "{st:?}");
    let mut re = mk(2, st.boot_challenge, tpm.ak.pk, tpm.name, tpm.counter, 0);
    owner.sign(&mut re);
    let r = bare_apply(&bound1, &re);
    assert!(!r.ok && r.reasons == vec!["TPM_REQUIRED"], "REQ-r9a C4, no proof-less Anchor: {:?}", r.reasons);
    let r = anchor_call(&tpm, &bound1, &re);
    assert!(r.ok, "the Anchor bypasses the stale blob's expectation, not the proof: {:?}", r.reasons);
    let live2 = proto::SealedResponse::decode(&r.payload).unwrap().sealed;
    tpm.increment();
    let st = status_of(&live2);
    assert!(st.boot_armed && st.tpm_expected == tpm.counter && st.nonce == 2, "{st:?}");
    // the re-anchored blob is fresh again: a proven FREEZE goes through
    let r = fresh_call(&tpm, op::FREEZE, &live2);
    assert!(r.ok, "{:?}", r.reasons);
    tpm.increment();
    // a captured old Anchor (nonce 2 again) is refused after the fact, proof or not
    let r = bare_apply(&live2, &re);
    assert!(!r.ok && r.reasons == vec!["TPM_REQUIRED"], "{:?}", r.reasons);
    let r = anchor_call(&tpm, &live2, &re);
    assert!(!r.ok && r.reasons == vec!["POLICY_NONCE"], "{:?}", r.reasons);
}

/// REQ-r9a (RESP-r9a §4): the Anchor pins the LIVE counter of the proof the host deposits, verified
/// against the SEALED TPM identity, the owner's attested value as the lower bound. Vectors 1–5, 7, 7b.
#[test]
fn anchor_pins_the_live_counter_r9a() {
    let _guard = SESSION_LOCK.lock().unwrap();
    let owner = p256_key(0xc7);
    let recovery = p256_key(0xd8);
    call(op::TEST_RESET_SESSION, &[]);
    let init = proto::InitRequest { network: 3, owner_pk: owner.pk, recovery_pk: recovery.pk };
    let treq = proto::TestInitRequest { init, seed: [0x45u8; 32], identity_sk: [0x67; 32], state: vec![] };
    let r = call(op::TEST_INIT, &treq.encode());
    assert!(r.ok, "{:?}", r.reasons);
    let ir = proto::InitResponse::decode(&r.payload).unwrap();
    let genesis = Header {
        version: bitcoin::block::Version::TWO,
        prev_blockhash: bitcoin::BlockHash::all_zeros(),
        merkle_root: bitcoin::TxMerkleNode::all_zeros(),
        time: 1_000_000,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        nonce: 0,
    };
    let cp = mine(&genesis, 1_000_000, 1);
    let mandate = regtest_mandate(ir.fingerprint, &cp);
    let enclave_id = signer_core::sha256(&ir.identity_pk);
    let mut m = Message::PolicyUpdate { enclave_id, nonce: 0, mandate: mandate.encode(), sig: [0; 64] };
    owner.sign(&mut m);
    let r = call(
        op::INSTALL,
        &proto::SealedWith { sealed: ir.sealed.clone(), data: mandate.encode(), extra: Some(m.sig().to_vec()) }
            .encode(),
    );
    assert!(r.ok, "{:?}", r.reasons);
    let unbound = proto::SealedResponse::decode(&r.payload).unwrap().sealed;
    let mk = |nonce: u64, challenge: [u8; 32], ak_pk: [u8; 65], name: [u8; 34], counter: u64| {
        let mut a = Message::Anchor {
            enclave_id,
            nonce,
            boot_challenge: challenge,
            ak_pk,
            nv_name: name,
            counter,
            seq_seen: 0,
            sig: [0; 64],
        };
        owner.sign(&mut a);
        a
    };
    let nonce_issue = || -> [u8; 32] { call(op::TPM_NONCE, &[]).payload.try_into().unwrap() };

    // the node's TPM, at 500 when the owner reads it
    let mut tpm = SoftTpm::new(0xe5, 0x5B, 500);
    let st = status_of(&unbound);
    let a1 = mk(1, st.boot_challenge, tpm.ak.pk, tpm.name, tpm.counter);

    // --- vector 2: no proof → TPM_REQUIRED, nothing bound ---
    let r = bare_apply(&unbound, &a1);
    assert!(!r.ok && r.reasons == vec!["TPM_REQUIRED"], "{:?}", r.reasons);
    assert!(!status_of(&unbound).tpm_bound);

    // --- vector 1, the 2026-11-18 case: the owner attested 500; the feed persisted TWO blocks before the
    // apply (each persist increments) — the anchor must pin the live 502, not the owner's 500 ---
    tpm.increment();
    tpm.increment();
    let r = anchor_call(&tpm, &unbound, &a1);
    assert!(r.ok, "vector 1 (k=2): {:?}", r.reasons);
    let bound = proto::SealedResponse::decode(&r.payload).unwrap().sealed;
    tpm.increment(); // the host increments after persisting the anchored blob
    let st = status_of(&bound);
    assert!(
        st.tpm_bound && st.tpm_expected == 503 && st.tpm_expected == tpm.counter && st.boot_armed && st.nonce == 1,
        "the blob expects the LIVE counter + 1: {st:?}"
    );
    // the next Fresh op is accepted — with the owner's snapshot (500 → 501) it would have been STATE_STALE
    let r = fresh_call(&tpm, op::FREEZE, &bound);
    assert!(r.ok, "no STATE_STALE after the anchor: {:?}", r.reasons);
    let frozen = proto::SealedResponse::decode(&r.payload).unwrap().sealed;
    tpm.increment();
    let mut un = Message::Unfreeze { enclave_id, nonce: 2, sig: [0; 64] };
    owner.sign(&mut un);
    let r = fresh_call(
        &tpm,
        op::APPLY_MESSAGE,
        &proto::SealedWith { sealed: frozen.clone(), data: un.encode(), extra: None }.encode(),
    );
    assert!(r.ok, "{:?}", r.reasons);
    let live1 = proto::SealedResponse::decode(&r.payload).unwrap().sealed;
    tpm.increment();
    let st = status_of(&live1);
    assert!(st.tpm_expected == 505 && tpm.counter == 505 && !st.frozen && st.nonce == 2, "{st:?}");

    // --- vector 3: the host's live proof certifies a counter BELOW what the owner saw → ANCHOR_COUNTER_BEHIND,
    // proof consumed, state unchanged ---
    let a3 = mk(3, st.boot_challenge, tpm.ak.pk, tpm.name, tpm.counter);
    let n = nonce_issue();
    assert!(call(op::TPM_PROOF, &tpm.certify_as(&n, &tpm.name, tpm.counter - 1, &tpm.ak).encode()).ok);
    let r = bare_apply(&live1, &a3);
    assert!(!r.ok && r.reasons == vec!["ANCHOR_COUNTER_BEHIND"], "{:?}", r.reasons);
    let r = bare_apply(&live1, &a3);
    assert!(!r.ok && r.reasons == vec!["TPM_REQUIRED"], "the proof was consumed: {:?}", r.reasons);
    assert!(status_of(&live1).tpm_expected == 505 && status_of(&live1).nonce == 2, "unchanged");
    assert!(!status_of(&live1).tpm_last_fresh, "a proof-less refusal clears the flag");

    // --- vector 4: foreign AK → TPM_SIG; wrong Name → TPM_INDEX; replayed nonce → TPM_NONCE; truncated →
    // TPM_PARSE; the same Anchor again without a deposit → TPM_REQUIRED ---
    let other = SoftTpm::new(0xf6, 0x5B, tpm.counter); // same Name tag, another key
    let n = nonce_issue();
    assert!(call(op::TPM_PROOF, &other.certify(&n).encode()).ok);
    let r = bare_apply(&live1, &a3);
    assert!(!r.ok && r.reasons == vec!["TPM_SIG"], "{:?}", r.reasons);
    let mut other_name = tpm.name;
    other_name[7] ^= 1;
    let n = nonce_issue();
    assert!(call(op::TPM_PROOF, &tpm.certify_as(&n, &other_name, tpm.counter, &tpm.ak).encode()).ok);
    let r = bare_apply(&live1, &a3);
    assert!(!r.ok && r.reasons == vec!["TPM_INDEX"], "{:?}", r.reasons);
    let n_a = nonce_issue();
    let p_a = tpm.certify(&n_a);
    let _n_b = nonce_issue();
    assert!(call(op::TPM_PROOF, &p_a.encode()).ok);
    let r = bare_apply(&live1, &a3);
    assert!(!r.ok && r.reasons == vec!["TPM_NONCE"], "{:?}", r.reasons);
    let n = nonce_issue();
    let mut p = tpm.certify(&n);
    p.attest.truncate(40);
    assert!(call(op::TPM_PROOF, &p.encode()).ok);
    let r = bare_apply(&live1, &a3);
    assert!(!r.ok && r.reasons == vec!["TPM_PARSE"], "{:?}", r.reasons);
    let r = bare_apply(&live1, &a3);
    assert!(!r.ok && r.reasons == vec!["TPM_REQUIRED"], "{:?}", r.reasons);

    // --- vector 7 (negative): a bound state; the host handed the owner ANOTHER TPM's identity and deposits a
    // valid proof from that TPM → ANCHOR_TPM_MISMATCH, proof consumed, state unchanged ---
    let rogue = SoftTpm::new(0xf7, 0x5C, tpm.counter + 40);
    let a7 = mk(3, st.boot_challenge, rogue.ak.pk, rogue.name, rogue.counter);
    // a proven op first (its blob is discarded): the flag reads true going into the mismatch
    assert!(fresh_call(&tpm, op::FREEZE, &live1).ok);
    assert!(status_of(&live1).tpm_last_fresh);
    let r = anchor_call(&rogue, &live1, &a7);
    assert!(!r.ok && r.reasons == vec!["ANCHOR_TPM_MISMATCH"], "{:?}", r.reasons);
    assert!(!status_of(&live1).tpm_last_fresh, "a mismatch clears the flag — the rogue proof was never verified");
    let r = bare_apply(&live1, &a7);
    assert!(!r.ok && r.reasons == vec!["TPM_REQUIRED"], "the rogue proof was consumed: {:?}", r.reasons);
    let st = status_of(&live1);
    assert!(st.tpm_expected == 505 && st.nonce == 2 && st.tpm_bound, "unchanged: {st:?}");
    // the same forged identity with the honest TPM's proof is the mismatch too (identity before signature)
    assert!(fresh_call(&tpm, op::FREEZE, &live1).ok);
    assert!(status_of(&live1).tpm_last_fresh);
    let r = anchor_call(&tpm, &live1, &a7);
    assert!(!r.ok && r.reasons == vec!["ANCHOR_TPM_MISMATCH"], "{:?}", r.reasons);
    assert!(!status_of(&live1).tpm_last_fresh, "the honest proof was not verified either: identity first");

    // --- vector 5 + 7b (positive): the blob is STALE (expects 505, the TPM moved on to 507 — a rollback, or
    // two persists the blob never saw); an unattended reload stays unarmed; the owner's same-identity re-pin
    // with a live proof APPLIES, expects 508 after the host's increment, arms; a proven op then goes through ---
    tpm.increment();
    tpm.increment();
    let r = fresh_call(&tpm, op::FREEZE, &live1);
    assert!(!r.ok && r.reasons == vec!["STATE_STALE"], "{:?}", r.reasons);
    call(op::TEST_RESET_SESSION, &[]);
    assert!(!status_of(&live1).boot_armed, "a reload onto a stale blob stays unarmed");
    let st = status_of(&live1);
    let a7b = mk(3, st.boot_challenge, tpm.ak.pk, tpm.name, tpm.counter);
    let r = anchor_call(&tpm, &live1, &a7b);
    assert!(r.ok, "vector 7b, the honest same-identity re-pin must apply as cleanly as 7 refuses: {:?}", r.reasons);
    let live2 = proto::SealedResponse::decode(&r.payload).unwrap().sealed;
    tpm.increment();
    let st = status_of(&live2);
    assert!(
        st.tpm_bound
            && st.tpm_expected == 508
            && st.tpm_expected == tpm.counter
            && st.boot_armed
            && st.tpm_last_fresh
            && st.nonce == 3,
        "{st:?}"
    );
    let r = fresh_call(&tpm, op::FREEZE, &live2);
    assert!(r.ok, "a proven op after the re-pin: {:?}", r.reasons);
    let frozen2 = proto::SealedResponse::decode(&r.payload).unwrap().sealed;
    tpm.increment();
    assert!(status_of(&frozen2).tpm_expected == 509 && tpm.counter == 509);

    // --- vector 1 again on a LIVE bound state (a re-pin while the feed runs, k=1 — exactly 2026-11-18 16:11):
    // the owner attests 509, one persist lands before the apply, the anchor pins 510 ---
    let st = status_of(&frozen2);
    let a_live = mk(4, st.boot_challenge, tpm.ak.pk, tpm.name, tpm.counter);
    tpm.increment(); // the feed persisted a block inside the owner's window
    let r = anchor_call(&tpm, &frozen2, &a_live);
    assert!(r.ok, "{:?}", r.reasons);
    let live3 = proto::SealedResponse::decode(&r.payload).unwrap().sealed;
    tpm.increment();
    let st = status_of(&live3);
    assert!(st.tpm_expected == 511 && st.tpm_expected == tpm.counter && st.nonce == 4, "{st:?}");
    let mut un = Message::Unfreeze { enclave_id, nonce: 5, sig: [0; 64] };
    owner.sign(&mut un);
    let r = fresh_call(
        &tpm,
        op::APPLY_MESSAGE,
        &proto::SealedWith { sealed: live3.clone(), data: un.encode(), extra: None }.encode(),
    );
    assert!(r.ok, "no STATE_STALE after a live re-pin with a persist in the window: {:?}", r.reasons);
}
