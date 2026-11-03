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
    let rc = unsafe { rcore::rcore_call(op_code, input.as_ptr(), input.len(), out.as_mut_ptr(), out.len(), &mut out_len) };
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
        let k = self.xpub.derive_pub(secp, &[ChildNumber::from_normal_idx(branch).unwrap(), ChildNumber::from_normal_idx(index).unwrap()]).unwrap();
        ScriptBuf::new_p2wpkh(&k.to_pub().wpubkey_hash())
    }
    fn pubkey(&self, secp: &Secp256k1<All>, branch: u32, index: u32) -> bitcoin::secp256k1::PublicKey {
        self.xpub.derive_pub(secp, &[ChildNumber::from_normal_idx(branch).unwrap(), ChildNumber::from_normal_idx(index).unwrap()]).unwrap().to_pub().0
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
        wallet: WalletSpec { fingerprint: fp, account: AccountPath { purpose: 84, coin: 1, account: 0 }, script_types: vec![ScriptType::P2wpkh] },
        destinations: Destinations { trusted: vec![], unlisted: ClassCaps { max_per_tx: 1_000_000, max_per_window: 5_000_000 } },
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
        rules: Rules { sighash: SighashRule::All, payjoin: PayjoinRule::None, op_return: OpReturnRule::None, rbf: true },
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

fn payout_psbt(secp: &Secp256k1<All>, w: &Wallet, coin: u32, in_index: u32, in_amount: u64, out_amount: u64, fee: u64) -> Psbt {
    let prev = Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_consensus(777),
        input: vec![TxIn { previous_output: OutPoint::null(), script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new() }],
        output: vec![TxOut { value: Amount::from_sat(in_amount), script_pubkey: w.spk(secp, 0, in_index) }],
    };
    let foreign = wallet(&[0x77; 32], bitcoin::Network::Regtest, 1).spk(secp, 0, 1);
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn { previous_output: OutPoint { txid: prev.compute_txid(), vout: 0 }, script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new() }],
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
    // a keys-only blob cannot be used for anything but INSTALL
    let r = call(op::STATUS, &ir.sealed);
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
    let r = call(op::INSTALL, &proto::SealedWith { sealed: ir.sealed.clone(), data: mandate.encode(), extra: Some(bad.sig().to_vec()) }.encode());
    assert!(!r.ok && r.reasons == vec!["POLICY_SIG"]);
    // a mandate for a different fingerprint is refused
    let mut other = mandate.clone();
    other.wallet.fingerprint = [9; 4];
    let mut mo = Message::PolicyUpdate { enclave_id, nonce: 0, mandate: other.encode(), sig: [0; 64] };
    owner.sign(&mut mo);
    let r = call(op::INSTALL, &proto::SealedWith { sealed: ir.sealed.clone(), data: other.encode(), extra: Some(mo.sig().to_vec()) }.encode());
    assert!(!r.ok && r.reasons == vec!["POLICY_WALLET"]);
    // the right one installs
    let r = call(op::INSTALL, &proto::SealedWith { sealed: ir.sealed.clone(), data: mandate.encode(), extra: Some(m.sig().to_vec()) }.encode());
    assert!(r.ok, "{:?}", r.reasons);
    let sealed0 = proto::SealedResponse::decode(&r.payload).unwrap().sealed;
    // installing twice is refused
    let r = call(op::INSTALL, &proto::SealedWith { sealed: sealed0.clone(), data: mandate.encode(), extra: Some(m.sig().to_vec()) }.encode());
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
    let r = call(op::SIGN, &proto::SealedWith { sealed: charged.clone(), data: stripped.serialize(), extra: None }.encode());
    assert!(!r.ok, "sign needs the exact judged bytes");
    // SIGN with the charged blob and the exact bytes signs; the receipt verifies
    let r = call(op::SIGN, &proto::SealedWith { sealed: charged.clone(), data: bytes.clone(), extra: None }.encode());
    assert!(r.ok, "{:?}", r.reasons);
    let sr = proto::SignResponse::decode(&r.payload).unwrap();
    let signed = Psbt::deserialize(&sr.psbt).unwrap();
    let (pk, sig) = signed.inputs[0].partial_sigs.iter().next().unwrap();
    let mut cache = SighashCache::new(&signed.unsigned_tx);
    let sh = cache.p2wpkh_signature_hash(0, &w.spk(&secp, 0, 5), Amount::from_sat(2_000_000), EcdsaSighashType::All).unwrap();
    secp.verify_ecdsa(&bitcoin::secp256k1::Message::from_digest(sh.to_byte_array()), &sig.signature, &pk.inner).unwrap();
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
    let r = call(op::JUDGE, &proto::SealedWith { sealed: sealed1.clone(), data: psbt_b.serialize(), extra: None }.encode());
    assert!(!r.ok && r.reasons == vec!["SEQ_BEHIND_SESSION"], "{:?}", r.reasons);
    // and so is every other operation on the stale blob
    let r = call(op::HEADERS, &proto::SealedWith { sealed: sealed1.clone(), data: vec![], extra: None }.encode());
    assert!(!r.ok && r.reasons == vec!["SEQ_BEHIND_SESSION"]);
    // the charged blob continues normally
    let r = call(op::JUDGE, &proto::SealedWith { sealed: charged.clone(), data: psbt_b.serialize(), extra: None }.encode());
    assert!(r.ok, "{:?}", r.reasons);
    let charged2 = proto::JudgeResponse::decode(&r.payload).unwrap().sealed;
    let st2 = proto::StatusResponse::decode(&call(op::STATUS, &charged2).payload).unwrap();
    assert_eq!(st2.seq, 2);
    assert_eq!(st2.window_outflow, 902_000 + 802_000);
    // after an enclave "reload" the mark is gone: the stale blob is accepted again — the labeled
    // limit the monitor exists for (session id changes)
    call(op::TEST_RESET_SESSION, &[]);
    let r = call(op::JUDGE, &proto::SealedWith { sealed: sealed1.clone(), data: psbt_b.serialize(), extra: None }.encode());
    assert!(r.ok, "a restart resets the volatile mark — by design, and labeled");
    let st3 = proto::StatusResponse::decode(&call(op::STATUS, &charged2).payload).unwrap();
    assert_ne!(st3.session_id, st.session_id);

    // --- FREEZE (unauthenticated) then a message ---
    let r = call(op::FREEZE, &charged2);
    assert!(r.ok);
    let frozen = proto::SealedResponse::decode(&r.payload).unwrap().sealed;
    let r = call(op::JUDGE, &proto::SealedWith { sealed: frozen.clone(), data: bytes.clone(), extra: None }.encode());
    assert!(!r.ok && r.reasons == vec!["FROZEN"]);
    let mut un = Message::Unfreeze { enclave_id, nonce: 1, sig: [0; 64] };
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
        let r = call(op::JUDGE, &proto::SealedWith { sealed: ir.sealed.clone(), data: psbt.clone(), extra: witness }.encode());
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
                let r = call(op::SIGN, &proto::SealedWith { sealed: jr.sealed, data: psbt.clone(), extra: None }.encode());
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
                        let sh = cache.p2wpkh_signature_hash(i, &prevout.script_pubkey, prevout.value, EcdsaSighashType::All).unwrap();
                        if secp.verify_ecdsa(&bitcoin::secp256k1::Message::from_digest(sh.to_byte_array()), &sig.signature, &pk.inner).is_err() {
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
                    failures.push(format!("{}: disarm payload presence {} want {}", v.name, !r.payload.is_empty(), v.disarms));
                }
            }
            _ => unreachable!(),
        }
    }
    assert!(failures.is_empty(), "replay failures:\n{}", failures.join("\n"));
}
