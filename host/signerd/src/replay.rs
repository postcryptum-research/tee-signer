//! The vector replay and the full-flow smoke test, over whichever enclave is loaded. On the SGX
//! box this is the hardware run of R2: the same bytes `core/tests/vectors.rs` judged on the host
//! go through the real ecalls, and the same init → install → headers → judge → sign flow that
//! `rcore/tests/replay.rs` runs in simulation runs against the sealed, launched enclave.
//! Needs a `test-init` enclave build (the release build refuses these ops).

use std::path::Path;

use anyhow::{anyhow, Result};
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
use serde::Deserialize;
use signer_core::mandate::*;
use signer_core::proto::{self, op, IdentityCard};
use signer_core::receipt::Receipt;
use signer_core::sign::verify_digest_secp;
use signer_core::state::State;
use signer_core::update::Message;

use crate::enclave::Enclave;

pub struct P256Key {
    sk: p256::ecdsa::SigningKey,
    pub pk: [u8; 65],
}

pub fn p256_key(b: u8) -> P256Key {
    let mut bytes = [b; 32];
    bytes[0] = 1;
    let sk = p256::ecdsa::SigningKey::from_bytes((&bytes).into()).expect("scalar");
    let point = sk.verifying_key().to_encoded_point(false);
    let mut pk = [0u8; 65];
    pk.copy_from_slice(point.as_bytes());
    P256Key { sk, pk }
}

impl P256Key {
    pub fn sign(&self, msg: &mut Message) {
        let d = msg.digest();
        let sig: p256::ecdsa::Signature = self.sk.sign_prehash(&d).expect("sign");
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
    pub fn raw_sk(&self) -> [u8; 32] {
        let mut b = [0u8; 32];
        b.copy_from_slice(&self.sk.to_bytes());
        b
    }
}

pub struct Wallet {
    pub xpub: Xpub,
    pub fingerprint: [u8; 4],
}

pub fn wallet(entropy: &[u8; 32], net: bitcoin::Network, coin: u32) -> Wallet {
    let secp = Secp256k1::new();
    let seed = signer_core::bip39::seed(&signer_core::bip39::mnemonic(entropy));
    let master = Xpriv::new_master(net, &seed).expect("master");
    let path = DerivationPath::from(vec![
        ChildNumber::from_hardened_idx(84).unwrap(),
        ChildNumber::from_hardened_idx(coin).unwrap(),
        ChildNumber::from_hardened_idx(0).unwrap(),
    ]);
    let account_xpriv = master.derive_priv(&secp, &path).expect("account");
    let xpub = Xpub::from_priv(&secp, &account_xpriv);
    let mut fingerprint = [0u8; 4];
    fingerprint.copy_from_slice(master.fingerprint(&secp).as_bytes());
    Wallet { xpub, fingerprint }
}

impl Wallet {
    fn child(&self, secp: &Secp256k1<All>, branch: u32, index: u32) -> Xpub {
        self.xpub
            .derive_pub(secp, &[ChildNumber::from_normal_idx(branch).unwrap(), ChildNumber::from_normal_idx(index).unwrap()])
            .expect("child")
    }
    pub fn spk(&self, secp: &Secp256k1<All>, branch: u32, index: u32) -> ScriptBuf {
        ScriptBuf::new_p2wpkh(&self.child(secp, branch, index).to_pub().wpubkey_hash())
    }
    pub fn pubkey(&self, secp: &Secp256k1<All>, branch: u32, index: u32) -> bitcoin::secp256k1::PublicKey {
        self.child(secp, branch, index).to_pub().0
    }
    pub fn origin(&self, coin: u32, branch: u32, index: u32) -> (Fingerprint, DerivationPath) {
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
    let mut psbt = Psbt::from_unsigned_tx(tx).expect("psbt");
    psbt.inputs[0].non_witness_utxo = Some(prev);
    psbt.inputs[0].bip32_derivation.insert(w.pubkey(secp, 0, in_index), w.origin(coin, 0, in_index));
    psbt.outputs[1].bip32_derivation.insert(w.pubkey(secp, 1, 0), w.origin(coin, 1, 0));
    psbt
}

fn check(cond: bool, what: &str) -> Result<()> {
    if cond {
        Ok(())
    } else {
        Err(anyhow!("smoke: {what}"))
    }
}

/// The full flow with a known seed. Every step is an assertion; the first failure returns.
pub fn smoke(e: &mut dyn Enclave) -> Result<()> {
    let secp = Secp256k1::new();
    let owner = p256_key(0xa1);
    let recovery = p256_key(0xb2);
    let entropy = [0x33u8; 32];

    e.call(op::TEST_RESET_SESSION, &[])?;
    let init = proto::InitRequest { network: 3, owner_pk: owner.pk, recovery_pk: recovery.pk };
    let treq = proto::TestInitRequest { init: init.clone(), seed: entropy, identity_sk: [0x55; 32], state: vec![] };
    let r = e.call(op::TEST_INIT, &treq.encode())?;
    check(r.ok, &format!("test init {:?}", r.reasons))?;
    let ir = proto::InitResponse::decode(&r.payload).map_err(|_| anyhow!("init decode"))?;
    let w = wallet(&entropy, bitcoin::Network::Regtest, 1);
    check(ir.xpub == w.xpub.encode(), "enclave and host derive the same account from the same entropy")?;
    check(ir.fingerprint == w.fingerprint, "fingerprint")?;
    let card = IdentityCard::decode(&ir.card).map_err(|_| anyhow!("card decode"))?;
    check(card.xpub == ir.xpub, "card names the wallet")?;
    check(verify_digest_secp(&secp, &ir.identity_pk, &card.digest(), &ir.card_sig), "card signature")?;
    println!("smoke: tier={} mrenclave={}", card.tier, hex::encode(card.mrenclave));
    check(card.mrenclave != [0u8; 32] || card.tier == "T0-nosgx", "MRENCLAVE present on hardware")?;
    let got = rcore_decrypt(&recovery.raw_sk(), &ir.fingerprint, &ir.xpub, &ir.recovery_blob)?;
    check(got == entropy, "recovery blob opens to the entropy")?;
    check(rcore_decrypt(&owner.raw_sk(), &ir.fingerprint, &ir.xpub, &ir.recovery_blob).is_err(), "recovery blob refuses the owner key")?;
    let r = e.call(op::STATUS, &ir.sealed)?;
    check(r.ok && !proto::StatusResponse::decode(&r.payload).map(|s| s.installed).unwrap_or(true), "keys-only blob reports installed=false")?;
    let r = e.call(op::POLICY, &ir.sealed)?;
    check(!r.ok && r.reasons == vec!["STATE_UNSEALABLE"], "keys-only blob has no policy")?;

    // INSTALL
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
    check(mandate.validate().is_ok(), "mandate validates")?;
    let enclave_id = signer_core::sha256(&ir.identity_pk);
    let mut m = Message::PolicyUpdate { enclave_id, nonce: 0, mandate: mandate.encode(), sig: [0; 64] };
    owner.sign(&mut m);
    let mut bad = m.clone();
    recovery.sign(&mut bad);
    let r = e.call(op::INSTALL, &proto::SealedWith { sealed: ir.sealed.clone(), data: mandate.encode(), extra: Some(bad.sig().to_vec()) }.encode())?;
    check(!r.ok && r.reasons == vec!["POLICY_SIG"], "install refuses the recovery key's signature")?;
    let mut other = mandate.clone();
    other.wallet.fingerprint = [9; 4];
    let mut mo = Message::PolicyUpdate { enclave_id, nonce: 0, mandate: other.encode(), sig: [0; 64] };
    owner.sign(&mut mo);
    let r = e.call(op::INSTALL, &proto::SealedWith { sealed: ir.sealed.clone(), data: other.encode(), extra: Some(mo.sig().to_vec()) }.encode())?;
    check(!r.ok && r.reasons == vec!["POLICY_WALLET"], "install refuses a foreign fingerprint")?;
    let r = e.call(op::INSTALL, &proto::SealedWith { sealed: ir.sealed.clone(), data: mandate.encode(), extra: Some(m.sig().to_vec()) }.encode())?;
    check(r.ok, &format!("install {:?}", r.reasons))?;
    let sealed0 = proto::SealedResponse::decode(&r.payload).map_err(|_| anyhow!("decode"))?.sealed;
    let r = e.call(op::INSTALL, &proto::SealedWith { sealed: sealed0.clone(), data: mandate.encode(), extra: Some(m.sig().to_vec()) }.encode())?;
    check(!r.ok, "install twice refuses")?;

    // STATUS / POLICY
    let r = e.call(op::STATUS, &sealed0)?;
    check(r.ok, "status")?;
    let st = proto::StatusResponse::decode(&r.payload).map_err(|_| anyhow!("status decode"))?;
    check(st.best_height == 100 && st.seq == 0, "status fields")?;
    let r = e.call(op::POLICY, &sealed0)?;
    let pol = proto::PolicyResponse::decode(&r.payload).map_err(|_| anyhow!("policy decode"))?;
    check(pol.mandate == mandate.encode() && pol.sig == *m.sig(), "policy round trip")?;

    // HEADERS
    let mut hs = Vec::new();
    let mut prev = cp;
    for i in 0..10u32 {
        let h = mine(&prev, prev.time + 10, 100 + i);
        hs.push(serialize(&h));
        prev = h;
    }
    let r = e.call(op::HEADERS, &proto::SealedWith { sealed: sealed0.clone(), data: hs.concat(), extra: None }.encode())?;
    check(r.ok, &format!("headers {:?}", r.reasons))?;
    let hr = proto::HeadersResponse::decode(&r.payload).map_err(|_| anyhow!("headers decode"))?;
    check(hr.accepted == 10 && hr.best_height == 110, "10 headers accepted")?;
    let sealed1 = hr.sealed;

    // JUDGE → SIGN
    let psbt = payout_psbt(&secp, &w, 1, 5, 2_000_000, 900_000, 2_000);
    let bytes = psbt.serialize();
    let r = e.call(op::JUDGE, &proto::SealedWith { sealed: sealed1.clone(), data: bytes.clone(), extra: None }.encode())?;
    check(r.ok, &format!("judge {:?}", r.reasons))?;
    let jr = proto::JudgeResponse::decode(&r.payload).map_err(|_| anyhow!("judge decode"))?;
    let charged = jr.sealed;
    let preview = Receipt::decode(&jr.receipt).map_err(|_| anyhow!("receipt decode"))?;
    check(preview.seq == 1 && preview.net_outflow == 902_000, "receipt preview")?;
    let r = e.call(op::SIGN, &proto::SealedWith { sealed: sealed1.clone(), data: bytes.clone(), extra: None }.encode())?;
    check(!r.ok, "sign needs the charged blob")?;
    let mut stripped = psbt.clone();
    stripped.outputs[1].bip32_derivation.clear();
    let r = e.call(op::SIGN, &proto::SealedWith { sealed: charged.clone(), data: stripped.serialize(), extra: None }.encode())?;
    check(!r.ok, "sign needs the exact judged bytes")?;
    let r = e.call(op::SIGN, &proto::SealedWith { sealed: charged.clone(), data: bytes.clone(), extra: None }.encode())?;
    check(r.ok, &format!("sign {:?}", r.reasons))?;
    let sr = proto::SignResponse::decode(&r.payload).map_err(|_| anyhow!("sign decode"))?;
    let signed = Psbt::deserialize(&sr.psbt)?;
    let (pk, sig) = signed.inputs[0].partial_sigs.iter().next().ok_or_else(|| anyhow!("no partial sig"))?;
    let mut cache = SighashCache::new(&signed.unsigned_tx);
    let sh = cache.p2wpkh_signature_hash(0, &w.spk(&secp, 0, 5), Amount::from_sat(2_000_000), EcdsaSighashType::All)?;
    secp.verify_ecdsa(&bitcoin::secp256k1::Message::from_digest(sh.to_byte_array()), &sig.signature, &pk.inner)?;
    let receipt = Receipt::decode(&sr.receipt).map_err(|_| anyhow!("receipt"))?;
    check(receipt == preview, "receipt equals preview")?;
    check(verify_digest_secp(&secp, &ir.identity_pk, &receipt.digest(), &sr.receipt_sig), "receipt signature")?;
    let r2 = e.call(op::SIGN, &proto::SealedWith { sealed: charged.clone(), data: bytes.clone(), extra: None }.encode())?;
    check(r2.ok && proto::SignResponse::decode(&r2.payload).map(|x| x.psbt).unwrap_or_default() == sr.psbt, "re-sign is idempotent")?;

    // the fork
    let psbt_b = payout_psbt(&secp, &w, 1, 6, 2_000_000, 800_000, 2_000);
    let r = e.call(op::JUDGE, &proto::SealedWith { sealed: sealed1.clone(), data: psbt_b.serialize(), extra: None }.encode())?;
    check(!r.ok && r.reasons == vec!["SEQ_BEHIND_SESSION"], &format!("fork refused: {:?}", r.reasons))?;
    let r = e.call(op::JUDGE, &proto::SealedWith { sealed: charged.clone(), data: psbt_b.serialize(), extra: None }.encode())?;
    check(r.ok, "the charged blob continues")?;
    let charged2 = proto::JudgeResponse::decode(&r.payload).map_err(|_| anyhow!("decode"))?.sealed;
    let st2 = proto::StatusResponse::decode(&e.call(op::STATUS, &charged2)?.payload).map_err(|_| anyhow!("status"))?;
    check(st2.seq == 2 && st2.window_outflow == 902_000 + 802_000, "window charged twice")?;
    e.call(op::TEST_RESET_SESSION, &[])?;
    let r = e.call(op::JUDGE, &proto::SealedWith { sealed: sealed1.clone(), data: psbt_b.serialize(), extra: None }.encode())?;
    check(r.ok, "a reload resets the volatile mark (labeled)")?;
    let st3 = proto::StatusResponse::decode(&e.call(op::STATUS, &charged2)?.payload).map_err(|_| anyhow!("status"))?;
    check(st3.session_id != st.session_id, "session id changed")?;

    // FREEZE / UNFREEZE / tamper
    let r = e.call(op::FREEZE, &charged2)?;
    let frozen = proto::SealedResponse::decode(&r.payload).map_err(|_| anyhow!("decode"))?.sealed;
    let r = e.call(op::JUDGE, &proto::SealedWith { sealed: frozen.clone(), data: bytes.clone(), extra: None }.encode())?;
    check(!r.ok && r.reasons == vec!["FROZEN"], "frozen refuses")?;
    let mut un = Message::Unfreeze { enclave_id, nonce: 1, sig: [0; 64] };
    owner.sign(&mut un);
    let r = e.call(op::APPLY_MESSAGE, &proto::SealedWith { sealed: frozen, data: un.encode(), extra: None }.encode())?;
    check(r.ok, "unfreeze")?;
    let mut tampered = charged2.clone();
    let n = tampered.len();
    tampered[n - 1] ^= 1;
    let r = e.call(op::STATUS, &tampered)?;
    // on hardware the seal MAC refuses a flipped byte; in simulation only truncation is caught
    if e.kind().starts_with("sgx") {
        check(!r.ok && r.reasons == vec!["STATE_UNSEALABLE"], "tampered blob refused by the seal MAC")?;
    }
    let truncated = charged2[..n - 1].to_vec();
    let r = e.call(op::STATUS, &truncated)?;
    check(!r.ok && r.reasons == vec!["STATE_UNSEALABLE"], "truncated blob refused")?;
    Ok(())
}

/// Recovery-blob decryption (the owner's side), duplicated from `rcore::recovery` so the daemon
/// does not depend on the enclave crate in SGX builds.
fn rcore_decrypt(recovery_sk: &[u8; 32], fingerprint: &[u8; 4], xpub: &[u8; 78], blob: &[u8]) -> Result<[u8; 32]> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Nonce};
    use hkdf::Hkdf;
    use sha2::Sha256;
    if blob.len() != 65 + 32 + 16 {
        return Err(anyhow!("blob length"));
    }
    let sk = p256::SecretKey::from_slice(recovery_sk)?;
    let eph_pk = p256::PublicKey::from_sec1_bytes(&blob[..65])?;
    let shared = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), eph_pk.as_affine());
    let hk = Hkdf::<Sha256>::new(Some(b"tee-signer/recovery/v1"), shared.raw_secret_bytes().as_slice());
    let mut info = Vec::with_capacity(82);
    info.extend_from_slice(fingerprint);
    info.extend_from_slice(xpub);
    let mut key = [0u8; 32];
    hk.expand(&info, &mut key).map_err(|_| anyhow!("hkdf"))?;
    let cipher = Aes256Gcm::new((&key).into());
    let mut aad = Vec::with_capacity(82);
    aad.extend_from_slice(fingerprint);
    aad.extend_from_slice(xpub);
    let pt = cipher.decrypt(Nonce::from_slice(&[0u8; 12]), Payload { msg: &blob[65..], aad: &aad }).map_err(|_| anyhow!("gcm"))?;
    let mut out = [0u8; 32];
    if pt.len() != 32 {
        return Err(anyhow!("plaintext length"));
    }
    out.copy_from_slice(&pt);
    Ok(out)
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    expect: String,
    reasons: Vec<String>,
    disarms: bool,
    state_hex: String,
    psbt_hex: String,
    witness_hex: Option<String>,
}

/// Replay every vector; returns a report line and fails on the first mismatch set.
pub fn replay_vectors(e: &mut dyn Enclave, dir: &Path) -> Result<String> {
    let secp = Secp256k1::new();
    let mut names: Vec<_> = std::fs::read_dir(dir)?.map(|x| x.map(|y| y.path())).collect::<std::result::Result<_, _>>()?;
    names.sort();
    let w = wallet(&[0x01; 32], bitcoin::Network::Signet, 1);
    let mut failures = Vec::new();
    let mut n_ok = 0usize;
    for path in &names {
        if path.extension().map(|x| x != "json").unwrap_or(true) {
            continue;
        }
        let v: Vector = serde_json::from_str(&std::fs::read_to_string(path)?)?;
        let state_bytes = hex::decode(&v.state_hex)?;
        let state = State::decode(&state_bytes).map_err(|_| anyhow!("{}: state", v.name))?;
        e.call(op::TEST_RESET_SESSION, &[])?;
        let treq = proto::TestInitRequest {
            init: proto::InitRequest { network: 2, owner_pk: state.owner_pk, recovery_pk: state.recovery_pk },
            seed: [0x01; 32],
            identity_sk: [0x55; 32],
            state: state_bytes,
        };
        let r = e.call(op::TEST_INIT, &treq.encode())?;
        if !r.ok {
            failures.push(format!("{}: test init {:?}", v.name, r.reasons));
            continue;
        }
        let ir = proto::InitResponse::decode(&r.payload).map_err(|_| anyhow!("init decode"))?;
        if ir.fingerprint != w.fingerprint {
            failures.push(format!("{}: fixture wallet mismatch", v.name));
            continue;
        }
        let psbt = hex::decode(&v.psbt_hex)?;
        let witness = match &v.witness_hex {
            Some(h) => Some(hex::decode(h)?),
            None => None,
        };
        let r = e.call(op::JUDGE, &proto::SealedWith { sealed: ir.sealed.clone(), data: psbt.clone(), extra: witness }.encode())?;
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
                let jr = proto::JudgeResponse::decode(&r.payload).map_err(|_| anyhow!("judge decode"))?;
                let r = e.call(op::SIGN, &proto::SealedWith { sealed: jr.sealed, data: psbt.clone(), extra: None }.encode())?;
                if !r.ok {
                    failures.push(format!("{}: sign {:?}", v.name, r.reasons));
                    continue;
                }
                let sr = proto::SignResponse::decode(&r.payload).map_err(|_| anyhow!("sign decode"))?;
                let signed = Psbt::deserialize(&sr.psbt)?;
                let mut cache = SighashCache::new(&signed.unsigned_tx);
                let mut n = 0;
                for (i, input) in signed.inputs.iter().enumerate() {
                    for (pk, sig) in &input.partial_sigs {
                        let prev = input.non_witness_utxo.as_ref().ok_or_else(|| anyhow!("prev"))?;
                        let prevout = &prev.output[signed.unsigned_tx.input[i].previous_output.vout as usize];
                        let sh = cache.p2wpkh_signature_hash(i, &prevout.script_pubkey, prevout.value, EcdsaSighashType::All)?;
                        if secp.verify_ecdsa(&bitcoin::secp256k1::Message::from_digest(sh.to_byte_array()), &sig.signature, &pk.inner).is_err() {
                            failures.push(format!("{}: bad signature on input {i}", v.name));
                        }
                        n += 1;
                    }
                }
                if n == 0 {
                    failures.push(format!("{}: nothing signed", v.name));
                }
                let receipt = Receipt::decode(&sr.receipt).map_err(|_| anyhow!("receipt"))?;
                if !verify_digest_secp(&secp, &ir.identity_pk, &receipt.digest(), &sr.receipt_sig) {
                    failures.push(format!("{}: receipt sig", v.name));
                }
                n_ok += 1;
            }
            "refuse" => {
                if r.ok {
                    failures.push(format!("{}: expected refuse {:?}, got accept", v.name, want));
                    continue;
                }
                if got != want {
                    failures.push(format!("{}: reasons {:?} want {:?}", v.name, got, want));
                    continue;
                }
                if v.disarms == r.payload.is_empty() {
                    failures.push(format!("{}: disarm payload presence {} want {}", v.name, !r.payload.is_empty(), v.disarms));
                    continue;
                }
                n_ok += 1;
            }
            _ => failures.push(format!("{}: unknown expect", v.name)),
        }
    }
    if !failures.is_empty() {
        return Err(anyhow!("replay failures:\n{}", failures.join("\n")));
    }
    Ok(format!("replay: {n_ok} vectors reproduced through {}", e.kind()))
}
