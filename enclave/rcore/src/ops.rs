//! The operations behind `rcore_call` (`docs/ENCLAVE.md §3`). Each takes untrusted bytes, opens
//! the sealed blob (if any), calls `signer-core`, and seals the result. Nothing here decides
//! policy; it marshals.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv, Xpub};
use bitcoin::secp256k1::{All, Secp256k1, SecretKey};
use zeroize::Zeroize;

use signer_core::classify::classify;
use signer_core::headers::apply_headers;
use signer_core::judge::{judge, Verdict};
use signer_core::mandate::{AccountPath, Mandate, Network, ScriptType, WalletSpec};
use signer_core::proto::{self, op, IdentityCard, Response};
use signer_core::reason::{Reason, Refusal};
use signer_core::receipt::Receipt;
use signer_core::sign::{sign_digest_secp, sign_own_inputs};
use signer_core::state::State;
use signer_core::update::{parse_p256_pubkey, Message};
use signer_core::wallet::Account;

use crate::envelope::{Envelope, LastJudged};
use crate::{recovery, session, sgx};
use signer_core::bip39;

fn refuse(r: Refusal) -> Response {
    Response::refuse(r.0.iter().map(|x| x.code().to_string()).collect(), Vec::new())
}

fn refuse_with(r: Refusal, payload: Vec<u8>) -> Response {
    Response::refuse(r.0.iter().map(|x| x.code().to_string()).collect(), payload)
}

fn refuse_code(code: &str) -> Response {
    Response::refuse(alloc::vec![code.to_string()], Vec::new())
}

/// A secp256k1 context randomized from the hardware source at every entry (C-R10c).
fn secp() -> Secp256k1<All> {
    let mut s = Secp256k1::new();
    let mut seed = [0u8; 32];
    sgx::read_rand(&mut seed);
    s.seeded_randomize(&seed);
    seed.zeroize();
    s
}

fn network_from(b: u8) -> Option<Network> {
    match b {
        0 => Some(Network::Mainnet),
        1 => Some(Network::Testnet4),
        2 => Some(Network::Signet),
        3 => Some(Network::Regtest),
        _ => None,
    }
}

/// Everything the wallet side needs, derived from the seed for the duration of one call.
struct Keys {
    account_xpriv: Xpriv,
    account: Account,
    xpub: [u8; 78],
    fingerprint: [u8; 4],
}

impl Drop for Keys {
    fn drop(&mut self) {
        // Xpriv holds the secret; overwrite the bytes we can reach
        let mut raw = self.account_xpriv.private_key.secret_bytes();
        raw.zeroize();
    }
}

fn derive_keys(secp: &Secp256k1<All>, network: Network, seed: &[u8; 32]) -> Option<Keys> {
    let m = bip39::mnemonic(seed);
    let mut seed64 = bip39::seed(&m);
    let master = Xpriv::new_master(network.to_bitcoin(), &seed64).ok();
    seed64.zeroize();
    let master = master?;
    let path = DerivationPath::from(alloc::vec![
        ChildNumber::from_hardened_idx(84).ok()?,
        ChildNumber::from_hardened_idx(network.coin_type()).ok()?,
        ChildNumber::from_hardened_idx(0).ok()?,
    ]);
    let account_xpriv = master.derive_priv(secp, &path).ok()?;
    let xpub_obj = Xpub::from_priv(secp, &account_xpriv);
    let mut fingerprint = [0u8; 4];
    fingerprint.copy_from_slice(master.fingerprint(secp).as_bytes());
    let xpub = xpub_obj.encode();
    let account = Account { fingerprint, path: AccountPath { purpose: 84, coin: network.coin_type(), account: 0 }, xpub: xpub_obj };
    Some(Keys { account_xpriv, account, xpub, fingerprint })
}

fn identity_pk(secp: &Secp256k1<All>, sk: &[u8; 32]) -> Option<[u8; 33]> {
    let k = SecretKey::from_slice(sk).ok()?;
    Some(k.public_key(secp).serialize())
}

fn clock_label(n: Network) -> &'static str {
    match n {
        Network::Mainnet => "",
        Network::Testnet4 => "testnet4: min-difficulty blocks allowed; the block clock is weaker than mainnet",
        Network::Signet => "signet: proof-of-work is cheap; the block clock is a correctness device here, not a security one",
        Network::Regtest => "regtest: no proof of work; windows and timelocks are not a defence",
    }
}

/// Dispatch one operation.
pub fn dispatch(op_code: u32, input: &[u8]) -> Response {
    match op_code {
        op::INIT => init(input),
        op::INSTALL => install(input),
        op::STATUS => status(input),
        op::POLICY => policy(input),
        op::APPLY_MESSAGE => apply_message(input),
        op::FREEZE => freeze(input),
        op::HEADERS => headers(input),
        op::JUDGE => judge_op(input),
        op::SIGN => sign_op(input),
        #[cfg(feature = "test-init")]
        op::TEST_INIT => test_init(input),
        #[cfg(feature = "test-init")]
        op::TEST_RESET_SESSION => {
            session::reset();
            Response::ok(Vec::new())
        }
        _ => refuse_code("UNKNOWN_OP"),
    }
}

fn open(sealed: &[u8]) -> Result<Envelope, Response> {
    Envelope::unseal(sealed).ok_or_else(|| refuse(Reason::StateUnsealable.into()))
}

fn open_full(sealed: &[u8]) -> Result<(Envelope, State), Response> {
    let env = open(sealed)?;
    let state = env.state.clone().ok_or_else(|| refuse(Reason::StateUnsealable.into()))?;
    Ok((env, state))
}

fn seal_or(env: &Envelope) -> Result<Vec<u8>, Response> {
    env.seal().ok_or_else(|| refuse_code("SEAL_FAILED"))
}

fn init(input: &[u8]) -> Response {
    let req = match proto::InitRequest::decode(input) {
        Ok(r) => r,
        Err(_) => return refuse(Reason::PolicyInvalid.into()),
    };
    let Some(network) = network_from(req.network) else { return refuse(Reason::PolicyNetwork.into()) };
    if parse_p256_pubkey(&req.owner_pk).is_none() || parse_p256_pubkey(&req.recovery_pk).is_none() || req.owner_pk == req.recovery_pk {
        return refuse(Reason::PolicyInvalid.into());
    }
    let secp = secp();
    let mut seed = [0u8; 32];
    sgx::read_rand(&mut seed);
    let mut identity_sk = [0u8; 32];
    loop {
        sgx::read_rand(&mut identity_sk);
        if SecretKey::from_slice(&identity_sk).is_ok() {
            break;
        }
    }
    build_init(secp, network, seed, identity_sk, req.owner_pk, req.recovery_pk, None)
}

#[allow(clippy::too_many_arguments)]
fn build_init(
    secp: Secp256k1<All>,
    network: Network,
    mut seed: [u8; 32],
    mut identity_sk: [u8; 32],
    owner_pk: [u8; 65],
    recovery_pk: [u8; 65],
    state: Option<State>,
) -> Response {
    let Some(keys) = derive_keys(&secp, network, &seed) else {
        seed.zeroize();
        identity_sk.zeroize();
        return refuse_code("KEY_DERIVATION");
    };
    let Some(idpk) = identity_pk(&secp, &identity_sk) else { return refuse_code("KEY_DERIVATION") };
    let Some(blob) = recovery::encrypt(&recovery_pk, &keys.fingerprint, &keys.xpub, &seed) else {
        seed.zeroize();
        identity_sk.zeroize();
        return refuse_code("RECOVERY_BLOB");
    };
    let card = IdentityCard {
        mrenclave: sgx::mrenclave(),
        network: network as u8,
        xpub: keys.xpub,
        fingerprint: keys.fingerprint,
        identity_pk: idpk,
        tier: sgx::tier().to_string(),
    };
    let Ok(id_sk) = SecretKey::from_slice(&identity_sk) else { return refuse_code("KEY_DERIVATION") };
    let card_sig = sign_digest_secp(&secp, &id_sk, &card.digest());
    let env = Envelope { network: network as u8, seed, identity_sk, owner_pk, recovery_pk, state, last_judged: None };
    let sealed = match seal_or(&env) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let resp = proto::InitResponse {
        sealed,
        xpub: keys.xpub,
        fingerprint: keys.fingerprint,
        identity_pk: idpk,
        card: card.encode(),
        card_sig,
        recovery_blob: blob,
    };
    Response::ok(resp.encode())
}

fn install(input: &[u8]) -> Response {
    let req = match proto::SealedWith::decode(input, signer_core::update::MAX_MANDATE_BYTES) {
        Ok(r) => r,
        Err(_) => return refuse(Reason::PolicyInvalid.into()),
    };
    let mut env = match open(&req.sealed) {
        Ok(e) => e,
        Err(r) => return r,
    };
    if env.state.is_some() {
        return refuse(Reason::PolicyPending.into()); // already installed: use APPLY_MESSAGE
    }
    let Some(sig_bytes) = req.extra.as_deref() else { return refuse(Reason::PolicySig.into()) };
    let Ok(sig) = <[u8; 64]>::try_from(sig_bytes) else { return refuse(Reason::PolicySig.into()) };
    let Some(network) = network_from(env.network) else { return refuse(Reason::PolicyNetwork.into()) };
    let secp = secp();
    let Some(keys) = derive_keys(&secp, network, &env.seed) else { return refuse_code("KEY_DERIVATION") };
    let Ok(id_sk) = SecretKey::from_slice(&env.identity_sk) else { return refuse_code("KEY_DERIVATION") };
    let enclave_id = signer_core::sha256(&id_sk.public_key(&secp).serialize());
    // the mandate: signed by the bound owner as PolicyUpdate nonce 0 for this enclave
    let msg = Message::PolicyUpdate { enclave_id, nonce: 0, mandate: req.data.clone(), sig };
    if !msg.verify(&env.owner_pk) {
        return refuse(Reason::PolicySig.into());
    }
    let Ok(mandate) = Mandate::decode(&req.data) else { return refuse(Reason::PolicyInvalid.into()) };
    if mandate.validate().is_err() {
        return refuse(Reason::PolicyInvalid.into());
    }
    if mandate.network != network {
        return refuse(Reason::PolicyNetwork.into());
    }
    let want = WalletSpec {
        fingerprint: keys.fingerprint,
        account: AccountPath { purpose: 84, coin: network.coin_type(), account: 0 },
        script_types: alloc::vec![ScriptType::P2wpkh],
    };
    if mandate.wallet != want {
        return refuse(Reason::PolicyWallet.into());
    }
    let state = State::new_at_init(enclave_id, env.owner_pk, env.recovery_pk, mandate, sig);
    env.state = Some(state);
    match seal_or(&env) {
        Ok(sealed) => Response::ok(proto::SealedResponse { sealed }.encode()),
        Err(r) => r,
    }
}

fn status(input: &[u8]) -> Response {
    let (env, s) = match open_full(input) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let secp = secp();
    let Some(network) = network_from(env.network) else { return refuse(Reason::PolicyNetwork.into()) };
    let Some(keys) = derive_keys(&secp, network, &env.seed) else { return refuse_code("KEY_DERIVATION") };
    let Some(idpk) = identity_pk(&secp, &env.identity_sk) else { return refuse_code("KEY_DERIVATION") };
    let mut st = s.clone();
    st.activate_pending();
    st.roll_window();
    let r = proto::StatusResponse {
        tier: sgx::tier().to_string(),
        mrenclave: sgx::mrenclave(),
        session_id: session::id(),
        network: env.network,
        xpub: keys.xpub,
        fingerprint: keys.fingerprint,
        identity_pk: idpk,
        nonce: st.nonce,
        seq: st.seq,
        frozen: st.frozen,
        armed: st.armed,
        chain_frozen: st.chain.frozen,
        best_height: st.chain.best.map(|b| b.height).unwrap_or(0),
        best_hash: st.chain.best.map(|b| b.hash).unwrap_or([0; 32]),
        window_start: st.window.start_height,
        window_outflow: st.window.outflow,
        window_unlisted: st.window.unlisted,
        window_fees: st.window.fees,
        mandate_hash: st.mandate.hash(),
        pending: st.pending.as_ref().map(|p| (p.mandate.hash(), p.activation_height)),
        pending_owner: st.pending_owner.as_ref().map(|p| p.activation_height),
        clock_label: clock_label(network).to_string(),
    };
    Response::ok(r.encode())
}

fn policy(input: &[u8]) -> Response {
    let (_, s) = match open_full(input) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let r = proto::PolicyResponse {
        mandate: s.mandate.encode(),
        sig: s.mandate_sig,
        nonce: s.nonce,
        pending: s.pending.as_ref().map(|p| (p.mandate.encode(), p.sig, p.nonce, p.activation_height)),
    };
    Response::ok(r.encode())
}

fn apply_message(input: &[u8]) -> Response {
    let req = match proto::SealedWith::decode(input, proto::limits::MAX_MESSAGE) {
        Ok(r) => r,
        Err(_) => return refuse(Reason::PolicyInvalid.into()),
    };
    let (mut env, s) = match open_full(&req.sealed) {
        Ok(x) => x,
        Err(r) => return r,
    };
    if !session::check_seq(s.seq) {
        return refuse(Reason::SeqBehindSession.into());
    }
    let Ok(msg) = Message::decode(&req.data) else { return refuse(Reason::PolicyInvalid.into()) };
    match s.apply_message(&msg) {
        Ok(ns) => {
            env.state = Some(ns);
            match seal_or(&env) {
                Ok(sealed) => Response::ok(proto::SealedResponse { sealed }.encode()),
                Err(r) => r,
            }
        }
        Err(r) => refuse(r),
    }
}

fn freeze(input: &[u8]) -> Response {
    let (mut env, mut s) = match open_full(input) {
        Ok(x) => x,
        Err(r) => return r,
    };
    s.freeze();
    env.state = Some(s);
    match seal_or(&env) {
        Ok(sealed) => Response::ok(proto::SealedResponse { sealed }.encode()),
        Err(r) => r,
    }
}

fn headers(input: &[u8]) -> Response {
    let req = match proto::SealedWith::decode(input, proto::limits::MAX_HEADERS.saturating_mul(80)) {
        Ok(r) => r,
        Err(_) => return refuse(Reason::HeaderInvalid.into()),
    };
    if req.data.len() % 80 != 0 {
        return refuse(Reason::HeaderInvalid.into());
    }
    let (mut env, mut s) = match open_full(&req.sealed) {
        Ok(x) => x,
        Err(r) => return r,
    };
    if !session::check_seq(s.seq) {
        return refuse(Reason::SeqBehindSession.into());
    }
    let hs: Vec<[u8; 80]> = req.data.chunks_exact(80).map(|c| {
        let mut a = [0u8; 80];
        a.copy_from_slice(c);
        a
    }).collect();
    let res = apply_headers(&mut s, &hs);
    let best_height = s.chain.best.map(|b| b.height).unwrap_or(0);
    env.state = Some(s);
    let sealed = match seal_or(&env) {
        Ok(x) => x,
        Err(r) => return r,
    };
    match res {
        Ok(accepted) => Response::ok(proto::HeadersResponse { sealed, accepted, best_height }.encode()),
        // a freeze is a state change the host must persist even though the batch refused
        Err(r) => refuse_with(r, proto::HeadersResponse { sealed, accepted: 0, best_height }.encode()),
    }
}

fn judge_op(input: &[u8]) -> Response {
    let req = match proto::SealedWith::decode(input, proto::limits::MAX_PSBT) {
        Ok(r) => r,
        Err(_) => return refuse(Reason::PsbtParse.into()),
    };
    let (mut env, s) = match open_full(&req.sealed) {
        Ok(x) => x,
        Err(r) => return r,
    };
    if !session::check_seq(s.seq) {
        return refuse(Reason::SeqBehindSession.into());
    }
    let witness = match &req.extra {
        None => None,
        Some(b) => match Message::decode(b) {
            Ok(m @ Message::WitnessToken { .. }) => Some(m),
            _ => return refuse(Reason::FreshnessSig.into()),
        },
    };
    let secp = secp();
    let Some(network) = network_from(env.network) else { return refuse(Reason::PolicyNetwork.into()) };
    let Some(keys) = derive_keys(&secp, network, &env.seed) else { return refuse_code("KEY_DERIVATION") };
    let classified = match classify(&secp, &req.data, &keys.account, &s.mandate, s.own_index_bound) {
        Ok(c) => c,
        Err(r) => return refuse(r),
    };
    match judge(&s, &classified, witness.as_ref()) {
        Verdict::Accept { state, summary } => {
            let receipt = Receipt::from_summary(state.enclave_id, &summary).encode();
            session::raise(state.seq);
            env.last_judged = Some(LastJudged {
                psbt_hash: signer_core::sha256(&req.data),
                txid: summary.txid,
                seq: state.seq,
                receipt: receipt.clone(),
            });
            env.state = Some(state);
            match seal_or(&env) {
                Ok(sealed) => Response::ok(proto::JudgeResponse { sealed, receipt }.encode()),
                Err(r) => r,
            }
        }
        Verdict::Refuse { refusal, disarm } => match disarm {
            None => refuse(refusal),
            Some(st) => {
                env.state = Some(st);
                match seal_or(&env) {
                    Ok(sealed) => refuse_with(refusal, proto::SealedResponse { sealed }.encode()),
                    Err(r) => r,
                }
            }
        },
    }
}

fn sign_op(input: &[u8]) -> Response {
    let req = match proto::SealedWith::decode(input, proto::limits::MAX_PSBT) {
        Ok(r) => r,
        Err(_) => return refuse(Reason::PsbtParse.into()),
    };
    let (env, s) = match open_full(&req.sealed) {
        Ok(x) => x,
        Err(r) => return r,
    };
    if !session::check_seq(s.seq) {
        return refuse(Reason::SeqBehindSession.into());
    }
    // the two-phase rule: only the PSBT this very blob was charged for, byte for byte
    let Some(lj) = env.last_judged.as_ref() else { return refuse(Reason::PsbtParse.into()) };
    if lj.psbt_hash != signer_core::sha256(&req.data) || lj.seq != s.seq {
        return refuse(Reason::PsbtParse.into());
    }
    let secp = secp();
    let Some(network) = network_from(env.network) else { return refuse(Reason::PolicyNetwork.into()) };
    let Some(keys) = derive_keys(&secp, network, &env.seed) else { return refuse_code("KEY_DERIVATION") };
    // classify again against the charged state's bounds minus nothing: the bytes are identical,
    // so the classification is identical; it is recomputed rather than stored (no state in the
    // blob that was not produced by the core)
    let mut bound = s.own_index_bound;
    // the charge raised the bounds; classification at sign time must see the pre-charge bounds
    // or wider — wider is fine (a larger search depth never admits a non-own key)
    bound[0] = bound[0].saturating_add(s.mandate.limits.own_index_gap);
    bound[1] = bound[1].saturating_add(s.mandate.limits.own_index_gap);
    let classified = match classify(&secp, &req.data, &keys.account, &s.mandate, bound) {
        Ok(c) => c,
        Err(r) => return refuse(r),
    };
    let Ok(mut psbt) = bitcoin::Psbt::deserialize(&req.data) else { return refuse(Reason::PsbtParse.into()) };
    if let Err(r) = sign_own_inputs(&secp, &mut psbt, &keys.account_xpriv, &classified) {
        return refuse(r);
    }
    let Ok(id_sk) = SecretKey::from_slice(&env.identity_sk) else { return refuse_code("KEY_DERIVATION") };
    let Ok(receipt) = Receipt::decode(&lj.receipt) else { return refuse(Reason::StateUnsealable.into()) };
    let receipt_sig = sign_digest_secp(&secp, &id_sk, &receipt.digest());
    let r = proto::SignResponse { psbt: psbt.serialize(), receipt: lj.receipt.clone(), receipt_sig, session_id: session::id() };
    Response::ok(r.encode())
}

#[cfg(feature = "test-init")]
fn test_init(input: &[u8]) -> Response {
    let req = match proto::TestInitRequest::decode(input) {
        Ok(r) => r,
        Err(_) => return refuse(Reason::PolicyInvalid.into()),
    };
    let Some(network) = network_from(req.init.network) else { return refuse(Reason::PolicyNetwork.into()) };
    let state = if req.state.is_empty() {
        None
    } else {
        match State::decode(&req.state) {
            Ok(s) => Some(s),
            Err(_) => return refuse(Reason::StateUnsealable.into()),
        }
    };
    build_init(secp(), network, req.seed, req.identity_sk, req.init.owner_pk, req.init.recovery_pk, state)
}

#[allow(dead_code)]
fn _unused(_: String) {}
