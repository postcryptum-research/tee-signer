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
    let account = Account {
        fingerprint,
        path: AccountPath { purpose: 84, coin: network.coin_type(), account: 0 },
        xpub: xpub_obj,
    };
    Some(Keys { account_xpriv, account, xpub, fingerprint })
}

fn identity_pk(secp: &Secp256k1<All>, sk: &[u8; 32]) -> Option<[u8; 33]> {
    let k = SecretKey::from_slice(sk).ok()?;
    Some(k.public_key(secp).serialize())
}

/// The tier as the card and STATUS carry it; an `auto-arm` build says so in the label itself,
/// so the fact travels with the measurement into every attestation (C-R7-7).
fn tier_label() -> String {
    #[cfg(feature = "auto-arm")]
    {
        alloc::format!("{}/AUTO_ARM", sgx::tier())
    }
    #[cfg(not(feature = "auto-arm"))]
    {
        sgx::tier().to_string()
    }
}

fn clock_label(n: Network) -> &'static str {
    match n {
        Network::Mainnet => "",
        Network::Testnet4 => "testnet4: min-difficulty blocks allowed; the block clock is weaker than mainnet",
        Network::Signet => {
            "signet: proof-of-work is cheap; the block clock is a correctness device here, not a security one"
        }
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
        op::REPORT => report(input),
        op::TPM_NONCE => tpm_nonce(),
        op::TPM_PROOF => tpm_proof(input),
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

/// REQ-r9 (C-R9-C): how each op treats the blob it reads. `Fresh` ops change state or sign and
/// must see a fresh counter proof when the state is TPM-bound; `Stale` ops only report and are
/// labeled possibly-stale (REQ-r9 §2.6); `NoBlob` ops read no sealed state. Every op code in
/// `proto::op` is classified here — the test `freshness_table_is_complete` refuses a new op that is
/// not — and the handlers call the helper of their class.
#[allow(dead_code)] // the table is the reviewable classification and the test gate's input
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Freshness {
    /// Verifies the proof (`open_full_fresh`).
    Fresh,
    /// Reads without a proof, information only (`open` / `open_full_stale`).
    Stale,
    /// No sealed state is read.
    NoBlob,
}

/// The classification of every op (C-R9-C).
#[allow(dead_code)]
pub const FRESHNESS: &[(u32, Freshness)] = &[
    (op::INIT, Freshness::NoBlob),
    (op::INSTALL, Freshness::Fresh),
    (op::STATUS, Freshness::Stale),
    (op::POLICY, Freshness::Stale),
    // APPLY_MESSAGE: Fresh for every message but `Anchor`, the attended override (see apply_message)
    (op::APPLY_MESSAGE, Freshness::Fresh),
    (op::FREEZE, Freshness::Fresh),
    (op::HEADERS, Freshness::Fresh),
    (op::JUDGE, Freshness::Fresh),
    (op::SIGN, Freshness::Fresh),
    (op::REPORT, Freshness::Stale),
    (op::TPM_NONCE, Freshness::NoBlob),
    (op::TPM_PROOF, Freshness::NoBlob),
    (op::TEST_INIT, Freshness::NoBlob),
    (op::TEST_RESET_SESSION, Freshness::NoBlob),
];

/// A full blob for an op that only reports (REQ-r9 §2.6): no counter proof, possibly stale.
fn open_full_stale(sealed: &[u8]) -> Result<(Envelope, State), Response> {
    let env = open(sealed)?;
    let state = env.state.clone().ok_or_else(|| refuse(Reason::StateUnsealable.into()))?;
    Ok((env, state))
}

/// A full blob for an op that changes state or signs (REQ-r9 §2): when the state is TPM-bound the
/// host must have deposited, for the nonce this enclave issued, a `TPM2_NV_Certify` proof that the
/// live counter equals the value this very blob expects. Nonce and proof are consumed whatever the
/// verdict (single-use). A fresh proof also arms this load (auto-arm on `counter == expected`,
/// RESP-r9 Q4): the counter has proven the blob is the latest, which is what the owner's `Arm`
/// would attest.
fn open_full_fresh(sealed: &[u8]) -> Result<(Envelope, State), Response> {
    let (env, state) = open_full_stale(sealed)?;
    if let Some(anchor) = state.tpm.as_ref() {
        let Some((nonce, bytes)) = session::tpm_proof_take() else {
            return Err(refuse(Reason::TpmRequired.into()));
        };
        let Ok(proof) = proto::TpmProof::decode(&bytes) else {
            session::tpm_set_last_fresh(false);
            return Err(refuse(Reason::TpmParse.into()));
        };
        match signer_core::tpm_attest::verify_nv_certify(&proof.attest, &proof.sig, anchor, &nonce) {
            Ok(_) => {
                session::tpm_set_last_fresh(true);
                session::arm();
            }
            Err(r) => {
                session::tpm_set_last_fresh(false);
                return Err(refuse(r.into()));
            }
        }
    }
    Ok((env, state))
}

/// The one seal helper (C-R9-B): every blob this enclave seals goes through here, and a TPM-bound
/// state leaves with `expected + 1` — the host increments the counter after persisting the blob.
fn seal_or(env: &mut Envelope) -> Result<Vec<u8>, Response> {
    if let Some(s) = env.state.as_mut() {
        s.bump_tpm();
    }
    env.seal().ok_or_else(|| refuse_code("SEAL_FAILED"))
}

/// REQ-r9: issue the nonce for the next blob-reading call.
fn tpm_nonce() -> Response {
    Response::ok(session::tpm_nonce_issue().to_vec())
}

/// REQ-r9: deposit the proof for the live nonce (verified by the next `Fresh` op, not here).
fn tpm_proof(input: &[u8]) -> Response {
    if proto::TpmProof::decode(input).is_err() {
        return refuse(Reason::TpmParse.into());
    }
    if !session::tpm_proof_store(input) {
        return refuse(Reason::TpmNonce.into());
    }
    Response::ok(Vec::new())
}

fn init(input: &[u8]) -> Response {
    let req = match proto::InitRequest::decode(input) {
        Ok(r) => r,
        Err(_) => return refuse(Reason::PolicyInvalid.into()),
    };
    let Some(network) = network_from(req.network) else { return refuse(Reason::PolicyNetwork.into()) };
    if parse_p256_pubkey(&req.owner_pk).is_none()
        || parse_p256_pubkey(&req.recovery_pk).is_none()
        || req.owner_pk == req.recovery_pk
    {
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
    let r = build_init(secp, network, seed, identity_sk, req.owner_pk, req.recovery_pk, None);
    if r.ok {
        // init is an attended owner operation on a fresh enclave: the process it runs in is armed
        session::arm();
    }
    r
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
        tier: tier_label(),
    };
    let Ok(id_sk) = SecretKey::from_slice(&identity_sk) else { return refuse_code("KEY_DERIVATION") };
    let card_sig = sign_digest_secp(&secp, &id_sk, &card.digest());
    let mut env =
        Envelope { network: network as u8, seed, identity_sk, owner_pk, recovery_pk, state, last_judged: None };
    let sealed = match seal_or(&mut env) {
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
    match seal_or(&mut env) {
        Ok(sealed) => Response::ok(proto::SealedResponse { sealed }.encode()),
        Err(r) => r,
    }
}

/// `REPORT` (REQ-r5 §3): a report for the quoting enclave with
/// `report_data = SHA-256(quote::DOMAIN ‖ nonce ‖ card bytes) ‖ 0[32]`. Read-only — no state
/// change, nothing secret in the output; the card is recomputed from the envelope at every call,
/// never cached. `target_info` and `nonce` are untrusted input of fixed size; anything else is
/// `ENCODING`. Allowed on a keys-only blob (the card exists from `INIT`).
fn report(input: &[u8]) -> Response {
    use signer_core::proto::quote;
    let req = match proto::SealedWith::decode(input, quote::INPUT_LEN) {
        Ok(r) => r,
        Err(_) => return refuse_code("ENCODING"),
    };
    if req.data.len() != quote::INPUT_LEN || req.extra.is_some() {
        return refuse_code("ENCODING");
    }
    let env = match open(&req.sealed) {
        Ok(e) => e,
        Err(r) => return r,
    };
    let secp = secp();
    let Some(network) = network_from(env.network) else { return refuse(Reason::PolicyNetwork.into()) };
    let Some(keys) = derive_keys(&secp, network, &env.seed) else { return refuse_code("KEY_DERIVATION") };
    let Some(idpk) = identity_pk(&secp, &env.identity_sk) else { return refuse_code("KEY_DERIVATION") };
    let card = proto::IdentityCard {
        mrenclave: sgx::mrenclave(),
        network: env.network,
        xpub: keys.xpub,
        fingerprint: keys.fingerprint,
        identity_pk: idpk,
        tier: tier_label(),
    };
    let mut target = [0u8; quote::TARGET_INFO_LEN];
    target.copy_from_slice(&req.data[..quote::TARGET_INFO_LEN]);
    let mut nonce = [0u8; quote::NONCE_LEN];
    nonce.copy_from_slice(&req.data[quote::TARGET_INFO_LEN..quote::INPUT_LEN]);
    let mut report_data = [0u8; 64];
    report_data[..32].copy_from_slice(&signer_core::sha256(&quote::preimage(&nonce, &card.encode())));
    let Some(report) = sgx::report_for(&target, &report_data) else { return refuse_code("REPORT") };
    Response::ok(proto::ReportResponse { report, card }.encode())
}

fn status(input: &[u8]) -> Response {
    let env = match open(input) {
        Ok(e) => e,
        Err(r) => return r,
    };
    let secp = secp();
    let Some(network) = network_from(env.network) else { return refuse(Reason::PolicyNetwork.into()) };
    let Some(keys) = derive_keys(&secp, network, &env.seed) else { return refuse_code("KEY_DERIVATION") };
    let Some(idpk) = identity_pk(&secp, &env.identity_sk) else { return refuse_code("KEY_DERIVATION") };
    let Some(s) = env.state.clone() else {
        // keys-only blob: identity and wallet facts, nothing else
        let r = proto::StatusResponse {
            installed: false,
            tier: tier_label(),
            mrenclave: sgx::mrenclave(),
            session_id: session::id(),
            network: env.network,
            xpub: keys.xpub,
            fingerprint: keys.fingerprint,
            identity_pk: idpk,
            nonce: 0,
            seq: 0,
            frozen: false,
            armed: true,
            chain_frozen: false,
            best_height: 0,
            best_hash: [0; 32],
            window_start: 0,
            window_outflow: 0,
            window_unlisted: 0,
            window_fees: 0,
            mandate_hash: [0; 32],
            pending: None,
            pending_owner: None,
            clock_label: clock_label(network).to_string(),
            boot_armed: session::armed(),
            boot_challenge: session::challenge(),
            auto_arm: cfg!(feature = "auto-arm"),
            tpm_bound: false,
            tpm_expected: 0,
            tpm_last_fresh: session::tpm_last_fresh(),
        };
        return Response::ok(r.encode());
    };
    let mut st = s.clone();
    st.activate_pending();
    st.roll_window();
    let r = proto::StatusResponse {
        installed: true,
        tier: tier_label(),
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
        boot_armed: session::armed(),
        boot_challenge: session::challenge(),
        auto_arm: cfg!(feature = "auto-arm"),
        tpm_bound: st.tpm.is_some(),
        tpm_expected: st.tpm.as_ref().map(|t| t.expected).unwrap_or(0),
        tpm_last_fresh: session::tpm_last_fresh(),
    };
    Response::ok(r.encode())
}

fn policy(input: &[u8]) -> Response {
    let (_, s) = match open_full_stale(input) {
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
    let Ok(msg) = Message::decode(&req.data) else { return refuse(Reason::PolicyInvalid.into()) };
    // REQ-r9 §2.5: the owner's `Anchor` is the attended override for a counter mismatch, so it is the
    // one message that opens the blob WITHOUT a counter proof — a stale blob could otherwise never be
    // re-anchored (found by the e2e rollback drill). Its own bindings stand in for the proof: the
    // owner's signature, the next nonce, THIS load's challenge, and `seq_seen` ≤ the enclave's seq.
    // Every other message needs the proof like any state change.
    let opened = match &msg {
        Message::Anchor { .. } => open_full_stale(&req.sealed),
        _ => open_full_fresh(&req.sealed),
    };
    let (mut env, s) = match opened {
        Ok(x) => x,
        Err(r) => return r,
    };
    if !session::check_seq(s.seq) {
        return refuse(Reason::SeqBehindSession.into());
    }
    let result = match &msg {
        // REQ-r7: the boot-arm takes THIS load's challenge as data; the core stays pure
        Message::Arm { .. } => s.apply_arm(&msg, &session::challenge()),
        // REQ-r9: the anchor is the owner's attended override; it arms like Arm and pins the TPM
        Message::Anchor { .. } => s.apply_anchor(&msg, &session::challenge()),
        _ => s.apply_message(&msg),
    };
    match result {
        Ok(ns) => {
            // the HWM ratchets on every accepted blob, Arm included (C-R7-3): an armed process can
            // never be handed a blob older than the one it was armed on
            session::raise(ns.seq);
            if matches!(msg, Message::Arm { .. } | Message::Anchor { .. }) {
                session::arm();
            }
            env.state = Some(ns);
            match seal_or(&mut env) {
                Ok(sealed) => Response::ok(proto::SealedResponse { sealed }.encode()),
                Err(r) => r,
            }
        }
        Err(r) => refuse(r),
    }
}

fn freeze(input: &[u8]) -> Response {
    let (mut env, mut s) = match open_full_fresh(input) {
        Ok(x) => x,
        Err(r) => return r,
    };
    s.freeze();
    env.state = Some(s);
    match seal_or(&mut env) {
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
    let (mut env, mut s) = match open_full_fresh(&req.sealed) {
        Ok(x) => x,
        Err(r) => return r,
    };
    if !session::check_seq(s.seq) {
        return refuse(Reason::SeqBehindSession.into());
    }
    let hs: Vec<[u8; 80]> = req
        .data
        .chunks_exact(80)
        .map(|c| {
            let mut a = [0u8; 80];
            a.copy_from_slice(c);
            a
        })
        .collect();
    let res = apply_headers(&mut s, &hs);
    let best_height = s.chain.best.map(|b| b.height).unwrap_or(0);
    env.state = Some(s);
    let sealed = match seal_or(&mut env) {
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
    let (mut env, s) = match open_full_fresh(&req.sealed) {
        Ok(x) => x,
        Err(r) => return r,
    };
    if !session::check_seq(s.seq) {
        return refuse(Reason::SeqBehindSession.into());
    }
    // REQ-r7 (C-R7-4): no judging, hence no charging and no signing, until the owner armed this load
    #[cfg(not(feature = "auto-arm"))]
    if !session::armed() {
        return refuse(Reason::NotArmed.into());
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
            match seal_or(&mut env) {
                Ok(sealed) => Response::ok(proto::JudgeResponse { sealed, receipt }.encode()),
                Err(r) => r,
            }
        }
        Verdict::Refuse { refusal, disarm } => match disarm {
            None => refuse(refusal),
            Some(st) => {
                env.state = Some(st);
                match seal_or(&mut env) {
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
    let (env, s) = match open_full_fresh(&req.sealed) {
        Ok(x) => x,
        Err(r) => return r,
    };
    if !session::check_seq(s.seq) {
        return refuse(Reason::SeqBehindSession.into());
    }
    // REQ-r7 (C-R7-4): the signing entrypoint checks the volatile boot-arm itself, not only judge
    #[cfg(not(feature = "auto-arm"))]
    if !session::armed() {
        return refuse(Reason::NotArmed.into());
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
    let r = proto::SignResponse {
        psbt: psbt.serialize(),
        receipt: lj.receipt.clone(),
        receipt_sig,
        session_id: session::id(),
    };
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
    let r = build_init(secp(), network, req.seed, req.identity_sk, req.init.owner_pk, req.init.recovery_pk, state);
    if r.ok {
        session::arm();
    }
    r
}

#[allow(dead_code)]
fn _unused(_: String) {}

#[cfg(test)]
mod tests {
    use super::*;

    /// C-R9-C: a new op code cannot appear without a freshness classification, and every classified
    /// op exists. The list below is the full `proto::op` module by hand — adding an op there without
    /// adding it here, or here without classifying it in `FRESHNESS`, fails this test.
    #[test]
    fn freshness_table_is_complete() {
        let all: &[u32] = &[
            op::INIT,
            op::INSTALL,
            op::STATUS,
            op::POLICY,
            op::APPLY_MESSAGE,
            op::FREEZE,
            op::HEADERS,
            op::JUDGE,
            op::SIGN,
            op::REPORT,
            op::TPM_NONCE,
            op::TPM_PROOF,
            op::TEST_INIT,
            op::TEST_RESET_SESSION,
        ];
        for o in all {
            assert!(FRESHNESS.iter().any(|(c, _)| c == o), "op {o} is not classified in FRESHNESS");
        }
        for (c, _) in FRESHNESS {
            assert!(all.contains(c), "FRESHNESS names an op {c} that does not exist");
        }
        // the ops that change state or sign are all Fresh; the pure reads are Stale
        for (c, f) in FRESHNESS {
            match *c {
                op::INSTALL | op::APPLY_MESSAGE | op::FREEZE | op::HEADERS | op::JUDGE | op::SIGN => {
                    assert_eq!(*f, Freshness::Fresh)
                }
                op::STATUS | op::POLICY | op::REPORT => assert_eq!(*f, Freshness::Stale),
                _ => assert_eq!(*f, Freshness::NoBlob),
            }
        }
    }
}
