//! signerd — the untrusted host daemon (`docs/DESIGN.md §1`, `docs/ENCLAVE.md`).
//!
//! Transport and storage only: it loads the enclave, keeps the sealed blob on disk (atomic
//! write, fsync, rename), serializes every ecall behind one mutex, serves the HTTP API the BTCPay
//! plugin and `owner-cli` use, feeds block headers from a bitcoind, and appends receipts to a
//! log. It cannot authorise anything: every decision is the enclave's, on bytes it verifies.
//!
//! Two-phase signing is honoured here as the enclave demands it: `JUDGE` → persist the charged
//! blob → `SIGN`. A crash between the two leaves a charged budget and no signature.
//!
//! `signerd replay` and `signerd smoke` drive the same enclave (real or simulated) through the
//! vector suite and the full init→install→headers→judge→sign flow; on the SGX box that is the
//! hardware run of R2.

mod enclave;
mod replay;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use axum::extract::State as AxState;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use signer_core::proto::{self, op, Response};
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use crate::enclave::Enclave;

#[derive(Parser, Debug, Clone)]
#[command(name = "signerd", about = "tee-signer host daemon")]
struct Args {
    /// Path to enclave.signed.so (sgx feature).
    #[arg(long, env = "SIGNERD_ENCLAVE", global = true)]
    enclave: Option<String>,
    /// Launch the enclave in debug mode (required on T1 hardware).
    #[arg(long, env = "SIGNERD_ENCLAVE_DEBUG", default_value_t = true, global = true)]
    enclave_debug: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug, Clone)]
enum Cmd {
    /// Serve the API (the daemon).
    Run {
        /// Directory for the sealed blob, the receipt log and the token.
        #[arg(long, env = "SIGNERD_STATE_DIR")]
        state_dir: PathBuf,
        /// Listen address.
        #[arg(long, env = "SIGNERD_LISTEN", default_value = "127.0.0.1:7390")]
        listen: String,
        /// bitcoind JSON-RPC URL for the header feed (e.g. http://127.0.0.1:10810).
        #[arg(long, env = "SIGNERD_BITCOIND_RPC")]
        bitcoind_rpc: Option<String>,
        /// bitcoind cookie file (read-only access is enough).
        #[arg(long, env = "SIGNERD_BITCOIND_COOKIE")]
        bitcoind_cookie: Option<PathBuf>,
        /// Header feed interval, seconds.
        #[arg(long, env = "SIGNERD_HEADERS_INTERVAL", default_value_t = 30)]
        headers_interval: u64,
    },
    /// Replay vectors/r1/*.json through the enclave (needs a test-init build).
    Replay {
        /// Directory of vector JSON files.
        #[arg(long)]
        vectors: PathBuf,
    },
    /// The full flow through the enclave with a known seed (needs a test-init build).
    Smoke,
}

#[allow(clippy::needless_return, unreachable_code)]
fn load_enclave(args: &Args) -> Result<Box<dyn Enclave>> {
    #[cfg(feature = "sgx")]
    {
        let path = args.enclave.clone().ok_or_else(|| anyhow!("--enclave is required with the sgx feature"))?;
        return Ok(Box::new(enclave::sgx::Sgx::load(&path, args.enclave_debug)?));
    }
    #[cfg(all(feature = "nosgx", not(feature = "sgx")))]
    {
        let _ = &args.enclave;
        let _ = args.enclave_debug;
        return Ok(Box::new(enclave::InProcess));
    }
    #[cfg(not(any(feature = "sgx", feature = "nosgx")))]
    {
        compile_error!("build signerd with --features sgx or --features nosgx");
    }
}

struct Daemon {
    enclave: Box<dyn Enclave>,
    state_dir: PathBuf,
    sealed: Option<Vec<u8>>,
    token: String,
    last_witness: Option<Vec<u8>>,
    bitcoind: Option<Bitcoind>,
}

type Shared = Arc<Mutex<Daemon>>;

impl Daemon {
    fn sealed_path(&self) -> PathBuf {
        self.state_dir.join("state.sealed")
    }
    fn receipts_path(&self) -> PathBuf {
        self.state_dir.join("receipts.jsonl")
    }

    /// Atomic persist: tmp → fsync → rename → fsync dir. Nothing reads a half-written blob.
    fn persist(&mut self, sealed: Vec<u8>) -> Result<()> {
        let path = self.sealed_path();
        let tmp = self.state_dir.join("state.sealed.tmp");
        {
            use std::io::Write;
            let mut f = open_0600(&tmp, false)?;
            f.write_all(&sealed)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &path)?;
        let dir = std::fs::File::open(&self.state_dir)?;
        dir.sync_all()?;
        self.sealed = Some(sealed);
        Ok(())
    }

    fn call(&mut self, op_code: u32, input: &[u8]) -> Result<Response> {
        self.enclave.call(op_code, input)
    }

    fn sealed(&self) -> Result<Vec<u8>> {
        self.sealed.clone().ok_or_else(|| anyhow!("not initialised: POST /v1/init first"))
    }

    fn status(&mut self) -> Result<proto::StatusResponse> {
        let sealed = self.sealed()?;
        let r = self.call(op::STATUS, &sealed)?;
        if !r.ok {
            return Err(anyhow!("status: {:?}", r.reasons));
        }
        proto::StatusResponse::decode(&r.payload).map_err(|_| anyhow!("status response"))
    }

    fn append_receipt(&self, rec: &ReceiptLine) -> Result<()> {
        use std::io::Write;
        let mut f = open_0600(&self.receipts_path(), true)?;
        writeln!(f, "{}", serde_json::to_string(rec)?)?;
        f.sync_all()?;
        Ok(())
    }
}

fn open_0600(path: &Path, append: bool) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut o = std::fs::OpenOptions::new();
    o.create(true).mode(0o600);
    if append {
        o.append(true);
    } else {
        o.write(true).truncate(true);
    }
    Ok(o.open(path)?)
}

#[derive(Serialize, Deserialize)]
struct ReceiptLine {
    ts: u64,
    session_id: String,
    seq: u64,
    txid: String,
    receipt_hex: String,
    sig_hex: String,
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

// ---------------------------------------------------------------- bitcoind header feed

struct Bitcoind {
    url: String,
    auth: String,
    http: reqwest::Client,
}

impl Bitcoind {
    fn new(url: &str, cookie: &Path) -> Result<Self> {
        let c = std::fs::read_to_string(cookie).with_context(|| format!("reading cookie {}", cookie.display()))?;
        let (user, pass) = c.trim().split_once(':').ok_or_else(|| anyhow!("cookie format"))?;
        use base64::Engine;
        let auth = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
        Ok(Bitcoind { url: url.to_string(), auth, http: reqwest::Client::new() })
    }
    async fn rpc(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
        let body = serde_json::json!({"jsonrpc": "1.0", "id": "signerd", "method": method, "params": params});
        let r = self
            .http
            .post(&self.url)
            .header("Authorization", format!("Basic {}", self.auth))
            .json(&body)
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;
        if !r["error"].is_null() {
            return Err(anyhow!("rpc {method}: {}", r["error"]));
        }
        Ok(r["result"].clone())
    }
    async fn tip_height(&self) -> Result<u32> {
        let v = self.rpc("getblockchaininfo", serde_json::json!([])).await?;
        Ok(v["headers"].as_u64().unwrap_or(0) as u32)
    }
    async fn header_hex(&self, height: u32) -> Result<String> {
        let h = self.rpc("getblockhash", serde_json::json!([height])).await?;
        let hash = h.as_str().ok_or_else(|| anyhow!("getblockhash"))?;
        let r = self.rpc("getblockheader", serde_json::json!([hash, false])).await?;
        Ok(r.as_str().ok_or_else(|| anyhow!("getblockheader"))?.to_string())
    }
}

/// One feed round: headers from (enclave best − 10) + 1 to the node's tip, in batches. The
/// enclave decides; a feed that lies or lags can only stall it. Only the read-only RPC subset is
/// used (`getblockchaininfo`, `getblockhash`, `getblockheader`) — owner decision D5.
async fn feed_once(shared: &Shared) -> Result<u32> {
    let (best_height, best_hash, url, auth) = {
        let mut d = shared.lock().await;
        let Some(b) = &d.bitcoind else { return Ok(0) };
        let (url, auth) = (b.url.clone(), b.auth.clone());
        let st = d.status()?;
        if !st.installed {
            return Ok(0); // keys only: nothing to feed until a mandate pins the checkpoint
        }
        (st.best_height, st.best_hash, url, auth)
    };
    let bd = Bitcoind { url, auth, http: reqwest::Client::new() };
    let tip = bd.tip_height().await?;
    if tip <= best_height {
        return Ok(0);
    }
    // extension when the node agrees with the enclave's best; otherwise offer the last ten
    // headers again so the enclave can judge the fork (it keeps a longer recent window)
    let node_best = bd.rpc("getblockhash", serde_json::json!([best_height])).await?;
    let same = node_best.as_str().map(|h| h == display_hash(best_hash)).unwrap_or(false);
    let start = if same { best_height.saturating_add(1) } else { best_height.saturating_sub(10).saturating_add(1).max(1) };
    let mut from = start;
    let mut total = 0u32;
    while from <= tip {
        let to = (from + 1999).min(tip);
        let mut bytes = Vec::with_capacity(((to - from + 1) * 80) as usize);
        for h in from..=to {
            bytes.extend_from_slice(&hex::decode(bd.header_hex(h).await?)?);
        }
        let mut d = shared.lock().await;
        let sealed = d.sealed()?;
        let r = d.call(op::HEADERS, &proto::SealedWith { sealed, data: bytes, extra: None }.encode())?;
        if r.ok {
            let hr = proto::HeadersResponse::decode(&r.payload).map_err(|_| anyhow!("headers response"))?;
            d.persist(hr.sealed)?;
            total += hr.accepted;
            info!(accepted = hr.accepted, best = hr.best_height, "headers");
        } else {
            if let Ok(hr) = proto::HeadersResponse::decode(&r.payload) {
                d.persist(hr.sealed)?; // a chain freeze is a state change the host must keep
            }
            return Err(anyhow!("headers refused: {:?}", r.reasons));
        }
        from = to + 1;
    }
    Ok(total)
}

// ---------------------------------------------------------------- HTTP API

#[derive(Serialize)]
struct ErrorBody {
    error: String,
    reasons: Vec<String>,
}

fn err(status: StatusCode, msg: impl Into<String>, reasons: Vec<String>) -> axum::response::Response {
    (status, Json(ErrorBody { error: msg.into(), reasons })).into_response()
}

fn authorized(headers: &HeaderMap, token: &str) -> bool {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.strip_prefix("Bearer ").map(|t| t == token).unwrap_or(false))
        .unwrap_or(false)
}

#[derive(Serialize)]
struct StatusJson {
    enclave: &'static str,
    initialised: bool,
    installed: bool,
    tier: String,
    mrenclave: String,
    session_id: String,
    network: u8,
    xpub: String,
    fingerprint: String,
    identity_pk: String,
    nonce: u64,
    seq: u64,
    frozen: bool,
    armed: bool,
    chain_frozen: bool,
    best_height: u32,
    best_hash: String,
    window_start: u32,
    window_outflow: u64,
    window_unlisted: u64,
    window_fees: u64,
    mandate_hash: String,
    pending: Option<(String, u32)>,
    pending_owner: Option<u32>,
    clock_label: String,
}

fn display_hash(mut h: [u8; 32]) -> String {
    h.reverse();
    hex::encode(h)
}

async fn h_status(AxState(s): AxState<Shared>, headers: HeaderMap) -> axum::response::Response {
    let mut d = s.lock().await;
    if !authorized(&headers, &d.token) {
        return err(StatusCode::UNAUTHORIZED, "token", vec![]);
    }
    if d.sealed.is_none() {
        return Json(serde_json::json!({"enclave": d.enclave.kind(), "initialised": false})).into_response();
    }
    match d.status() {
        Ok(st) => Json(StatusJson {
            enclave: d.enclave.kind(),
            initialised: true,
            installed: st.installed,
            tier: st.tier,
            mrenclave: hex::encode(st.mrenclave),
            session_id: hex::encode(st.session_id),
            network: st.network,
            xpub: bitcoin::bip32::Xpub::decode(&st.xpub).map(|x| x.to_string()).unwrap_or_default(),
            fingerprint: hex::encode(st.fingerprint),
            identity_pk: hex::encode(st.identity_pk),
            nonce: st.nonce,
            seq: st.seq,
            frozen: st.frozen,
            armed: st.armed,
            chain_frozen: st.chain_frozen,
            best_height: st.best_height,
            best_hash: display_hash(st.best_hash),
            window_start: st.window_start,
            window_outflow: st.window_outflow,
            window_unlisted: st.window_unlisted,
            window_fees: st.window_fees,
            mandate_hash: hex::encode(st.mandate_hash),
            pending: st.pending.map(|(h, a)| (hex::encode(h), a)),
            pending_owner: st.pending_owner,
            clock_label: st.clock_label,
        })
        .into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string(), vec![]),
    }
}

#[derive(Deserialize)]
struct InitJson {
    network: u8,
    owner_pk_hex: String,
    recovery_pk_hex: String,
}

#[derive(Serialize)]
struct InitOut {
    xpub: String,
    fingerprint: String,
    identity_pk: String,
    card_hex: String,
    card_sig_hex: String,
    recovery_blob_hex: String,
}

fn fixed<const N: usize>(hex_s: &str) -> Result<[u8; N]> {
    let v = hex::decode(hex_s)?;
    <[u8; N]>::try_from(v.as_slice()).map_err(|_| anyhow!("expected {N} bytes"))
}

async fn h_init(AxState(s): AxState<Shared>, headers: HeaderMap, Json(req): Json<InitJson>) -> axum::response::Response {
    let mut d = s.lock().await;
    if !authorized(&headers, &d.token) {
        return err(StatusCode::UNAUTHORIZED, "token", vec![]);
    }
    if d.sealed.is_some() || d.sealed_path().exists() {
        return err(StatusCode::CONFLICT, "already initialised; refuse to overwrite a wallet", vec![]);
    }
    let (owner_pk, recovery_pk) = match (fixed::<65>(&req.owner_pk_hex), fixed::<65>(&req.recovery_pk_hex)) {
        (Ok(a), Ok(b)) => (a, b),
        _ => return err(StatusCode::BAD_REQUEST, "keys must be 65-byte SEC1 hex", vec![]),
    };
    let r = match d.call(op::INIT, &proto::InitRequest { network: req.network, owner_pk, recovery_pk }.encode()) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string(), vec![]),
    };
    if !r.ok {
        return err(StatusCode::UNPROCESSABLE_ENTITY, "init refused", r.reasons);
    }
    let Ok(ir) = proto::InitResponse::decode(&r.payload) else { return err(StatusCode::INTERNAL_SERVER_ERROR, "init decode", vec![]) };
    if let Err(e) = d.persist(ir.sealed.clone()) {
        return err(StatusCode::INTERNAL_SERVER_ERROR, format!("persist: {e}"), vec![]);
    }
    Json(InitOut {
        xpub: bitcoin::bip32::Xpub::decode(&ir.xpub).map(|x| x.to_string()).unwrap_or_default(),
        fingerprint: hex::encode(ir.fingerprint),
        identity_pk: hex::encode(ir.identity_pk),
        card_hex: hex::encode(&ir.card),
        card_sig_hex: hex::encode(ir.card_sig),
        recovery_blob_hex: hex::encode(&ir.recovery_blob),
    })
    .into_response()
}

#[derive(Deserialize)]
struct InstallJson {
    mandate_hex: String,
    sig_hex: String,
}

async fn h_install(AxState(s): AxState<Shared>, headers: HeaderMap, Json(req): Json<InstallJson>) -> axum::response::Response {
    let mut d = s.lock().await;
    if !authorized(&headers, &d.token) {
        return err(StatusCode::UNAUTHORIZED, "token", vec![]);
    }
    let Ok(sealed) = d.sealed() else { return err(StatusCode::CONFLICT, "not initialised", vec![]) };
    let (mandate, sig) = match (hex::decode(&req.mandate_hex), hex::decode(&req.sig_hex)) {
        (Ok(m), Ok(s)) => (m, s),
        _ => return err(StatusCode::BAD_REQUEST, "hex", vec![]),
    };
    let r = match d.call(op::INSTALL, &proto::SealedWith { sealed, data: mandate, extra: Some(sig) }.encode()) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string(), vec![]),
    };
    if !r.ok {
        return err(StatusCode::UNPROCESSABLE_ENTITY, "install refused", r.reasons);
    }
    let Ok(sr) = proto::SealedResponse::decode(&r.payload) else { return err(StatusCode::INTERNAL_SERVER_ERROR, "decode", vec![]) };
    if let Err(e) = d.persist(sr.sealed) {
        return err(StatusCode::INTERNAL_SERVER_ERROR, format!("persist: {e}"), vec![]);
    }
    Json(serde_json::json!({"installed": true})).into_response()
}

async fn h_policy(AxState(s): AxState<Shared>, headers: HeaderMap) -> axum::response::Response {
    let mut d = s.lock().await;
    if !authorized(&headers, &d.token) {
        return err(StatusCode::UNAUTHORIZED, "token", vec![]);
    }
    let Ok(sealed) = d.sealed() else { return err(StatusCode::CONFLICT, "not initialised", vec![]) };
    match d.call(op::POLICY, &sealed) {
        Ok(r) if r.ok => match proto::PolicyResponse::decode(&r.payload) {
            Ok(p) => Json(serde_json::json!({
                "mandate_hex": hex::encode(&p.mandate),
                "sig_hex": hex::encode(p.sig),
                "nonce": p.nonce,
                "pending": p.pending.map(|(m, s, n, a)| serde_json::json!({"mandate_hex": hex::encode(m), "sig_hex": hex::encode(s), "nonce": n, "activation_height": a})),
            }))
            .into_response(),
            Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "decode", vec![]),
        },
        Ok(r) => err(StatusCode::CONFLICT, "policy refused", r.reasons),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string(), vec![]),
    }
}

#[derive(Deserialize)]
struct MessageJson {
    message_hex: String,
}

async fn h_message(AxState(s): AxState<Shared>, headers: HeaderMap, Json(req): Json<MessageJson>) -> axum::response::Response {
    let mut d = s.lock().await;
    if !authorized(&headers, &d.token) {
        return err(StatusCode::UNAUTHORIZED, "token", vec![]);
    }
    let Ok(sealed) = d.sealed() else { return err(StatusCode::CONFLICT, "not initialised", vec![]) };
    let Ok(msg) = hex::decode(&req.message_hex) else { return err(StatusCode::BAD_REQUEST, "hex", vec![]) };
    // a witness token is cached for the next sign, not applied
    if let Ok(signer_core::update::Message::WitnessToken { .. }) = signer_core::update::Message::decode(&msg) {
        d.last_witness = Some(msg);
        return Json(serde_json::json!({"witness": "cached"})).into_response();
    }
    let r = match d.call(op::APPLY_MESSAGE, &proto::SealedWith { sealed, data: msg, extra: None }.encode()) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string(), vec![]),
    };
    if !r.ok {
        return err(StatusCode::UNPROCESSABLE_ENTITY, "message refused", r.reasons);
    }
    let Ok(sr) = proto::SealedResponse::decode(&r.payload) else { return err(StatusCode::INTERNAL_SERVER_ERROR, "decode", vec![]) };
    if let Err(e) = d.persist(sr.sealed) {
        return err(StatusCode::INTERNAL_SERVER_ERROR, format!("persist: {e}"), vec![]);
    }
    Json(serde_json::json!({"applied": true})).into_response()
}

async fn h_freeze(AxState(s): AxState<Shared>, headers: HeaderMap) -> axum::response::Response {
    let mut d = s.lock().await;
    if !authorized(&headers, &d.token) {
        return err(StatusCode::UNAUTHORIZED, "token", vec![]);
    }
    let Ok(sealed) = d.sealed() else { return err(StatusCode::CONFLICT, "not initialised", vec![]) };
    let r = match d.call(op::FREEZE, &sealed) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string(), vec![]),
    };
    let Ok(sr) = proto::SealedResponse::decode(&r.payload) else { return err(StatusCode::INTERNAL_SERVER_ERROR, "decode", vec![]) };
    if let Err(e) = d.persist(sr.sealed) {
        return err(StatusCode::INTERNAL_SERVER_ERROR, format!("persist: {e}"), vec![]);
    }
    Json(serde_json::json!({"frozen": true})).into_response()
}

#[derive(Deserialize)]
struct SignJson {
    /// base64 (BTCPay's native form) or hex
    psbt: String,
    witness_hex: Option<String>,
}

#[derive(Serialize)]
struct SignOut {
    psbt: String,
    receipt_hex: String,
    receipt_sig_hex: String,
    session_id: String,
    seq: u64,
    txid: String,
}

fn psbt_bytes(s: &str) -> Result<Vec<u8>> {
    if let Ok(b) = hex::decode(s) {
        if bitcoin::Psbt::deserialize(&b).is_ok() {
            return Ok(b);
        }
    }
    use base64::Engine;
    let b = base64::engine::general_purpose::STANDARD.decode(s)?;
    bitcoin::Psbt::deserialize(&b).map_err(|e| anyhow!("psbt: {e}"))?;
    Ok(b)
}

async fn h_sign(AxState(s): AxState<Shared>, headers: HeaderMap, Json(req): Json<SignJson>) -> axum::response::Response {
    let mut d = s.lock().await;
    if !authorized(&headers, &d.token) {
        return err(StatusCode::UNAUTHORIZED, "token", vec![]);
    }
    let Ok(sealed) = d.sealed() else { return err(StatusCode::CONFLICT, "not initialised", vec![]) };
    let Ok(psbt) = psbt_bytes(&req.psbt) else { return err(StatusCode::BAD_REQUEST, "psbt: not base64/hex or not a PSBT", vec![]) };
    let witness = match &req.witness_hex {
        Some(h) => match hex::decode(h) {
            Ok(b) => Some(b),
            Err(_) => return err(StatusCode::BAD_REQUEST, "witness hex", vec![]),
        },
        None => d.last_witness.clone(),
    };
    // phase 1: judge
    let r = match d.call(op::JUDGE, &proto::SealedWith { sealed, data: psbt.clone(), extra: witness }.encode()) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string(), vec![]),
    };
    if !r.ok {
        if !r.payload.is_empty() {
            // the refusal changed the state (disarm): persist it
            if let Ok(sr) = proto::SealedResponse::decode(&r.payload) {
                if let Err(e) = d.persist(sr.sealed) {
                    error!("persist after disarm: {e}");
                }
            }
        }
        return err(StatusCode::UNPROCESSABLE_ENTITY, "refused", r.reasons);
    }
    let Ok(jr) = proto::JudgeResponse::decode(&r.payload) else { return err(StatusCode::INTERNAL_SERVER_ERROR, "judge decode", vec![]) };
    // persist the CHARGED blob before asking for a signature (two-phase)
    if let Err(e) = d.persist(jr.sealed.clone()) {
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("persist charged state: {e} — budget may be charged, no signature issued"),
            vec![],
        );
    }
    // phase 2: sign
    let r = match d.call(op::SIGN, &proto::SealedWith { sealed: jr.sealed, data: psbt, extra: None }.encode()) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string(), vec![]),
    };
    if !r.ok {
        return err(StatusCode::UNPROCESSABLE_ENTITY, "sign refused after a successful judge (persisted charge stands)", r.reasons);
    }
    let Ok(sr) = proto::SignResponse::decode(&r.payload) else { return err(StatusCode::INTERNAL_SERVER_ERROR, "sign decode", vec![]) };
    let (seq, txid) = signer_core::receipt::Receipt::decode(&sr.receipt)
        .map(|r| (r.seq, display_hash(r.txid)))
        .unwrap_or((0, String::new()));
    let line = ReceiptLine {
        ts: now(),
        session_id: hex::encode(sr.session_id),
        seq,
        txid: txid.clone(),
        receipt_hex: hex::encode(&sr.receipt),
        sig_hex: hex::encode(sr.receipt_sig),
    };
    if let Err(e) = d.append_receipt(&line) {
        warn!("receipt log: {e}");
    }
    use base64::Engine;
    Json(SignOut {
        psbt: base64::engine::general_purpose::STANDARD.encode(&sr.psbt),
        receipt_hex: line.receipt_hex,
        receipt_sig_hex: line.sig_hex,
        session_id: line.session_id,
        seq,
        txid,
    })
    .into_response()
}

#[derive(Deserialize)]
struct HeadersJson {
    headers_hex: Vec<String>,
}

async fn h_headers(AxState(s): AxState<Shared>, headers: HeaderMap, Json(req): Json<HeadersJson>) -> axum::response::Response {
    let mut d = s.lock().await;
    if !authorized(&headers, &d.token) {
        return err(StatusCode::UNAUTHORIZED, "token", vec![]);
    }
    let Ok(sealed) = d.sealed() else { return err(StatusCode::CONFLICT, "not initialised", vec![]) };
    let mut bytes = Vec::new();
    for h in &req.headers_hex {
        match hex::decode(h) {
            Ok(b) if b.len() == 80 => bytes.extend_from_slice(&b),
            _ => return err(StatusCode::BAD_REQUEST, "each header is 80 bytes hex", vec![]),
        }
    }
    let r = match d.call(op::HEADERS, &proto::SealedWith { sealed, data: bytes, extra: None }.encode()) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string(), vec![]),
    };
    let payload = proto::HeadersResponse::decode(&r.payload).ok();
    if let Some(hr) = &payload {
        if let Err(e) = d.persist(hr.sealed.clone()) {
            return err(StatusCode::INTERNAL_SERVER_ERROR, format!("persist: {e}"), vec![]);
        }
    }
    if !r.ok {
        return err(StatusCode::UNPROCESSABLE_ENTITY, "headers refused", r.reasons);
    }
    match payload {
        Some(hr) => Json(serde_json::json!({"accepted": hr.accepted, "best_height": hr.best_height})).into_response(),
        None => err(StatusCode::INTERNAL_SERVER_ERROR, "decode", vec![]),
    }
}

async fn h_receipts(AxState(s): AxState<Shared>, headers: HeaderMap) -> axum::response::Response {
    let d = s.lock().await;
    if !authorized(&headers, &d.token) {
        return err(StatusCode::UNAUTHORIZED, "token", vec![]);
    }
    let text = std::fs::read_to_string(d.receipts_path()).unwrap_or_default();
    let lines: Vec<serde_json::Value> = text.lines().filter_map(|l| serde_json::from_str(l).ok()).collect();
    Json(lines).into_response()
}

async fn h_health() -> &'static str {
    "ok"
}

// ---------------------------------------------------------------- main

// One runtime thread: every ecall comes from the same OS thread, the mutex serializes them, and
// the enclave's single unbound TCS is never contended.
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();
    let args = Args::parse();
    let mut enclave = load_enclave(&args)?;

    match args.cmd.clone() {
        Cmd::Replay { vectors } => {
            let report = replay::replay_vectors(enclave.as_mut(), &vectors)?;
            println!("{report}");
            return Ok(());
        }
        Cmd::Smoke => {
            replay::smoke(enclave.as_mut())?;
            println!("smoke: OK ({})", enclave.kind());
            return Ok(());
        }
        Cmd::Run { .. } => {}
    }
    let Cmd::Run { state_dir, listen, bitcoind_rpc, bitcoind_cookie, headers_interval } = args.cmd else { unreachable!() };
    std::fs::create_dir_all(&state_dir)?;

    let token_path = state_dir.join("token");
    let token = match std::fs::read_to_string(&token_path) {
        Ok(t) => t.trim().to_string(),
        Err(_) => {
            use rand::RngCore;
            let mut b = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut b);
            let t = hex::encode(b);
            use std::io::Write;
            let mut f = open_0600(&token_path, false)?;
            writeln!(f, "{t}")?;
            info!("bearer token written to {}", token_path.display());
            t
        }
    };
    let sealed = std::fs::read(state_dir.join("state.sealed")).ok();
    let bitcoind = match (&bitcoind_rpc, &bitcoind_cookie) {
        (Some(u), Some(c)) => Some(Bitcoind::new(u, c)?),
        _ => None,
    };
    info!(enclave = enclave.kind(), initialised = sealed.is_some(), feed = bitcoind.is_some(), "signerd starting");
    let daemon = Daemon { enclave, state_dir, sealed, token, last_witness: None, bitcoind };
    let shared: Shared = Arc::new(Mutex::new(daemon));

    if bitcoind_rpc.is_some() {
        let s2 = shared.clone();
        let every = Duration::from_secs(headers_interval.max(5));
        tokio::spawn(async move {
            loop {
                match feed_once(&s2).await {
                    Ok(n) if n > 0 => info!(n, "headers fed"),
                    Ok(_) => {}
                    Err(e) => warn!("header feed: {e}"),
                }
                tokio::time::sleep(every).await;
            }
        });
    }

    let app = Router::new()
        .route("/healthz", get(h_health))
        .route("/v1/status", get(h_status))
        .route("/v1/init", post(h_init))
        .route("/v1/install", post(h_install))
        .route("/v1/policy", get(h_policy))
        .route("/v1/message", post(h_message))
        .route("/v1/freeze", post(h_freeze))
        .route("/v1/sign", post(h_sign))
        .route("/v1/headers", post(h_headers))
        .route("/v1/receipts", get(h_receipts))
        .with_state(shared);
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    info!(listen = %listen, "serving");
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
