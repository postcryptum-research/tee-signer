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
mod tpm;
#[cfg(feature = "tss")]
mod tpm_tss;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use axum::extract::{Query, State as AxState};
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
    /// Path to `dcap-quote-helper` (T2 only): `GET /v1/quote` is 501 without it.
    #[arg(long, env = "SIGNERD_QUOTE_HELPER", global = true)]
    quote_helper: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug, Clone)]
enum Cmd {
    /// R8 (no tunnel): write the running daemon's status to a file the owner carries away.
    Status {
        #[arg(long, env = "SIGNERD_STATE_DIR")]
        state_dir: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:7390")]
        url: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// R8 (no tunnel): hand a signed owner message file (hex, written by `owner-cli … --out`) to the
    /// daemon; the enclave's answer goes to a file. A `PolicyUpdate` at nonce 0 is the install.
    Submit {
        #[arg(long, env = "SIGNERD_STATE_DIR")]
        state_dir: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:7390")]
        url: String,
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// R8 (no tunnel): initialise the enclave wallet with the owner's two PUBLIC keys; the response
    /// (identity card, recovery blob, xpub) goes to a file the owner carries to their machine.
    Init {
        #[arg(long, env = "SIGNERD_STATE_DIR")]
        state_dir: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:7390")]
        url: String,
        /// mainnet | testnet4 | signet | regtest
        #[arg(long)]
        network: String,
        /// The owner's PUBLIC key, hex — or a file holding it (`owner-cli pubkey … > owner.pub`, carried here).
        #[arg(long, conflicts_with = "owner_pk_file")]
        owner_pk: Option<String>,
        #[arg(long)]
        owner_pk_file: Option<PathBuf>,
        /// The recovery PUBLIC key, hex — or a file holding it.
        #[arg(long, conflicts_with = "recovery_pk_file")]
        recovery_pk: Option<String>,
        #[arg(long)]
        recovery_pk_file: Option<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
    /// R8 (no tunnel): write the installed mandate (and the pending one) to a file for `owner-cli policy-show --installed-file`.
    Policy {
        #[arg(long, env = "SIGNERD_STATE_DIR")]
        state_dir: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:7390")]
        url: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// R8 (no tunnel): freeze signing right here on the server (no signature needed); only the owner's
    /// signed `unfreeze` lifts it.
    Freeze {
        #[arg(long, env = "SIGNERD_STATE_DIR")]
        state_dir: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:7390")]
        url: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// R8 (no tunnel, T2): fetch a DCAP quote for the owner's nonce into a file for `owner-cli attest --replay`.
    Quote {
        #[arg(long, env = "SIGNERD_STATE_DIR")]
        state_dir: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:7390")]
        url: String,
        /// 32 bytes hex, chosen by the owner on their machine — or a file holding it, carried here.
        #[arg(long, conflicts_with = "nonce_file")]
        nonce: Option<String>,
        #[arg(long)]
        nonce_file: Option<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
    /// REQ-r9 (no tunnel): the TPM transport's key, index Name and counter, for the owner's anchoring.
    TpmInfo {
        #[arg(long, env = "SIGNERD_STATE_DIR")]
        state_dir: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:7390")]
        url: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// REQ-r9 (no tunnel): an attested counter read — `TPM2_NV_Certify` over the owner's nonce — for the
    /// owner's `anchor` (C-R9-D: the counter value comes from this proof, never from the status file).
    TpmCertify {
        #[arg(long, env = "SIGNERD_STATE_DIR")]
        state_dir: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:7390")]
        url: String,
        /// 32 bytes hex, chosen by the owner on their machine — or a file holding it, carried here.
        #[arg(long, conflicts_with = "nonce_file")]
        nonce: Option<String>,
        #[arg(long)]
        nonce_file: Option<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
    /// REQ-r9 (`--features tss`, run ON the TPM's machine, once): create the attestation key and the
    /// counter index at EXPLICIT handles. Refuses an occupied handle or index (C-R9-E: never
    /// evicts, never reuses another project's objects). `SIGNERD_TPM_AUTH` (optional) becomes the
    /// authValue of both — set it on a shared TPM.
    #[cfg(feature = "tss")]
    TpmSetup {
        /// TCTI, e.g. `device:/dev/tpmrm0` (the default).
        #[arg(long, default_value = tpm_tss::DEFAULT_TCTI)]
        tcti: String,
        /// Persistent handle for the attestation key, hex: `0x81......` — mandatory, must be free.
        #[arg(long, value_parser = parse_tpm_handle)]
        ak_handle: u32,
        /// NV index for the counter, hex: `0x01......` — mandatory, must be free.
        #[arg(long, value_parser = parse_tpm_handle)]
        nv_index: u32,
        /// Plain (non-hybrid) counter: every increment writes NV. Default is a hybrid
        /// (`TPMA_NV_ORDERLY`) index, the design's allocation default (RESP-r9 Q1); a virtual TPM has
        /// no flash to save and may prefer `--no-orderly` (no forward jump after a hard reset).
        #[arg(long)]
        no_orderly: bool,
        /// Where to write the key, the index Name and the counter (the same JSON as `tpm-info`).
        #[arg(long)]
        out: PathBuf,
    },
    /// REQ-r9 (`--features tss`): remove EXACTLY the two objects `tpm-setup` recorded in its `--out`
    /// file — the key's public point and the index Name must match what sits at the named handles,
    /// and both must match `tpm-setup`'s templates (someone else's key or index is refused). Any
    /// state anchored to them becomes STATE_STALE until the owner anchors again.
    #[cfg(feature = "tss")]
    TpmTeardown {
        #[arg(long, default_value = tpm_tss::DEFAULT_TCTI)]
        tcti: String,
        #[arg(long, value_parser = parse_tpm_handle)]
        ak_handle: u32,
        #[arg(long, value_parser = parse_tpm_handle)]
        nv_index: u32,
        /// The file `tpm-setup --out` wrote (or a later `tpm-info` of the same objects).
        #[arg(long)]
        setup_file: PathBuf,
    },
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
    quote_helper: Option<PathBuf>,
    /// REQ-r9: the TPM counter transport (`SIGNERD_TPM`), None = no counter in front of the enclave.
    tpm: Option<Box<dyn tpm::TpmTransport>>,
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
        // REQ-r9: every persisted blob expects the counter one higher — increment after the blob is
        // durable (seal → persist → increment). A failure here leaves blob = N+1, counter = N: the
        // next call is STATE_STALE until the owner anchors — a pause, never a loss.
        if let Some(t) = self.tpm.as_mut() {
            match t.increment() {
                Ok(c) => tracing::debug!(counter = c, "tpm counter incremented"),
                Err(e) => error!("tpm increment failed after persist: {e} — the enclave will refuse STATE_STALE until the owner anchors"),
            }
        }
        Ok(())
    }

    fn call(&mut self, op_code: u32, input: &[u8]) -> Result<Response> {
        self.enclave.call(op_code, input)
    }

    /// REQ-r9: a blob-reading call that changes state or signs. With a TPM transport configured the
    /// host first asks the enclave for a nonce, has the TPM certify the counter over it, deposits the
    /// proof, then makes the call; the enclave verifies the proof against the blob it is handed.
    /// Without a transport it is a plain call (an unanchored state needs no proof; an anchored one
    /// then refuses TPM_REQUIRED, which is the honest answer).
    fn call_fresh(&mut self, op_code: u32, input: &[u8]) -> Result<Response> {
        if let Some(t) = self.tpm.as_mut() {
            let r = self.enclave.call(op::TPM_NONCE, &[])?;
            if !r.ok {
                return Ok(r);
            }
            let nonce = <[u8; 32]>::try_from(r.payload.as_slice()).map_err(|_| anyhow!("tpm nonce length"))?;
            let proof = t.certify(&nonce)?;
            let r = self.enclave.call(op::TPM_PROOF, &proof.encode())?;
            if !r.ok {
                return Ok(r);
            }
        }
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
    /// The cookie file, re-read every feed round: bitcoind rotates it at each restart (the T2
    /// node's switch to pruning left the daemon with a stale cookie and a silently stalled feed).
    cookie: Option<PathBuf>,
    http: reqwest::Client,
}

fn auth_from_cookie(cookie: &Path) -> Result<String> {
    let c = std::fs::read_to_string(cookie).with_context(|| format!("reading cookie {}", cookie.display()))?;
    let (user, pass) = c.trim().split_once(':').ok_or_else(|| anyhow!("cookie format"))?;
    use base64::Engine;
    Ok(base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}")))
}

impl Bitcoind {
    fn new(url: &str, cookie: &Path) -> Result<Self> {
        let auth = auth_from_cookie(cookie)?;
        Ok(Bitcoind { url: url.to_string(), auth, cookie: Some(cookie.to_path_buf()), http: reqwest::Client::new() })
    }
    /// Pick up a rotated cookie; a missing or malformed file keeps the last value (and the RPC
    /// then fails loudly instead of the feed dying here).
    fn refresh_auth(&mut self) {
        if let Some(p) = &self.cookie {
            if let Ok(a) = auth_from_cookie(p) {
                self.auth = a;
            }
        }
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
        json_height(&v["headers"], "getblockchaininfo headers")
    }
    async fn header_hex(&self, height: u32) -> Result<String> {
        let h = self.rpc("getblockhash", serde_json::json!([height])).await?;
        let hash = h.as_str().ok_or_else(|| anyhow!("getblockhash"))?;
        let r = self.rpc("getblockheader", serde_json::json!([hash, false])).await?;
        Ok(r.as_str().ok_or_else(|| anyhow!("getblockheader"))?.to_string())
    }
}

/// One feed round: headers from the enclave's best + 1 to the node's tip, in batches; on a
/// fork at the enclave's best, the sibling chain is probed from the shallowest fork point. The
/// enclave decides; a feed that lies or lags can only stall it. Only the read-only RPC subset is
/// used (`getblockchaininfo`, `getblockhash`, `getblockheader`) — owner decision D5.
/// How far below the enclave's best the fork probe walks; the enclave keeps at most
/// maxReorg + 12 recent headers, so deeper probes cannot attach anyway.
const FORK_PROBE_DEPTH: u32 = 32;

/// A height from bitcoind's JSON that must fit the enclave's u32: missing or out of range is an error,
/// never 0 and never a truncated value (rule 9; #18).
fn json_height(v: &serde_json::Value, what: &str) -> Result<u32> {
    v.as_u64().and_then(|h| u32::try_from(h).ok()).ok_or_else(|| anyhow!("{what}: not a u32 height: {v}"))
}

/// A capacity hint for the `to − from + 1` serialized headers (80 bytes each) of one HEADERS call. A hint
/// only, and the callers bound the range; saturating keeps it a hint.
fn headers_capacity(from: u32, to: u32) -> usize {
    usize::try_from(to.saturating_sub(from).saturating_add(1)).unwrap_or(0).saturating_mul(80)
}

async fn feed_once(shared: &Shared) -> Result<u32> {
    let (best_height, best_hash, url, auth) = {
        let mut d = shared.lock().await;
        let Some(b) = d.bitcoind.as_mut() else { return Ok(0) };
        b.refresh_auth();
        let (url, auth) = (b.url.clone(), b.auth.clone());
        let st = d.status()?;
        if !st.installed {
            return Ok(0); // keys only: nothing to feed until a mandate pins the checkpoint
        }
        (st.best_height, st.best_hash, url, auth)
    };
    let bd = Bitcoind { url, auth, cookie: None, http: reqwest::Client::new() };
    let tip = bd.tip_height().await?;
    if tip <= best_height {
        return Ok(0);
    }
    let node_best = bd.rpc("getblockhash", serde_json::json!([best_height])).await?;
    let same = node_best.as_str().map(|h| h == display_hash(best_hash)).unwrap_or(false);
    let mut total = 0u32;
    let mut from = if same {
        best_height.saturating_add(1)
    } else {
        // The node disagrees at the enclave's best: a fork. The enclave knows only the headers
        // from its checkpoint to its best, and the host does not know which; so probe from the
        // shallowest fork point down — the node's headers [best−k ..= best+1] for k = 0, 1, … —
        // until the enclave accepts. Each refused probe changes nothing; a fork deeper than the
        // mandate's maxReorg makes the enclave freeze itself, which is kept, not retried.
        let probe_top = best_height.saturating_add(1);
        let mut resume = None;
        for k in 0..=FORK_PROBE_DEPTH {
            let start = best_height.saturating_sub(k).max(1);
            let mut bytes = Vec::with_capacity(headers_capacity(start, probe_top));
            for h in start..=probe_top {
                bytes.extend_from_slice(&hex::decode(bd.header_hex(h).await?)?);
            }
            let mut d = shared.lock().await;
            let sealed = d.sealed()?;
            let r = d.call_fresh(op::HEADERS, &proto::SealedWith { sealed, data: bytes, extra: None }.encode())?;
            let hr = proto::HeadersResponse::decode(&r.payload).ok();
            if let Some(hr) = &hr {
                d.persist(hr.sealed.clone())?; // accepted fork, or a chain freeze: both are state
            }
            if r.ok {
                let accepted = hr.map(|h| h.accepted).unwrap_or(0);
                total = total.saturating_add(accepted);
                warn!(
                    fork_depth = k.saturating_add(1),
                    accepted, "header feed: the node forked from the enclave's best; fork accepted"
                );
                resume = Some(probe_top.saturating_add(1));
                break;
            }
            if r.reasons.iter().any(|x| x == "HEADER_INVALID") && start > 1 {
                continue; // the probe attached below what the enclave knows, or not at all: deeper
            }
            return Err(anyhow!("headers refused at fork probe depth {}: {:?}", k.saturating_add(1), r.reasons));
        }
        match resume {
            Some(f) => f,
            None => {
                return Err(anyhow!(
                    "fork below the enclave's known headers (checkpoint..best): the owner must re-pin the checkpoint"
                ))
            }
        }
    };
    while from <= tip {
        let to = from.saturating_add(1999).min(tip);
        let mut bytes = Vec::with_capacity(headers_capacity(from, to));
        for h in from..=to {
            bytes.extend_from_slice(&hex::decode(bd.header_hex(h).await?)?);
        }
        let mut d = shared.lock().await;
        let sealed = d.sealed()?;
        let r = d.call_fresh(op::HEADERS, &proto::SealedWith { sealed, data: bytes, extra: None }.encode())?;
        if r.ok {
            let hr = proto::HeadersResponse::decode(&r.payload).map_err(|_| anyhow!("headers response"))?;
            d.persist(hr.sealed)?;
            total = total.saturating_add(hr.accepted);
            info!(accepted = hr.accepted, best = hr.best_height, "headers");
        } else {
            if let Ok(hr) = proto::HeadersResponse::decode(&r.payload) {
                d.persist(hr.sealed)?; // a chain freeze is a state change the host must keep
            }
            return Err(anyhow!("headers refused: {:?}", r.reasons));
        }
        from = match to.checked_add(1) {
            Some(f) => f,
            None => break, // no chain has a height above u32::MAX
        };
    }
    Ok(total)
}

// ---------------------------------------------------------------- HTTP API

#[derive(Serialize)]
struct ErrorBody {
    error: String,
    reasons: Vec<String>,
    /// REQ-r9a C6: the sanctioned next step for the first reason that has one (host-side text).
    #[serde(skip_serializing_if = "Option::is_none")]
    hint: Option<&'static str>,
}

fn err(status: StatusCode, msg: impl Into<String>, reasons: Vec<String>) -> axum::response::Response {
    let hint = reasons.iter().find_map(|r| signer_core::reason::hint_for_code(r));
    (status, Json(ErrorBody { error: msg.into(), reasons, hint })).into_response()
}

/// R8: one server-side owner step — file in, file out. The daemon's token is read from its state
/// directory (this runs on the server, as the same user); the answer is written verbatim as JSON
/// with the HTTP status, so a refusal travels to the owner's machine exactly as the enclave said it.
enum OwnerStep {
    Status,
    Submit(PathBuf),
    Init { network: String, owner_pk: String, recovery_pk: String },
    Quote(String),
    Freeze,
    Policy,
    TpmInfo,
    TpmCertify(String),
}

/// A value given directly, or read (trimmed) from a carried file.
/// `0x81000200` → a TPM handle (hex with `0x` only — a handle is never a decimal).
#[cfg(feature = "tss")]
fn parse_tpm_handle(s: &str) -> Result<u32, String> {
    tpm_tss::parse_handle(s, "handle").map_err(|e| e.to_string())
}

fn value_or_file(value: &Option<String>, file: &Option<PathBuf>, what: &str) -> Result<String> {
    match (value, file) {
        (Some(v), _) => Ok(v.trim().to_string()),
        (None, Some(f)) => {
            Ok(std::fs::read_to_string(f).with_context(|| format!("reading {}", f.display()))?.trim().to_string())
        }
        (None, None) => anyhow::bail!("{what}"),
    }
}

async fn owner_step(state_dir: &Path, url: &str, out: &Path, step: OwnerStep) -> Result<()> {
    let token = std::fs::read_to_string(state_dir.join("token"))
        .with_context(|| format!("reading {}/token (is the daemon initialised here?)", state_dir.display()))?;
    let token = token.trim().to_string();
    let http = reqwest::Client::new();
    let base = url.trim_end_matches('/');
    let resp = match step {
        OwnerStep::Status => http.get(format!("{base}/v1/status")).bearer_auth(&token).send().await?,
        OwnerStep::Freeze => http.post(format!("{base}/v1/freeze")).bearer_auth(&token).send().await?,
        OwnerStep::Policy => http.get(format!("{base}/v1/policy")).bearer_auth(&token).send().await?,
        OwnerStep::Quote(nonce) => {
            http.get(format!("{base}/v1/quote")).query(&[("nonce", nonce)]).bearer_auth(&token).send().await?
        }
        OwnerStep::TpmInfo => http.get(format!("{base}/v1/tpm/info")).bearer_auth(&token).send().await?,
        OwnerStep::TpmCertify(nonce) => {
            http.get(format!("{base}/v1/tpm/certify")).query(&[("nonce", nonce)]).bearer_auth(&token).send().await?
        }
        OwnerStep::Init { network, owner_pk, recovery_pk } => {
            let net: u8 = match network.as_str() {
                "mainnet" => 0,
                "testnet4" => 1,
                "signet" => 2,
                "regtest" => 3,
                other => anyhow::bail!("network {other:?}: mainnet | testnet4 | signet | regtest"),
            };
            http.post(format!("{base}/v1/init"))
                .bearer_auth(&token)
                .json(&serde_json::json!({"network": net, "owner_pk_hex": owner_pk, "recovery_pk_hex": recovery_pk}))
                .send()
                .await?
        }
        OwnerStep::Submit(file) => {
            let hex_text = std::fs::read_to_string(&file).with_context(|| format!("reading {}", file.display()))?;
            let bytes = hex::decode(hex_text.trim()).context("the message file is not hex")?;
            let msg = signer_core::update::Message::decode(&bytes)
                .map_err(|_| anyhow::anyhow!("the file does not decode as an owner message"))?;
            match &msg {
                signer_core::update::Message::PolicyUpdate { nonce: 0, mandate, sig, .. } => {
                    http.post(format!("{base}/v1/install"))
                        .bearer_auth(&token)
                        .json(&serde_json::json!({"mandate_hex": hex::encode(mandate), "sig_hex": hex::encode(sig)}))
                        .send()
                        .await?
                }
                _ => {
                    http.post(format!("{base}/v1/message"))
                        .bearer_auth(&token)
                        .json(&serde_json::json!({"message_hex": hex_text.trim()}))
                        .send()
                        .await?
                }
            }
        }
    };
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
    let record = serde_json::json!({"http_status": status.as_u16(), "ok": status.is_success(), "response": body});
    std::fs::write(out, serde_json::to_string_pretty(&record)?)?;
    println!("{} -> {}", if status.is_success() { "ok" } else { "REFUSED" }, out.display());
    if !status.is_success() {
        // REQ-r9a C6: the operator reads the next step next to the code, not only in the docs
        if let Some(reasons) = body.get("reasons").and_then(|v| v.as_array()) {
            for code in reasons.iter().filter_map(|r| r.as_str()) {
                if let Some(h) = signer_core::reason::hint_for_code(code) {
                    println!("  {code}: {h}");
                }
            }
        }
        std::process::exit(1);
    }
    Ok(())
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
    boot_armed: bool,
    boot_challenge: String,
    auto_arm: bool,
    /// REQ-r9: the state pins a TPM counter.
    tpm_bound: bool,
    /// REQ-r9: the counter value the blob expects — read without a proof, possibly stale (§2.6).
    tpm_expected: u64,
    /// REQ-r9: the last proof verified in this enclave load was fresh.
    tpm_last_fresh: bool,
    /// REQ-r9: the host's transport (`SIGNERD_TPM`), if any.
    tpm_transport: Option<String>,
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
            boot_armed: st.boot_armed,
            boot_challenge: hex::encode(st.boot_challenge),
            auto_arm: st.auto_arm,
            tpm_bound: st.tpm_bound,
            tpm_expected: st.tpm_expected,
            tpm_last_fresh: st.tpm_last_fresh,
            tpm_transport: d.tpm.as_ref().map(|t| t.describe()),
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

async fn h_init(
    AxState(s): AxState<Shared>,
    headers: HeaderMap,
    Json(req): Json<InitJson>,
) -> axum::response::Response {
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
    let Ok(ir) = proto::InitResponse::decode(&r.payload) else {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "init decode", vec![]);
    };
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

async fn h_install(
    AxState(s): AxState<Shared>,
    headers: HeaderMap,
    Json(req): Json<InstallJson>,
) -> axum::response::Response {
    let mut d = s.lock().await;
    if !authorized(&headers, &d.token) {
        return err(StatusCode::UNAUTHORIZED, "token", vec![]);
    }
    let Ok(sealed) = d.sealed() else { return err(StatusCode::CONFLICT, "not initialised", vec![]) };
    let (mandate, sig) = match (hex::decode(&req.mandate_hex), hex::decode(&req.sig_hex)) {
        (Ok(m), Ok(s)) => (m, s),
        _ => return err(StatusCode::BAD_REQUEST, "hex", vec![]),
    };
    let r = match d.call_fresh(op::INSTALL, &proto::SealedWith { sealed, data: mandate, extra: Some(sig) }.encode()) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string(), vec![]),
    };
    if !r.ok {
        return err(StatusCode::UNPROCESSABLE_ENTITY, "install refused", r.reasons);
    }
    let Ok(sr) = proto::SealedResponse::decode(&r.payload) else {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "decode", vec![]);
    };
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

async fn h_message(
    AxState(s): AxState<Shared>,
    headers: HeaderMap,
    Json(req): Json<MessageJson>,
) -> axum::response::Response {
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
    let r = match d.call_fresh(op::APPLY_MESSAGE, &proto::SealedWith { sealed, data: msg, extra: None }.encode()) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string(), vec![]),
    };
    if !r.ok {
        return err(StatusCode::UNPROCESSABLE_ENTITY, "message refused", r.reasons);
    }
    let Ok(sr) = proto::SealedResponse::decode(&r.payload) else {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "decode", vec![]);
    };
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
    let r = match d.call_fresh(op::FREEZE, &sealed) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string(), vec![]),
    };
    if !r.ok {
        // REQ-r9: a freeze is a state change too — a stale or unproven blob is refused by name
        return err(StatusCode::UNPROCESSABLE_ENTITY, "freeze refused", r.reasons);
    }
    let Ok(sr) = proto::SealedResponse::decode(&r.payload) else {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "decode", vec![]);
    };
    if let Err(e) = d.persist(sr.sealed) {
        return err(StatusCode::INTERNAL_SERVER_ERROR, format!("persist: {e}"), vec![]);
    }
    Json(serde_json::json!({"frozen": true})).into_response()
}

#[derive(Deserialize)]
struct QuoteQuery {
    /// 32 bytes hex, generated by the verifier (REQ-r5 §3/§4: anti-replay).
    nonce: String,
}

#[derive(Serialize)]
struct QuoteJson {
    /// `IdentityCard::encode()` as the enclave recomputed it for this report.
    card_hex: String,
    nonce: String,
    /// `sgx_report_t` the enclave produced for the quoting enclave (for the record; the quote is what verifies).
    report_hex: String,
    /// The DCAP ECDSA quote.
    quote_hex: String,
    quoted_via: &'static str,
    tier: String,
    mrenclave: String,
}

/// `GET /v1/quote?nonce=<hex32>` (T2): one helper process does the whole DCAP flow around one
/// `REPORT` ecall — target_info out, report in, quote out — because the quoting library cannot
/// share a process with the loaded enclave and loses its attestation key between processes.
/// Untrusted plumbing: the verifier (owner-cli attest) decides, and only from the quote.
async fn h_quote(
    AxState(s): AxState<Shared>,
    headers: HeaderMap,
    Query(q): Query<QuoteQuery>,
) -> axum::response::Response {
    use signer_core::proto::quote;
    use std::io::{Read, Write};
    let mut d = s.lock().await;
    if !authorized(&headers, &d.token) {
        return err(StatusCode::UNAUTHORIZED, "token", vec![]);
    }
    let Some(helper) = d.quote_helper.clone() else {
        return err(StatusCode::NOT_IMPLEMENTED, "no quote helper configured (T1 cannot attest)", vec![]);
    };
    let nonce = match hex::decode(&q.nonce) {
        Ok(n) if n.len() == quote::NONCE_LEN => n,
        _ => return err(StatusCode::BAD_REQUEST, "nonce: 32 bytes hex", vec![]),
    };
    let Ok(sealed) = d.sealed() else { return err(StatusCode::CONFLICT, "not initialised", vec![]) };
    let mut child = match std::process::Command::new(&helper)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, format!("quote helper: {e}"), vec![]),
    };
    let mut stdout = child.stdout.take().expect("piped");
    let mut stdin = child.stdin.take().expect("piped");
    let mut target = [0u8; quote::TARGET_INFO_LEN];
    if let Err(e) = stdout.read_exact(&mut target) {
        let _ = child.kill();
        return err(StatusCode::INTERNAL_SERVER_ERROR, format!("quote helper target_info: {e}"), vec![]);
    }
    let mut data = target.to_vec();
    data.extend_from_slice(&nonce);
    let r = match d.call(op::REPORT, &proto::SealedWith { sealed, data, extra: None }.encode()) {
        Ok(r) => r,
        Err(e) => {
            let _ = child.kill();
            return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string(), vec![]);
        }
    };
    if !r.ok {
        let _ = child.kill();
        return err(StatusCode::UNPROCESSABLE_ENTITY, "report refused", r.reasons);
    }
    let Ok(rr) = proto::ReportResponse::decode(&r.payload) else {
        let _ = child.kill();
        return err(StatusCode::INTERNAL_SERVER_ERROR, "report decode", vec![]);
    };
    if let Err(e) = stdin.write_all(&rr.report).and_then(|_| stdin.flush()) {
        let _ = child.kill();
        return err(StatusCode::INTERNAL_SERVER_ERROR, format!("quote helper report: {e}"), vec![]);
    }
    drop(stdin);
    let mut len = [0u8; 4];
    if let Err(e) = stdout.read_exact(&mut len) {
        let _ = child.kill();
        let mut es = String::new();
        if let Some(mut se) = child.stderr.take() {
            let _ = se.read_to_string(&mut es);
        }
        return err(StatusCode::BAD_GATEWAY, format!("quote helper quote: {e}; helper said: {}", es.trim()), vec![]);
    }
    let n = u32::from_le_bytes(len) as usize;
    if n == 0 || n > 1 << 20 {
        let _ = child.kill();
        return err(StatusCode::BAD_GATEWAY, format!("quote helper: bad quote size {n}"), vec![]);
    }
    let mut quote_bytes = vec![0u8; n];
    if let Err(e) = stdout.read_exact(&mut quote_bytes) {
        let _ = child.kill();
        return err(StatusCode::BAD_GATEWAY, format!("quote helper quote body: {e}"), vec![]);
    }
    let _ = child.wait();
    Json(QuoteJson {
        card_hex: hex::encode(rr.card.encode()),
        nonce: q.nonce,
        report_hex: hex::encode(rr.report),
        quote_hex: hex::encode(quote_bytes),
        quoted_via: "dcap-quote-helper (libsgx_dcap_ql) through the node's aesmd",
        tier: rr.card.tier,
        mrenclave: hex::encode(rr.card.mrenclave),
    })
    .into_response()
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

async fn h_sign(
    AxState(s): AxState<Shared>,
    headers: HeaderMap,
    Json(req): Json<SignJson>,
) -> axum::response::Response {
    let mut d = s.lock().await;
    if !authorized(&headers, &d.token) {
        return err(StatusCode::UNAUTHORIZED, "token", vec![]);
    }
    let Ok(sealed) = d.sealed() else { return err(StatusCode::CONFLICT, "not initialised", vec![]) };
    let Ok(psbt) = psbt_bytes(&req.psbt) else {
        return err(StatusCode::BAD_REQUEST, "psbt: not base64/hex or not a PSBT", vec![]);
    };
    let witness = match &req.witness_hex {
        Some(h) => match hex::decode(h) {
            Ok(b) => Some(b),
            Err(_) => return err(StatusCode::BAD_REQUEST, "witness hex", vec![]),
        },
        None => d.last_witness.clone(),
    };
    // phase 1: judge
    let r = match d.call_fresh(op::JUDGE, &proto::SealedWith { sealed, data: psbt.clone(), extra: witness }.encode()) {
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
    let Ok(jr) = proto::JudgeResponse::decode(&r.payload) else {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "judge decode", vec![]);
    };
    // persist the CHARGED blob before asking for a signature (two-phase)
    if let Err(e) = d.persist(jr.sealed.clone()) {
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("persist charged state: {e} — budget may be charged, no signature issued"),
            vec![],
        );
    }
    // phase 2: sign
    let r = match d.call_fresh(op::SIGN, &proto::SealedWith { sealed: jr.sealed, data: psbt, extra: None }.encode()) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string(), vec![]),
    };
    if !r.ok {
        return err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "sign refused after a successful judge (persisted charge stands)",
            r.reasons,
        );
    }
    let Ok(sr) = proto::SignResponse::decode(&r.payload) else {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "sign decode", vec![]);
    };
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

async fn h_headers(
    AxState(s): AxState<Shared>,
    headers: HeaderMap,
    Json(req): Json<HeadersJson>,
) -> axum::response::Response {
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
    let r = match d.call_fresh(op::HEADERS, &proto::SealedWith { sealed, data: bytes, extra: None }.encode()) {
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

/// `GET /v1/tpm/info`: the transport's view (unauthenticated read of the TPM; the owner anchors from `certify`).
async fn h_tpm_info(AxState(s): AxState<Shared>, headers: HeaderMap) -> axum::response::Response {
    let mut d = s.lock().await;
    if !authorized(&headers, &d.token) {
        return err(StatusCode::UNAUTHORIZED, "token", vec![]);
    }
    let Some(t) = d.tpm.as_mut() else {
        return err(StatusCode::NOT_IMPLEMENTED, "no TPM transport (SIGNERD_TPM unset)", vec![]);
    };
    match t.info() {
        Ok(i) => Json(i).into_response(),
        Err(e) => err(StatusCode::BAD_GATEWAY, format!("tpm: {e}"), vec![]),
    }
}

#[derive(Deserialize)]
struct TpmCertifyQuery {
    /// 32 bytes hex chosen by the owner (their anti-replay for the anchoring read).
    nonce: String,
}

/// `GET /v1/tpm/certify?nonce=<hex32>`: `TPM2_NV_Certify` over the owner's nonce, as a file-able JSON.
async fn h_tpm_certify(
    AxState(s): AxState<Shared>,
    headers: HeaderMap,
    Query(q): Query<TpmCertifyQuery>,
) -> axum::response::Response {
    let mut d = s.lock().await;
    if !authorized(&headers, &d.token) {
        return err(StatusCode::UNAUTHORIZED, "token", vec![]);
    }
    let Ok(nonce) = fixed::<32>(&q.nonce) else { return err(StatusCode::BAD_REQUEST, "nonce: 32 bytes hex", vec![]) };
    let Some(t) = d.tpm.as_mut() else {
        return err(StatusCode::NOT_IMPLEMENTED, "no TPM transport (SIGNERD_TPM unset)", vec![]);
    };
    match t.certify(&nonce) {
        Ok(p) => Json(serde_json::json!({
            "nonce": q.nonce,
            "attest_hex": hex::encode(&p.attest),
            "sig_hex": hex::encode(p.sig),
            "transport": t.describe(),
        }))
        .into_response(),
        Err(e) => err(StatusCode::BAD_GATEWAY, format!("tpm: {e}"), vec![]),
    }
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
    // R8: the file commands talk to the running daemon on this machine; no enclave is loaded here
    match &args.cmd {
        Cmd::Status { state_dir, url, out } => return owner_step(state_dir, url, out, OwnerStep::Status).await,
        Cmd::Submit { state_dir, url, file, out } => {
            return owner_step(state_dir, url, out, OwnerStep::Submit(file.clone())).await
        }
        Cmd::Init { state_dir, url, network, owner_pk, owner_pk_file, recovery_pk, recovery_pk_file, out } => {
            let owner_pk = value_or_file(owner_pk, owner_pk_file, "--owner-pk or --owner-pk-file")?;
            let recovery_pk = value_or_file(recovery_pk, recovery_pk_file, "--recovery-pk or --recovery-pk-file")?;
            return owner_step(
                state_dir,
                url,
                out,
                OwnerStep::Init { network: network.clone(), owner_pk, recovery_pk },
            )
            .await;
        }
        Cmd::Quote { state_dir, url, nonce, nonce_file, out } => {
            let nonce = value_or_file(nonce, nonce_file, "--nonce or --nonce-file")?;
            return owner_step(state_dir, url, out, OwnerStep::Quote(nonce)).await;
        }
        Cmd::Freeze { state_dir, url, out } => return owner_step(state_dir, url, out, OwnerStep::Freeze).await,
        Cmd::TpmInfo { state_dir, url, out } => return owner_step(state_dir, url, out, OwnerStep::TpmInfo).await,
        Cmd::TpmCertify { state_dir, url, nonce, nonce_file, out } => {
            let nonce = value_or_file(nonce, nonce_file, "--nonce or --nonce-file")?;
            return owner_step(state_dir, url, out, OwnerStep::TpmCertify(nonce)).await;
        }
        Cmd::Policy { state_dir, url, out } => return owner_step(state_dir, url, out, OwnerStep::Policy).await,
        #[cfg(feature = "tss")]
        Cmd::TpmSetup { tcti, ak_handle, nv_index, no_orderly, out } => {
            let spec = tpm_tss::TssSpec { tcti: tcti.clone(), ak: *ak_handle, nv: *nv_index };
            let info = tpm_tss::setup(&spec, !*no_orderly)?;
            std::fs::write(out, serde_json::to_string_pretty(&info)?)?;
            eprintln!(
                "created: attestation key 0x{ak_handle:08x}, counter 0x{nv_index:08x} ({}); run the daemon with SIGNERD_TPM={}",
                if *no_orderly { "plain" } else { "hybrid/orderly" },
                spec.describe()
            );
            return Ok(());
        }
        #[cfg(feature = "tss")]
        Cmd::TpmTeardown { tcti, ak_handle, nv_index, setup_file } => {
            let spec = tpm_tss::TssSpec { tcti: tcti.clone(), ak: *ak_handle, nv: *nv_index };
            for line in tpm_tss::teardown(&spec, setup_file)? {
                println!("{line}");
            }
            return Ok(());
        }
        _ => {}
    }
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
        _ => unreachable!("the file commands returned above"),
    }
    let Cmd::Run { state_dir, listen, bitcoind_rpc, bitcoind_cookie, headers_interval } = args.cmd else {
        unreachable!()
    };
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
    let tpm_transport = tpm::from_env()?;
    if let Some(t) = tpm_transport.as_ref() {
        info!(transport = t.describe(), "tpm counter transport configured (REQ-r9)");
    }
    let daemon = Daemon {
        enclave,
        state_dir,
        sealed,
        token,
        last_witness: None,
        bitcoind,
        quote_helper: args.quote_helper.clone(),
        tpm: tpm_transport,
    };
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
        .route("/v1/quote", get(h_quote))
        .route("/v1/tpm/info", get(h_tpm_info))
        .route("/v1/tpm/certify", get(h_tpm_certify))
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

#[cfg(test)]
mod rule9_tests {
    //! The SafeMath helpers (rule 9; #18): a height that does not fit is refused by name, never truncated.
    use super::*;

    #[test]
    fn json_height_refuses_what_does_not_fit() {
        assert_eq!(json_height(&serde_json::json!(850_000), "h").unwrap(), 850_000);
        assert_eq!(json_height(&serde_json::json!(u32::MAX), "h").unwrap(), u32::MAX);
        assert!(json_height(&serde_json::json!(u64::from(u32::MAX) + 1), "h").is_err());
        assert!(json_height(&serde_json::json!(u64::MAX), "h").is_err());
        assert!(json_height(&serde_json::json!(-1), "h").is_err());
        assert!(json_height(&serde_json::json!("850000"), "h").is_err());
        assert!(json_height(&serde_json::Value::Null, "h").is_err());
    }

    #[test]
    fn headers_capacity_is_a_bounded_hint() {
        assert_eq!(headers_capacity(5, 5), 80);
        assert_eq!(headers_capacity(1, 2000), 2000 * 80);
        assert_eq!(headers_capacity(10, 5), 80);
        let _ = headers_capacity(0, u32::MAX);
    }
}
