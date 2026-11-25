//! The owner's monitor (REQ-r4 / RESP-r4): chain observation first, receipts second, FREEZE as the
//! reflex. Runs on the operator machine with its OWN chain source; `signerd` is untrusted input and
//! a receipt is believed only after its identity signature verifies. Not TCB — which is why its
//! alarm is believable: nothing on the signer host decides what the monitor sees.
//!
//! One pass = one verdict (OK / WARN / ALARM). The only state kept across runs is the verified
//! receipt high-water mark `(session_id, seq)`, written BEFORE the pass's verdict so a restarted
//! monitor cannot forget a seq it has seen (C-R4-5: the journal line per pass is the heartbeat).
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use signer_core::update::Message;

use crate::{hash_of, open_locator, sign_message, submit_message, MandateJson, Signerd, WalletRecord};

#[derive(Clone, Debug)]
pub struct Cfg {
    pub wallet: PathBuf,
    pub mandate: PathBuf,
    pub esplora: String,
    pub interval: u64,
    pub journal: PathBuf,
    pub once: bool,
    pub freeze: bool,
    pub witness_key: Option<String>,
    pub stall_after: u32,
    pub max_tip_lag: Option<u32>,
    pub max_addresses: u32,
    /// Pause between Esplora requests (a public Esplora rate-limits; the owner's own node does not).
    pub esplora_delay_ms: u64,
    /// A full scan of the reachable range every N passes (1 = always); other passes are incremental.
    pub full_every: u64,
    /// The owner's own node (C-R4-3): read-only RPC + cookie. When set, it is the chain source and
    /// `esplora` is ignored.
    pub node_rpc: Option<String>,
    pub node_cookie: Option<PathBuf>,
    /// Spends the owner has looked at and accepted as known losses/known events: they stop
    /// re-alarming (persisted beside the journal). An acknowledgement is a human decision, logged.
    pub acknowledge: Vec<String>,
}

/// The persisted high-water mark (C-R4-5 / D-R4-6): written before the verdict.
#[derive(Serialize, Deserialize, Default, Clone, Debug)]
struct Hwm {
    session_id: String,
    seq: u64,
    passes: u64,
    stall_passes: u32,
    /// Verified receipt txids seen so far (display order), so a receipt line that vanishes from
    /// the host's log is itself visible as a regression.
    #[serde(default)]
    txids: Vec<String>,
}

#[derive(Serialize)]
struct PassLine<'a> {
    ts: u64,
    pass: u64,
    verdict: &'static str,
    codes: Vec<String>,
    tip_height: u32,
    enclave_best: u32,
    hwm_session: &'a str,
    hwm_seq: u64,
    receipts_verified: usize,
    spends_onchain: usize,
    outflow_window_sat: u64,
    scanned_addresses: u32,
    froze: bool,
    notes: Vec<String>,
}

#[derive(Clone, Debug)]
struct Verified {
    session_id: String,
    seq: u64,
    txid: String,
    net_outflow: u64,
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

struct Esplora {
    base: String,
    http: reqwest::blocking::Client,
    delay: std::time::Duration,
}

impl Esplora {
    fn new(base: &str, delay_ms: u64) -> Self {
        Esplora {
            base: base.trim_end_matches('/').to_string(),
            http: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
            delay: std::time::Duration::from_millis(delay_ms),
        }
    }
    /// One request, throttled; a 429 or a transport error backs off (2, 4, 8, 16, 32 s) before
    /// giving up — a public Esplora throttles bursts, and the monitor must outlive that.
    fn text(&self, path: &str) -> Result<String> {
        let mut backoff = 2u64;
        let mut last = String::new();
        for attempt in 0..6 {
            std::thread::sleep(self.delay);
            match self.http.get(format!("{}{path}", self.base)).send() {
                Ok(r) if r.status().as_u16() == 429 => last = "429".into(),
                Ok(r) => return Ok(r.error_for_status()?.text()?),
                Err(e) => last = e.to_string(),
            }
            if attempt < 5 {
                std::thread::sleep(std::time::Duration::from_secs(backoff));
                backoff = backoff.saturating_mul(2);
            }
        }
        Err(anyhow!("{} gave up after retries: {last}", self.base))
    }
    fn json(&self, path: &str) -> Result<serde_json::Value> {
        Ok(serde_json::from_str(&self.text(path)?)?)
    }
    fn tip(&self) -> Result<(u32, String)> {
        let h: u32 = self.text("/blocks/tip/height")?.trim().parse()?;
        let hash = self.text("/blocks/tip/hash")?.trim().to_string();
        Ok((h, hash))
    }
    /// Every transaction touching `addr`: one call returns the mempool ones plus the first 25
    /// confirmed; the chain part is paged by 25 until a short page — complete for the address.
    fn address_txs(&self, addr: &str) -> Result<Vec<serde_json::Value>> {
        let mut out: Vec<serde_json::Value> =
            self.json(&format!("/address/{addr}/txs"))?.as_array().cloned().unwrap_or_default();
        let mut confirmed_in_page = out.iter().filter(|t| t["status"]["confirmed"].as_bool() == Some(true)).count();
        let mut last = out
            .iter()
            .rev()
            .find(|t| t["status"]["confirmed"].as_bool() == Some(true))
            .and_then(|t| t["txid"].as_str())
            .map(String::from);
        while confirmed_in_page >= 25 {
            let Some(l) = last.clone() else { break };
            let page: Vec<serde_json::Value> =
                self.json(&format!("/address/{addr}/txs/chain/{l}"))?.as_array().cloned().unwrap_or_default();
            confirmed_in_page = page.len();
            last = page.last().and_then(|t| t["txid"].as_str()).map(String::from);
            out.extend(page);
        }
        Ok(out)
    }
}

/// Receipts from the (untrusted) host, each believed only after its identity signature verifies.
fn verified_receipts(
    sd: &Signerd,
    w: &WalletRecord,
    codes: &mut Vec<String>,
    notes: &mut Vec<String>,
) -> Result<Vec<Verified>> {
    let lines = sd.get("/v1/receipts")?;
    verify_receipt_lines(&lines, &w.identity_pk, &w.enclave_id, codes, notes)
}

/// The pure part: host-supplied receipt lines → the verified subset, with a code per rejected line.
fn verify_receipt_lines(
    lines: &serde_json::Value,
    identity_pk_hex: &str,
    enclave_id_hex: &str,
    codes: &mut Vec<String>,
    notes: &mut Vec<String>,
) -> Result<Vec<Verified>> {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let idpk = <[u8; 33]>::try_from(hex::decode(identity_pk_hex)?.as_slice()).map_err(|_| anyhow!("identity pk"))?;
    let enclave_id =
        <[u8; 32]>::try_from(hex::decode(enclave_id_hex)?.as_slice()).map_err(|_| anyhow!("enclave id"))?;
    let mut out = Vec::new();
    for (i, l) in lines.as_array().cloned().unwrap_or_default().iter().enumerate() {
        let rh = l["receipt_hex"].as_str().unwrap_or("");
        let sh = l["sig_hex"].as_str().unwrap_or("");
        let (Ok(rb), Ok(sb)) = (hex::decode(rh), hex::decode(sh)) else {
            codes.push("RECEIPT_SIG".into());
            notes.push(format!("receipt line {i}: not hex"));
            continue;
        };
        let Ok(r) = signer_core::receipt::Receipt::decode(&rb) else {
            codes.push("RECEIPT_SIG".into());
            notes.push(format!("receipt line {i}: does not decode"));
            continue;
        };
        let Ok(sig) = <[u8; 64]>::try_from(sb.as_slice()) else {
            codes.push("RECEIPT_SIG".into());
            notes.push(format!("receipt line {i}: signature length"));
            continue;
        };
        if r.enclave_id != enclave_id {
            codes.push("RECEIPT_SIG".into());
            notes.push(format!("receipt line {i}: foreign enclave id"));
            continue;
        }
        if !signer_core::sign::verify_digest_secp(&secp, &idpk, &r.digest(), &sig) {
            codes.push("RECEIPT_SIG".into());
            notes.push(format!("receipt line {i} (claimed seq {}): identity signature does not verify", l["seq"]));
            continue;
        }
        let mut t = r.txid;
        t.reverse();
        let txid = hex::encode(t);
        // the host's line must describe the receipt it carries; a mismatch is the host lying
        if l["seq"].as_u64() != Some(r.seq) || l["txid"].as_str() != Some(txid.as_str()) {
            codes.push("RECEIPT_SIG".into());
            notes.push(format!(
                "receipt line {i}: line fields disagree with the signed receipt (seq {} txid {txid})",
                r.seq
            ));
            continue;
        }
        out.push(Verified {
            session_id: l["session_id"].as_str().unwrap_or("").to_string(),
            seq: r.seq,
            txid,
            net_outflow: r.net_outflow,
        });
    }
    Ok(out)
}

/// `(session_id, seq)` discipline (§3.1, D-R4-4): same seq + same txid = idempotent re-sign;
/// same seq + different txid = fork; a seq below the stored HWM = regression.
fn check_sequence(v: &[Verified], hwm: &Hwm, codes: &mut Vec<String>, notes: &mut Vec<String>) -> (String, u64) {
    let mut by_seq: BTreeMap<u64, HashSet<String>> = BTreeMap::new();
    let mut session_of: HashMap<u64, HashSet<String>> = HashMap::new();
    for r in v {
        by_seq.entry(r.seq).or_default().insert(r.txid.clone());
        session_of.entry(r.seq).or_default().insert(r.session_id.clone());
    }
    for (seq, txids) in &by_seq {
        if txids.len() > 1 {
            codes.push("SEQ_FORK".into());
            notes.push(format!(
                "seq {seq} carries {} different txids: {:?} (sessions {:?})",
                txids.len(),
                txids,
                session_of.get(seq)
            ));
        }
    }
    let max_seq = by_seq.keys().next_back().copied().unwrap_or(0);
    if max_seq < hwm.seq {
        codes.push("SEQ_REGRESSION".into());
        notes.push(format!(
            "highest verified seq {max_seq} is below the stored high-water mark {} — the receipt log shrank",
            hwm.seq
        ));
    }
    for t in &hwm.txids {
        if !v.iter().any(|r| &r.txid == t) {
            codes.push("SEQ_REGRESSION".into());
            notes.push(format!("a previously verified receipt ({t}) is gone from the host's log"));
        }
    }
    // gaps: a withheld receipt; the chain check is what catches its spend
    let mut expected = 1u64;
    for seq in by_seq.keys() {
        if *seq > expected {
            notes.push(format!(
                "receipt gap: seq {} to {} missing (withheld by the host? the chain check covers their spends)",
                expected,
                seq - 1
            ));
            codes.push("RECEIPT_GAP".into());
        }
        expected = seq + 1;
    }
    let last_session = v.iter().filter(|r| r.seq == max_seq).map(|r| r.session_id.clone()).next().unwrap_or_default();
    if !hwm.session_id.is_empty() && last_session != hwm.session_id && max_seq >= hwm.seq {
        notes.push(format!(
            "session changed {} → {} with seq continuity (benign restart)",
            hwm.session_id, last_session
        ));
    }
    (last_session, max_seq)
}

struct Chain {
    spends: Vec<(String, bool, Option<u32>, u64)>, // txid, confirmed, height, net outflow sat
    scanned: u32,
    complete: bool,
}

/// Which addresses have ever had history, so an incremental pass re-reads only those plus the
/// live window after the highest used index per branch; a FULL pass (every `full_every`) reads the
/// whole reachable range — that is where completeness (C-R4-1) is re-established.
#[derive(Serialize, Deserialize, Default)]
struct ScanCache {
    with_history: HashSet<String>,
    highest_used: [u32; 2],
    full_passes: u64,
}

/// Every on-chain spend of the wallet's scripts within the signer's reachable range (C-R4-1):
/// `(hwm_seq + 1) × (ownIndexGap + 1)` per branch, from zero. `full` reads every address of the
/// range; otherwise the addresses with history plus `gap + 1` after the highest used index.
fn scan_chain(
    es: &Esplora,
    w: &WalletRecord,
    gap: u32,
    hwm_seq: u64,
    max_addresses: u32,
    cache: &mut ScanCache,
    full: bool,
) -> Result<Chain> {
    let net = crate::network_of(&w.network)?;
    let range = ((hwm_seq.saturating_add(1)).saturating_mul(u64::from(gap).saturating_add(1)))
        .min(u64::from(max_addresses)) as u32;
    let mut ours: HashSet<String> = HashSet::new();
    let mut addrs: Vec<(u32, u32, String)> = Vec::new();
    for branch in 0..2u32 {
        for index in 0..range {
            let a = crate::psbt::address(&w.xpub, net, branch, index)?;
            ours.insert(a.clone());
            addrs.push((branch, index, a));
        }
    }
    let mut txs: HashMap<String, serde_json::Value> = HashMap::new();
    let mut read = 0u32;
    for (branch, index, a) in &addrs {
        let live = *index <= cache.highest_used[*branch as usize].saturating_add(gap).saturating_add(1);
        if !(full || cache.with_history.contains(a) || live) {
            continue;
        }
        let list = es.address_txs(a)?;
        read = read.saturating_add(1);
        if !list.is_empty() {
            cache.with_history.insert(a.clone());
            if *index > cache.highest_used[*branch as usize] {
                cache.highest_used[*branch as usize] = *index;
            }
        }
        for t in list {
            if let Some(id) = t["txid"].as_str() {
                txs.entry(id.to_string()).or_insert(t);
            }
        }
    }
    if full {
        cache.full_passes = cache.full_passes.saturating_add(1);
    }
    let mut spends = Vec::new();
    for (id, t) in &txs {
        let mut our_in = 0u64;
        let mut our_out = 0u64;
        for vin in t["vin"].as_array().cloned().unwrap_or_default() {
            if vin["prevout"]["scriptpubkey_address"].as_str().map(|a| ours.contains(a)).unwrap_or(false) {
                our_in = our_in.saturating_add(vin["prevout"]["value"].as_u64().unwrap_or(0));
            }
        }
        for vout in t["vout"].as_array().cloned().unwrap_or_default() {
            if vout["scriptpubkey_address"].as_str().map(|a| ours.contains(a)).unwrap_or(false) {
                our_out = our_out.saturating_add(vout["value"].as_u64().unwrap_or(0));
            }
        }
        if our_in > 0 {
            let confirmed = t["status"]["confirmed"].as_bool().unwrap_or(false);
            let height = t["status"]["block_height"].as_u64().map(|h| h as u32);
            spends.push((id.clone(), confirmed, height, our_in.saturating_sub(our_out)));
        }
    }
    spends.sort_by(|a, b| a.2.cmp(&b.2).then(a.0.cmp(&b.0)));
    Ok(Chain { spends, scanned: read, complete: true })
}

/// Read-only RPC to the owner's node with a timeout long enough for `scantxoutset`.
struct NodeRpc {
    url: String,
    auth: String,
    http: reqwest::blocking::Client,
}

impl NodeRpc {
    fn new(url: &str, cookie: &std::path::Path) -> Result<Self> {
        use base64::Engine;
        let c = std::fs::read_to_string(cookie).with_context(|| format!("cookie {}", cookie.display()))?;
        let (u, p) = c.trim().split_once(':').ok_or_else(|| anyhow!("cookie format"))?;
        Ok(NodeRpc {
            url: url.to_string(),
            auth: base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}")),
            http: reqwest::blocking::Client::builder().timeout(std::time::Duration::from_secs(900)).build()?,
        })
    }
}

/// What the monitor asks of its node: one JSON-RPC call. `NodeRpc` is the owner's node over HTTP; the
/// tests drive `scan_node` with a scripted chain behind the same trait (#14).
trait Rpc {
    fn rpc(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value>;
}

impl Rpc for NodeRpc {
    fn rpc(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
        let r = self
            .http
            .post(&self.url)
            .header("Authorization", format!("Basic {}", self.auth))
            .json(&serde_json::json!({ "jsonrpc": "1.0", "id": "monitor", "method": method, "params": params }))
            .send()?;
        let v: serde_json::Value = r.json()?;
        if !v["error"].is_null() {
            return Err(anyhow!("{method}: {}", v["error"]));
        }
        Ok(v["result"].clone())
    }
}

/// What the node source remembers between passes: every output ever seen as ours (so a spend of
/// it is recognised), and the last block fully walked.
#[derive(Serialize, Deserialize, Default)]
struct NodeCache {
    /// outpoint "txid:vout" → (value sat, address)
    outputs: HashMap<String, (u64, String)>,
    last_block: u32,
    /// spends found so far: txid → (confirmed, height, net outflow sat)
    spends: HashMap<String, (bool, Option<u32>, u64)>,
    /// mempool txids already read for incoming outputs (C-R4-7), so a pass reads only new ones
    #[serde(default)]
    mempool_seen: HashSet<String>,
}

/// The owner's own node as the chain source. Completeness comes from `scantxoutset` over the
/// descriptor range (every unspent output of ours in the whole chain) plus a walk of every block
/// since the last pass (every spend of ours, and every new output), plus `gettxspendingprevout`
/// for the mempool. The first pass walks the last `window` blocks so the cap accounting starts full.
#[allow(clippy::too_many_arguments)]
fn scan_node(
    node: &dyn Rpc,
    w: &WalletRecord,
    gap: u32,
    hwm_seq: u64,
    max_addresses: u32,
    window: u32,
    cache: &mut NodeCache,
    utxo_scan: bool,
    receipt_txids: &[String],
) -> Result<(Chain, (u32, String))> {
    let net = crate::network_of(&w.network)?;
    let range = ((hwm_seq.saturating_add(1)).saturating_mul(u64::from(gap).saturating_add(1)))
        .min(u64::from(max_addresses)) as u32;
    let mut ours: HashSet<String> = HashSet::new();
    for branch in 0..2u32 {
        for index in 0..range {
            ours.insert(crate::psbt::address(&w.xpub, net, branch, index)?);
        }
    }
    let info = node.rpc("getblockchaininfo", serde_json::json!([]))?;
    let tip = info["blocks"].as_u64().unwrap_or(0) as u32;
    let tip_hash = info["bestblockhash"].as_str().unwrap_or("").to_string();
    // 1. every unspent output of ours, from the UTXO set itself (not from any index the host could
    //    lie through) — on the first pass and on every resync pass; the block walk keeps it current
    if utxo_scan {
        let descs = serde_json::json!([
            { "desc": format!("wpkh({}/0/*)", w.xpub), "range": [0, range.saturating_sub(1)] },
            { "desc": format!("wpkh({}/1/*)", w.xpub), "range": [0, range.saturating_sub(1)] }
        ]);
        let scan = node.rpc("scantxoutset", serde_json::json!(["start", descs]))?;
        if scan["success"].as_bool() != Some(true) {
            return Err(anyhow!("scantxoutset did not succeed: {scan}"));
        }
        for u in scan["unspents"].as_array().cloned().unwrap_or_default() {
            let op = format!("{}:{}", u["txid"].as_str().unwrap_or(""), u["vout"].as_u64().unwrap_or(0));
            let sat = (u["amount"].as_f64().unwrap_or(0.0) * 1e8).round() as u64;
            let spk = u["scriptPubKey"].as_str().unwrap_or("");
            let addr =
                node.rpc("decodescript", serde_json::json!([spk]))?["address"].as_str().unwrap_or("").to_string();
            cache.outputs.entry(op).or_insert((sat, addr));
        }
    }
    // 2. walk the blocks since the last pass (first pass: the last `window` blocks)
    let from = if cache.last_block == 0 { tip.saturating_sub(window) } else { cache.last_block.saturating_add(1) };
    for h in from..=tip {
        let hash = node.rpc("getblockhash", serde_json::json!([h]))?;
        let block = node.rpc("getblock", serde_json::json!([hash, 2]))?;
        for tx in block["tx"].as_array().cloned().unwrap_or_default() {
            note_tx(&tx, &ours, cache, true, Some(h));
        }
    }
    cache.last_block = tip;
    // 2b. outputs we created that are still unconfirmed (our own change in the mempool): the UTXO
    //     set and the blocks do not know them yet, so a thief spending them would be invisible —
    //     every receipted transaction not yet confirmed is read from the node and its outputs noted
    for t in receipt_txids {
        if cache.spends.get(t).map(|(c, ..)| *c).unwrap_or(false) {
            continue;
        }
        if let Ok(tx) = node.rpc("getrawtransaction", serde_json::json!([t, true])) {
            let confirmed = tx["confirmations"].as_u64().unwrap_or(0) > 0;
            note_tx(&tx, &ours, cache, confirmed, None);
        }
    }
    // 2c. incoming outputs still in the mempool (C-R4-7): a third party's unconfirmed payment to
    //     us could be spent by a thief before it confirms; every mempool transaction not read
    //     before is read once and its outputs to our addresses noted (cheap on signet; on mainnet
    //     this is the per-pass cost the operator pays for closing that one-pass window)
    let mempool: Vec<String> = node
        .rpc("getrawmempool", serde_json::json!([]))?
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();
    let current: HashSet<String> = mempool.iter().cloned().collect();
    cache.mempool_seen.retain(|t| current.contains(t));
    for t in &mempool {
        if cache.mempool_seen.contains(t) {
            continue;
        }
        if let Ok(tx) = node.rpc("getrawtransaction", serde_json::json!([t, true])) {
            note_tx(&tx, &ours, cache, false, None);
        }
        cache.mempool_seen.insert(t.clone());
    }
    // 3. the mempool: anything spending an output of ours right now
    let outpoints: Vec<serde_json::Value> = cache
        .outputs
        .keys()
        .filter_map(|op| {
            let (t, v) = op.split_once(':')?;
            Some(serde_json::json!({ "txid": t, "vout": v.parse::<u32>().ok()? }))
        })
        .collect();
    for chunk in outpoints.chunks(100) {
        let r = node.rpc("gettxspendingprevout", serde_json::json!([chunk]))?;
        for e in r.as_array().cloned().unwrap_or_default() {
            if let Some(spender) = e["spendingtxid"].as_str() {
                if !cache.spends.contains_key(spender) {
                    if let Ok(tx) = node.rpc("getrawtransaction", serde_json::json!([spender, true])) {
                        note_tx(&tx, &ours, cache, false, None);
                    }
                }
            }
        }
    }
    let mut spends: Vec<(String, bool, Option<u32>, u64)> =
        cache.spends.iter().map(|(t, (c, h, n))| (t.clone(), *c, *h, *n)).collect();
    spends.sort_by(|a, b| a.2.cmp(&b.2).then(a.0.cmp(&b.0)));
    Ok((Chain { spends, scanned: range.saturating_mul(2), complete: true }, (tip, tip_hash)))
}

/// Record a transaction's effect on us: outputs to our addresses become known outputs; inputs
/// from our known outputs make it a spend with a net outflow.
fn note_tx(
    tx: &serde_json::Value,
    ours: &HashSet<String>,
    cache: &mut NodeCache,
    confirmed: bool,
    height: Option<u32>,
) {
    let txid = tx["txid"].as_str().unwrap_or("").to_string();
    let mut our_in = 0u64;
    for vin in tx["vin"].as_array().cloned().unwrap_or_default() {
        let (Some(t), Some(v)) = (vin["txid"].as_str(), vin["vout"].as_u64()) else { continue };
        if let Some((sat, _)) = cache.outputs.get(&format!("{t}:{v}")) {
            our_in = our_in.saturating_add(*sat);
        }
    }
    let mut our_out = 0u64;
    for vout in tx["vout"].as_array().cloned().unwrap_or_default() {
        let addr = vout["scriptPubKey"]["address"].as_str().unwrap_or("");
        if ours.contains(addr) {
            let sat = (vout["value"].as_f64().unwrap_or(0.0) * 1e8).round() as u64;
            our_out = our_out.saturating_add(sat);
            cache
                .outputs
                .entry(format!("{txid}:{}", vout["n"].as_u64().unwrap_or(0)))
                .or_insert((sat, addr.to_string()));
        }
    }
    if our_in > 0 {
        let e = cache.spends.entry(txid).or_insert((confirmed, height, our_in.saturating_sub(our_out)));
        if confirmed {
            *e = (true, height, our_in.saturating_sub(our_out));
        }
    }
}

fn journal(path: &PathBuf, line: &PassLine) -> Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("journal {}", path.display()))?;
    writeln!(f, "{}", serde_json::to_string(line)?)?;
    Ok(())
}

fn hwm_path(cfg: &Cfg) -> PathBuf {
    let mut p = cfg.journal.clone();
    p.set_extension("hwm.json");
    p
}

/// One pass. Returns the verdict code: 0 OK, 1 WARN, 2 ALARM.
pub fn pass(sd: &Signerd, cfg: &Cfg) -> Result<i32> {
    let w: WalletRecord = serde_json::from_str(&std::fs::read_to_string(&cfg.wallet)?)?;
    let m: MandateJson = serde_json::from_str(&std::fs::read_to_string(&cfg.mandate)?).context("mandate JSON")?;
    let es = Esplora::new(&cfg.esplora, cfg.esplora_delay_ms);
    let mut hwm: Hwm =
        std::fs::read_to_string(hwm_path(cfg)).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
    let mut codes: Vec<String> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    let mut alarm = false;
    let mut warn = false;

    // 1. receipts — believed only after the identity signature verifies
    let receipts = match verified_receipts(sd, &w, &mut codes, &mut notes) {
        Ok(v) => v,
        Err(e) => {
            codes.push("SIGNERD_UNREACHABLE".into());
            notes.push(format!("receipts: {e}"));
            Vec::new()
        }
    };
    let (last_session, max_seq) = check_sequence(&receipts, &hwm, &mut codes, &mut notes);
    if codes.iter().any(|c| c == "RECEIPT_SIG" || c == "SEQ_FORK" || c == "SEQ_REGRESSION") {
        alarm = true;
    }
    if codes.iter().any(|c| c == "RECEIPT_GAP" || c == "SIGNERD_UNREACHABLE") {
        warn = true;
    }
    // the HWM only ever advances, and it is written BEFORE the verdict
    if max_seq > hwm.seq || (max_seq == hwm.seq && !last_session.is_empty()) {
        hwm.seq = hwm.seq.max(max_seq);
        hwm.session_id = last_session.clone();
    }
    for r in &receipts {
        if !hwm.txids.contains(&r.txid) {
            hwm.txids.push(r.txid.clone());
        }
    }
    hwm.passes = hwm.passes.saturating_add(1);
    std::fs::write(hwm_path(cfg), serde_json::to_string_pretty(&hwm)?)?;

    // 2. chain — the ground truth, from the owner's source; a source failure is a WARN (the
    //    checks below are skipped for this pass and the heartbeat says so), never a dead monitor
    let range = ((hwm.seq.saturating_add(1)).saturating_mul(u64::from(m.limits.own_index_gap).saturating_add(1)))
        .min(u64::from(cfg.max_addresses));
    let mut cache_path = cfg.journal.clone();
    cache_path.set_extension("cache.json");
    let (chain, (tip_height, tip_hash)) = if let (Some(url), Some(cookie)) = (&cfg.node_rpc, &cfg.node_cookie) {
        let mut cache: NodeCache =
            std::fs::read_to_string(&cache_path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
        let utxo_scan = cache.last_block == 0 || cfg.full_every <= 1 || hwm.passes % cfg.full_every.max(1) == 1;
        let receipt_txids: Vec<String> = receipts.iter().map(|r| r.txid.clone()).collect();
        let r = NodeRpc::new(url, cookie).and_then(|node| {
            scan_node(
                &node,
                &w,
                m.limits.own_index_gap,
                hwm.seq,
                cfg.max_addresses,
                m.limits.window.blocks,
                &mut cache,
                utxo_scan,
                &receipt_txids,
            )
        });
        match r {
            Ok((c, tip)) => {
                std::fs::write(&cache_path, serde_json::to_string(&cache)?)?;
                notes.push(format!("chain source: own node {url} ({}blocks to {} + mempool; {} outputs of ours known, {} spends); reachable range {range} per branch", if utxo_scan { "UTXO set + " } else { "" }, tip.0, cache.outputs.len(), cache.spends.len()));
                (c, tip)
            }
            Err(e) => {
                warn = true;
                codes.push("CHAIN_SOURCE".into());
                notes.push(format!("node scan failed, spend/cap checks skipped this pass: {e}"));
                (Chain { spends: Vec::new(), scanned: 0, complete: false }, (0, String::new()))
            }
        }
    } else {
        let tip = es.tip().context("chain tip")?;
        let mut cache: ScanCache =
            std::fs::read_to_string(&cache_path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
        let full = cache.full_passes == 0 || cfg.full_every <= 1 || hwm.passes % cfg.full_every.max(1) == 1;
        let c = match scan_chain(&es, &w, m.limits.own_index_gap, hwm.seq, cfg.max_addresses, &mut cache, full) {
            Ok(c) => c,
            Err(e) => {
                warn = true;
                codes.push("CHAIN_SOURCE".into());
                notes.push(format!("chain scan failed, spend/cap checks skipped this pass: {e}"));
                Chain { spends: Vec::new(), scanned: 0, complete: false }
            }
        };
        std::fs::write(&cache_path, serde_json::to_string(&cache)?)?;
        notes.push(format!(
            "chain source: Esplora {} — {} ({} addresses read; reachable range {range} per branch)",
            cfg.esplora,
            if full { "FULL" } else { "incremental" },
            c.scanned
        ));
        (c, tip)
    };
    if tip_height == 0 {
        // no chain view this pass: nothing below can be judged
        warn = true;
    }
    let mut ack_path = cfg.journal.clone();
    ack_path.set_extension("ack.json");
    let mut acked: Vec<String> =
        std::fs::read_to_string(&ack_path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
    for a in &cfg.acknowledge {
        if !acked.contains(a) {
            acked.push(a.clone());
            notes.push(format!("owner acknowledged {a}: it will not re-alarm (recorded in {})", ack_path.display()));
        }
    }
    std::fs::write(&ack_path, serde_json::to_string_pretty(&acked)?)?;
    let receipted: HashMap<&str, &Verified> = receipts.iter().map(|r| (r.txid.as_str(), r)).collect();
    for (txid, confirmed, height, net) in &chain.spends {
        match receipted.get(txid.as_str()) {
            None if acked.contains(txid) => {
                notes.push(format!("{txid}: spend without receipt, acknowledged by the owner ({net} sat)"));
            }
            None => {
                alarm = true;
                codes.push("SPEND_WITHOUT_RECEIPT".into());
                notes.push(format!("{txid} spends {net} sat of the wallet ({}) and no verified receipt names it — someone signed for this wallet outside the enclave: either the host replayed a forked blob (the freeze stops that) or the seed is out (then nothing stops it)", if *confirmed { format!("confirmed at {}", height.unwrap_or(0)) } else { "in the mempool".into() }));
            }
            Some(r) if r.net_outflow != *net => {
                warn = true;
                codes.push("RECEIPT_AMOUNT".into());
                notes.push(format!(
                    "{txid}: the receipt (seq {}) claims net outflow {} sat, the chain shows {net} sat",
                    r.seq, r.net_outflow
                ));
            }
            _ => {}
        }
    }
    if chain.complete {
        for r in &receipts {
            if !chain.spends.iter().any(|(t, ..)| t == &r.txid) {
                notes.push(format!("receipt seq {} ({}) not seen on-chain yet (not broadcast?)", r.seq, r.txid));
            }
        }
    }
    // 3. cap accounting from the chain, independently of the enclave
    let window_from = tip_height.saturating_sub(m.limits.window.blocks.saturating_sub(1));
    let outflow: u64 = chain
        .spends
        .iter()
        .filter(|(_, c, h, _)| !*c || h.map(|h| h >= window_from).unwrap_or(true))
        .map(|(_, _, _, n)| *n)
        .fold(0u64, |a, b| a.saturating_add(b));
    if outflow > m.limits.window.max_outflow {
        alarm = true;
        codes.push("CAP_EXCEEDED".into());
        notes.push(format!(
            "chain outflow in the last {} blocks = {outflow} sat > mandate maxOutflow {}",
            m.limits.window.blocks, m.limits.window.max_outflow
        ));
    }

    // 4. the feed, and the enclave's own freeze state
    let mut enclave_best = 0u32;
    match sd.get("/v1/status") {
        Ok(st) => {
            enclave_best = st["best_height"].as_u64().unwrap_or(0) as u32;
            let lag_limit = cfg.max_tip_lag.unwrap_or(m.freshness.max_tip_lag);
            let lag = tip_height.saturating_sub(enclave_best);
            if st["installed"].as_bool() == Some(true) && lag > lag_limit {
                hwm.stall_passes = hwm.stall_passes.saturating_add(1);
                codes.push("FEED_STALL".into());
                notes.push(format!("enclave best {enclave_best} is {lag} blocks behind the chain tip {tip_height} (limit {lag_limit}); {} consecutive passes", hwm.stall_passes));
                if hwm.stall_passes >= cfg.stall_after {
                    alarm = true;
                } else {
                    warn = true;
                }
            } else {
                hwm.stall_passes = 0;
            }
            if st["chain_frozen"].as_bool() == Some(true) {
                alarm = true;
                codes.push("CHAIN_REORG".into());
                notes.push("the enclave froze itself on a fork deeper than maxReorg; the owner must re-pin".into());
            }
            if st["frozen"].as_bool() == Some(true) {
                notes.push("signer is frozen".into());
            }
            std::fs::write(hwm_path(cfg), serde_json::to_string_pretty(&hwm)?)?;
        }
        Err(e) => {
            warn = true;
            codes.push("SIGNERD_UNREACHABLE".into());
            notes.push(format!("status: {e}"));
        }
    }

    // 6. freshness witness, from the monitor's own view (D-R4-5)
    if m.freshness.required {
        match &cfg.witness_key {
            Some(k) => {
                let key = open_locator(k)?;
                let enclave_id =
                    <[u8; 32]>::try_from(hex::decode(&w.enclave_id)?.as_slice()).map_err(|_| anyhow!("enclave id"))?;
                let mut msg = Message::WitnessToken {
                    enclave_id,
                    tip_hash: hash_of(&tip_hash)?,
                    tip_height,
                    last_seen_seq: hwm.seq,
                    issued: now(),
                    sig: [0; 64],
                };
                sign_message(&key, &mut msg)?;
                match submit_message(sd, &msg) {
                    Ok(()) => notes.push(format!("witness token issued: tip {tip_height}, last_seen_seq {}", hwm.seq)),
                    Err(e) => {
                        warn = true;
                        codes.push("WITNESS_REFUSED".into());
                        notes.push(format!("witness token refused: {e}"));
                    }
                }
            }
            None => {
                warn = true;
                codes.push("WITNESS_KEY_MISSING".into());
                notes.push("the mandate requires freshness but no --witness-key was given: signing will starve".into());
            }
        }
    }

    // 8. the reflex
    let mut froze = false;
    if alarm && cfg.freeze {
        match sd.post("/v1/freeze", serde_json::json!({})) {
            Ok(_) => {
                froze = true;
                notes.push(
                    "FREEZE sent (unsigned, tightening); un-freezing needs the owner's key after a human looks".into(),
                );
            }
            Err(e) => notes.push(format!(
                "FREEZE failed: {e} — the signer host may be gone; the enclave is not signing for you either way"
            )),
        }
    }
    let verdict = if alarm {
        "ALARM"
    } else if warn {
        "WARN"
    } else {
        "OK"
    };
    codes.sort();
    codes.dedup();
    let line = PassLine {
        ts: now(),
        pass: hwm.passes,
        verdict,
        codes: codes.clone(),
        tip_height,
        enclave_best,
        hwm_session: &hwm.session_id,
        hwm_seq: hwm.seq,
        receipts_verified: receipts.len(),
        spends_onchain: chain.spends.len(),
        outflow_window_sat: outflow,
        scanned_addresses: chain.scanned,
        froze,
        notes: notes.clone(),
    };
    journal(&cfg.journal, &line)?;
    println!(
        "{verdict} pass {} tip {tip_height} enclave {enclave_best} hwm {}:{} receipts {} spends {} outflow {} sat{}",
        hwm.passes,
        hwm.session_id,
        hwm.seq,
        receipts.len(),
        chain.spends.len(),
        outflow,
        if froze { " — FROZE" } else { "" }
    );
    for c in &codes {
        println!("  {c}");
    }
    for n in &notes {
        println!("  - {n}");
    }
    Ok(if alarm {
        2
    } else if warn {
        1
    } else {
        0
    })
}

pub fn run(sd: &Signerd, cfg: &Cfg) -> Result<i32> {
    if cfg.once {
        return pass(sd, cfg);
    }
    loop {
        match pass(sd, cfg) {
            Ok(2) => println!("ALARM latched; still watching"),
            Ok(_) => {}
            Err(e) => println!("pass failed: {e}"),
        }
        std::thread::sleep(std::time::Duration::from_secs(cfg.interval.max(10)));
    }
}

#[cfg(test)]
mod tests {
    //! The receipt discipline on synthetic receipts signed by a throwaway identity key: no network,
    //! no signer — the monitor's judgement is a pure function of the lines it is handed.
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    fn identity() -> (SecretKey, String, String) {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x5a; 32]).unwrap();
        let pk = sk.public_key(&secp).serialize();
        (sk, hex::encode(pk), hex::encode(signer_core::sha256(&pk)))
    }

    fn receipt_line(
        sk: &SecretKey,
        enclave_id_hex: &str,
        session: &str,
        seq: u64,
        txid_byte: u8,
        net: u64,
        tamper: bool,
    ) -> serde_json::Value {
        let secp = Secp256k1::new();
        let mut txid = [0u8; 32];
        txid[0] = txid_byte;
        let r = signer_core::receipt::Receipt {
            enclave_id: <[u8; 32]>::try_from(hex::decode(enclave_id_hex).unwrap().as_slice()).unwrap(),
            seq,
            txid,
            net_outflow: net,
            unlisted: net,
            trusted: Vec::new(),
            fee: 100,
            height: 1000,
            mandate_hash: [7u8; 32],
            pending_hash: None,
            nonce: 0,
        };
        let mut bytes = r.encode();
        let sig = signer_core::sign::sign_digest_secp(&secp, sk, &r.digest());
        if tamper {
            bytes[20] ^= 1;
        }
        let mut disp = txid;
        disp.reverse();
        serde_json::json!({ "ts": 0, "session_id": session, "seq": seq, "txid": hex::encode(disp), "receipt_hex": hex::encode(bytes), "sig_hex": hex::encode(sig) })
    }

    #[test]
    fn genuine_receipts_verify_and_sequence() {
        let (sk, pk, eid) = identity();
        let lines = serde_json::json!([
            receipt_line(&sk, &eid, "s1", 1, 1, 5000, false),
            receipt_line(&sk, &eid, "s1", 2, 2, 2000, false),
            receipt_line(&sk, &eid, "s2", 3, 3, 1000, false)
        ]);
        let (mut codes, mut notes) = (Vec::new(), Vec::new());
        let v = verify_receipt_lines(&lines, &pk, &eid, &mut codes, &mut notes).unwrap();
        assert_eq!(v.len(), 3);
        assert!(codes.is_empty(), "{codes:?}");
        let hwm = Hwm { session_id: "s1".into(), seq: 2, ..Default::default() };
        let (last, max) = check_sequence(&v, &hwm, &mut codes, &mut notes);
        assert_eq!((last.as_str(), max), ("s2", 3));
        assert!(codes.is_empty(), "{codes:?}");
        assert!(notes.iter().any(|n| n.contains("benign restart")), "{notes:?}");
    }

    #[test]
    fn tampered_receipt_is_refused_by_name() {
        let (sk, pk, eid) = identity();
        let lines = serde_json::json!([receipt_line(&sk, &eid, "s1", 1, 1, 5000, true)]);
        let (mut codes, mut notes) = (Vec::new(), Vec::new());
        let v = verify_receipt_lines(&lines, &pk, &eid, &mut codes, &mut notes).unwrap();
        assert!(v.is_empty());
        assert_eq!(codes, vec!["RECEIPT_SIG".to_string()], "{notes:?}");
    }

    #[test]
    fn host_line_disagreeing_with_its_receipt_is_refused() {
        let (sk, pk, eid) = identity();
        let mut l = receipt_line(&sk, &eid, "s1", 1, 1, 5000, false);
        l["seq"] = serde_json::json!(9);
        let (mut codes, mut notes) = (Vec::new(), Vec::new());
        let v = verify_receipt_lines(&serde_json::json!([l]), &pk, &eid, &mut codes, &mut notes).unwrap();
        assert!(v.is_empty());
        assert_eq!(codes, vec!["RECEIPT_SIG".to_string()], "{notes:?}");
    }

    #[test]
    fn same_seq_different_txid_is_a_fork_but_same_txid_is_idempotent() {
        let (sk, pk, eid) = identity();
        // idempotent re-sign: same seq, same txid, twice
        let lines = serde_json::json!([
            receipt_line(&sk, &eid, "s1", 1, 1, 5000, false),
            receipt_line(&sk, &eid, "s1", 1, 1, 5000, false)
        ]);
        let (mut codes, mut notes) = (Vec::new(), Vec::new());
        let v = verify_receipt_lines(&lines, &pk, &eid, &mut codes, &mut notes).unwrap();
        check_sequence(&v, &Hwm::default(), &mut codes, &mut notes);
        assert!(codes.is_empty(), "{codes:?}");
        // the fork: same seq, different txid, across sessions
        let lines = serde_json::json!([
            receipt_line(&sk, &eid, "s1", 1, 1, 5000, false),
            receipt_line(&sk, &eid, "s2", 1, 9, 5000, false)
        ]);
        let (mut codes, mut notes) = (Vec::new(), Vec::new());
        let v = verify_receipt_lines(&lines, &pk, &eid, &mut codes, &mut notes).unwrap();
        check_sequence(&v, &Hwm::default(), &mut codes, &mut notes);
        assert!(codes.contains(&"SEQ_FORK".to_string()), "{codes:?} {notes:?}");
    }

    #[test]
    fn a_shrunk_log_is_a_regression() {
        let (sk, pk, eid) = identity();
        let lines = serde_json::json!([receipt_line(&sk, &eid, "s1", 1, 1, 5000, false)]);
        let (mut codes, mut notes) = (Vec::new(), Vec::new());
        let v = verify_receipt_lines(&lines, &pk, &eid, &mut codes, &mut notes).unwrap();
        let hwm = Hwm { session_id: "s1".into(), seq: 3, txids: vec!["dead".into()], ..Default::default() };
        check_sequence(&v, &hwm, &mut codes, &mut notes);
        assert!(codes.iter().filter(|c| *c == "SEQ_REGRESSION").count() >= 1, "{codes:?}");
    }

    #[test]
    fn a_foreign_enclave_receipt_is_refused() {
        let (sk, pk, eid) = identity();
        let other = hex::encode([3u8; 32]);
        let lines = serde_json::json!([receipt_line(&sk, &other, "s1", 1, 1, 5000, false)]);
        let (mut codes, mut notes) = (Vec::new(), Vec::new());
        let v = verify_receipt_lines(&lines, &pk, &eid, &mut codes, &mut notes).unwrap();
        assert!(v.is_empty());
        assert_eq!(codes, vec!["RECEIPT_SIG".to_string()], "{notes:?}");
    }

    // ---- the two reproducers of the external review of 2026-11-25 (#13, #14): red on `main` @ 2ff937e

    use std::sync::{Arc, Mutex};

    /// A throwaway regtest master key (seed of 0x42 bytes) — labeled: never funded, never a wallet.
    fn throwaway_xpub() -> String {
        let secp = Secp256k1::new();
        let xprv = bitcoin::bip32::Xpriv::new_master(bitcoin::Network::Regtest, &[0x42u8; 32]).unwrap();
        bitcoin::bip32::Xpub::from_priv(&secp, &xprv).to_string()
    }

    fn wallet_json(xpub: &str, identity_pk_hex: &str, enclave_id_hex: &str) -> serde_json::Value {
        serde_json::json!({
            "network": "regtest", "xpub": xpub, "fingerprint": "00000000", "identity_pk": identity_pk_hex,
            "enclave_id": enclave_id_hex, "card_hex": "", "card_sig_hex": "", "mrenclave": "", "tier": "T0-test",
            "recovery_blob_hex": "", "owner_pk": "", "recovery_pk": ""
        })
    }

    fn mandate_json() -> &'static str {
        r#"{ "version": 1, "network": "regtest",
  "wallet": { "fingerprint": "00000000", "account": "84'/1'/0'", "scriptTypes": ["p2wpkh"] },
  "destinations": { "trusted": [], "unlisted": { "maxPerTx": 1000000, "maxPerWindow": 5000000 } },
  "limits": { "maxPerTx": 100000000, "window": { "blocks": 144, "maxOutflow": 500000000 }, "maxFeeAbs": 100000, "maxFeeRate": 100, "maxInputs": 64, "maxOutputs": 32, "ownIndexGap": 2, "maxReorg": 6 },
  "rules": { "sighash": "ALL", "payjoin": "none", "opReturn": "none", "rbf": true },
  "freshness": { "required": false, "maxTipLag": 6 },
  "validity": { "notAfterHeight": 100000 }, "timelockBlocks": 144 }"#
    }

    /// A scratch directory of this test alone, removed by the test by its own path.
    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("tee-signer-owner-cli-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A loopback stand-in for `signerd` (and, on every other path, for a failing Esplora): answers
    /// `/v1/receipts` with the given lines, `/v1/status` with a bare installed status, `/v1/freeze` with
    /// `{}`, and 404 to anything else. Every request is recorded as "METHOD path".
    fn fake_signerd(receipts: serde_json::Value) -> (String, Arc<Mutex<Vec<String>>>) {
        use std::io::{BufRead, BufReader, Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let calls = Arc::new(Mutex::new(Vec::new()));
        let seen = calls.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { break };
                let mut rd = BufReader::new(s.try_clone().unwrap());
                let mut line = String::new();
                if rd.read_line(&mut line).is_err() {
                    continue;
                }
                let mut parts = line.split_whitespace();
                let method = parts.next().unwrap_or("").to_string();
                let path = parts.next().unwrap_or("").to_string();
                let mut len = 0usize;
                loop {
                    let mut h = String::new();
                    if rd.read_line(&mut h).unwrap_or(0) == 0 || h == "\r\n" {
                        break;
                    }
                    if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap_or(0);
                    }
                }
                let mut body = vec![0u8; len];
                if len > 0 {
                    let _ = rd.read_exact(&mut body);
                }
                seen.lock().unwrap().push(format!("{method} {path}"));
                let (status, body) = match (method.as_str(), path.as_str()) {
                    ("GET", "/v1/receipts") => ("200 OK", receipts.to_string()),
                    ("GET", "/v1/status") => {
                        ("200 OK", serde_json::json!({ "installed": true, "best_height": 0 }).to_string())
                    }
                    ("POST", "/v1/freeze") => ("200 OK", "{}".to_string()),
                    _ => ("404 Not Found", "{\"error\":\"no such path\"}".to_string()),
                };
                let _ = write!(
                    s,
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.flush();
            }
        });
        (url, calls)
    }

    #[test]
    fn the_reflex_fires_when_the_chain_source_is_down() {
        // #13: the receipts raise an alarm (RECEIPT_SIG) while the Esplora tip cannot be read (the fake
        // answers 404 to every path that is not signerd's). The pass must still reach its verdict, send
        // FREEZE once and write its journal line — on `main` @ 2ff937e it returns Err("chain tip") instead.
        let (sk, pk, eid) = identity();
        let (url, calls) = fake_signerd(serde_json::json!([receipt_line(&sk, &eid, "s1", 1, 1, 5000, true)]));
        let dir = scratch("reflex");
        std::fs::write(dir.join("wallet.json"), wallet_json(&throwaway_xpub(), &pk, &eid).to_string()).unwrap();
        std::fs::write(dir.join("mandate.json"), mandate_json()).unwrap();
        let cfg = Cfg {
            wallet: dir.join("wallet.json"),
            mandate: dir.join("mandate.json"),
            esplora: url.clone(),
            interval: 0,
            journal: dir.join("monitor.jsonl"),
            once: true,
            freeze: true,
            witness_key: None,
            stall_after: 3,
            max_tip_lag: None,
            max_addresses: 4,
            esplora_delay_ms: 0,
            full_every: 1,
            node_rpc: None,
            node_cookie: None,
            acknowledge: Vec::new(),
        };
        let sd = Signerd { url, token: "t".into(), record: None, offline: None, out: None };
        let code = pass(&sd, &cfg).expect("the pass reaches its verdict although the chain source is down");
        assert_eq!(code, 2, "ALARM");
        let freezes = calls.lock().unwrap().iter().filter(|c| *c == "POST /v1/freeze").count();
        assert_eq!(freezes, 1, "{:?}", calls.lock().unwrap());
        let j = std::fs::read_to_string(dir.join("monitor.jsonl")).unwrap();
        assert!(j.contains("\"verdict\":\"ALARM\"") && j.contains("RECEIPT_SIG") && j.contains("CHAIN_SOURCE"), "{j}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A scripted node: the chain as (height, hash, transactions), replaceable mid-test.
    struct FakeNode {
        chain: Mutex<Vec<(u32, String, Vec<serde_json::Value>)>>,
    }

    fn tx(txid: &str, vin: &[(&str, u32)], vout: &[(&str, f64)]) -> serde_json::Value {
        serde_json::json!({
            "txid": txid,
            "vin": vin.iter().map(|(t, v)| serde_json::json!({ "txid": t, "vout": v })).collect::<Vec<_>>(),
            "vout": vout.iter().enumerate().map(|(n, (a, btc))| serde_json::json!({ "n": n, "value": btc, "scriptPubKey": { "address": a } })).collect::<Vec<_>>(),
        })
    }

    impl Rpc for FakeNode {
        fn rpc(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
            let chain = self.chain.lock().unwrap();
            let (tip_h, tip_hash, _) = chain.last().cloned().ok_or_else(|| anyhow!("empty chain"))?;
            Ok(match method {
                "getblockchaininfo" => serde_json::json!({ "blocks": tip_h, "bestblockhash": tip_hash }),
                "getblockhash" => {
                    let h = params[0].as_u64().unwrap_or(u64::MAX);
                    serde_json::json!(chain
                        .iter()
                        .find(|b| u64::from(b.0) == h)
                        .map(|b| b.1.clone())
                        .ok_or_else(|| anyhow!("Block height out of range"))?)
                }
                "getblock" => {
                    let hash = params[0].as_str().unwrap_or("");
                    let b = chain.iter().find(|b| b.1 == hash).ok_or_else(|| anyhow!("Block not found"))?;
                    serde_json::json!({ "hash": b.1, "height": b.0, "tx": b.2 })
                }
                "scantxoutset" => {
                    let all: Vec<&serde_json::Value> = chain.iter().flat_map(|b| b.2.iter()).collect();
                    let mut unspents = Vec::new();
                    for t in &all {
                        for o in t["vout"].as_array().unwrap() {
                            let (txid, n) = (t["txid"].as_str().unwrap(), o["n"].as_u64().unwrap());
                            let spent = all.iter().any(|u| {
                                u["vin"]
                                    .as_array()
                                    .unwrap()
                                    .iter()
                                    .any(|i| i["txid"] == txid && i["vout"].as_u64() == Some(n))
                            });
                            if !spent {
                                unspents.push(serde_json::json!({ "txid": txid, "vout": n, "amount": o["value"], "scriptPubKey": o["scriptPubKey"]["address"] }));
                            }
                        }
                    }
                    serde_json::json!({ "success": true, "unspents": unspents })
                }
                "getrawtransaction" => {
                    let id = params[0].as_str().unwrap_or("");
                    let (h, t) = chain
                        .iter()
                        .flat_map(|b| b.2.iter().map(move |t| (b.0, t)))
                        .find(|(_, t)| t["txid"] == id)
                        .ok_or_else(|| anyhow!("No such mempool or blockchain transaction"))?;
                    let mut t = t.clone();
                    t["confirmations"] = serde_json::json!(tip_h - h + 1);
                    t
                }
                "getrawmempool" | "gettxspendingprevout" => serde_json::json!([]),
                "decodescript" => serde_json::json!({ "address": params[0] }),
                m => return Err(anyhow!("unexpected rpc {m}")),
            })
        }
    }

    #[test]
    fn a_spend_confirmed_only_in_the_winning_fork_is_found() {
        // #14: pass 1 walks blocks 96..=101 (block 100 funds us); then block 101 is replaced by one that
        // spends our output to a stranger, a transaction that was never in our node's mempool between the
        // passes. Pass 2 must see the spend — on `main` @ 2ff937e it resumes at 102 and sees nothing.
        let xpub = throwaway_xpub();
        let w: WalletRecord =
            serde_json::from_value(wallet_json(&xpub, &hex::encode([2u8; 33]), &hex::encode([1u8; 32]))).unwrap();
        let ours = crate::psbt::address(&xpub, signer_core::mandate::Network::Regtest, 0, 0).unwrap();
        let (ftx, stx) = ("aa".repeat(32), "bb".repeat(32));
        let funding = tx(&ftx, &[("00".repeat(32).as_str(), 0)], &[(ours.as_str(), 1.0)]);
        let mut blocks: Vec<(u32, String, Vec<serde_json::Value>)> =
            (96..=99).map(|h| (h, format!("h{h}"), vec![])).collect();
        blocks.push((100, "h100".into(), vec![funding]));
        blocks.push((101, "h101".into(), vec![]));
        let node = FakeNode { chain: Mutex::new(blocks) };
        let mut cache = NodeCache::default();
        let (c1, tip1) = scan_node(&node, &w, 2, 0, 10, 5, &mut cache, true, &[]).unwrap();
        assert!(c1.spends.is_empty(), "{:?}", c1.spends);
        assert_eq!(tip1.0, 101);
        assert!(cache.outputs.contains_key(&format!("{ftx}:0")), "the funding output is known");
        // the reorg: a different block 101, carrying the spend
        let spend = tx(&stx, &[(ftx.as_str(), 0)], &[("bcrt1qstranger", 0.9999)]);
        {
            let mut ch = node.chain.lock().unwrap();
            ch.pop();
            ch.push((101, "h101b".into(), vec![spend]));
        }
        let (c2, tip2) = scan_node(&node, &w, 2, 0, 10, 5, &mut cache, false, &[]).unwrap();
        assert_eq!(tip2, (101, "h101b".to_string()));
        let found = c2.spends.iter().find(|(t, ..)| *t == stx);
        let (_, confirmed, height, net) =
            found.unwrap_or_else(|| panic!("the spend in the replacement block must be seen: {:?}", c2.spends));
        assert_eq!((*confirmed, *height, *net), (true, Some(101), 100_000_000));
    }
}
