//! owner-cli — the owner's side (`docs/DESIGN.md §6–7`). Runs on the owner's machine, never on
//! the BTCPay box. Holds or reaches the owner key, builds mandates from JSON into the canonical
//! bytes the enclave signs over, shows the diff against what is installed, signs, submits; runs
//! init and verifies the identity card and the recovery blob offline.
//!
//! Key backends in this build: an encrypted keyfile (scrypt N=2^18 + AES-256-GCM; the permitted
//! floor, owner decision D3) and `software` for tests. Hardware backends (YubiKey PIV, TPM 2.0,
//! Secure Enclave) come through TPM_sign's `hw-signer` in the next step; the trait boundary is
//! the same: a 32-byte digest in, `(r, s)` out.

use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{anyhow, bail, Context, Result};
use bitcoin::bip32::Xpub;
use clap::{Parser, Subcommand};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use serde::{Deserialize, Serialize};
use signer_core::mandate::*;
use signer_core::proto::IdentityCard;
use signer_core::update::Message;
use zeroize::Zeroize;

mod psbt;

// ---------------------------------------------------------------- keys

#[derive(Serialize, Deserialize)]
struct KeyFile {
    version: u8,
    kdf: String,
    log_n: u8,
    r: u32,
    p: u32,
    salt_hex: String,
    nonce_hex: String,
    ct_hex: String,
    pubkey_hex: String,
    role: String,
}

fn passphrase(prompt: &str, confirm: bool) -> Result<String> {
    if let Ok(p) = std::env::var("OWNER_PASSPHRASE") {
        return Ok(p);
    }
    let a = rpassword::prompt_password(format!("{prompt}: "))?;
    if confirm {
        let b = rpassword::prompt_password("again: ")?;
        if a != b {
            bail!("passphrases differ");
        }
    }
    if a.len() < 8 {
        bail!("passphrase too short (8+)");
    }
    Ok(a)
}

fn kdf(pass: &str, salt: &[u8], log_n: u8, r: u32, p: u32) -> Result<[u8; 32]> {
    let params = scrypt::Params::new(log_n, r, p, 32).map_err(|e| anyhow!("scrypt params: {e}"))?;
    let mut key = [0u8; 32];
    scrypt::scrypt(pass.as_bytes(), salt, &params, &mut key).map_err(|e| anyhow!("scrypt: {e}"))?;
    Ok(key)
}

fn keygen(path: &Path, role: &str) -> Result<[u8; 65]> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    use rand::RngCore;
    if path.exists() {
        bail!("{} exists; refusing to overwrite a key", path.display());
    }
    let sk = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
    let pk = sk.verifying_key().to_encoded_point(false);
    let pass = passphrase(&format!("passphrase for the {role} key"), true)?;
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let (log_n, r, p) = (18u8, 8u32, 1u32);
    let mut key = kdf(&pass, &salt, log_n, r, p)?;
    let cipher = Aes256Gcm::new((&key).into());
    let mut scalar = sk.to_bytes();
    let ct = cipher.encrypt(Nonce::from_slice(&nonce), scalar.as_slice()).map_err(|_| anyhow!("gcm"))?;
    scalar.zeroize();
    key.zeroize();
    let kf = KeyFile {
        version: 1,
        kdf: "scrypt".into(),
        log_n,
        r,
        p,
        salt_hex: hex::encode(salt),
        nonce_hex: hex::encode(nonce),
        ct_hex: hex::encode(ct),
        pubkey_hex: hex::encode(pk.as_bytes()),
        role: role.into(),
    };
    use std::os::unix::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new().create_new(true).write(true).mode(0o600).open(path)?;
    serde_json::to_writer_pretty(f, &kf)?;
    let mut out = [0u8; 65];
    out.copy_from_slice(pk.as_bytes());
    Ok(out)
}

struct OpenKey {
    sk: p256::ecdsa::SigningKey,
    pk: [u8; 65],
}

impl Drop for OpenKey {
    fn drop(&mut self) {
        // SigningKey zeroizes on drop in p256 0.13
    }
}

fn open_key(path: &Path) -> Result<OpenKey> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    let kf: KeyFile = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    if kf.version != 1 || kf.kdf != "scrypt" || kf.log_n < 18 {
        bail!("keyfile: unsupported or below the required strength (scrypt N ≥ 2^18)");
    }
    let pass = passphrase(&format!("passphrase for the {} key", kf.role), false)?;
    let mut key = kdf(&pass, &hex::decode(&kf.salt_hex)?, kf.log_n, kf.r, kf.p)?;
    let cipher = Aes256Gcm::new((&key).into());
    let pt = cipher
        .decrypt(Nonce::from_slice(&hex::decode(&kf.nonce_hex)?), hex::decode(&kf.ct_hex)?.as_slice())
        .map_err(|_| anyhow!("wrong passphrase or corrupted keyfile"))?;
    key.zeroize();
    let sk = p256::ecdsa::SigningKey::from_slice(&pt).map_err(|_| anyhow!("scalar"))?;
    let pk_bytes = sk.verifying_key().to_encoded_point(false);
    let mut pk = [0u8; 65];
    pk.copy_from_slice(pk_bytes.as_bytes());
    if hex::encode(pk) != kf.pubkey_hex {
        bail!("keyfile public key does not match its secret");
    }
    Ok(OpenKey { sk, pk })
}

fn pubkey_of(path: &Path) -> Result<[u8; 65]> {
    let kf: KeyFile = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    let v = hex::decode(&kf.pubkey_hex)?;
    <[u8; 65]>::try_from(v.as_slice()).map_err(|_| anyhow!("pubkey length"))
}

fn sign_message(key: &OpenKey, msg: &mut Message) -> Result<()> {
    let d = msg.digest();
    let sig: p256::ecdsa::Signature = key.sk.sign_prehash(&d)?;
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
    Ok(())
}

// ---------------------------------------------------------------- mandate JSON

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct MandateJson {
    version: u16,
    network: String,
    wallet: WalletJson,
    destinations: DestinationsJson,
    limits: LimitsJson,
    rules: RulesJson,
    #[serde(default)]
    chain: Option<ChainJson>,
    freshness: FreshnessJson,
    validity: ValidityJson,
    timelock_blocks: u32,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct WalletJson {
    fingerprint: String,
    account: String,
    script_types: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DestinationsJson {
    trusted: Vec<TrustedJson>,
    unlisted: CapsJson,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct TrustedJson {
    label: String,
    #[serde(default)]
    address: Option<String>,
    #[serde(default)]
    descriptor: Option<String>,
    #[serde(default)]
    gap: Option<u32>,
    max_per_tx: u64,
    max_per_window: u64,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CapsJson {
    max_per_tx: u64,
    max_per_window: u64,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct LimitsJson {
    max_per_tx: u64,
    window: WindowJson,
    max_fee_abs: u64,
    max_fee_rate: u64,
    #[serde(default)]
    max_fee_per_window: Option<u64>,
    max_inputs: u32,
    max_outputs: u32,
    own_index_gap: u32,
    max_reorg: u32,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct WindowJson {
    blocks: u32,
    max_outflow: u64,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RulesJson {
    sighash: String,
    payjoin: String,
    op_return: String,
    rbf: bool,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ChainJson {
    checkpoint: CheckpointJson,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CheckpointJson {
    hash: String,
    height: u32,
    time: u32,
    bits: String,
    period_start_time: u32,
    period_bits: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct FreshnessJson {
    required: bool,
    #[serde(default)]
    witness_pub_key: Option<String>,
    max_tip_lag: u32,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ValidityJson {
    not_after_height: u32,
}

fn network_of(s: &str) -> Result<Network> {
    Ok(match s {
        "mainnet" => Network::Mainnet,
        "testnet4" => Network::Testnet4,
        "signet" => Network::Signet,
        "regtest" => Network::Regtest,
        _ => bail!("network: {s}"),
    })
}

fn bits_of(s: &str) -> Result<u32> {
    Ok(u32::from_str_radix(s.trim_start_matches("0x"), 16)?)
}

fn hash_of(s: &str) -> Result<[u8; 32]> {
    // display order (as RPC prints) → internal order
    let mut v = hex::decode(s)?;
    if v.len() != 32 {
        bail!("hash length");
    }
    v.reverse();
    Ok(<[u8; 32]>::try_from(v.as_slice()).unwrap())
}

/// `wpkh([fp/84h/1h/0h]tpub.../<0;1>/*)` or `wpkh(tpub.../0/*)` → (xpub bytes, branches)
fn parse_descriptor(d: &str) -> Result<([u8; 78], Vec<u32>)> {
    let inner = d.strip_prefix("wpkh(").and_then(|x| x.strip_suffix(')')).ok_or_else(|| anyhow!("v1 accepts wpkh(KEY/branch/*) descriptors only"))?;
    let inner = inner.split_once('#').map(|(a, _)| a).unwrap_or(inner);
    let key_part = if let Some(rest) = inner.strip_prefix('[') {
        rest.split_once(']').map(|(_, k)| k).ok_or_else(|| anyhow!("origin"))?
    } else {
        inner
    };
    let (xpub_s, path) = key_part.split_once('/').ok_or_else(|| anyhow!("descriptor needs /branch/*"))?;
    let xpub = Xpub::from_str(xpub_s).map_err(|e| anyhow!("xpub: {e}"))?;
    let branches: Vec<u32> = match path {
        "0/*" => vec![0],
        "1/*" => vec![1],
        "<0;1>/*" | "<1;0>/*" => vec![0, 1],
        other => bail!("descriptor path {other}: v1 accepts /0/*, /1/* or /<0;1>/*"),
    };
    Ok((xpub.encode(), branches))
}

fn to_mandate(j: &MandateJson) -> Result<Mandate> {
    let network = network_of(&j.network)?;
    let bnet = network.to_bitcoin();
    let fp = hex::decode(&j.wallet.fingerprint)?;
    let fingerprint = <[u8; 4]>::try_from(fp.as_slice()).map_err(|_| anyhow!("fingerprint is 4 bytes hex"))?;
    let acc: Vec<u32> = j
        .wallet
        .account
        .split('/')
        .map(|p| p.trim_end_matches(['\'', 'h']).parse::<u32>().map_err(|e| anyhow!("account path: {e}")))
        .collect::<Result<_>>()?;
    if acc.len() != 3 {
        bail!("account path is purpose'/coin'/account'");
    }
    let script_types = j
        .wallet
        .script_types
        .iter()
        .map(|s| match s.as_str() {
            "p2wpkh" => Ok(ScriptType::P2wpkh),
            o => Err(anyhow!("scriptType {o}")),
        })
        .collect::<Result<_>>()?;
    let mut trusted = Vec::new();
    for t in &j.destinations.trusted {
        let matcher = match (&t.address, &t.descriptor) {
            (Some(a), None) => {
                let addr = bitcoin::Address::from_str(a)?.require_network(bnet).map_err(|e| anyhow!("address {a}: {e}"))?;
                Matcher::Address { script_pubkey: addr.script_pubkey().to_bytes() }
            }
            (None, Some(d)) => {
                let (xpub, branches) = parse_descriptor(d)?;
                Matcher::Descriptor { xpub, branches, gap: t.gap.unwrap_or(20) }
            }
            _ => bail!("trusted '{}': exactly one of address / descriptor", t.label),
        };
        trusted.push(TrustedDest { label: t.label.clone(), matcher, max_per_tx: t.max_per_tx, max_per_window: t.max_per_window });
    }
    let checkpoint = match &j.chain {
        Some(c) => Checkpoint {
            hash: hash_of(&c.checkpoint.hash)?,
            height: c.checkpoint.height,
            time: c.checkpoint.time,
            bits: bits_of(&c.checkpoint.bits)?,
            period_start_time: c.checkpoint.period_start_time,
            period_bits: bits_of(&c.checkpoint.period_bits)?,
        },
        None => bail!("chain.checkpoint missing: run `policy build --node-rpc …` to fill it from a node"),
    };
    let witness_pk = match &j.freshness.witness_pub_key {
        Some(h) => Some(<[u8; 65]>::try_from(hex::decode(h)?.as_slice()).map_err(|_| anyhow!("witness key is 65 bytes hex"))?),
        None => None,
    };
    let m = Mandate {
        version: j.version,
        network,
        wallet: WalletSpec { fingerprint, account: AccountPath { purpose: acc[0], coin: acc[1], account: acc[2] }, script_types },
        destinations: Destinations { trusted, unlisted: ClassCaps { max_per_tx: j.destinations.unlisted.max_per_tx, max_per_window: j.destinations.unlisted.max_per_window } },
        limits: Limits {
            max_per_tx: j.limits.max_per_tx,
            window_blocks: j.limits.window.blocks,
            window_max_outflow: j.limits.window.max_outflow,
            max_fee_abs: j.limits.max_fee_abs,
            max_fee_rate: j.limits.max_fee_rate,
            max_fee_per_window: j.limits.max_fee_per_window,
            max_inputs: j.limits.max_inputs,
            max_outputs: j.limits.max_outputs,
            own_index_gap: j.limits.own_index_gap,
            max_reorg: j.limits.max_reorg,
        },
        rules: Rules {
            sighash: match j.rules.sighash.as_str() {
                "ALL" => SighashRule::All,
                o => bail!("sighash {o}"),
            },
            payjoin: match j.rules.payjoin.as_str() {
                "none" => PayjoinRule::None,
                "inflow-only" => PayjoinRule::InflowOnly,
                "outflow-allowed" => PayjoinRule::OutflowAllowed,
                o => bail!("payjoin {o}"),
            },
            op_return: match j.rules.op_return.as_str() {
                "none" => OpReturnRule::None,
                "zero-value" => OpReturnRule::ZeroValue,
                o => bail!("opReturn {o}"),
            },
            rbf: j.rules.rbf,
        },
        checkpoint,
        freshness: Freshness { required: j.freshness.required, witness_pk, max_tip_lag: j.freshness.max_tip_lag },
        not_after_height: j.validity.not_after_height,
        timelock_blocks: j.timelock_blocks,
    };
    m.validate().map_err(|e| anyhow!("mandate invalid: {e:?}"))?;
    Ok(m)
}

/// Human view of a canonical mandate, for `policy show` / `diff`.
fn describe(m: &Mandate) -> Vec<(String, String)> {
    let mut v = vec![
        ("network".into(), format!("{:?}", m.network)),
        ("wallet.fingerprint".into(), hex::encode(m.wallet.fingerprint)),
        ("wallet.account".into(), format!("{}'/{}'/{}'", m.wallet.account.purpose, m.wallet.account.coin, m.wallet.account.account)),
    ];
    for t in &m.destinations.trusted {
        let how = match &t.matcher {
            Matcher::Address { script_pubkey } => format!("address {}", bitcoin::Address::from_script(bitcoin::Script::from_bytes(script_pubkey), m.network.to_bitcoin()).map(|a| a.to_string()).unwrap_or_else(|_| hex::encode(script_pubkey))),
            Matcher::Descriptor { xpub, branches, gap } => format!("descriptor {} branches {:?} gap {}", Xpub::decode(xpub).map(|x| x.to_string()).unwrap_or_default(), branches, gap),
        };
        v.push((format!("trusted[{}]", t.label), format!("{how}; maxPerTx {} maxPerWindow {}", t.max_per_tx, t.max_per_window)));
    }
    let l = &m.limits;
    v.extend([
        ("unlisted.maxPerTx".into(), m.destinations.unlisted.max_per_tx.to_string()),
        ("unlisted.maxPerWindow".into(), m.destinations.unlisted.max_per_window.to_string()),
        ("limits.maxPerTx".into(), l.max_per_tx.to_string()),
        ("limits.window".into(), format!("{} blocks, maxOutflow {}", l.window_blocks, l.window_max_outflow)),
        ("limits.maxFeeAbs".into(), l.max_fee_abs.to_string()),
        ("limits.maxFeeRate".into(), format!("{} sat/vB (lower-bound vsize)", l.max_fee_rate)),
        ("limits.maxFeePerWindow".into(), l.max_fee_per_window.map(|x| x.to_string()).unwrap_or_else(|| "none".into())),
        ("limits.maxInputs/maxOutputs".into(), format!("{}/{}", l.max_inputs, l.max_outputs)),
        ("limits.ownIndexGap".into(), l.own_index_gap.to_string()),
        ("limits.maxReorg".into(), l.max_reorg.to_string()),
        ("rules".into(), format!("sighash {:?}, payjoin {:?}, opReturn {:?}, rbf {}", m.rules.sighash, m.rules.payjoin, m.rules.op_return, m.rules.rbf)),
        ("chain.checkpoint".into(), {
            let mut h = m.checkpoint.hash;
            h.reverse();
            format!("{} @ {} (bits {:08x}, period start {} bits {:08x})", hex::encode(h), m.checkpoint.height, m.checkpoint.bits, m.checkpoint.period_start_time, m.checkpoint.period_bits)
        }),
        ("freshness".into(), format!("required {}, maxTipLag {}, witness {}", m.freshness.required, m.freshness.max_tip_lag, m.freshness.witness_pk.map(hex::encode).unwrap_or_else(|| "none".into()))),
        ("validity.notAfterHeight".into(), m.not_after_height.to_string()),
        ("timelockBlocks".into(), m.timelock_blocks.to_string()),
        ("hash".into(), hex::encode(m.hash())),
    ]);
    v
}

// ---------------------------------------------------------------- node RPC (read-only subset)

struct Node {
    url: String,
    auth: String,
}

impl Node {
    fn new(url: &str, cookie: &Path) -> Result<Self> {
        let c = std::fs::read_to_string(cookie)?;
        let (u, p) = c.trim().split_once(':').ok_or_else(|| anyhow!("cookie"))?;
        use base64::Engine;
        Ok(Node { url: url.into(), auth: base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}")) })
    }
    fn rpc(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
        let r: serde_json::Value = reqwest::blocking::Client::new()
            .post(&self.url)
            .header("Authorization", format!("Basic {}", self.auth))
            .json(&serde_json::json!({"jsonrpc":"1.0","id":"owner-cli","method":method,"params":params}))
            .send()?
            .json()?;
        if !r["error"].is_null() {
            bail!("rpc {method}: {}", r["error"]);
        }
        Ok(r["result"].clone())
    }
    fn header(&self, height: u32) -> Result<serde_json::Value> {
        let h = self.rpc("getblockhash", serde_json::json!([height]))?;
        self.rpc("getblockheader", serde_json::json!([h.as_str().unwrap_or(""), true]))
    }
    fn checkpoint(&self, height: u32) -> Result<CheckpointJson> {
        let h = self.header(height)?;
        let period_start = height - height % 2016;
        let p = self.header(period_start)?;
        Ok(CheckpointJson {
            hash: h["hash"].as_str().unwrap_or("").into(),
            height,
            time: h["time"].as_u64().unwrap_or(0) as u32,
            bits: h["bits"].as_str().unwrap_or("").into(),
            period_start_time: p["time"].as_u64().unwrap_or(0) as u32,
            period_bits: p["bits"].as_str().unwrap_or("").into(),
        })
    }
}

// ---------------------------------------------------------------- signerd client

struct Signerd {
    url: String,
    token: String,
}

impl Signerd {
    fn get(&self, path: &str) -> Result<serde_json::Value> {
        let r = reqwest::blocking::Client::new().get(format!("{}{path}", self.url)).bearer_auth(&self.token).send()?;
        let status = r.status();
        let v: serde_json::Value = r.json()?;
        if !status.is_success() {
            bail!("signerd {path}: {status} {v}");
        }
        Ok(v)
    }
    fn post(&self, path: &str, body: serde_json::Value) -> Result<serde_json::Value> {
        let r = reqwest::blocking::Client::new().post(format!("{}{path}", self.url)).bearer_auth(&self.token).json(&body).send()?;
        let status = r.status();
        let v: serde_json::Value = r.json()?;
        if !status.is_success() {
            bail!("signerd {path}: {status} {v}");
        }
        Ok(v)
    }
    fn enclave_id(&self) -> Result<[u8; 32]> {
        let st = self.get("/v1/status")?;
        let pk = hex::decode(st["identity_pk"].as_str().ok_or_else(|| anyhow!("status has no identity_pk (not initialised?)"))?)?;
        Ok(signer_core::sha256(&pk))
    }
    fn nonce(&self) -> Result<u64> {
        Ok(self.get("/v1/status")?["nonce"].as_u64().unwrap_or(0))
    }
}

// ---------------------------------------------------------------- wallet record

#[derive(Serialize, Deserialize)]
struct WalletRecord {
    network: String,
    xpub: String,
    fingerprint: String,
    identity_pk: String,
    enclave_id: String,
    card_hex: String,
    card_sig_hex: String,
    mrenclave: String,
    tier: String,
    recovery_blob_hex: String,
    owner_pk: String,
    recovery_pk: String,
}

// ---------------------------------------------------------------- CLI

#[derive(Parser)]
#[command(name = "owner-cli", about = "tee-signer owner tool")]
struct Cli {
    /// signerd base URL (through an SSH tunnel in practice).
    #[arg(long, env = "SIGNERD_URL", default_value = "http://127.0.0.1:7390", global = true)]
    signerd: String,
    /// signerd bearer token (or file path with --token-file).
    #[arg(long, env = "SIGNERD_TOKEN", global = true)]
    token: Option<String>,
    #[arg(long, env = "SIGNERD_TOKEN_FILE", global = true)]
    token_file: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate an encrypted keyfile (owner, recovery or witness role).
    Keygen {
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value = "owner")]
        role: String,
    },
    /// Print a keyfile's public key.
    Pubkey {
        #[arg(long)]
        key: PathBuf,
    },
    /// Initialise the enclave wallet: keys generated inside, owner and recovery bound; stores the identity card and the recovery blob.
    Init {
        #[arg(long)]
        network: String,
        #[arg(long)]
        owner_pk: String,
        #[arg(long)]
        recovery_pk: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Fill a mandate JSON's chain.checkpoint from a node (read-only RPC) or an Esplora API, and print the canonical hex + hash.
    PolicyBuild {
        #[arg(long)]
        json: PathBuf,
        #[arg(long)]
        node_rpc: Option<String>,
        #[arg(long)]
        node_cookie: Option<PathBuf>,
        /// e.g. https://mempool.space/signet/api
        #[arg(long)]
        esplora: Option<String>,
        #[arg(long)]
        checkpoint_height: Option<u32>,
        /// write the completed JSON back
        #[arg(long)]
        write: bool,
    },
    /// Show the installed mandate, or the diff between it and a JSON file.
    PolicyShow {
        #[arg(long)]
        json: Option<PathBuf>,
    },
    /// Sign a mandate JSON with the owner key and submit it (nonce 0 = install; otherwise an update).
    PolicySign {
        #[arg(long)]
        json: PathBuf,
        #[arg(long)]
        key: PathBuf,
        /// override the nonce (default: installed + 1, or 0 when not installed)
        #[arg(long)]
        nonce: Option<u64>,
        /// print the message hex only; do not submit
        #[arg(long)]
        dry_run: bool,
    },
    /// Owner / recovery messages.
    Cancel {
        #[arg(long)]
        key: PathBuf,
    },
    Unfreeze {
        #[arg(long)]
        key: PathBuf,
    },
    Rearm {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        seq: u64,
    },
    RotateOwner {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        new_owner_pk: String,
    },
    Recover {
        #[arg(long)]
        recovery_key: PathBuf,
        #[arg(long)]
        new_owner_pk: String,
    },
    /// Freeze signing (no signature needed).
    Freeze,
    /// Status.
    Status,
    /// Verify the recovery blob offline: decrypt with the recovery key, derive the xpub, compare.
    RecoveryVerify {
        #[arg(long)]
        wallet: PathBuf,
        #[arg(long)]
        recovery_key: PathBuf,
        /// print the 24 words (do this on an offline machine)
        #[arg(long)]
        print_mnemonic: bool,
    },
    /// Derive a receive or change address of the wallet (for funding and for trusted lists).
    Address {
        #[arg(long)]
        wallet: PathBuf,
        #[arg(long, default_value_t = 0)]
        branch: u32,
        #[arg(long, default_value_t = 0)]
        index: u32,
    },
    /// Build a PSBT spending one of the wallet's UTXOs (previous tx fetched from an Esplora API).
    PsbtBuild {
        #[arg(long)]
        wallet: PathBuf,
        #[arg(long, default_value = "https://mempool.space/signet/api")]
        esplora: String,
        /// txid:vout of the wallet's coin
        #[arg(long)]
        utxo: String,
        /// branch/index of the coin's address
        #[arg(long, default_value_t = 0)]
        branch: u32,
        #[arg(long, default_value_t = 0)]
        index: u32,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u64,
        #[arg(long)]
        fee: u64,
        #[arg(long, default_value_t = 0)]
        change_index: u32,
    },
    /// Ask signerd to judge and sign a PSBT (base64 or hex); prints the signed PSBT and the receipt.
    Sign {
        #[arg(long)]
        psbt: String,
    },
    /// Finalize a signed P2WPKH PSBT and print the raw transaction hex.
    Finalize {
        #[arg(long)]
        psbt: String,
    },
    /// Broadcast a raw transaction through an Esplora API.
    Broadcast {
        #[arg(long, default_value = "https://mempool.space/signet/api")]
        esplora: String,
        #[arg(long)]
        tx_hex: String,
    },
    /// Issue a freshness-witness token (the monitor's job; here for tests and manual operation).
    WitnessToken {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        tip_hash: String,
        #[arg(long)]
        tip_height: u32,
        #[arg(long)]
        last_seen_seq: u64,
        #[arg(long, default_value_t = 1)]
        issued: u64,
        /// submit to signerd (cached for the next sign)
        #[arg(long)]
        submit: bool,
    },
}

fn client(cli: &Cli) -> Result<Signerd> {
    let token = match (&cli.token, &cli.token_file) {
        (Some(t), _) => t.clone(),
        (None, Some(f)) => std::fs::read_to_string(f)?.trim().to_string(),
        _ => bail!("--token or --token-file"),
    };
    Ok(Signerd { url: cli.signerd.trim_end_matches('/').to_string(), token })
}

fn pk65(s: &str) -> Result<[u8; 65]> {
    <[u8; 65]>::try_from(hex::decode(s)?.as_slice()).map_err(|_| anyhow!("public key is 65 bytes SEC1 hex"))
}

fn submit_message(sd: &Signerd, msg: &Message) -> Result<()> {
    let r = sd.post("/v1/message", serde_json::json!({"message_hex": hex::encode(msg.encode())}))?;
    println!("{r}");
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match &cli.cmd {
        Cmd::Keygen { out, role } => {
            let pk = keygen(out, role)?;
            println!("{} key written to {} (scrypt N=2^18 + AES-256-GCM; keep it OFF the BTCPay box)", role, out.display());
            println!("pubkey: {}", hex::encode(pk));
        }
        Cmd::Pubkey { key } => println!("{}", hex::encode(pubkey_of(key)?)),
        Cmd::Init { network, owner_pk, recovery_pk, out } => {
            let sd = client(&cli)?;
            if owner_pk == recovery_pk {
                bail!("owner and recovery keys must differ (and live on different media and machines)");
            }
            let net = network_of(network)?;
            let r = sd.post("/v1/init", serde_json::json!({"network": net as u8, "owner_pk_hex": owner_pk, "recovery_pk_hex": recovery_pk}))?;
            let card_hex = r["card_hex"].as_str().unwrap_or("").to_string();
            let card = IdentityCard::decode(&hex::decode(&card_hex)?).map_err(|_| anyhow!("card"))?;
            let identity_pk = hex::decode(r["identity_pk"].as_str().unwrap_or(""))?;
            let card_sig = <[u8; 64]>::try_from(hex::decode(r["card_sig_hex"].as_str().unwrap_or(""))?.as_slice()).map_err(|_| anyhow!("card sig"))?;
            let secp = bitcoin::secp256k1::Secp256k1::new();
            let idpk = <[u8; 33]>::try_from(identity_pk.as_slice()).map_err(|_| anyhow!("identity pk"))?;
            if !signer_core::sign::verify_digest_secp(&secp, &idpk, &card.digest(), &card_sig) {
                bail!("identity card signature does not verify — do not fund this wallet");
            }
            if card.identity_pk != idpk || Xpub::decode(&card.xpub).map(|x| x.to_string()).unwrap_or_default() != r["xpub"].as_str().unwrap_or("") {
                bail!("identity card does not name the returned wallet — do not fund this wallet");
            }
            let rec = WalletRecord {
                network: network.clone(),
                xpub: r["xpub"].as_str().unwrap_or("").into(),
                fingerprint: r["fingerprint"].as_str().unwrap_or("").into(),
                identity_pk: hex::encode(idpk),
                enclave_id: hex::encode(signer_core::sha256(&idpk)),
                card_hex,
                card_sig_hex: hex::encode(card_sig),
                mrenclave: hex::encode(card.mrenclave),
                tier: card.tier.clone(),
                recovery_blob_hex: r["recovery_blob_hex"].as_str().unwrap_or("").into(),
                owner_pk: owner_pk.clone(),
                recovery_pk: recovery_pk.clone(),
            };
            std::fs::write(out, serde_json::to_string_pretty(&rec)?)?;
            println!("wallet record written to {}", out.display());
            println!("tier:        {}", rec.tier);
            println!("MRENCLAVE:   {}", rec.mrenclave);
            println!("xpub:        {}", rec.xpub);
            println!("fingerprint: {}", rec.fingerprint);
            println!("enclave id:  {}", rec.enclave_id);
            println!("Next: verify the recovery blob OFFLINE (`recovery-verify`), then `policy-build` and `policy-sign` (nonce 0 installs).");
        }
        Cmd::PolicyBuild { json, node_rpc, node_cookie, esplora, checkpoint_height, write } => {
            let text = std::fs::read_to_string(json)?;
            let mut j: MandateJson = serde_json::from_str(&text).context("mandate JSON (unknown fields are errors)")?;
            if let (Some(url), Some(cookie)) = (node_rpc, node_cookie) {
                let node = Node::new(url, cookie)?;
                let height = match checkpoint_height {
                    Some(h) => *h,
                    None => node.rpc("getblockchaininfo", serde_json::json!([]))?["headers"].as_u64().unwrap_or(0) as u32 - 6,
                };
                j.chain = Some(ChainJson { checkpoint: node.checkpoint(height)? });
                println!("checkpoint filled from the node at height {height}");
            } else if let Some(es) = esplora {
                let es = es.trim_end_matches('/');
                let tip: u32 = reqwest::blocking::get(format!("{es}/blocks/tip/height"))?.error_for_status()?.text()?.trim().parse()?;
                let height = checkpoint_height.unwrap_or(tip.saturating_sub(6));
                let hdr = |h: u32| -> Result<serde_json::Value> {
                    let hash = reqwest::blocking::get(format!("{es}/block-height/{h}"))?.error_for_status()?.text()?;
                    let v: serde_json::Value = reqwest::blocking::get(format!("{es}/block/{}", hash.trim()))?.error_for_status()?.json()?;
                    Ok(v)
                };
                let h = hdr(height)?;
                let p = hdr(height - height % 2016)?;
                j.chain = Some(ChainJson {
                    checkpoint: CheckpointJson {
                        hash: h["id"].as_str().unwrap_or("").into(),
                        height,
                        time: h["timestamp"].as_u64().unwrap_or(0) as u32,
                        bits: format!("{:08x}", h["bits"].as_u64().unwrap_or(0)),
                        period_start_time: p["timestamp"].as_u64().unwrap_or(0) as u32,
                        period_bits: format!("{:08x}", p["bits"].as_u64().unwrap_or(0)),
                    },
                });
                println!("checkpoint filled from {es} at height {height} (tip {tip})");
            }
            let m = to_mandate(&j)?;
            if *write {
                std::fs::write(json, serde_json::to_string_pretty(&j)?)?;
                println!("written back to {}", json.display());
            }
            for (k, v) in describe(&m) {
                println!("  {k:<28} {v}");
            }
            println!("canonical hex: {}", hex::encode(m.encode()));
        }
        Cmd::PolicyShow { json } => {
            let sd = client(&cli)?;
            let p = sd.get("/v1/policy")?;
            let installed = Mandate::decode(&hex::decode(p["mandate_hex"].as_str().unwrap_or(""))?).map_err(|_| anyhow!("installed mandate undecodable"))?;
            println!("installed (nonce {}):", p["nonce"]);
            let inst = describe(&installed);
            match json {
                None => {
                    for (k, v) in &inst {
                        println!("  {k:<28} {v}");
                    }
                }
                Some(path) => {
                    let j: MandateJson = serde_json::from_str(&std::fs::read_to_string(path)?)?;
                    let new = to_mandate(&j)?;
                    let nw = describe(&new);
                    for (k, v) in &nw {
                        let old = inst.iter().find(|(ik, _)| ik == k).map(|(_, iv)| iv.clone());
                        match old {
                            Some(ref o) if o == v => println!("  ok   {k:<28} {v}"),
                            Some(o) => println!("  DIFF {k:<28} installed: {o}\n       {:<28} file:      {v}", ""),
                            None => println!("  NEW  {k:<28} {v}"),
                        }
                    }
                    for (k, v) in &inst {
                        if !nw.iter().any(|(nk, _)| nk == k) {
                            println!("  GONE {k:<28} {v}");
                        }
                    }
                    match compare(&installed, &new) {
                        Ok(Change::Tightening) => println!("classification: TIGHTENING (applies at once)"),
                        Ok(Change::Loosening) => println!("classification: LOOSENING (waits {} blocks after acceptance)", installed.timelock_blocks),
                        Err(e) => println!("classification: REFUSED — immutable field changed: {e:?}"),
                    }
                }
            }
            if !p["pending"].is_null() {
                println!("pending: {}", p["pending"]);
            }
        }
        Cmd::PolicySign { json, key, nonce, dry_run } => {
            let j: MandateJson = serde_json::from_str(&std::fs::read_to_string(json)?)?;
            let m = to_mandate(&j)?;
            let sd = client(&cli)?;
            let enclave_id = sd.enclave_id()?;
            let installed = sd.get("/v1/policy").ok();
            let nonce = match nonce {
                Some(n) => *n,
                None => match &installed {
                    Some(p) => p["nonce"].as_u64().unwrap_or(0) + 1,
                    None => 0,
                },
            };
            println!("signing mandate {} for enclave {} at nonce {nonce}", hex::encode(m.hash()), hex::encode(enclave_id));
            for (k, v) in describe(&m) {
                println!("  {k:<28} {v}");
            }
            // WYSIWYS: what is hashed is exactly the canonical bytes shown above (hash line)
            let okey = open_key(key)?;
            println!("signer (owner key): {}", hex::encode(okey.pk));
            let mut msg = Message::PolicyUpdate { enclave_id, nonce, mandate: m.encode(), sig: [0; 64] };
            sign_message(&okey, &mut msg)?;
            if *dry_run {
                println!("message hex: {}", hex::encode(msg.encode()));
                return Ok(());
            }
            if nonce == 0 {
                let r = sd.post("/v1/install", serde_json::json!({"mandate_hex": hex::encode(m.encode()), "sig_hex": hex::encode(msg.sig())}))?;
                println!("installed: {r}");
            } else {
                submit_message(&sd, &msg)?;
            }
        }
        Cmd::Cancel { key } => {
            let sd = client(&cli)?;
            let okey = open_key(key)?;
            let mut msg = Message::Cancel { enclave_id: sd.enclave_id()?, nonce: sd.nonce()? + 1, sig: [0; 64] };
            sign_message(&okey, &mut msg)?;
            submit_message(&sd, &msg)?;
        }
        Cmd::Unfreeze { key } => {
            let sd = client(&cli)?;
            let okey = open_key(key)?;
            let mut msg = Message::Unfreeze { enclave_id: sd.enclave_id()?, nonce: sd.nonce()? + 1, sig: [0; 64] };
            sign_message(&okey, &mut msg)?;
            submit_message(&sd, &msg)?;
        }
        Cmd::Rearm { key, seq } => {
            let sd = client(&cli)?;
            let okey = open_key(key)?;
            let mut msg = Message::Rearm { enclave_id: sd.enclave_id()?, nonce: sd.nonce()? + 1, seq: *seq, sig: [0; 64] };
            sign_message(&okey, &mut msg)?;
            submit_message(&sd, &msg)?;
        }
        Cmd::RotateOwner { key, new_owner_pk } => {
            let sd = client(&cli)?;
            let okey = open_key(key)?;
            let mut msg = Message::RotateOwner { enclave_id: sd.enclave_id()?, nonce: sd.nonce()? + 1, new_owner_pk: pk65(new_owner_pk)?, sig: [0; 64] };
            sign_message(&okey, &mut msg)?;
            submit_message(&sd, &msg)?;
        }
        Cmd::Recover { recovery_key, new_owner_pk } => {
            let sd = client(&cli)?;
            let rkey = open_key(recovery_key)?;
            let mut msg = Message::Recover { enclave_id: sd.enclave_id()?, nonce: sd.nonce()? + 1, new_owner_pk: pk65(new_owner_pk)?, sig: [0; 64] };
            sign_message(&rkey, &mut msg)?;
            submit_message(&sd, &msg)?;
        }
        Cmd::Freeze => {
            let sd = client(&cli)?;
            println!("{}", sd.post("/v1/freeze", serde_json::json!({}))?);
        }
        Cmd::Status => {
            let sd = client(&cli)?;
            println!("{}", serde_json::to_string_pretty(&sd.get("/v1/status")?)?);
        }
        Cmd::RecoveryVerify { wallet, recovery_key, print_mnemonic } => {
            let w: WalletRecord = serde_json::from_str(&std::fs::read_to_string(wallet)?)?;
            let rkey = open_key(recovery_key)?;
            let fp = <[u8; 4]>::try_from(hex::decode(&w.fingerprint)?.as_slice()).map_err(|_| anyhow!("fingerprint"))?;
            let xpub = Xpub::from_str(&w.xpub)?.encode();
            let mut sk_bytes = [0u8; 32];
            sk_bytes.copy_from_slice(&rkey.sk.to_bytes());
            let entropy = recovery_decrypt(&sk_bytes, &fp, &xpub, &hex::decode(&w.recovery_blob_hex)?)?;
            sk_bytes.zeroize();
            let mnemonic = signer_core::bip39::mnemonic(&entropy);
            let seed = signer_core::bip39::seed(&mnemonic);
            let net = network_of(&w.network)?;
            let secp = bitcoin::secp256k1::Secp256k1::new();
            let master = bitcoin::bip32::Xpriv::new_master(net.to_bitcoin(), &seed)?;
            let path = bitcoin::bip32::DerivationPath::from(vec![
                bitcoin::bip32::ChildNumber::from_hardened_idx(84)?,
                bitcoin::bip32::ChildNumber::from_hardened_idx(net.coin_type())?,
                bitcoin::bip32::ChildNumber::from_hardened_idx(0)?,
            ]);
            let derived = Xpub::from_priv(&secp, &master.derive_priv(&secp, &path)?);
            if derived.encode() != xpub || *master.fingerprint(&secp).as_bytes() != fp {
                bail!("the recovery blob decrypts, but NOT to this wallet — do not fund it");
            }
            println!("recovery blob OK: decrypts to a 24-word mnemonic whose m/84'/{}'/0' xpub and fingerprint match the wallet record", net.coin_type());
            if *print_mnemonic {
                println!("{mnemonic}");
            }
        }
        Cmd::Address { wallet, branch, index } => {
            let w: WalletRecord = serde_json::from_str(&std::fs::read_to_string(wallet)?)?;
            println!("{}", psbt::address(&w.xpub, network_of(&w.network)?, *branch, *index)?);
        }
        Cmd::PsbtBuild { wallet, esplora, utxo, branch, index, to, amount, fee, change_index } => {
            let w: WalletRecord = serde_json::from_str(&std::fs::read_to_string(wallet)?)?;
            let b64 = psbt::build(&w.xpub, &w.fingerprint, network_of(&w.network)?, esplora, utxo, *branch, *index, to, *amount, *fee, *change_index)?;
            println!("{b64}");
        }
        Cmd::Sign { psbt } => {
            let sd = client(&cli)?;
            let r = sd.post("/v1/sign", serde_json::json!({"psbt": psbt}))?;
            println!("{}", serde_json::to_string_pretty(&r)?);
        }
        Cmd::Finalize { psbt } => println!("{}", psbt::finalize(psbt)?),
        Cmd::Broadcast { esplora, tx_hex } => println!("{}", psbt::broadcast(esplora, tx_hex)?),
        Cmd::WitnessToken { key, tip_hash, tip_height, last_seen_seq, issued, submit } => {
            let sd = client(&cli)?;
            let wkey = open_key(key)?;
            let mut msg = Message::WitnessToken {
                enclave_id: sd.enclave_id()?,
                tip_hash: hash_of(tip_hash)?,
                tip_height: *tip_height,
                last_seen_seq: *last_seen_seq,
                issued: *issued,
                sig: [0; 64],
            };
            sign_message(&wkey, &mut msg)?;
            println!("token hex: {}", hex::encode(msg.encode()));
            if *submit {
                submit_message(&sd, &msg)?;
            }
        }
    }
    Ok(())
}

fn recovery_decrypt(recovery_sk: &[u8; 32], fingerprint: &[u8; 4], xpub: &[u8; 78], blob: &[u8]) -> Result<[u8; 32]> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Nonce};
    use hkdf::Hkdf;
    use sha2::Sha256;
    if blob.len() != 65 + 32 + 16 {
        bail!("blob length");
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
    let pt = cipher.decrypt(Nonce::from_slice(&[0u8; 12]), Payload { msg: &blob[65..], aad: &aad }).map_err(|_| anyhow!("the blob does not open with this key for this wallet"))?;
    key.zeroize();
    let mut out = [0u8; 32];
    if pt.len() != 32 {
        bail!("plaintext length");
    }
    out.copy_from_slice(&pt);
    Ok(out)
}
