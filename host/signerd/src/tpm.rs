//! REQ-r9 — the host's side of the TPM counter: a transport that can `certify` the pinned NV
//! counter over the enclave's nonce and `increment` it after every persisted blob. Untrusted
//! plumbing by design: a lying transport can only make the enclave refuse (`STATE_STALE`,
//! `TPM_SIG`, …), never accept a stale state. Three transports: `software` (the T0 bench — a key
//! and a counter in a file, with switches to lie for the negative vectors), `remote` (the dev
//! bench — the owner's laptop TPM behind a two-operation agent reached over a reverse ssh tunnel),
//! and `tss` (a local TPM through libtss2 — `tpm_tss.rs`, build feature `tss`). Configured by
//! `SIGNERD_TPM`.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use serde::{Deserialize, Serialize};
use signer_core::proto::TpmProof;
use signer_core::tpm_attest::{build_nv_attest, NV_NAME_LEN};

/// What the owner needs to anchor: the attestation key, the index Name, the live counter.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TpmInfo {
    pub ak_pk_hex: String,
    pub nv_name_hex: String,
    pub counter: u64,
    pub transport: String,
}

/// The two operations the enclave's freshness needs, plus a read for the owner's anchoring.
pub trait TpmTransport: Send {
    /// A label for logs and status.
    fn describe(&self) -> String;
    /// The key, the Name and the counter as the transport sees them (an unauthenticated read;
    /// the owner anchors from an attested `certify`, C-R9-D).
    fn info(&mut self) -> Result<TpmInfo>;
    /// `TPM2_NV_Certify` over the pinned index with `nonce` as qualifying data.
    fn certify(&mut self, nonce: &[u8; 32]) -> Result<TpmProof>;
    /// `TPM2_NV_Increment`; returns the new value when the transport knows it.
    fn increment(&mut self) -> Result<u64>;
}

/// `SIGNERD_TPM=software:<file>` | `remote:<http://host:port>` | `tss:<tcti>?ak=0x…&nv=0x…` | unset.
pub fn from_env() -> Result<Option<Box<dyn TpmTransport>>> {
    let Ok(spec) = std::env::var("SIGNERD_TPM") else { return Ok(None) };
    let spec = spec.trim();
    if spec.is_empty() || spec == "none" {
        return Ok(None);
    }
    if let Some(path) = spec.strip_prefix("software:") {
        return Ok(Some(Box::new(SoftwareTpm::open(Path::new(path))?)));
    }
    if let Some(url) = spec.strip_prefix("remote:") {
        return Ok(Some(Box::new(RemoteTpm::new(url)?)));
    }
    if let Some(rest) = spec.strip_prefix("tss:") {
        #[cfg(feature = "tss")]
        {
            let spec = crate::tpm_tss::TssSpec::parse(rest)?;
            return Ok(Some(Box::new(crate::tpm_tss::TssTpm::open(spec)?)));
        }
        #[cfg(not(feature = "tss"))]
        {
            let _ = rest;
            return Err(anyhow!("SIGNERD_TPM=tss:… needs a signerd built with `--features tss`"));
        }
    }
    Err(anyhow!("SIGNERD_TPM: use software:<file>, remote:<url> or tss:<tcti>?ak=0x…&nv=0x…"))
}

// ---------------------------------------------------------------------------------------------
// software stand-in (T0)

#[derive(Serialize, Deserialize)]
struct SoftFile {
    sk_hex: String,
    name_hex: String,
    counter: u64,
}

/// A P-256 key and a counter in a file. `SIGNERD_TPM_LIE=stale|nonce|sig|index|parse` makes it
/// lie in one specific way — the negative vectors of `scripts/e2e-local.sh`.
pub struct SoftwareTpm {
    path: PathBuf,
    sk: p256::ecdsa::SigningKey,
    name: [u8; NV_NAME_LEN],
    counter: u64,
    lie: Option<String>,
}

impl SoftwareTpm {
    pub fn open(path: &Path) -> Result<Self> {
        let lie = std::env::var("SIGNERD_TPM_LIE").ok().filter(|s| !s.is_empty());
        if path.exists() {
            let f: SoftFile = serde_json::from_str(&std::fs::read_to_string(path)?).context("software tpm file")?;
            let sk_bytes = hex::decode(&f.sk_hex)?;
            let sk = p256::ecdsa::SigningKey::from_slice(&sk_bytes).map_err(|_| anyhow!("software tpm key"))?;
            let name_v = hex::decode(&f.name_hex)?;
            let name = <[u8; NV_NAME_LEN]>::try_from(name_v.as_slice()).map_err(|_| anyhow!("software tpm name"))?;
            return Ok(SoftwareTpm { path: path.to_path_buf(), sk, name, counter: f.counter, lie });
        }
        use rand::RngCore;
        let sk = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let mut name = [0u8; NV_NAME_LEN];
        rand::thread_rng().fill_bytes(&mut name[2..]);
        name[0] = 0x00;
        name[1] = 0x0B;
        let t = SoftwareTpm { path: path.to_path_buf(), sk, name, counter: 0, lie };
        t.save()?;
        Ok(t)
    }
    fn save(&self) -> Result<()> {
        let f = SoftFile {
            sk_hex: hex::encode(self.sk.to_bytes()),
            name_hex: hex::encode(self.name),
            counter: self.counter,
        };
        let tmp = self.path.with_extension("tmp");
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut o = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
            o.write_all(serde_json::to_string_pretty(&f)?.as_bytes())?;
            o.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
    fn ak_pk(&self) -> [u8; 65] {
        let mut pk = [0u8; 65];
        pk.copy_from_slice(self.sk.verifying_key().to_encoded_point(false).as_bytes());
        pk
    }
    fn sign(sk: &p256::ecdsa::SigningKey, attest: &[u8]) -> [u8; 64] {
        let d = signer_core::sha256(attest);
        let sig: p256::ecdsa::Signature = sk.sign_prehash(&d).expect("sign");
        let sig = sig.normalize_s().unwrap_or(sig);
        let mut s = [0u8; 64];
        s.copy_from_slice(&sig.to_bytes());
        s
    }
}

impl TpmTransport for SoftwareTpm {
    fn describe(&self) -> String {
        format!(
            "software:{}{}",
            self.path.display(),
            self.lie.as_ref().map(|l| format!(" (LYING: {l})")).unwrap_or_default()
        )
    }
    fn info(&mut self) -> Result<TpmInfo> {
        Ok(TpmInfo {
            ak_pk_hex: hex::encode(self.ak_pk()),
            nv_name_hex: hex::encode(self.name),
            counter: self.counter,
            transport: self.describe(),
        })
    }
    fn certify(&mut self, nonce: &[u8; 32]) -> Result<TpmProof> {
        let signer_name = [0u8; NV_NAME_LEN];
        let (mut n, mut name, mut counter, mut sk) = (*nonce, self.name, self.counter, self.sk.clone());
        match self.lie.as_deref() {
            Some("stale") => counter = counter.saturating_sub(1),
            Some("nonce") => n[0] ^= 0xFF,
            Some("index") => name[5] ^= 0xFF,
            Some("sig") => sk = p256::ecdsa::SigningKey::random(&mut rand::thread_rng()),
            Some("parse") => {
                let attest = build_nv_attest(&signer_name, &n, &name, counter);
                let sig = Self::sign(&sk, &attest);
                return Ok(TpmProof { attest: attest[..attest.len() - 3].to_vec(), sig });
            }
            _ => {}
        }
        let attest = build_nv_attest(&signer_name, &n, &name, counter);
        let sig = Self::sign(&sk, &attest);
        Ok(TpmProof { attest, sig })
    }
    fn increment(&mut self) -> Result<u64> {
        self.counter = self.counter.checked_add(1).ok_or_else(|| anyhow!("counter exhausted"))?;
        self.save()?;
        Ok(self.counter)
    }
}

// ---------------------------------------------------------------------------------------------
// remote agent (dev bench: the owner's laptop TPM behind `tee-tpm-agent`, reached over a tunnel)

/// A minimal HTTP/1.1 client over `std::net` (no async, no extra crate): the agent speaks three
/// routes — `GET /info`, `POST /certify` `{"nonce_hex"}`, `POST /increment`.
pub struct RemoteTpm {
    host: String,
    port: u16,
    base_path: String,
}

#[derive(Deserialize)]
struct CertifyOut {
    attest_hex: String,
    sig_hex: String,
}

#[derive(Deserialize)]
struct IncrementOut {
    counter: u64,
}

impl RemoteTpm {
    pub fn new(url: &str) -> Result<Self> {
        let rest =
            url.strip_prefix("http://").ok_or_else(|| anyhow!("remote tpm: http:// only (loopback or a tunnel)"))?;
        let (hostport, path) = match rest.find('/') {
            Some(i) => (&rest[..i], rest[i..].trim_end_matches('/').to_string()),
            None => (rest, String::new()),
        };
        let (host, port) = match hostport.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse::<u16>().context("remote tpm port")?),
            None => (hostport.to_string(), 80),
        };
        Ok(RemoteTpm { host, port, base_path: path })
    }
    fn request(&self, method: &str, path: &str, body: Option<&str>) -> Result<String> {
        let mut s = TcpStream::connect((self.host.as_str(), self.port)).context("remote tpm: connect")?;
        s.set_read_timeout(Some(Duration::from_secs(20)))?;
        s.set_write_timeout(Some(Duration::from_secs(20)))?;
        let body = body.unwrap_or("");
        let req = format!(
            "{method} {}{path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            self.base_path,
            self.host,
            body.len()
        );
        s.write_all(req.as_bytes())?;
        let mut resp = Vec::new();
        s.read_to_end(&mut resp)?;
        let text = String::from_utf8_lossy(&resp);
        let (head, b) = text.split_once("\r\n\r\n").ok_or_else(|| anyhow!("remote tpm: malformed response"))?;
        let status = head.lines().next().unwrap_or("");
        if !status.contains(" 200") {
            return Err(anyhow!("remote tpm: {status}: {}", b.trim()));
        }
        Ok(b.to_string())
    }
}

impl TpmTransport for RemoteTpm {
    fn describe(&self) -> String {
        format!("remote:http://{}:{}{}", self.host, self.port, self.base_path)
    }
    fn info(&mut self) -> Result<TpmInfo> {
        let b = self.request("GET", "/info", None)?;
        let mut i: TpmInfo = serde_json::from_str(&b).context("remote tpm: info json")?;
        i.transport = self.describe();
        Ok(i)
    }
    fn certify(&mut self, nonce: &[u8; 32]) -> Result<TpmProof> {
        let b = self.request("POST", "/certify", Some(&format!("{{\"nonce_hex\":\"{}\"}}", hex::encode(nonce))))?;
        let o: CertifyOut = serde_json::from_str(&b).context("remote tpm: certify json")?;
        let sig_v = hex::decode(&o.sig_hex)?;
        let sig = <[u8; 64]>::try_from(sig_v.as_slice()).map_err(|_| anyhow!("remote tpm: sig length"))?;
        Ok(TpmProof { attest: hex::decode(&o.attest_hex)?, sig })
    }
    fn increment(&mut self) -> Result<u64> {
        let b = self.request("POST", "/increment", Some("{}"))?;
        let o: IncrementOut = serde_json::from_str(&b).context("remote tpm: increment json")?;
        Ok(o.counter)
    }
}
