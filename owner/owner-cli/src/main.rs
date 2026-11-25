//! owner-cli — the owner's side (`docs/DESIGN.md §6–7`). Runs on the owner's machine, never on
//! the BTCPay box. Holds or reaches the owner key, builds mandates from JSON into the canonical
//! bytes the enclave signs over, shows the diff against what is installed, signs, submits; runs
//! init and verifies the identity card and the recovery blob offline.
//!
//! Key backends in this build: an encrypted keyfile (scrypt N=2^18 + AES-256-GCM; the permitted
//! floor, owner decision D3), a TPM 2.0 persistent key (`tpm:<handle>`, REQ-r6 scenario 1) and a
//! YubiKey 5 PIV slot (`piv:<slot>[@<serial>]`, REQ-r6 scenario 2), the last two through TPM_sign's
//! `hw-signer`. The trait boundary is the same for all: a 32-byte digest in, low-s `(r, s)` out;
//! the enclave never learns which backend signed.

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

mod monitor;
mod piv_attest;
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
    /// Owner-written reminder of WHERE the passphrase is kept (never what it is) — shown before the
    /// prompt. Optional; absent in files written before 2026-11-12.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hint: Option<String>,
}

/// A hint may say where the passphrase is kept, never what it is: it must be non-empty, short, and must
/// not contain the passphrase (either direction, case-insensitive). The format of the passphrase is
/// not checkable here — the FAQ says why "4 digits" or "like the PIN" is a bad hint.
fn check_hint(hint: &str, pass: &str) -> Result<String> {
    let h = hint.trim();
    if h.is_empty() {
        bail!("empty hint");
    }
    if h.chars().count() > 200 {
        bail!("hint too long (200 characters max)");
    }
    let (hl, pl) = (h.to_lowercase(), pass.to_lowercase());
    if hl.contains(&pl) || pl.contains(&hl) {
        bail!("REFUSED: the hint contains the passphrase (or the passphrase contains the hint) — a hint says WHERE the passphrase is kept, never what it is");
    }
    Ok(h.to_string())
}

/// The owner's PIN hint from the wallet record (set with `key-hint --pin --set …`), shown before a
/// YubiKey PIN prompt. Set once at start-up when `--wallet-record` is given.
static PIN_HINT: std::sync::OnceLock<String> = std::sync::OnceLock::new();

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
    // Owner's rule (2026-11-10): a floor of 4 characters, not 8 — a passphrase the owner forgets or
    // sticks to the monitor protects nothing; the keyfile relies on scrypt (N=2^18) and on never
    // leaving the owner's machine. Checked when a passphrase is set, not when it is used.
    if confirm && a.chars().count() < 4 {
        bail!("passphrase too short (4+)");
    }
    Ok(a)
}

/// An activity indicator for steps that take seconds (scrypt, Intel collateral, the explorer): a
/// spinner line on stderr while the work runs, cleared when it ends; a single plain line when stderr is
/// not a terminal (logs). Owner's ask, 2026-11-12: "a black screen is not a status".
struct Busy {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
    width: usize,
}

fn busy(msg: &str) -> Busy {
    use std::io::{IsTerminal, Write};
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let width = msg.chars().count().saturating_add(4);
    if !std::io::stderr().is_terminal() {
        eprintln!("… {msg}");
        return Busy { stop, handle: None, width: 0 };
    }
    let (s2, m) = (stop.clone(), msg.to_string());
    let handle = std::thread::spawn(move || {
        let frames = ['|', '/', '-', '\\'];
        let mut i = 0usize;
        while !s2.load(std::sync::atomic::Ordering::Relaxed) {
            eprint!("\r{} {m} ", frames[i % 4]);
            let _ = std::io::stderr().flush();
            i = i.wrapping_add(1); // the spinner's frame counter: wraps by design
            std::thread::sleep(std::time::Duration::from_millis(150));
        }
    });
    Busy { stop, handle: Some(handle), width }
}

impl Drop for Busy {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
            eprint!("\r{:width$}\r", "", width = self.width);
        }
    }
}

fn kdf(pass: &str, salt: &[u8], log_n: u8, r: u32, p: u32) -> Result<[u8; 32]> {
    let params = scrypt::Params::new(log_n, r, p, 32).map_err(|e| anyhow!("scrypt params: {e}"))?;
    let mut key = [0u8; 32];
    let _b = busy("deriving the key from the passphrase (scrypt N=2^18 — up to half a minute)");
    scrypt::scrypt(pass.as_bytes(), salt, &params, &mut key).map_err(|e| anyhow!("scrypt: {e}"))?;
    Ok(key)
}

fn keygen(path: &Path, role: &str, hint: Option<&str>) -> Result<[u8; 65]> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    use rand::RngCore;
    if path.exists() {
        bail!("{} exists; refusing to overwrite a key", path.display());
    }
    let sk = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
    let pk = sk.verifying_key().to_encoded_point(false);
    let pass = passphrase(&format!("passphrase for the {role} key"), true)?;
    // The hint is written at creation, because the owner will not remember it either (owner, 2026-11-12):
    // without --hint, ask for it when a human is at the terminal (Enter = none). Non-interactive runs
    // (tests, OWNER_PASSPHRASE set) are not asked.
    let asked;
    let hint = match hint {
        Some(h) => Some(h),
        None if std::env::var("OWNER_PASSPHRASE").is_err() && std::io::IsTerminal::is_terminal(&std::io::stdin()) => {
            eprint!("hint for this key — where the passphrase is kept; stored in the key file and shown before every prompt (Enter = none): ");
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            asked = line.trim().to_string();
            if asked.is_empty() {
                None
            } else {
                Some(asked.as_str())
            }
        }
        None => None,
    };
    let hint = hint.map(|h| check_hint(h, &pass)).transpose()?;
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
        hint,
    };
    use std::os::unix::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new().create_new(true).write(true).mode(0o600).open(path)?;
    serde_json::to_writer_pretty(f, &kf)?;
    let mut out = [0u8; 65];
    out.copy_from_slice(pk.as_bytes());
    Ok(out)
}

/// Where a P-256 owner/recovery/witness key lives. The enclave never learns which: the message
/// digest and the 64-byte signature are the same either way (REQ-r6 §2).
enum Signer {
    /// Encrypted keyfile (scrypt + AES-256-GCM), decrypted into memory for one command.
    File(p256::ecdsa::SigningKey),
    /// TPM 2.0 persistent key: the scalar never exists outside the TPM; `sign_digest` runs inside it.
    Tpm(hw_signer::tpm::TpmSigner),
    /// YubiKey 5 PIV slot: the key was generated on the device (`ykman piv keys generate`, PIN
    /// ALWAYS + touch ALWAYS); every signature is a PIN and a touch on the key (C-R6-3).
    Piv(hw_signer::yubikey_piv::YubiKeyPivSigner),
}

struct OpenKey {
    signer: Signer,
    pk: [u8; 65],
}

impl OpenKey {
    /// ECDSA over a 32-byte digest, low-s, `r ‖ s`.
    fn sign_digest(&self, d: &[u8; 32]) -> Result<[u8; 64]> {
        let mut out = [0u8; 64];
        match &self.signer {
            Signer::File(sk) => {
                let sig: p256::ecdsa::Signature = sk.sign_prehash(d)?;
                let sig = sig.normalize_s().unwrap_or(sig);
                out.copy_from_slice(&sig.to_bytes());
            }
            Signer::Tpm(t) => out = hw_sign(t, d, "TPM")?,
            Signer::Piv(y) => out = hw_sign(y, d, "YubiKey")?,
        }
        Ok(out)
    }
    /// The raw scalar — only a keyfile has one (the recovery key's ECDH); a hardware key refuses.
    fn scalar(&self) -> Result<zeroize::Zeroizing<[u8; 32]>> {
        match &self.signer {
            Signer::File(sk) => {
                let mut b = zeroize::Zeroizing::new([0u8; 32]);
                b.copy_from_slice(&sk.to_bytes());
                Ok(b)
            }
            Signer::Tpm(_) | Signer::Piv(_) => bail!("this key lives in hardware; the recovery key must be an (offline) keyfile because opening the recovery blob needs ECDH"),
        }
    }
}

/// One signature on a hardware backend: low-s normalised by `hw-signer` (the same function for the
/// TPM and the YubiKey), then `r ‖ s` — the format the enclave verifies, whatever signed.
fn hw_sign(s: &impl hw_signer::HardwareSigner, d: &[u8; 32], what: &str) -> Result<[u8; 64]> {
    let sig = hw_signer::normalize_low_s(s.sign_digest(d).map_err(|e| anyhow!("{what} sign: {e}"))?);
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&sig.r);
    out[32..].copy_from_slice(&sig.s);
    Ok(out)
}

/// `tpm:0x81000100` → the persistent handle; anything else is a keyfile path.
fn tpm_handle(locator: &str) -> Option<Result<u32>> {
    let h = locator.strip_prefix("tpm:")?;
    Some(u32::from_str_radix(h.trim_start_matches("0x"), 16).map_err(|_| anyhow!("TPM handle: hex like 0x81000100")))
}

/// `piv:9a` or `piv:9a@12345678` → the PIV slot and, when given, the YubiKey's serial number.
fn piv_locator(locator: &str) -> Option<Result<(hw_signer::yubikey_piv::PivSlot, Option<u32>)>> {
    let rest = locator.strip_prefix("piv:")?;
    let (slot, serial) = match rest.split_once('@') {
        Some((s, n)) => (s, Some(n)),
        None => (rest, None),
    };
    Some((|| {
        let slot: hw_signer::yubikey_piv::PivSlot =
            slot.parse().map_err(|e| anyhow!("PIV slot {slot:?}: {e} (9a, 9c, 9d, 9e or 82..95)"))?;
        let serial = serial
            .map(|n| n.parse::<u32>().map_err(|_| anyhow!("YubiKey serial {n:?}: decimal, as `ykman info` prints it")))
            .transpose()?;
        Ok((slot, serial))
    })())
}

/// Open an owner-role key in a YubiKey PIV slot. Refuses any slot whose metadata does not say
/// PIN ALWAYS and touch ALWAYS: an owner signature is a PIN and a touch on the key, every time;
/// a CACHED touch would let malware on this machine piggyback on one touch. With `for_signing`
/// the PIN is prompted at the first signature (never stored, never taken from the environment);
/// without, the key can show its public key and nothing else.
fn open_piv(
    slot: hw_signer::yubikey_piv::PivSlot,
    serial: Option<u32>,
    for_signing: bool,
) -> Result<hw_signer::yubikey_piv::YubiKeyPivSigner> {
    use hw_signer::yubikey_piv::{slot_name, YubiKeyPivSigner};
    let y = YubiKeyPivSigner::open(serial, slot)
        .map_err(|e| anyhow!("YubiKey open piv:{}: {e} (is pcscd running? is the key plugged in?)", slot_name(slot)))?;
    let name = format!("piv:{}@{}", slot_name(slot), y.serial());
    owner_slot_policy_ok(&name, y.pin_policy(), y.touch_policy())?;
    let y = y.with_touch_notice(move || eprintln!("touch the YubiKey to sign ({name})…"));
    if !for_signing {
        return Ok(y);
    }
    let prompt = format!("PIN for the YubiKey PIV slot {} (serial {})", slot_name(slot), y.serial());
    Ok(y.with_pin_provider(move || piv_pin(&prompt).map_err(|e| hw_signer::SignerError::Key(format!("PIN: {e}")))))
}

/// The owner role accepts exactly PIN ALWAYS + touch ALWAYS (the auditor's ship-condition on C-R6-3):
/// `Once` would let one PIN cover a whole card session, `Cached` lets one touch cover 15 s of
/// signatures, `Never` removes the human from the loop. `Default` is refused too: what it means
/// depends on the slot, and an owner key is generated with explicit policies.
fn owner_slot_policy_ok(
    name: &str,
    pin: hw_signer::yubikey_piv::PivPinPolicy,
    touch: hw_signer::yubikey_piv::PivTouchPolicy,
) -> Result<()> {
    use hw_signer::yubikey_piv::{PivPinPolicy, PivTouchPolicy};
    if matches!(pin, PivPinPolicy::Always) && matches!(touch, PivTouchPolicy::Always) {
        return Ok(());
    }
    bail!(
        "REFUSED: {name} has PIN policy {pin:?} and touch policy {touch:?}; an owner key must be PIN ALWAYS + touch ALWAYS \
         (`ykman piv keys generate -a ECCP256 --pin-policy ALWAYS --touch-policy ALWAYS <slot>`; C-R6-3)"
    )
}

/// The PIV PIN, typed at the signature. Unlike `passphrase()` it is never read from the
/// environment and has no local length rule (the applet's is 6–8 characters); it lives only in
/// the backend's zeroized memory for this one command (C-R6-3).
fn piv_pin(prompt: &str) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    if let Some(h) = PIN_HINT.get() {
        eprintln!("hint for the PIN: {h}");
    }
    let pin = zeroize::Zeroizing::new(rpassword::prompt_password(format!("{prompt}: "))?);
    if pin.is_empty() {
        bail!("empty PIN");
    }
    Ok(zeroize::Zeroizing::new(pin.as_bytes().to_vec()))
}

/// Open a key by locator: a keyfile path, `tpm:<handle>` (the authValue is the passphrase typed
/// at use, as with a keyfile; it is never stored) or `piv:<slot>[@<serial>]` (PIN typed at the
/// signature, touch on the key).
fn open_locator(locator: &str) -> Result<OpenKey> {
    if let Some(h) = tpm_handle(locator) {
        let handle = h?;
        let pass = passphrase(&format!("authValue for the TPM key at {locator}"), false)?;
        let t = hw_signer::tpm::TpmSigner::open_persistent_protected(handle, pass.as_bytes())
            .map_err(|e| anyhow!("TPM open {locator}: {e}"))?;
        let pk = tpm_pk(&t)?;
        return Ok(OpenKey { signer: Signer::Tpm(t), pk });
    }
    if let Some(p) = piv_locator(locator) {
        let (slot, serial) = p?;
        let y = open_piv(slot, serial, true)?;
        let pk = hw_pk(&y, "YubiKey")?;
        return Ok(OpenKey { signer: Signer::Piv(y), pk });
    }
    open_key(Path::new(locator))
}

fn tpm_pk(t: &hw_signer::tpm::TpmSigner) -> Result<[u8; 65]> {
    hw_pk(t, "TPM")
}

/// The backend's P-256 point as the uncompressed 65-byte key every owner-cli command prints and sends.
fn hw_pk(s: &impl hw_signer::HardwareSigner, what: &str) -> Result<[u8; 65]> {
    let p = s.public_key().map_err(|e| anyhow!("{what} public key: {e}"))?;
    let mut pk = [0u8; 65];
    pk[0] = 4;
    pk[1..33].copy_from_slice(&p.x);
    pk[33..].copy_from_slice(&p.y);
    Ok(pk)
}

/// The slot's attestation certificate and the device's f9 certificate, both DER. No PIN.
fn piv_certs(y: &hw_signer::yubikey_piv::YubiKeyPivSigner) -> Result<(Vec<u8>, Vec<u8>)> {
    use der::Encode as _;
    let slot_der = y.attestation().map_err(|e| anyhow!("slot attestation: {e}"))?;
    let mut yk = yubikey::YubiKey::open_by_serial(yubikey::Serial(y.serial()))
        .map_err(|e| anyhow!("YubiKey {}: {e}", y.serial()))?;
    let c = yubikey::certificate::Certificate::read(&mut yk, hw_signer::yubikey_piv::PivSlot::Attestation)
        .map_err(|e| anyhow!("read f9 certificate: {e}"))?;
    Ok((slot_der, c.cert.to_der()?))
}

/// The public key a locator names, for SETTING the owner (`init`, `rotate-owner`, `recover`).
/// This is the one place a raw hex key is NOT accepted, so that a PIV slot cannot become the
/// owner without its attestation (the auditor's hardening on C-R6-3): slot metadata can say
/// ALWAYS/ALWAYS for an imported key too; only a verified attestation proves the key was
/// generated on the device. `piv:` runs `owner_slot_policy_ok` and `piv_attest::verify` and
/// refuses on any failure; `tpm:` reads the persistent key; a path reads the keyfile's public key.
fn owner_pk_of_locator(locator: &str) -> Result<([u8; 65], String)> {
    if let Some(h) = tpm_handle(locator) {
        let t = hw_signer::tpm::TpmSigner::open_persistent(h?).map_err(|e| anyhow!("TPM open {locator}: {e}"))?;
        return Ok((tpm_pk(&t)?, locator.to_string()));
    }
    if let Some(p) = piv_locator(locator) {
        let (slot, serial) = p?;
        let y = open_piv(slot, serial, false)?;
        let pk = hw_pk(&y, "YubiKey")?;
        let (slot_der, f9_der) = piv_certs(&y)?;
        let a = piv_attest::verify(&slot_der, &f9_der, y.serial(), &pk)
            .map_err(|e| anyhow!("{locator} cannot become the owner: {e}"))?;
        eprintln!(
            "ATTESTED: {locator} generated on YubiKey {} (firmware {}), PIN {} / touch {}, chain to {}",
            a.serial,
            a.firmware,
            a.pin_policy,
            a.touch_policy,
            a.chain.last().cloned().unwrap_or_default()
        );
        return Ok((
            pk,
            format!("piv:{}@{} (attested, firmware {})", hw_signer::yubikey_piv::slot_name(slot), a.serial, a.firmware),
        ));
    }
    Ok((pubkey_of(Path::new(locator))?, locator.to_string()))
}

/// Is `handle` already a persistent object in this TPM? (C-R6-2: `keygen` never evicts another
/// project's key — the same co-tenancy rule as on the SGX nodes.)
fn tpm_handle_in_use(handle: u32) -> Result<bool> {
    use std::str::FromStr as _;
    use tss_esapi::constants::CapabilityType;
    use tss_esapi::structures::CapabilityData;
    use tss_esapi::tcti_ldr::TctiNameConf;
    let tcti = TctiNameConf::from_environment_variable()
        .or_else(|_| TctiNameConf::from_str("device:/dev/tpmrm0"))
        .map_err(|e| anyhow!("TPM TCTI: {e}"))?;
    let mut ctx = tss_esapi::Context::new(tcti).map_err(|e| anyhow!("TPM context: {e}"))?;
    let mut from = 0x8100_0000u32;
    loop {
        let (data, more) =
            ctx.get_capability(CapabilityType::Handles, from, 64).map_err(|e| anyhow!("TPM capability: {e}"))?;
        let CapabilityData::Handles(list) = data else { return Ok(false) };
        let handles: Vec<u32> = list.into_inner().into_iter().map(u32::from).collect();
        if handles.contains(&handle) {
            return Ok(true);
        }
        match (more, handles.last()) {
            (true, Some(last)) if *last < 0x81FF_FFFF => from = last.saturating_add(1),
            _ => return Ok(false),
        }
    }
}

/// Create a P-256 key inside the TPM under the SRK, protected by an authValue, and persist it.
/// Refuses an occupied handle before anything is created (C-R6-2).
fn keygen_tpm(handle: u32, role: &str) -> Result<[u8; 65]> {
    if !(0x8100_0000..=0x81FF_FFFF).contains(&handle) {
        bail!("TPM handle 0x{handle:08x} is not in the persistent range 0x81000000–0x81FFFFFF");
    }
    if tpm_handle_in_use(handle)? {
        bail!("REFUSED: TPM persistent handle 0x{handle:08x} is already in use by another key; never evicted — pick a free one with --handle (tpm2_getcap handles-persistent)");
    }
    let pass =
        passphrase(&format!("authValue for the {role} key in the TPM (typed at every use, never stored)"), true)?;
    let mut t = hw_signer::tpm::TpmSigner::create_protected_under(hw_signer::tpm::DEFAULT_PARENT, pass.as_bytes())
        .map_err(|e| anyhow!("TPM create: {e}"))?;
    t.persist(handle)
        .map_err(|e| anyhow!("TPM persist at 0x{handle:08x}: {e} (handle in use? pick another with --handle)"))?;
    tpm_pk(&t)
}

impl Drop for OpenKey {
    fn drop(&mut self) {
        // SigningKey zeroizes on drop in p256 0.13
    }
}

fn open_key(path: &Path) -> Result<OpenKey> {
    let kf: KeyFile = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    if kf.version != 1 || kf.kdf != "scrypt" || kf.log_n < 18 {
        bail!("keyfile: unsupported or below the required strength (scrypt N ≥ 2^18)");
    }
    if let (Some(h), Err(_)) = (kf.hint.as_deref(), std::env::var("OWNER_PASSPHRASE")) {
        eprintln!("hint for the {} key: {h}", kf.role);
    }
    let pass = passphrase(&format!("passphrase for the {} key", kf.role), false)?;
    open_key_with(path, &pass)
}

/// Decrypt a keyfile with a given passphrase (the body of `open_key`, also used by `key-hint --set`).
fn open_key_with(path: &Path, pass: &str) -> Result<OpenKey> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    let kf: KeyFile = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    if kf.version != 1 || kf.kdf != "scrypt" || kf.log_n < 18 {
        bail!("keyfile: unsupported or below the required strength (scrypt N ≥ 2^18)");
    }
    let mut key = kdf(pass, &hex::decode(&kf.salt_hex)?, kf.log_n, kf.r, kf.p)?;
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
    Ok(OpenKey { signer: Signer::File(sk), pk })
}

fn pubkey_of(path: &Path) -> Result<[u8; 65]> {
    let kf: KeyFile = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    let v = hex::decode(&kf.pubkey_hex)?;
    <[u8; 65]>::try_from(v.as_slice()).map_err(|_| anyhow!("pubkey length"))
}

fn sign_message(key: &OpenKey, msg: &mut Message) -> Result<()> {
    let d = msg.digest();
    let s = key.sign_digest(&d)?;
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

/// A JSON number that must fit a u32 (a height, a block time): missing, negative, fractional or above
/// `u32::MAX` is refused by name — never silently 0, never truncated (rule 9; #18).
fn json_u32(v: &serde_json::Value, what: &str) -> Result<u32> {
    v.as_u64().and_then(|n| u32::try_from(n).ok()).ok_or_else(|| anyhow!("{what}: not a u32: {v}"))
}

/// A bitcoind amount in BTC (a JSON float) to satoshi through `Amount::from_btc` — the rounding the node
/// itself uses; a malformed or negative amount is an error, never 0 (rule 9).
fn btc_sat(v: &serde_json::Value) -> Result<u64> {
    let btc = v.as_f64().ok_or_else(|| anyhow!("amount: not a number: {v}"))?;
    Ok(bitcoin::Amount::from_btc(btc).map_err(|e| anyhow!("amount {btc}: {e}"))?.to_sat())
}

/// The mandate's next nonce from the one the (untrusted) daemon reports: `+ 1`, refused at the end of
/// the range instead of wrapping to 0.
fn next_nonce(current: u64) -> Result<u64> {
    current.checked_add(1).ok_or_else(|| anyhow!("nonce {current} cannot advance: the nonce space is exhausted"))
}

/// The first height of the 2016-block retarget period `height` is in. `height % 2016 ≤ height`, so the
/// subtraction cannot underflow; the saturating form says so to the linter (rule 9).
fn period_start(height: u32) -> u32 {
    height.saturating_sub(height % 2016)
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
    let inner = d
        .strip_prefix("wpkh(")
        .and_then(|x| x.strip_suffix(')'))
        .ok_or_else(|| anyhow!("v1 accepts wpkh(KEY/branch/*) descriptors only"))?;
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
                let addr =
                    bitcoin::Address::from_str(a)?.require_network(bnet).map_err(|e| anyhow!("address {a}: {e}"))?;
                Matcher::Address { script_pubkey: addr.script_pubkey().to_bytes() }
            }
            (None, Some(d)) => {
                let (xpub, branches) = parse_descriptor(d)?;
                Matcher::Descriptor { xpub, branches, gap: t.gap.unwrap_or(20) }
            }
            _ => bail!("trusted '{}': exactly one of address / descriptor", t.label),
        };
        trusted.push(TrustedDest {
            label: t.label.clone(),
            matcher,
            max_per_tx: t.max_per_tx,
            max_per_window: t.max_per_window,
        });
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
        Some(h) => {
            Some(<[u8; 65]>::try_from(hex::decode(h)?.as_slice()).map_err(|_| anyhow!("witness key is 65 bytes hex"))?)
        }
        None => None,
    };
    let m = Mandate {
        version: j.version,
        network,
        wallet: WalletSpec {
            fingerprint,
            account: AccountPath { purpose: acc[0], coin: acc[1], account: acc[2] },
            script_types,
        },
        destinations: Destinations {
            trusted,
            unlisted: ClassCaps {
                max_per_tx: j.destinations.unlisted.max_per_tx,
                max_per_window: j.destinations.unlisted.max_per_window,
            },
        },
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
        (
            "wallet.account".into(),
            format!("{}'/{}'/{}'", m.wallet.account.purpose, m.wallet.account.coin, m.wallet.account.account),
        ),
    ];
    for t in &m.destinations.trusted {
        let how = match &t.matcher {
            Matcher::Address { script_pubkey } => format!(
                "address {}",
                bitcoin::Address::from_script(bitcoin::Script::from_bytes(script_pubkey), m.network.to_bitcoin())
                    .map(|a| a.to_string())
                    .unwrap_or_else(|_| hex::encode(script_pubkey))
            ),
            Matcher::Descriptor { xpub, branches, gap } => format!(
                "descriptor {} branches {:?} gap {}",
                Xpub::decode(xpub).map(|x| x.to_string()).unwrap_or_default(),
                branches,
                gap
            ),
        };
        v.push((
            format!("trusted[{}]", t.label),
            format!("{how}; maxPerTx {} maxPerWindow {}", t.max_per_tx, t.max_per_window),
        ));
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
        (
            "rules".into(),
            format!(
                "sighash {:?}, payjoin {:?}, opReturn {:?}, rbf {}",
                m.rules.sighash, m.rules.payjoin, m.rules.op_return, m.rules.rbf
            ),
        ),
        ("chain.checkpoint".into(), {
            let mut h = m.checkpoint.hash;
            h.reverse();
            format!(
                "{} @ {} (bits {:08x}, period start {} bits {:08x})",
                hex::encode(h),
                m.checkpoint.height,
                m.checkpoint.bits,
                m.checkpoint.period_start_time,
                m.checkpoint.period_bits
            )
        }),
        (
            "freshness".into(),
            format!(
                "required {}, maxTipLag {}, witness {}",
                m.freshness.required,
                m.freshness.max_tip_lag,
                m.freshness.witness_pk.map(hex::encode).unwrap_or_else(|| "none".into())
            ),
        ),
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
        let p = self.header(period_start(height))?;
        Ok(CheckpointJson {
            hash: h["hash"].as_str().unwrap_or("").into(),
            height,
            time: json_u32(&h["time"], "block time")?,
            bits: h["bits"].as_str().unwrap_or("").into(),
            period_start_time: json_u32(&p["time"], "period start time")?,
            period_bits: p["bits"].as_str().unwrap_or("").into(),
        })
    }
}

// ---------------------------------------------------------------- signerd client

struct Signerd {
    url: String,
    token: String,
    /// The owner's wallet record on THIS machine (C-R7-5): every status read raises its
    /// `last_seen_seq`, so `arm` can tell a rolled-back enclave from the one the owner last saw.
    record: Option<PathBuf>,
    /// R8: a status file instead of the live daemon; `get("/v1/status")` returns it, nothing else is reachable.
    offline: Option<serde_json::Value>,
    /// R8: write signed messages here instead of posting them.
    out: Option<PathBuf>,
}

impl Signerd {
    fn get(&self, path: &str) -> Result<serde_json::Value> {
        let v: serde_json::Value = match &self.offline {
            Some(st) if path == "/v1/status" => st.clone(),
            Some(_) => bail!("no tunnel: {path} is not in the status file; this step needs the live daemon's answer carried as a file"),
            None => {
                let r = reqwest::blocking::Client::new().get(format!("{}{path}", self.url)).bearer_auth(&self.token).send()?;
                let status = r.status();
                let v: serde_json::Value = r.json()?;
                if !status.is_success() {
                    bail!("signerd {path}: {status} {v}");
                }
                v
            }
        };
        if path == "/v1/status" {
            if let (Some(rec), Some(seq)) = (&self.record, v["seq"].as_u64()) {
                if let Err(e) = note_seq(rec, seq) {
                    eprintln!("warning: could not record the sequence in {}: {e}", rec.display());
                }
            }
            if v["auto_arm"].as_bool() == Some(true) {
                eprintln!("AUTO_ARM: this enclave was built WITHOUT the pause after a restart — rollback protection OFF; the loss bound against root is the hot-wallet float (REQ-r7 §2.6)");
            }
        }
        Ok(v)
    }
    fn post(&self, path: &str, body: serde_json::Value) -> Result<serde_json::Value> {
        if self.offline.is_some() {
            bail!("no tunnel: nothing is sent from this machine; use --out <file> and carry the file to the server ({path})");
        }
        let r = reqwest::blocking::Client::new()
            .post(format!("{}{path}", self.url))
            .bearer_auth(&self.token)
            .json(&body)
            .send()?;
        let status = r.status();
        let v: serde_json::Value = r.json()?;
        if !status.is_success() {
            bail!("signerd {path}: {status} {v}");
        }
        Ok(v)
    }
    fn enclave_id(&self) -> Result<[u8; 32]> {
        let st = self.get("/v1/status")?;
        let pk = hex::decode(
            st["identity_pk"].as_str().ok_or_else(|| anyhow!("status has no identity_pk (not initialised?)"))?,
        )?;
        Ok(signer_core::sha256(&pk))
    }
    fn nonce(&self) -> Result<u64> {
        Ok(self.get("/v1/status")?["nonce"].as_u64().unwrap_or(0))
    }
    /// The nonce the next owner message must carry: the daemon's `+ 1`, refused at the end of the range.
    fn next_nonce(&self) -> Result<u64> {
        next_nonce(self.nonce()?)
    }
}

// ---------------------------------------------------------------- wallet record

#[derive(Serialize, Deserialize, Clone, Debug)]
struct AttestRecord {
    at_unix: u64,
    tier: String,
    tcb_status: String,
    advisory_ids: Vec<String>,
    accepted_exceptions: Vec<String>,
    collateral_source: String,
    verifier: String,
    quote_sha256: String,
}

/// Raise the record's `last_seen_seq` to `seq` (never lowered here; `arm --i-have-investigated`
/// is the one place it is reset, and that is logged in the record).
fn note_seq(path: &Path, seq: u64) -> Result<()> {
    let mut w: WalletRecord = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    if seq > w.last_seen_seq.unwrap_or(0) {
        w.last_seen_seq = Some(seq);
        std::fs::write(path, serde_json::to_string_pretty(&w)?)?;
    }
    Ok(())
}

/// A value given directly, or read (trimmed) from a carried file.
fn value_or_file(value: &Option<String>, file: &Option<PathBuf>, what: &str) -> Result<String> {
    match (value, file) {
        (Some(v), _) => Ok(v.trim().to_string()),
        (None, Some(f)) => {
            Ok(std::fs::read_to_string(f).with_context(|| format!("reading {}", f.display()))?.trim().to_string())
        }
        (None, None) => bail!("{what}"),
    }
}

/// `T2-release/AUTO_ARM` → `T2-release`: the tier the hardware gives, without the build flag.
fn tier_base(tier: &str) -> &str {
    tier.split('/').next().unwrap_or(tier)
}

/// The enclave says it was built with the pause compiled out (REQ-r7 §2.6): own MRENCLAVE, never
/// ceremony-signed, labeled in every attestation (C-R7-7).
fn is_auto_arm(tier: &str) -> bool {
    tier.split('/').any(|p| p == "AUTO_ARM")
}

fn now_utc() -> String {
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    format!("{t}")
}

#[derive(Serialize, Deserialize)]
struct WalletRecord {
    network: String,
    xpub: String,
    fingerprint: String,
    identity_pk: String,
    enclave_id: String,
    card_hex: String,
    card_sig_hex: String,
    /// T2: MRSIGNER pinned at the first `attest --pin` (hex). Labeled: a dev key until the ceremony (C-R5-4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mrsigner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signing_key_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    isv_prod_id: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    isv_svn: Option<u16>,
    /// T2: the last successful attestation (what was checked, when, with which exceptions).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    attested: Option<AttestRecord>,
    /// What this record rests on: "attested" (C-R5-6: `init` ran the verifier before writing it) or a
    /// TOFU label naming why no attestation exists (T1/T0 hardware).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    trust_label: Option<String>,
    mrenclave: String,
    tier: String,
    recovery_blob_hex: String,
    owner_pk: String,
    recovery_pk: String,
    /// REQ-r7 (C-R7-5): the highest receipt sequence this machine has seen from the enclave. Lives
    /// here, on the owner's machine, never on the server; `arm` refuses when the enclave remembers less.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_seen_seq: Option<u64>,
    /// Every time the owner armed over a sequence regression with `--i-have-investigated`: an
    /// owner-attested acceptance of a rollback, kept on record (unix time, enclave seq, last seen).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rollback_acceptances: Option<Vec<String>>,
    /// Owner-written reminder of WHERE the YubiKey PIN is kept (never what it is), shown before a PIN prompt
    /// when this record is given (`key-hint --pin --set …`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    owner_pin_hint: Option<String>,
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
    /// The wallet record on this machine (`init --out`); every status read raises its `last_seen_seq`,
    /// which `arm` needs to tell a rolled-back enclave from the one you last saw (REQ-r7, C-R7-5).
    #[arg(long, env = "OWNER_WALLET", global = true)]
    wallet_record: Option<PathBuf>,
    /// R8 (no tunnel): the daemon's status as a FILE (`signerd status --out …` on the server, carried
    /// here). With it, owner-cli never talks to the server: it reads the enclave's id, nonce, sequence
    /// and boot challenge from the file.
    #[arg(long, env = "OWNER_STATUS", global = true)]
    status_file: Option<PathBuf>,
    /// R8 (no tunnel): write the signed owner message to this FILE (hex) instead of sending it; carry it
    /// to the server and hand it to `signerd submit --file …`.
    #[arg(long, global = true)]
    out: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate an encrypted keyfile (owner, recovery or witness role).
    Keygen {
        /// Keyfile path (`--backend file`); ignored for the TPM.
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long, default_value = "owner")]
        role: String,
        /// `file` (encrypted keyfile), `tpm` (P-256 key created inside the TPM 2.0 and persisted; REQ-r6 §2)
        /// or `piv` (refused: a YubiKey PIV key is generated on the device by `ykman`, which holds the
        /// management key; owner-cli never does — it prints the recipe).
        #[arg(long, default_value = "file")]
        backend: String,
        /// TPM persistent handle for `--backend tpm` (0x81000100 is this project's; other handles belong to other keys).
        #[arg(long, default_value = "0x81000100")]
        handle: String,
        /// `--backend file` only: a reminder of WHERE the passphrase is kept (a password-manager entry, an
        /// envelope) — never what it is or what it looks like. Shown before every passphrase prompt.
        #[arg(long)]
        hint: Option<String>,
    },
    /// Show, set or clear the hint of a keyfile (`--key FILE`; setting asks the passphrase once, so the hint
    /// is checked against it) or the PIN hint in the wallet record (`--pin`, with `--wallet-record`).
    KeyHint {
        #[arg(long, conflicts_with = "pin")]
        key: Option<PathBuf>,
        #[arg(long)]
        pin: bool,
        #[arg(long, conflicts_with = "clear")]
        set: Option<String>,
        #[arg(long)]
        clear: bool,
    },
    /// Print a key's public key (keyfile path, `tpm:<handle>` or `piv:<slot>[@<serial>]`; a YubiKey needs no PIN for this).
    Pubkey {
        #[arg(long)]
        key: String,
    },
    /// Verify a YubiKey slot's attestation to Yubico's pinned root: the key was GENERATED on that device, with
    /// PIN ALWAYS + touch ALWAYS (C-R6-3). No PIN needed. Prints a JSON record; `--out DIR` also saves the certificates.
    PivAttest {
        /// `piv:<slot>[@<serial>]`
        #[arg(long)]
        key: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Initialise the enclave wallet: keys generated inside, owner and recovery bound; stores the identity card and the recovery blob.
    Init {
        #[arg(long)]
        network: String,
        /// Owner key LOCATOR, never a raw key: keyfile path, `tpm:<handle>` or `piv:<slot>[@<serial>]`
        /// (a PIV slot is attested to Yubico's pinned root first and refused unless it verifies; C-R6-3).
        #[arg(long)]
        owner: String,
        /// Recovery public key, hex (a keyfile, kept offline; see `keygen --role recovery`) — or a file holding it.
        #[arg(long, conflicts_with = "recovery_pk_file")]
        recovery_pk: Option<String>,
        #[arg(long)]
        recovery_pk_file: Option<PathBuf>,
        #[arg(long)]
        out: PathBuf,
        /// T2 (C-R5-6): `init` runs the DCAP verifier BEFORE writing the record and refuses to write it on any
        /// failure. These are the `attest` inputs; on T1/T0 hardware no attestation exists and the record is
        /// written labeled TOFU.
        #[arg(long)]
        expect_mrenclave: Option<String>,
        #[arg(long)]
        signing_key_label: Option<String>,
        #[arg(long = "accept-advisory")]
        accept: Vec<String>,
        #[arg(long, default_value = "https://api.trustedservices.intel.com")]
        pccs: String,
        /// Accept an enclave built with AUTO_ARM (the pause after a restart compiled out; REQ-r7 §2.6).
        /// Without it, `init` refuses to write a record for such an enclave.
        #[arg(long)]
        accept_auto_arm: bool,
        /// R8 (no tunnel): the file `signerd init --out …` wrote on the server, carried here; nothing is sent.
        #[arg(long)]
        response: Option<PathBuf>,
        /// R8 (no tunnel, T2): the file `signerd quote --nonce <your nonce> --out …` wrote; verified here with `--nonce`.
        #[arg(long)]
        quote: Option<PathBuf>,
        /// The 32-byte hex nonce YOU chose for that quote (so a saved quote for another nonce is refused) — or the file you wrote it to.
        #[arg(long, conflicts_with = "nonce_file")]
        nonce: Option<String>,
        #[arg(long)]
        nonce_file: Option<PathBuf>,
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
        /// R8 (no tunnel): the file `signerd policy --out …` wrote on the server, carried here, instead of the live daemon.
        #[arg(long)]
        installed_file: Option<PathBuf>,
    },
    /// Sign a mandate JSON with the owner key and submit it (nonce 0 = install; otherwise an update).
    PolicySign {
        #[arg(long)]
        json: PathBuf,
        #[arg(long)]
        key: String,
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
        key: String,
    },
    Unfreeze {
        #[arg(long)]
        key: String,
    },
    Rearm {
        #[arg(long)]
        key: String,
        #[arg(long)]
        seq: u64,
    },
    /// Approve THIS enclave load (REQ-r7): after every restart the enclave signs nothing until the owner
    /// signs the challenge it drew at that load. Needs `--wallet-record` (the sequence you last saw lives
    /// there, on this machine); refuses when the enclave remembers less than that — the signature of a
    /// state rollback — unless `--i-have-investigated` is given, which is logged in the record.
    Arm {
        #[arg(long)]
        key: String,
        /// Arm over a sequence regression anyway (an owner-attested acceptance of a rollback; logged).
        #[arg(long)]
        i_have_investigated: bool,
    },
    /// REQ-r9: pin the TPM counter that proves the state's freshness (or re-pin it after a mismatch).
    /// The counter value is taken from an ATTESTED read — the `signerd tpm-certify` answer over a nonce
    /// you chose — never from the status file (C-R9-D). Arms this load like `arm`.
    Anchor {
        #[arg(long)]
        key: String,
        /// The `signerd tpm-info --out` file (the transport's key and index Name) …
        #[arg(long, conflicts_with_all = ["ak_pk_file", "nv_name_file"])]
        tpm_info_file: Option<PathBuf>,
        /// … or the two values in files of their own (hex), as the owner verified them.
        #[arg(long, requires = "nv_name_file")]
        ak_pk_file: Option<PathBuf>,
        #[arg(long)]
        nv_name_file: Option<PathBuf>,
        /// The `signerd tpm-certify --nonce-file … --out` answer.
        #[arg(long)]
        proof_file: PathBuf,
        /// The nonce you gave to `tpm-certify` (32 bytes hex), the file you carried there.
        #[arg(long)]
        proof_nonce_file: PathBuf,
        /// Anchor over a sequence regression anyway (an owner-attested acceptance of a rollback; logged).
        #[arg(long)]
        i_have_investigated: bool,
    },
    /// Hand the owner role to another key (a timelocked loosening, signed by the current owner).
    RotateOwner {
        #[arg(long)]
        key: String,
        /// New owner key LOCATOR, never a raw key (`piv:` is attested first; C-R6-3).
        #[arg(long)]
        new_owner: String,
    },
    /// Replace a lost owner key with the recovery key's signature.
    Recover {
        #[arg(long)]
        recovery_key: PathBuf,
        /// New owner key LOCATOR, never a raw key (`piv:` is attested first; C-R6-3).
        #[arg(long)]
        new_owner: String,
    },
    /// Freeze signing (no signature needed).
    Freeze,
    /// The owner's monitor (REQ-r4): verifies receipts under the identity key, watches the chain
    /// from an INDEPENDENT source for spends without a receipt, cross-checks the window cap, watches the
    /// feed, issues witness tokens when the mandate requires freshness, and FREEZES (unsigned) on any ALARM.
    Monitor {
        #[arg(long)]
        wallet: PathBuf,
        /// The owner's copy of the installed mandate JSON (caps, ownIndexGap, freshness).
        #[arg(long)]
        mandate: PathBuf,
        /// Independent chain source. Signet/dev: a public Esplora; for value: the owner's own node (C-R4-3).
        #[arg(long, default_value = "https://mempool.space/signet/api")]
        esplora: String,
        #[arg(long, default_value_t = 300)]
        interval: u64,
        /// Pause between Esplora requests in ms (a public Esplora rate-limits; 0 for the owner's node).
        #[arg(long, default_value_t = 300)]
        esplora_delay_ms: u64,
        /// Full scan of the whole reachable range every N passes; the others re-read addresses with history + the live window.
        #[arg(long, default_value_t = 12)]
        full_every: u64,
        /// Append-only JSONL journal (one line per pass = the heartbeat); the HWM sits beside it.
        #[arg(long, default_value = "monitor.jsonl")]
        journal: PathBuf,
        /// One pass, then exit 0 OK / 1 WARN / 2 ALARM.
        #[arg(long)]
        once: bool,
        /// Do not send FREEZE on ALARM (tests only; the reflex is on by default).
        #[arg(long)]
        no_freeze: bool,
        /// Witness key locator (keyfile or tpm:<handle>) when the mandate requires freshness.
        #[arg(long)]
        witness_key: Option<String>,
        /// Consecutive stalled passes before FEED_STALL becomes an ALARM.
        #[arg(long, default_value_t = 3)]
        stall_after: u32,
        /// Override the mandate's maxTipLag for the stall check (tests).
        #[arg(long)]
        max_tip_lag: Option<u32>,
        /// Upper bound on addresses scanned per branch (the computed range is usually far smaller).
        #[arg(long, default_value_t = 2000)]
        max_addresses: u32,
        /// The owner's own node as the chain source (C-R4-3): read-only RPC URL + cookie file; overrides --esplora.
        #[arg(long)]
        node_rpc: Option<String>,
        #[arg(long)]
        node_cookie: Option<PathBuf>,
        /// A spend without receipt the owner has reviewed and accepts (txid); persisted, stops re-alarming.
        #[arg(long = "acknowledge")]
        acknowledge: Vec<String>,
    },
    /// Status.
    Status,
    /// T2: fetch a DCAP quote for a fresh nonce from signerd and verify it HERE (REQ-r5 §4):
    /// 1 chain+collateral from Intel PCS, 2 DEBUG==0, 3 MRENCLAVE == card == pinned, 4 MRSIGNER/ProdID/SVN pinned,
    /// 5 card signature + tier T2-release, 6 report_data recomputed with this nonce, 7 TCB policy.
    /// A failure at any step refuses and names the step. The Intel SGX Root CA is pinned in this binary.
    Attest {
        #[arg(long)]
        wallet: PathBuf,
        /// Expected MRENCLAVE (hex) from the reproducible build; defaults to the wallet record's.
        #[arg(long)]
        expect_mrenclave: Option<String>,
        /// Expected MRSIGNER (hex); defaults to the pinned one in the record. `--pin` stores it on the first attest.
        #[arg(long)]
        expect_mrsigner: Option<String>,
        /// What the signing key is, stored with the pin: e.g. "dev key enclave-dev-2.28.pem, not a ceremony key".
        #[arg(long)]
        signing_key_label: Option<String>,
        /// Ledgered exception `ADVISORY-ID:YYYY-MM-DD:reason`, e.g. `INTEL-SA-00334:2026-11-03:LVI mitigated in the build (gate 6)`.
        /// Under SW_HARDENING_NEEDED every advisory the platform reports must be listed, or the quote is refused.
        #[arg(long = "accept-advisory")]
        accept: Vec<String>,
        /// Collateral source: Intel PCS v4 (authoritative). Not Azure THIM.
        #[arg(long, default_value = "https://api.trustedservices.intel.com")]
        pccs: String,
        /// Store MRSIGNER/ProdID/SVN and this attestation in the wallet record.
        #[arg(long)]
        pin: bool,
        /// Write the quote and the verification output as JSON.
        #[arg(long)]
        save: Option<PathBuf>,
        /// Negative vector: verify a previously saved quote (`--save` output) against a FRESH nonce — a
        /// genuine quote from an earlier run must be refused at step 6 (replay).
        #[arg(long)]
        replay: Option<PathBuf>,
        /// R8 (no tunnel): with `--replay <quote file>`, the 32-byte hex nonce YOU chose for it — then the
        /// file is the carried quote and must verify; without `--nonce`, `--replay` is the negative vector.
        #[arg(long, conflicts_with = "nonce_file")]
        nonce: Option<String>,
        /// The file you wrote that nonce to (`openssl rand -hex 32 > nonce.txt`).
        #[arg(long)]
        nonce_file: Option<PathBuf>,
    },
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
        /// The previous transaction's raw hex (from the operator's own node), instead of fetching it from the Esplora.
        #[arg(long)]
        prev_tx_hex: Option<String>,
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
        key: String,
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

/// A file written by `signerd … --out` wraps the answer as `{"http_status", "ok", "response"}`; a bare
/// answer (an older file, or a hand-copied one) is accepted as is.
fn unwrap_server_file(v: serde_json::Value) -> Result<serde_json::Value> {
    if let Some(r) = v.get("response") {
        if v.get("ok") == Some(&serde_json::Value::Bool(false)) {
            bail!("the server file records a refusal: {r}");
        }
        return Ok(r.clone());
    }
    Ok(v)
}

fn client(cli: &Cli) -> Result<Signerd> {
    if let Some(f) = &cli.status_file {
        let st = unwrap_server_file(serde_json::from_str(
            &std::fs::read_to_string(f).with_context(|| format!("reading {}", f.display()))?,
        )?)?;
        return Ok(Signerd {
            url: String::new(),
            token: String::new(),
            record: cli.wallet_record.clone(),
            offline: Some(st),
            out: cli.out.clone(),
        });
    }
    let token = match (&cli.token, &cli.token_file) {
        (Some(t), _) => t.clone(),
        (None, Some(f)) => std::fs::read_to_string(f)?.trim().to_string(),
        _ => bail!("--token or --token-file (live), or --status-file (no tunnel)"),
    };
    Ok(Signerd {
        url: cli.signerd.trim_end_matches('/').to_string(),
        token,
        record: cli.wallet_record.clone(),
        offline: None,
        out: cli.out.clone(),
    })
}

fn submit_message(sd: &Signerd, msg: &Message) -> Result<()> {
    if let Some(out) = &sd.out {
        std::fs::write(out, hex::encode(msg.encode()))?;
        println!("signed message written to {} — carry it to the server and run there: signerd submit --file <it> --out <answer>", out.display());
        return Ok(());
    }
    let r = sd.post("/v1/message", serde_json::json!({"message_hex": hex::encode(msg.encode())}))?;
    println!("{r}");
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if let Some(rp) = cli.wallet_record.as_ref() {
        if let Ok(w) = std::fs::read_to_string(rp)
            .map_err(anyhow::Error::from)
            .and_then(|t| Ok(serde_json::from_str::<WalletRecord>(&t)?))
        {
            if let Some(h) = w.owner_pin_hint {
                let _ = PIN_HINT.set(h);
            }
        }
    }
    match &cli.cmd {
        Cmd::KeyHint { key, pin, set, clear } => {
            if *pin {
                let rec_path =
                    cli.wallet_record.clone().ok_or_else(|| anyhow!("--pin needs --wallet-record <wallet.json>"))?;
                let mut w: WalletRecord = serde_json::from_str(&std::fs::read_to_string(&rec_path)?)?;
                if let Some(h) = set {
                    let h = h.trim();
                    if h.is_empty() || h.chars().count() > 200 {
                        bail!("hint: 1–200 characters");
                    }
                    if h.chars().all(|c| c.is_ascii_digit()) {
                        bail!(
                            "REFUSED: a PIN hint that is all digits looks like the PIN itself — say WHERE it is kept"
                        );
                    }
                    w.owner_pin_hint = Some(h.to_string());
                    std::fs::write(&rec_path, serde_json::to_string_pretty(&w)?)?;
                    println!("PIN hint set in {}", rec_path.display());
                } else if *clear {
                    w.owner_pin_hint = None;
                    std::fs::write(&rec_path, serde_json::to_string_pretty(&w)?)?;
                    println!("PIN hint cleared");
                } else {
                    println!("{}", w.owner_pin_hint.as_deref().unwrap_or("(no PIN hint in this record)"));
                }
                return Ok(());
            }
            let path = key.clone().ok_or_else(|| anyhow!("--key <keyfile> or --pin"))?;
            let mut kf: KeyFile = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
            if let Some(h) = set {
                // the passphrase is asked once: the hint must belong to this key and must not contain it
                let pass =
                    passphrase(&format!("passphrase for the {} key (to check the hint against it)", kf.role), false)?;
                let probe = open_key_with(&path, &pass)?;
                drop(probe);
                kf.hint = Some(check_hint(h, &pass)?);
            } else if *clear {
                kf.hint = None;
            } else {
                println!("{}", kf.hint.as_deref().unwrap_or("(no hint in this keyfile)"));
                return Ok(());
            }
            let tmp = path.with_extension("hint.tmp");
            {
                use std::os::unix::fs::OpenOptionsExt;
                let f = std::fs::OpenOptions::new().create_new(true).write(true).mode(0o600).open(&tmp)?;
                serde_json::to_writer_pretty(f, &kf)?;
            }
            let check: KeyFile = serde_json::from_str(&std::fs::read_to_string(&tmp)?)?;
            if check.ct_hex != kf.ct_hex || check.pubkey_hex != kf.pubkey_hex {
                std::fs::remove_file(&tmp)?;
                bail!("rewrite check failed; keyfile untouched");
            }
            std::fs::rename(&tmp, &path)?;
            println!("hint {} for {}", if kf.hint.is_some() { "set" } else { "cleared" }, path.display());
            return Ok(());
        }
        Cmd::Keygen { out, role, backend, handle, hint } => {
            if backend == "piv" {
                bail!(
                    "REFUSED: owner-cli does not generate YubiKey PIV keys (it never holds the management key). Generate the {role} key \
                     on the device, in a slot that is EMPTY (`ykman piv keys info <slot>` must say no key; another project's slot is never overwritten):\n  \
                     ykman piv keys generate -a ECCP256 --pin-policy ALWAYS --touch-policy ALWAYS <slot> <slot>.pub.pem\n\
                     then use the locator piv:<slot> (e.g. piv:9a); `owner-cli pubkey --key piv:<slot>` prints the key"
                );
            }
            if backend == "tpm" {
                let h = tpm_handle(&format!("tpm:{handle}")).unwrap()?;
                let pk = keygen_tpm(h, role)?;
                println!("TPM key created and persisted at 0x{h:08x}; locator: tpm:0x{h:08x}");
                println!("{}", hex::encode(pk));
                return Ok(());
            }
            let out = out.clone().ok_or_else(|| anyhow!("--out is required for --backend file"))?;
            let out = &out;
            let pk = keygen(out, role, hint.as_deref())?;
            println!(
                "{} key written to {} (scrypt N=2^18 + AES-256-GCM; keep it OFF the BTCPay box)",
                role,
                out.display()
            );
            println!("pubkey: {}", hex::encode(pk));
        }
        Cmd::Pubkey { key } => {
            if let Some(h) = tpm_handle(key) {
                let t = hw_signer::tpm::TpmSigner::open_persistent(h?).map_err(|e| anyhow!("TPM open: {e}"))?;
                println!("{}", hex::encode(tpm_pk(&t)?));
            } else if let Some(p) = piv_locator(key) {
                let (slot, serial) = p?;
                let y = open_piv(slot, serial, false)?;
                eprintln!(
                    "YubiKey serial {} slot {}: P-256, PIN policy {:?}, touch policy {:?}",
                    y.serial(),
                    hw_signer::yubikey_piv::slot_name(slot),
                    y.pin_policy(),
                    y.touch_policy()
                );
                println!("{}", hex::encode(hw_pk(&y, "YubiKey")?));
            } else {
                println!("{}", hex::encode(pubkey_of(Path::new(key))?));
            }
        }
        Cmd::PivAttest { key, out } => {
            let (slot, serial) = piv_locator(key).ok_or_else(|| anyhow!("--key must be piv:<slot>[@<serial>]"))??;
            let y = open_piv(slot, serial, false)?;
            let pk = hw_pk(&y, "YubiKey")?;
            let (slot_der, f9_der) = piv_certs(&y)?;
            let a = piv_attest::verify(&slot_der, &f9_der, y.serial(), &pk)?;
            if let Some(dir) = out {
                std::fs::create_dir_all(dir)?;
                let name = hw_signer::yubikey_piv::slot_name(slot);
                std::fs::write(dir.join(format!("slot-{name}.attest.der")), &slot_der)?;
                std::fs::write(dir.join("f9.der"), &f9_der)?;
                std::fs::write(dir.join(format!("slot-{name}.attest.json")), serde_json::to_vec_pretty(&a)?)?;
                eprintln!("certificates and record written to {} (they name the device's serial: keep them out of the repository)", dir.display());
            }
            println!("{}", serde_json::to_string_pretty(&a)?);
            eprintln!(
                "ATTESTED: generated on YubiKey {} (firmware {}), PIN {} / touch {}, chain {}",
                a.serial,
                a.firmware,
                a.pin_policy,
                a.touch_policy,
                a.chain.join(" <- ")
            );
        }
        Cmd::Init {
            network,
            owner,
            recovery_pk,
            recovery_pk_file,
            out,
            expect_mrenclave,
            signing_key_label,
            accept,
            pccs,
            accept_auto_arm,
            response,
            quote,
            nonce,
            nonce_file,
        } => {
            let recovery_pk = &value_or_file(recovery_pk, recovery_pk_file, "--recovery-pk or --recovery-pk-file")?;
            let nonce = &match (nonce, nonce_file) {
                (None, Some(f)) => Some(std::fs::read_to_string(f)?.trim().to_string()),
                (n, _) => n.clone(),
            };
            // no tunnel: with a carried response nothing is sent from this machine at all
            let sd = match response {
                Some(_) => Signerd {
                    url: String::new(),
                    token: String::new(),
                    record: cli.wallet_record.clone(),
                    offline: Some(serde_json::Value::Null),
                    out: cli.out.clone(),
                },
                None => client(&cli)?,
            };
            let (opk, owner_label) = owner_pk_of_locator(owner)?;
            let owner_pk = &hex::encode(opk);
            eprintln!("owner key: {owner_label}");
            if owner_pk == recovery_pk {
                bail!("owner and recovery keys must differ (and live on different media and machines)");
            }
            let net = network_of(network)?;
            let r = match response {
                Some(f) => unwrap_server_file(serde_json::from_str(
                    &std::fs::read_to_string(f).with_context(|| format!("reading {}", f.display()))?,
                )?)?,
                None => sd.post(
                    "/v1/init",
                    serde_json::json!({"network": net as u8, "owner_pk_hex": owner_pk, "recovery_pk_hex": recovery_pk}),
                )?,
            };
            let card_hex = r["card_hex"].as_str().unwrap_or("").to_string();
            let card = IdentityCard::decode(&hex::decode(&card_hex)?).map_err(|_| anyhow!("card"))?;
            let identity_pk = hex::decode(r["identity_pk"].as_str().unwrap_or(""))?;
            let card_sig = <[u8; 64]>::try_from(hex::decode(r["card_sig_hex"].as_str().unwrap_or(""))?.as_slice())
                .map_err(|_| anyhow!("card sig"))?;
            let secp = bitcoin::secp256k1::Secp256k1::new();
            let idpk = <[u8; 33]>::try_from(identity_pk.as_slice()).map_err(|_| anyhow!("identity pk"))?;
            if !signer_core::sign::verify_digest_secp(&secp, &idpk, &card.digest(), &card_sig) {
                bail!("identity card signature does not verify — do not fund this wallet");
            }
            if card.identity_pk != idpk
                || Xpub::decode(&card.xpub).map(|x| x.to_string()).unwrap_or_default()
                    != r["xpub"].as_str().unwrap_or("")
            {
                bail!("identity card does not name the returned wallet — do not fund this wallet");
            }
            let mut rec = WalletRecord {
                network: network.clone(),
                xpub: r["xpub"].as_str().unwrap_or("").into(),
                fingerprint: r["fingerprint"].as_str().unwrap_or("").into(),
                identity_pk: hex::encode(idpk),
                mrsigner: None,
                signing_key_label: None,
                isv_prod_id: None,
                isv_svn: None,
                attested: None,
                trust_label: None,
                enclave_id: hex::encode(signer_core::sha256(&idpk)),
                card_hex,
                card_sig_hex: hex::encode(card_sig),
                mrenclave: hex::encode(card.mrenclave),
                tier: card.tier.clone(),
                recovery_blob_hex: r["recovery_blob_hex"].as_str().unwrap_or("").into(),
                owner_pk: owner_pk.clone(),
                recovery_pk: recovery_pk.clone(),
                last_seen_seq: Some(0),
                rollback_acceptances: None,
                owner_pin_hint: None,
            };
            if is_auto_arm(&rec.tier) {
                eprintln!("AUTO_ARM: this enclave was built with the pause after a restart compiled OUT (REQ-r7 §2.6). Rollback protection is OFF: the loss bound against root is the hot-wallet float. It has its own MRENCLAVE and is never ceremony-signed.");
                if !*accept_auto_arm {
                    bail!("REFUSED: not writing a record for an AUTO_ARM enclave without --accept-auto-arm (the enclave holds a fresh key set: wipe signerd's state dir if you did not mean this)");
                }
            }
            // C-R5-6: on T2 the verifier decides whether a record exists at all. The enclave has
            // generated its keys either way; a failed attestation means: do not keep, do not fund —
            // wipe the daemon's state and start over.
            if tier_base(&rec.tier) == "T2-release" {
                println!("T2 card: running the verifier before writing the record (C-R5-6)");
                if sd.offline.is_some() && quote.is_none() {
                    bail!("REFUSED: a T2 card with no tunnel needs the quote as a file: on the server `signerd quote --nonce <your 32-byte hex> --out quote.json`, then here `--quote quote.json --nonce <the same hex>`; no record is written");
                }
                if let Err(e) = attest_record(
                    &sd,
                    &mut rec,
                    expect_mrenclave.clone(),
                    None,
                    signing_key_label.clone(),
                    accept,
                    pccs,
                    true,
                    quote.clone(),
                    nonce.clone(),
                ) {
                    bail!("REFUSED: attestation failed — {e}\nThe wallet record is NOT written. The enclave holds a fresh, untrusted key set: wipe signerd's state dir and initialise again; do not fund.");
                }
                rec.trust_label = Some("attested".into());
            } else {
                rec.trust_label = Some(format!(
                    "TOFU: tier {} — no attestation exists on this hardware; the identity card is trusted on first use",
                    rec.tier
                ));
                println!("WARNING: {} (not attested)", rec.trust_label.as_deref().unwrap_or(""));
            }
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
                    None => {
                        let headers = json_u32(
                            &node.rpc("getblockchaininfo", serde_json::json!([]))?["headers"],
                            "node headers height",
                        )?;
                        headers
                            .checked_sub(6)
                            .ok_or_else(|| anyhow!("the node's chain is shorter than 6 blocks: no checkpoint to pin"))?
                    }
                };
                j.chain = Some(ChainJson { checkpoint: node.checkpoint(height)? });
                println!("checkpoint filled from the node at height {height}");
            } else if let Some(es) = esplora {
                let es = es.trim_end_matches('/');
                let b = busy("fetching the chain checkpoint from the explorer (network)");
                let tip: u32 = reqwest::blocking::get(format!("{es}/blocks/tip/height"))?
                    .error_for_status()?
                    .text()?
                    .trim()
                    .parse()?;
                let height = checkpoint_height.unwrap_or(tip.saturating_sub(6));
                let hdr = |h: u32| -> Result<serde_json::Value> {
                    let hash = reqwest::blocking::get(format!("{es}/block-height/{h}"))?.error_for_status()?.text()?;
                    let v: serde_json::Value =
                        reqwest::blocking::get(format!("{es}/block/{}", hash.trim()))?.error_for_status()?.json()?;
                    Ok(v)
                };
                let h = hdr(height)?;
                let p = hdr(period_start(height))?;
                drop(b);
                j.chain = Some(ChainJson {
                    checkpoint: CheckpointJson {
                        hash: h["id"].as_str().unwrap_or("").into(),
                        height,
                        time: json_u32(&h["timestamp"], "block timestamp")?,
                        bits: format!("{:08x}", json_u64(&h["bits"], "block bits")?),
                        period_start_time: json_u32(&p["timestamp"], "period start timestamp")?,
                        period_bits: format!("{:08x}", json_u64(&p["bits"], "period start bits")?),
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
        Cmd::PolicyShow { json, installed_file } => {
            let p = match installed_file {
                Some(f) => unwrap_server_file(serde_json::from_str(
                    &std::fs::read_to_string(f).with_context(|| format!("reading {}", f.display()))?,
                )?)?,
                None => client(&cli)?.get("/v1/policy")?,
            };
            let installed = Mandate::decode(&hex::decode(p["mandate_hex"].as_str().unwrap_or(""))?)
                .map_err(|_| anyhow!("installed mandate undecodable"))?;
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
                        Ok(Change::Loosening) => println!(
                            "classification: LOOSENING (waits {} blocks after acceptance)",
                            installed.timelock_blocks
                        ),
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
            let st = sd.get("/v1/status")?;
            let nonce = match nonce {
                Some(n) => *n,
                None => {
                    if st["installed"].as_bool() == Some(true) {
                        next_nonce(st["nonce"].as_u64().unwrap_or(0))?
                    } else {
                        0
                    }
                }
            };
            println!(
                "signing mandate {} for enclave {} at nonce {nonce}",
                hex::encode(m.hash()),
                hex::encode(enclave_id)
            );
            for (k, v) in describe(&m) {
                println!("  {k:<28} {v}");
            }
            // WYSIWYS: what is hashed is exactly the canonical bytes shown above (hash line)
            let okey = open_locator(key)?;
            println!("signer (owner key): {}", hex::encode(okey.pk));
            let mut msg = Message::PolicyUpdate { enclave_id, nonce, mandate: m.encode(), sig: [0; 64] };
            sign_message(&okey, &mut msg)?;
            if *dry_run {
                println!("message hex: {}", hex::encode(msg.encode()));
                return Ok(());
            }
            if nonce == 0 {
                if sd.out.is_some() {
                    submit_message(&sd, &msg)?; // `signerd submit` routes a nonce-0 PolicyUpdate to /v1/install
                } else {
                    let r = sd.post(
                        "/v1/install",
                        serde_json::json!({"mandate_hex": hex::encode(m.encode()), "sig_hex": hex::encode(msg.sig())}),
                    )?;
                    println!("installed: {r}");
                }
            } else {
                submit_message(&sd, &msg)?;
            }
        }
        Cmd::Cancel { key } => {
            let sd = client(&cli)?;
            let okey = open_locator(key)?;
            let mut msg = Message::Cancel { enclave_id: sd.enclave_id()?, nonce: sd.next_nonce()?, sig: [0; 64] };
            sign_message(&okey, &mut msg)?;
            submit_message(&sd, &msg)?;
        }
        Cmd::Unfreeze { key } => {
            let sd = client(&cli)?;
            let okey = open_locator(key)?;
            let mut msg = Message::Unfreeze { enclave_id: sd.enclave_id()?, nonce: sd.next_nonce()?, sig: [0; 64] };
            sign_message(&okey, &mut msg)?;
            submit_message(&sd, &msg)?;
        }
        Cmd::Rearm { key, seq } => {
            let sd = client(&cli)?;
            let okey = open_locator(key)?;
            let mut msg =
                Message::Rearm { enclave_id: sd.enclave_id()?, nonce: sd.next_nonce()?, seq: *seq, sig: [0; 64] };
            sign_message(&okey, &mut msg)?;
            submit_message(&sd, &msg)?;
        }
        Cmd::RotateOwner { key, new_owner } => {
            let sd = client(&cli)?;
            let (new_owner_pk, label) = owner_pk_of_locator(new_owner)?;
            eprintln!("new owner: {label}");
            let okey = open_locator(key)?;
            let mut msg = Message::RotateOwner {
                enclave_id: sd.enclave_id()?,
                nonce: sd.next_nonce()?,
                new_owner_pk,
                sig: [0; 64],
            };
            sign_message(&okey, &mut msg)?;
            submit_message(&sd, &msg)?;
        }
        Cmd::Recover { recovery_key, new_owner } => {
            let sd = client(&cli)?;
            let (new_owner_pk, label) = owner_pk_of_locator(new_owner)?;
            eprintln!("new owner: {label}");
            let rkey = open_key(recovery_key)?;
            let mut msg =
                Message::Recover { enclave_id: sd.enclave_id()?, nonce: sd.next_nonce()?, new_owner_pk, sig: [0; 64] };
            sign_message(&rkey, &mut msg)?;
            submit_message(&sd, &msg)?;
        }
        Cmd::Freeze => {
            let sd = client(&cli)?;
            println!("{}", sd.post("/v1/freeze", serde_json::json!({}))?);
        }
        Cmd::Attest {
            wallet,
            expect_mrenclave,
            expect_mrsigner,
            signing_key_label,
            accept,
            pccs,
            pin,
            save,
            replay,
            nonce,
            nonce_file,
        } => {
            let nonce = &match (nonce, nonce_file) {
                (None, Some(f)) => Some(std::fs::read_to_string(f)?.trim().to_string()),
                (n, _) => n.clone(),
            };
            // a carried quote needs no server; a live attest does
            let sd = if replay.is_some()
                && nonce.is_some()
                && cli.token.is_none()
                && cli.token_file.is_none()
                && cli.status_file.is_none()
            {
                Signerd {
                    url: String::new(),
                    token: String::new(),
                    record: cli.wallet_record.clone(),
                    offline: Some(serde_json::Value::Null),
                    out: cli.out.clone(),
                }
            } else {
                client(&cli)?
            };
            attest(
                &sd,
                wallet,
                expect_mrenclave.clone(),
                expect_mrsigner.clone(),
                signing_key_label.clone(),
                accept,
                pccs,
                *pin,
                save.clone(),
                replay.clone(),
                nonce.clone(),
            )?;
        }
        Cmd::Monitor {
            wallet,
            mandate,
            esplora,
            interval,
            esplora_delay_ms,
            full_every,
            journal,
            once,
            no_freeze,
            witness_key,
            stall_after,
            max_tip_lag,
            max_addresses,
            node_rpc,
            node_cookie,
            acknowledge,
        } => {
            let sd = client(&cli)?;
            let cfg = monitor::Cfg {
                wallet: wallet.clone(),
                mandate: mandate.clone(),
                esplora: esplora.clone(),
                interval: *interval,
                journal: journal.clone(),
                once: *once,
                freeze: !*no_freeze,
                witness_key: witness_key.clone(),
                stall_after: *stall_after,
                max_tip_lag: *max_tip_lag,
                max_addresses: *max_addresses,
                esplora_delay_ms: *esplora_delay_ms,
                full_every: *full_every,
                node_rpc: node_rpc.clone(),
                node_cookie: node_cookie.clone(),
                acknowledge: acknowledge.clone(),
            };
            let code = monitor::run(&sd, &cfg)?;
            std::process::exit(code);
        }
        Cmd::Status => {
            let sd = client(&cli)?;
            let st = sd.get("/v1/status")?;
            println!("{}", serde_json::to_string_pretty(&st)?);
            if st["initialised"].as_bool() == Some(true) && st["boot_armed"].as_bool() == Some(false) {
                eprintln!("NOT ARMED: the enclave was (re)started and signs nothing until you approve this load: owner-cli arm --key <owner> --wallet-record <wallet.json> (REQ-r7)");
            }
        }
        Cmd::Arm { key, i_have_investigated } => {
            let sd = client(&cli)?;
            let rec_path = cli.wallet_record.clone().ok_or_else(|| anyhow!("arm needs --wallet-record <wallet.json> (or OWNER_WALLET): the sequence you last saw lives there, on this machine (C-R7-5)"))?;
            // the record FIRST: a status read raises its last_seen_seq to the enclave's, and the whole
            // point of this command is to compare the enclave against what the owner saw BEFORE
            let mut w: WalletRecord = serde_json::from_str(&std::fs::read_to_string(&rec_path)?)?;
            let last = w.last_seen_seq.unwrap_or(0);
            let st = sd.get("/v1/status")?;
            let seq = json_u64(&st["seq"], "status seq")?;
            let armed = st["boot_armed"].as_bool().unwrap_or(false);
            let challenge_hex = st["boot_challenge"].as_str().unwrap_or("").to_string();
            let session = st["session_id"].as_str().unwrap_or("").to_string();
            if armed {
                bail!("this enclave load is already armed (session {session}); nothing to do");
            }
            println!("enclave load {session}: boot challenge {challenge_hex}");
            println!("enclave remembers seq {seq}; you last saw seq {last}");
            let mut seq_seen = last;
            if seq < last {
                eprintln!("ROLLBACK SIGNATURE: the enclave remembers {} fewer operations than you last saw (it has {seq}, you saw {last}). This is what a restored older state file looks like. Do NOT arm unless you know why (a restore from backup you did yourself, a crash between an operation and this record).", last.saturating_sub(seq));
                if !*i_have_investigated {
                    bail!("REFUSED to arm over a sequence regression; after investigating, repeat with --i-have-investigated (this acceptance is logged in the record)");
                }
                let line =
                    format!("{} enclave seq {seq} < last seen {last}: armed with --i-have-investigated", now_utc());
                eprintln!("ACCEPTED BY THE OWNER and logged: {line}");
                w.rollback_acceptances.get_or_insert_with(Vec::new).push(line);
                w.last_seen_seq = Some(seq);
                std::fs::write(&rec_path, serde_json::to_string_pretty(&w)?)?;
                seq_seen = seq;
            }
            let boot_challenge = <[u8; 32]>::try_from(hex::decode(&challenge_hex)?.as_slice())
                .map_err(|_| anyhow!("boot challenge is not 32 bytes"))?;
            let okey = open_locator(key)?;
            let mut msg = Message::Arm {
                enclave_id: sd.enclave_id()?,
                nonce: sd.next_nonce()?,
                boot_challenge,
                seq_seen,
                sig: [0; 64],
            };
            sign_message(&okey, &mut msg)?;
            submit_message(&sd, &msg)?;
            if sd.out.is_some() {
                println!("after `signerd submit` on the server, `signerd status --out …` there will show boot_armed: true for load {session}");
            } else {
                let st = sd.get("/v1/status")?;
                if st["boot_armed"].as_bool() == Some(true) {
                    println!("armed: this load (session {session}) signs inside the mandate again");
                } else {
                    bail!("the enclave did not report armed after the message was accepted");
                }
            }
        }
        Cmd::Anchor {
            key,
            tpm_info_file,
            ak_pk_file,
            nv_name_file,
            proof_file,
            proof_nonce_file,
            i_have_investigated,
        } => {
            let sd = client(&cli)?;
            let rec_path = cli.wallet_record.clone().ok_or_else(|| anyhow!("anchor needs --wallet-record <wallet.json> (or OWNER_WALLET): the sequence you last saw lives there (C-R7-5)"))?;
            let mut w: WalletRecord = serde_json::from_str(&std::fs::read_to_string(&rec_path)?)?;
            let last = w.last_seen_seq.unwrap_or(0);
            // the pinned material: from the transport's info file, or from the owner's own two files
            let (ak_pk, nv_name): ([u8; 65], [u8; signer_core::tpm_attest::NV_NAME_LEN]) =
                match (tpm_info_file, ak_pk_file, nv_name_file) {
                    (Some(f), _, _) => {
                        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(f)?)?;
                        let v = unwrap_server_file(v)?;
                        let ak =
                            hex::decode(v["ak_pk_hex"].as_str().ok_or_else(|| anyhow!("tpm-info file: ak_pk_hex"))?)?;
                        let nm = hex::decode(
                            v["nv_name_hex"].as_str().ok_or_else(|| anyhow!("tpm-info file: nv_name_hex"))?,
                        )?;
                        (
                            <[u8; 65]>::try_from(ak.as_slice()).map_err(|_| anyhow!("ak_pk: 65 bytes"))?,
                            <[u8; 34]>::try_from(nm.as_slice()).map_err(|_| anyhow!("nv_name: 34 bytes"))?,
                        )
                    }
                    (None, Some(a), Some(n)) => {
                        let ak = hex::decode(std::fs::read_to_string(a)?.trim())?;
                        let nm = hex::decode(std::fs::read_to_string(n)?.trim())?;
                        (
                            <[u8; 65]>::try_from(ak.as_slice()).map_err(|_| anyhow!("ak_pk: 65 bytes"))?,
                            <[u8; 34]>::try_from(nm.as_slice()).map_err(|_| anyhow!("nv_name: 34 bytes"))?,
                        )
                    }
                    _ => bail!("give --tpm-info-file, or --ak-pk-file and --nv-name-file"),
                };
            // C-R9-D: the counter comes from an attested read over the owner's own nonce
            let proof_nonce =
                <[u8; 32]>::try_from(hex::decode(std::fs::read_to_string(proof_nonce_file)?.trim())?.as_slice())
                    .map_err(|_| anyhow!("proof nonce: 32 bytes"))?;
            let pv: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(proof_file)?)?;
            let pv = unwrap_server_file(pv)?;
            let attest = hex::decode(pv["attest_hex"].as_str().ok_or_else(|| anyhow!("proof file: attest_hex"))?)?;
            let sig_v = hex::decode(pv["sig_hex"].as_str().ok_or_else(|| anyhow!("proof file: sig_hex"))?)?;
            let sig = <[u8; 64]>::try_from(sig_v.as_slice()).map_err(|_| anyhow!("proof sig: 64 bytes"))?;
            let parsed = signer_core::tpm_attest::parse_nv_attest(&attest)
                .map_err(|r| anyhow!("the certify proof does not parse: {}", r.code()))?;
            let probe = signer_core::tpm_attest::TpmAnchor { ak_pk, nv_name, expected: parsed.counter };
            let counter = signer_core::tpm_attest::verify_nv_certify(&attest, &sig, &probe, &proof_nonce)
                .map_err(|r| anyhow!("the certify proof is REFUSED ({}): not this key, not this index, or not your nonce — do not anchor", r.code()))?;
            println!(
                "attested counter: {counter} (index {}…, key {}…)",
                hex::encode(&nv_name[..6]),
                hex::encode(&ak_pk[1..7])
            );
            let st = sd.get("/v1/status")?;
            let seq = json_u64(&st["seq"], "status seq")?;
            let challenge_hex = st["boot_challenge"].as_str().unwrap_or("").to_string();
            let session = st["session_id"].as_str().unwrap_or("").to_string();
            if st["tpm_bound"].as_bool() == Some(true) {
                println!(
                    "the state is already TPM-bound (expects {}); this anchor RE-PINS it",
                    st["tpm_expected"].as_u64().unwrap_or(0)
                );
            }
            println!("enclave load {session}: boot challenge {challenge_hex}");
            println!("enclave remembers seq {seq}; you last saw seq {last}");
            let mut seq_seen = last;
            if seq < last {
                eprintln!("ROLLBACK SIGNATURE: the enclave remembers {} fewer operations than you last saw (it has {seq}, you saw {last}). Do NOT anchor unless you know why.", last.saturating_sub(seq));
                if !*i_have_investigated {
                    bail!("REFUSED to anchor over a sequence regression; after investigating, repeat with --i-have-investigated (logged in the record)");
                }
                let line =
                    format!("{} enclave seq {seq} < last seen {last}: anchored with --i-have-investigated", now_utc());
                eprintln!("ACCEPTED BY THE OWNER and logged: {line}");
                w.rollback_acceptances.get_or_insert_with(Vec::new).push(line);
                w.last_seen_seq = Some(seq);
                std::fs::write(&rec_path, serde_json::to_string_pretty(&w)?)?;
                seq_seen = seq;
            }
            let boot_challenge = <[u8; 32]>::try_from(hex::decode(&challenge_hex)?.as_slice())
                .map_err(|_| anyhow!("boot challenge is not 32 bytes"))?;
            let okey = open_locator(key)?;
            let mut msg = Message::Anchor {
                enclave_id: sd.enclave_id()?,
                nonce: sd.next_nonce()?,
                boot_challenge,
                ak_pk,
                nv_name,
                counter,
                seq_seen,
                sig: [0; 64],
            };
            sign_message(&okey, &mut msg)?;
            submit_message(&sd, &msg)?;
            if sd.out.is_some() {
                println!("after `signerd submit` on the server, `signerd status --out …` there will show tpm_bound: true, tpm_expected: at least {} (REQ-r9a: the counter the TPM certifies at apply time, plus one — the daemon's own state writes may have moved it past what you saw) and boot_armed: true for load {session}", counter.saturating_add(1));
            } else {
                let st = sd.get("/v1/status")?;
                if st["tpm_bound"].as_bool() == Some(true) && st["boot_armed"].as_bool() == Some(true) {
                    println!("anchored: the state expects counter {} and this load is armed; restarts now need no owner while the TPM agrees", st["tpm_expected"].as_u64().unwrap_or(0));
                } else {
                    bail!("the enclave did not report tpm_bound + armed after the anchor was accepted");
                }
            }
        }
        Cmd::RecoveryVerify { wallet, recovery_key, print_mnemonic } => {
            let w: WalletRecord = serde_json::from_str(&std::fs::read_to_string(wallet)?)?;
            let rkey = open_key(recovery_key)?;
            let fp =
                <[u8; 4]>::try_from(hex::decode(&w.fingerprint)?.as_slice()).map_err(|_| anyhow!("fingerprint"))?;
            let xpub = Xpub::from_str(&w.xpub)?.encode();
            let sk_bytes = rkey.scalar()?;
            let entropy = recovery_decrypt(&sk_bytes, &fp, &xpub, &hex::decode(&w.recovery_blob_hex)?)?;
            drop(sk_bytes);
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
                eprintln!("WARNING: these 24 words ARE the wallet. Whoever sees them takes everything; no enclave, mandate or monitor can undo that.");
                eprintln!("         Print them only on an offline machine, only to restore the wallet elsewhere. Verifying the blob needs no printing.");
                let ok = passphrase("type PRINT to continue", false)?;
                if ok != "PRINT" {
                    bail!("not printed");
                }
                println!("{mnemonic}");
            }
        }
        Cmd::Address { wallet, branch, index } => {
            let w: WalletRecord = serde_json::from_str(&std::fs::read_to_string(wallet)?)?;
            println!("{}", psbt::address(&w.xpub, network_of(&w.network)?, *branch, *index)?);
        }
        Cmd::PsbtBuild { wallet, esplora, prev_tx_hex, utxo, branch, index, to, amount, fee, change_index } => {
            let w: WalletRecord = serde_json::from_str(&std::fs::read_to_string(wallet)?)?;
            let b64 = psbt::build(
                &w.xpub,
                &w.fingerprint,
                network_of(&w.network)?,
                esplora,
                prev_tx_hex.as_deref(),
                utxo,
                *branch,
                *index,
                to,
                *amount,
                *fee,
                *change_index,
            )?;
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
            let wkey = open_locator(key)?;
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
    let pt = cipher
        .decrypt(Nonce::from_slice(&[0u8; 12]), Payload { msg: &blob[65..], aad: &aad })
        .map_err(|_| anyhow!("the blob does not open with this key for this wallet"))?;
    key.zeroize();
    let mut out = [0u8; 32];
    if pt.len() != 32 {
        bail!("plaintext length");
    }
    out.copy_from_slice(&pt);
    Ok(out)
}

/// SHA-256 of the DER of Intel's SGX Root CA as served at
/// certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.pem on
/// 2026-11-03 (notAfter 2049-12-31). The PEM is compiled in; the verifier crate's own copy must
/// agree, so the root is pinned twice and supplied by neither the host nor the network (C-R5-2).
const INTEL_SGX_ROOT_CA_SHA256: &str = "44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3";
const INTEL_SGX_ROOT_CA_PEM: &str = include_str!("intel_sgx_root_ca.pem");
/// The ceremony enclave-signing key's MRSIGNER, pinned in the repo (`enclave/ceremony/mrsigner.txt`,
/// REQ-r6 §3) and compiled in: the default expectation at step 4 when neither the record nor the
/// command line pins one, so a fused `init` refuses any other signer unless told so explicitly.
const CEREMONY_MRSIGNER: &str = include_str!("../../../enclave/ceremony/mrsigner.txt");

fn pem_der(pem: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    Ok(base64::engine::general_purpose::STANDARD.decode(body.trim())?)
}

/// The `attest` command: load the record, verify, optionally pin and save.
#[allow(clippy::too_many_arguments)]
fn attest(
    sd: &Signerd,
    wallet: &Path,
    expect_mrenclave: Option<String>,
    expect_mrsigner: Option<String>,
    signing_key_label: Option<String>,
    accept: &[String],
    pccs: &str,
    pin: bool,
    save: Option<PathBuf>,
    replay: Option<PathBuf>,
    nonce_hex: Option<String>,
) -> Result<()> {
    let mut w: WalletRecord = serde_json::from_str(&std::fs::read_to_string(wallet)?)?;
    let (_rec, out) = attest_record(
        sd,
        &mut w,
        expect_mrenclave,
        expect_mrsigner,
        signing_key_label,
        accept,
        pccs,
        pin,
        replay,
        nonce_hex,
    )?;
    if pin {
        std::fs::write(wallet, serde_json::to_string_pretty(&w)?)?;
        println!("wallet record updated (pinned MRSIGNER, ProdID, SVN; attestation recorded)");
    }
    if let Some(path) = save {
        std::fs::write(&path, serde_json::to_string_pretty(&out)?)?;
        println!("saved {}", path.display());
    }
    Ok(())
}

/// REQ-r5 §4 on an in-memory record (so `init` can refuse to write one — C-R5-6). Every step
/// refuses by name; nothing is a warning. With `pin`, MRSIGNER/ProdID/SVN and the attestation are
/// set on the record (the caller writes it).
#[allow(clippy::too_many_arguments)]
fn attest_record(
    sd: &Signerd,
    w: &mut WalletRecord,
    expect_mrenclave: Option<String>,
    expect_mrsigner: Option<String>,
    signing_key_label: Option<String>,
    accept: &[String],
    pccs: &str,
    pin: bool,
    replay: Option<PathBuf>,
    nonce_hex: Option<String>,
) -> Result<(AttestRecord, serde_json::Value)> {
    use dcap_qvl::quote::Report;
    use dcap_qvl::verify::QuoteVerifier;
    use sha2::Digest;
    use signer_core::proto::quote;

    // the root of trust, pinned twice
    let root_der = pem_der(INTEL_SGX_ROOT_CA_PEM)?;
    let root_sha = hex::encode(sha2::Sha256::digest(&root_der));
    if root_sha != INTEL_SGX_ROOT_CA_SHA256 {
        bail!("refused: the compiled-in Intel SGX Root CA does not match its pinned hash ({root_sha})");
    }
    if !pccs.starts_with("https://api.trustedservices.intel.com") {
        bail!("refused: collateral must come from Intel PCS v4 (got {pccs}); Azure THIM is not the authority here (C-R5-2)");
    }

    // the nonce the quote must bind: fresh here (live), or the one the owner chose for a carried quote
    let nonce: [u8; 32] = match &nonce_hex {
        Some(h) => {
            <[u8; 32]>::try_from(hex::decode(h)?.as_slice()).map_err(|_| anyhow!("--nonce must be 32 bytes hex"))?
        }
        None => rand::random(),
    };
    let r = match &replay {
        Some(path) => {
            if nonce_hex.is_some() {
                println!(
                    "NO TUNNEL: verifying the quote carried in {} against the nonce you chose, {}",
                    path.display(),
                    hex::encode(nonce)
                );
            } else {
                println!(
                    "REPLAY VECTOR: verifying the quote saved in {} against the fresh nonce {}",
                    path.display(),
                    hex::encode(nonce)
                );
            }
            unwrap_server_file(serde_json::from_str::<serde_json::Value>(&std::fs::read_to_string(path)?)?)?
        }
        None => sd.get(&format!("/v1/quote?nonce={}", hex::encode(nonce)))?,
    };
    let quote_bytes = hex::decode(r["quote_hex"].as_str().ok_or_else(|| anyhow!("quote_hex"))?)?;
    let card_bytes = hex::decode(r["card_hex"].as_str().ok_or_else(|| anyhow!("card_hex"))?)?;
    let card = IdentityCard::decode(&card_bytes).map_err(|_| anyhow!("card decode"))?;
    println!("quote: {} bytes via {}", quote_bytes.len(), r["quoted_via"].as_str().unwrap_or("?"));

    // 1. chain + collateral (Intel PCS v4) + expiry
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let b = busy("fetching Intel's collateral and verifying the quote chain (network)");
    let collateral = rt
        .block_on(async {
            let c = dcap_qvl::collateral::CollateralClient::with_default_http(pccs)?;
            c.fetch(&quote_bytes).await
        })
        .map_err(|e| anyhow!("step 1 refused: collateral from {pccs}: {e}"))?;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
    let vr = QuoteVerifier::new(root_der).verify(&quote_bytes, &collateral, now).map_err(|e| {
        let m = e.to_string();
        if m.contains("Debug mode") {
            // the verifier crate refuses a debug quote inside its authenticated check — the only
            // place ATTRIBUTES may be believed — so this is step 2, decided before any measurement
            anyhow!("step 2 refused: ATTRIBUTES.DEBUG is set — a debug enclave (host-readable memory) can attest nothing ({m})")
        } else {
            anyhow!("step 1 refused: quote chain/collateral: {m}")
        }
    })?;
    // the verifier crate's own embedded root must agree with ours (two independent pins of one CA)
    QuoteVerifier::new_prod().verify(&quote_bytes, &collateral, now).map_err(|e| {
        anyhow!("step 1 refused: the verifier crate's embedded Intel root disagrees with the pinned one: {e}")
    })?;
    drop(b);
    println!("step 1 ok: quote chain verifies to the pinned Intel SGX Root CA (sha256 {INTEL_SGX_ROOT_CA_SHA256}); collateral from {pccs}");

    // 2. DEBUG == 0, before anything else about the enclave is believed
    let Report::SgxEnclave(body) = vr.report else { bail!("step 2 refused: not an SGX enclave quote") };
    let attr_flags = u64::from_le_bytes(body.attributes[..8].try_into().map_err(|_| anyhow!("attributes"))?);
    if attr_flags & 0x2 != 0 {
        bail!("step 2 refused: ATTRIBUTES.DEBUG is set — a debug enclave (host-readable memory) can attest nothing");
    }
    println!("step 2 ok: ATTRIBUTES.DEBUG = 0 (flags 0x{attr_flags:x})");

    // 3. MRENCLAVE == card == pinned
    let expected_mr = expect_mrenclave.unwrap_or_else(|| w.mrenclave.clone());
    let q_mr = hex::encode(body.mr_enclave);
    if q_mr != hex::encode(card.mrenclave) || q_mr != expected_mr.to_lowercase() {
        bail!("step 3 refused: MRENCLAVE quote {q_mr} / card {} / expected {expected_mr}", hex::encode(card.mrenclave));
    }
    println!("step 3 ok: MRENCLAVE {q_mr}");

    // 4. MRSIGNER / ProdID / SVN
    let q_ms = hex::encode(body.mr_signer);
    let ceremony = CEREMONY_MRSIGNER.trim().to_lowercase();
    let expected = expect_mrsigner
        .as_deref()
        .map(|s| s.to_lowercase())
        .or_else(|| w.mrsigner.clone())
        .unwrap_or_else(|| ceremony.clone());
    if expected != q_ms {
        bail!(
            "step 4 refused: MRSIGNER {q_ms}, expected {expected}{}",
            if expected == ceremony {
                " (the pinned ceremony key; a dev-key enclave must be named explicitly with --expect-mrsigner and labeled)"
            } else {
                ""
            }
        );
    }
    if q_ms == ceremony {
        println!("step 4: MRSIGNER is the pinned ceremony key");
    } else if w.mrsigner.is_none() {
        println!(
            "step 4: MRSIGNER {q_ms} named explicitly ({})",
            signing_key_label.clone().unwrap_or_else(|| "UNLABELED".into())
        );
    }
    if let Some(p) = w.isv_prod_id {
        if p != body.isv_prod_id {
            bail!("step 4 refused: ISV ProdID {} != pinned {p}", body.isv_prod_id)
        }
    }
    if let Some(v) = w.isv_svn {
        if body.isv_svn < v {
            bail!("step 4 refused: ISV SVN {} below pinned {v}", body.isv_svn)
        }
    }
    println!(
        "step 4 ok: MRSIGNER {q_ms} ({}), ProdID {}, SVN {}",
        signing_key_label.clone().or(w.signing_key_label.clone()).unwrap_or_else(|| "label pending".into()),
        body.isv_prod_id,
        body.isv_svn
    );

    // 5. the card is the one INIT signed, under the identity key, and says T2
    let rec_card = hex::decode(&w.card_hex)?;
    if rec_card != card_bytes {
        bail!("step 5 refused: the enclave's card differs from the wallet record's (xpub/identity/tier changed?)");
    }
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let idpk = <[u8; 33]>::try_from(hex::decode(&w.identity_pk)?.as_slice()).map_err(|_| anyhow!("identity pk"))?;
    let card_sig = <[u8; 64]>::try_from(hex::decode(&w.card_sig_hex)?.as_slice()).map_err(|_| anyhow!("card sig"))?;
    if !signer_core::sign::verify_digest_secp(&secp, &idpk, &card.digest(), &card_sig) {
        bail!("step 5 refused: the card's identity signature does not verify");
    }
    if tier_base(&card.tier) != "T2-release" {
        bail!("step 5 refused: card tier is {}, not T2-release", card.tier);
    }
    if is_auto_arm(&card.tier) {
        eprintln!("AUTO_ARM: the attested card says the pause after a restart is compiled OUT — rollback protection OFF, loss bound against root = hot-wallet float; this MRENCLAVE is not the pinned pause build and is never ceremony-signed (REQ-r7 §2.6, C-R7-7)");
    }
    println!("step 5 ok: card signed by identity {}, tier {}", w.identity_pk, card.tier);

    // 6. report_data binds this nonce and this card
    let expect = signer_core::sha256(&quote::preimage(&nonce, &card_bytes));
    if body.report_data[..32] != expect[..] || body.report_data[32..] != [0u8; 32] {
        // Two different failures hide behind one mismatch (T2 migration, 2026-11-12): the server's quote
        // record names the nonce the server was handed; if report_data binds THAT nonce, the quote is a
        // genuine fresh quote over a nonce that is not ours — the nonce did not reach the server (a stale
        // nonce.txt there) — refused all the same, but the operator is told to check the transfer, not to
        // suspect a replay or a foreign enclave.
        let server_nonce = r["nonce"].as_str().and_then(|h| hex::decode(h).ok());
        if let Some(sn) = server_nonce.as_deref().filter(|n| n.len() == 32 && *n != &nonce[..]) {
            let over_server_nonce =
                signer_core::sha256(&quote::preimage(sn.try_into().unwrap_or(&[0u8; 32]), &card_bytes));
            if body.report_data[..32] == over_server_nonce[..] && body.report_data[32..] == [0u8; 32] {
                bail!(
                    "step 6 refused: the server quoted over nonce {}…, not over yours ({}…) — the nonce you chose did not reach the server (a stale nonce.txt in its exchange directory?). Not a replay by itself: carry your nonce to the server, quote again, verify again",
                    hex::encode(&sn[..8]),
                    hex::encode(&nonce[..8])
                );
            }
        }
        bail!("step 6 refused: report_data does not equal SHA-256(domain ‖ our nonce ‖ card) ‖ 0 — a replayed or foreign quote");
    }
    println!("step 6 ok: report_data = SHA-256(domain ‖ nonce {} ‖ card)", hex::encode(nonce));

    // 7. TCB policy: OK, or SW_HARDENING_NEEDED with every advisory in the ledger; everything else refused
    let status = vr.status.clone();
    let mut used = Vec::new();
    match status.as_str() {
        "UpToDate" => {}
        "SWHardeningNeeded" => {
            let ledger: Vec<(String, String, String)> = accept
                .iter()
                .map(|e| {
                    let mut it = e.splitn(3, ':');
                    (
                        it.next().unwrap_or("").to_string(),
                        it.next().unwrap_or("").to_string(),
                        it.next().unwrap_or("").to_string(),
                    )
                })
                .collect();
            for adv in &vr.advisory_ids {
                match ledger.iter().find(|(id, _, _)| id == adv) {
                    Some((id, date, why)) if !date.is_empty() && !why.is_empty() => used.push(format!("{id} ({date}: {why})")),
                    _ => bail!("step 7 refused: TCB status SWHardeningNeeded with advisory {adv} not in the dated exception ledger (--accept-advisory {adv}:YYYY-MM-DD:reason)"),
                }
            }
            if vr.advisory_ids.is_empty() {
                bail!("step 7 refused: SWHardeningNeeded with no advisory IDs — nothing to ledger against");
            }
        }
        other => bail!("step 7 refused: TCB status {other} (advisories {:?})", vr.advisory_ids),
    }
    if used.is_empty() {
        println!("step 7 ok: TCB status {status} — attested");
    } else {
        println!("step 7 ok: TCB status {status} — attested WITH RECORDED EXCEPTIONS: {}", used.join("; "));
    }

    let quote_sha = hex::encode(sha2::Sha256::digest(&quote_bytes));
    let rec = AttestRecord {
        at_unix: now,
        tier: card.tier.clone(),
        tcb_status: status.clone(),
        advisory_ids: vr.advisory_ids.clone(),
        accepted_exceptions: used.clone(),
        collateral_source: pccs.to_string(),
        verifier: "dcap-qvl 0.7.1 (pure Rust, owner's machine), Intel SGX Root CA pinned".into(),
        quote_sha256: quote_sha.clone(),
    };
    println!(
        "ATTESTED: MRENCLAVE {q_mr}, MRSIGNER {q_ms}, {} ; quote sha256 {quote_sha}",
        if used.is_empty() { "TCB OK".to_string() } else { format!("TCB {status} with recorded exceptions") }
    );
    if pin {
        w.mrsigner = Some(q_ms.clone());
        if signing_key_label.is_some() {
            w.signing_key_label = signing_key_label.clone();
        }
        w.isv_prod_id = Some(body.isv_prod_id);
        w.isv_svn = Some(body.isv_svn);
        w.attested = Some(rec.clone());
        w.trust_label = Some("attested".into());
    }
    let out = serde_json::json!({
        "nonce": hex::encode(nonce), "quote_hex": hex::encode(&quote_bytes), "card_hex": hex::encode(&card_bytes),
        "mrenclave": q_mr, "mrsigner": q_ms, "isv_prod_id": body.isv_prod_id, "isv_svn": body.isv_svn,
        "attributes_flags": format!("0x{attr_flags:x}"), "verification": rec,
    });
    Ok((rec, out))
}

#[cfg(test)]
mod piv_locator_tests {
    use super::*;
    use hw_signer::yubikey_piv::PivSlot;

    #[test]
    fn piv_locator_parses_slot_and_optional_serial() {
        let (slot, serial) = piv_locator("piv:9a").unwrap().unwrap();
        assert_eq!(slot, PivSlot::Authentication);
        assert_eq!(serial, None);
        let (slot, serial) = piv_locator("piv:9c@12345678").unwrap().unwrap();
        assert_eq!(slot, PivSlot::Signature);
        assert_eq!(serial, Some(12345678));
        let (slot, _) = piv_locator("piv:82").unwrap().unwrap();
        assert_eq!(hw_signer::yubikey_piv::slot_name(slot), "82");
    }

    #[test]
    fn owner_role_accepts_only_pin_always_touch_always() {
        use hw_signer::yubikey_piv::{PivPinPolicy as P, PivTouchPolicy as T};
        assert!(owner_slot_policy_ok("piv:9a@1", P::Always, T::Always).is_ok());
        for (pin, touch) in [
            (P::Always, T::Cached),
            (P::Always, T::Never),
            (P::Always, T::Default),
            (P::Once, T::Always),
            (P::Never, T::Always),
            (P::Default, T::Always),
            (P::Once, T::Cached),
            (P::Never, T::Never),
            (P::Default, T::Default),
        ] {
            let e = owner_slot_policy_ok("piv:9a@1", pin, touch).unwrap_err().to_string();
            assert!(e.starts_with("REFUSED:"), "{pin:?}/{touch:?}: {e}");
        }
    }

    #[test]
    fn piv_locator_refuses_garbage_and_ignores_other_locators() {
        assert!(piv_locator("piv:zz").unwrap().is_err());
        assert!(piv_locator("piv:9a@notanumber").unwrap().is_err());
        assert!(piv_locator("piv:").unwrap().is_err());
        assert!(piv_locator("tpm:0x81000100").is_none());
        assert!(piv_locator(".local/signet/owner.key").is_none());
    }
}

#[cfg(test)]
mod hint_tests {
    use super::check_hint;

    #[test]
    fn hint_never_contains_the_passphrase() {
        assert_eq!(
            check_hint("  password manager, entry tee-recovery ", "correct horse").unwrap(),
            "password manager, entry tee-recovery"
        );
        assert!(check_hint("", "x").is_err(), "empty");
        assert!(check_hint(&"h".repeat(201), "x").is_err(), "too long");
        assert!(check_hint("it is Correct Horse battery", "correct horse").is_err(), "hint contains the passphrase");
        assert!(check_hint("horse", "correct horse battery").is_err(), "passphrase contains the hint");
    }
}

#[cfg(test)]
mod rule9_tests {
    //! The SafeMath helpers (rule 9; #18): a value that does not fit is refused by name, never truncated.
    use super::*;

    #[test]
    fn json_u32_refuses_what_does_not_fit() {
        assert_eq!(json_u32(&serde_json::json!(7), "h").unwrap(), 7);
        assert_eq!(json_u32(&serde_json::json!(u32::MAX), "h").unwrap(), u32::MAX);
        assert!(json_u32(&serde_json::json!(u64::from(u32::MAX) + 1), "h").is_err());
        assert!(json_u32(&serde_json::json!(u64::MAX), "h").is_err());
        assert!(json_u32(&serde_json::json!(-1), "h").is_err());
        assert!(json_u32(&serde_json::json!(1.5), "h").is_err());
        assert!(json_u32(&serde_json::json!("7"), "h").is_err());
        assert!(json_u32(&serde_json::Value::Null, "h").is_err());
    }

    #[test]
    fn btc_sat_rounds_as_the_node_does_and_refuses_garbage() {
        assert_eq!(btc_sat(&serde_json::json!(1.0)).unwrap(), 100_000_000);
        assert_eq!(btc_sat(&serde_json::json!(0.00000001)).unwrap(), 1);
        assert_eq!(btc_sat(&serde_json::json!(0.29999999)).unwrap(), 29_999_999);
        assert_eq!(btc_sat(&serde_json::json!(20999999.9769)).unwrap(), 2_099_999_997_690_000);
        assert!(btc_sat(&serde_json::json!(-1.0)).is_err());
        assert!(btc_sat(&serde_json::json!("1.0")).is_err());
        assert!(btc_sat(&serde_json::Value::Null).is_err());
    }

    #[test]
    fn next_nonce_stops_at_the_end_of_the_range() {
        assert_eq!(next_nonce(0).unwrap(), 1);
        assert_eq!(next_nonce(41).unwrap(), 42);
        assert!(next_nonce(u64::MAX).is_err());
    }

    #[test]
    fn period_start_is_the_retarget_boundary() {
        assert_eq!(period_start(0), 0);
        assert_eq!(period_start(2015), 0);
        assert_eq!(period_start(2016), 2016);
        assert_eq!(period_start(4031), 2016);
        assert_eq!(period_start(u32::MAX), u32::MAX - u32::MAX % 2016);
    }
}
