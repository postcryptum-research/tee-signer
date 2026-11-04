//! YubiKey PIV slot attestation (C-R6-3, the auditor's recommendation at scenario 2).
//!
//! Proves, under Yubico's published attestation root pinned here, that the key in a slot was
//! GENERATED on this device (Yubico attests generated keys only: an imported key has no
//! attestation certificate) with the PIN and touch policies the owner role needs. The device's
//! own metadata answer says the same things but is unsigned; the attestation is the signed form.
//!
//! Chain (firmware 5.7+): slot certificate (signed by the device's f9 attestation key) ← f9
//! certificate ← `Yubico PIV Attestation <X>` ← `Yubico Attestation Intermediate <X>` ←
//! `Yubico Attestation Root 1`. Every link is RSA-2048 / SHA-256 PKCS#1 v1.5; the root is
//! trusted by pin, not by its self-signature. Firmware older than 5.7 chains to the retired
//! `Yubico PIV Root CA Serial 263751`, which this verifier does not accept.
//!
//! Not checked: certificate validity dates (the owner's laptop has no trusted clock for this
//! purpose; Yubico's attestation certificates are long-lived by design) and revocation (Yubico
//! publishes none for attestation).

use anyhow::{anyhow, bail, Result};
use der::{Decode, Encode};
use rsa::signature::Verifier;
use sha2::{Digest, Sha256};
use x509_cert::Certificate;

/// `https://developers.yubico.com/PKI/yubico-ca-1.pem`, fetched 2026-11-04; pinned by hash.
pub const YUBICO_ROOT_PEM: &str = include_str!("yubico-ca-1.pem");
pub const YUBICO_ROOT_SHA256: &str = "9271d914d48d05487666703586aea27d9a69ad0c8ddf8c2fc4c8734a04285887";
/// `https://developers.yubico.com/PKI/yubico-intermediate.pem`, fetched 2026-11-04; pinned by hash.
pub const YUBICO_INTERMEDIATES_PEM: &str = include_str!("yubico-intermediate.pem");
pub const YUBICO_INTERMEDIATES_SHA256: &str = "ec0172fe38838e3de174aae4e058bb44920be47cebd8d658a0fba1634b82aee1";

const OID_SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";
const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const OID_P256: &str = "1.2.840.10045.3.1.7";
const OID_BASIC_CONSTRAINTS: &str = "2.5.29.19";
const OID_YK_FIRMWARE: &str = "1.3.6.1.4.1.41482.3.3";
const OID_YK_SERIAL: &str = "1.3.6.1.4.1.41482.3.7";
const OID_YK_POLICY: &str = "1.3.6.1.4.1.41482.3.8";
const OID_YK_FORM_FACTOR: &str = "1.3.6.1.4.1.41482.3.9";
const MAX_CHAIN: usize = 8;

/// What the verified attestation says about the key.
#[derive(Debug, serde::Serialize)]
pub struct Attested {
    pub serial: u32,
    pub firmware: String,
    pub pin_policy: String,
    pub touch_policy: String,
    pub form_factor: Option<u8>,
    /// Subjects from the slot certificate up to the pinned root.
    pub chain: Vec<String>,
    pub root_sha256: String,
    pub pubkey_hex: String,
}

/// Verify `slot_der` (the slot's attestation certificate) through `f9_der` (the device's
/// attestation certificate) to the pinned Yubico root, and check that it attests `expect_pk`
/// on the device `expect_serial` with PIN ALWAYS and touch ALWAYS. Any doubt is an error.
pub fn verify(slot_der: &[u8], f9_der: &[u8], expect_serial: u32, expect_pk: &[u8; 65]) -> Result<Attested> {
    let (root, intermediates) = pinned()?;
    let slot = Certificate::from_der(slot_der).map_err(|e| anyhow!("slot attestation certificate: {e}"))?;
    let f9 = Certificate::from_der(f9_der).map_err(|e| anyhow!("f9 certificate: {e}"))?;

    // --- the chain: slot ← f9 ← pinned intermediates ← pinned root
    let mut pool: Vec<&Certificate> = vec![&f9];
    pool.extend(intermediates.iter());
    let chain = build_chain(&slot, &pool, &root)?;

    // --- what the slot certificate says
    let spki = &slot.tbs_certificate().subject_public_key_info();
    if spki.algorithm.oid.to_string() != OID_EC_PUBLIC_KEY
        || spki.algorithm.parameters.as_ref().and_then(|p| p.decode_as::<der::oid::ObjectIdentifier>().ok()).map(|o| o.to_string()).as_deref()
            != Some(OID_P256)
    {
        bail!("REFUSED: the attested key is not P-256");
    }
    let pk = spki.subject_public_key.as_bytes().ok_or_else(|| anyhow!("attested public key: unused bits"))?;
    if pk != expect_pk {
        bail!("REFUSED: the attestation certificate carries a different public key than the slot reports");
    }
    let serial = ext(&slot, OID_YK_SERIAL).and_then(der_integer_u32).ok_or_else(|| anyhow!("REFUSED: attestation without a serial-number extension"))?;
    if serial != expect_serial {
        bail!("REFUSED: the attestation names device serial {serial}, the key answered as {expect_serial}");
    }
    let policy = ext(&slot, OID_YK_POLICY).ok_or_else(|| anyhow!("REFUSED: attestation without a PIN/touch policy extension"))?;
    if policy.len() != 2 {
        bail!("REFUSED: malformed policy extension ({} bytes)", policy.len());
    }
    let (pin, touch) = (pin_policy_name(policy[0]), touch_policy_name(policy[1]));
    if policy != [3, 2] {
        bail!("REFUSED: the attestation says PIN {pin} / touch {touch}; the owner role needs PIN ALWAYS / touch ALWAYS");
    }
    let firmware = ext(&slot, OID_YK_FIRMWARE)
        .filter(|v| v.len() == 3)
        .map(|v| format!("{}.{}.{}", v[0], v[1], v[2]))
        .ok_or_else(|| anyhow!("REFUSED: attestation without a firmware extension"))?;
    let form_factor = ext(&slot, OID_YK_FORM_FACTOR).filter(|v| v.len() == 1).map(|v| v[0]);
    Ok(Attested {
        serial,
        firmware,
        pin_policy: pin.into(),
        touch_policy: touch.into(),
        form_factor,
        chain,
        root_sha256: YUBICO_ROOT_SHA256.into(),
        pubkey_hex: hex::encode(pk),
    })
}

/// The pinned Yubico certificates, refused if the compiled-in text does not hash to the pins.
fn pinned() -> Result<(Certificate, Vec<Certificate>)> {
    if hex::encode(Sha256::digest(YUBICO_ROOT_PEM.as_bytes())) != YUBICO_ROOT_SHA256 {
        bail!("compiled-in Yubico root does not match its pin");
    }
    if hex::encode(Sha256::digest(YUBICO_INTERMEDIATES_PEM.as_bytes())) != YUBICO_INTERMEDIATES_SHA256 {
        bail!("compiled-in Yubico intermediates do not match their pin");
    }
    let mut roots = pem_certs(YUBICO_ROOT_PEM)?;
    if roots.len() != 1 {
        bail!("expected exactly one pinned root, found {}", roots.len());
    }
    Ok((roots.remove(0), pem_certs(YUBICO_INTERMEDIATES_PEM)?))
}

/// Walk from `leaf` to `root` through `pool`, verifying every signature; returns the subjects.
fn build_chain(leaf: &Certificate, pool: &[&Certificate], root: &Certificate) -> Result<Vec<String>> {
    let root_subject = root.tbs_certificate().subject().to_der()?;
    let mut names = vec![leaf.tbs_certificate().subject().to_string()];
    let mut cur = leaf;
    for _ in 0..MAX_CHAIN {
        let issuer_name = cur.tbs_certificate().issuer().to_der()?;
        if issuer_name == root_subject {
            verify_signature(cur, root)?;
            names.push(root.tbs_certificate().subject().to_string());
            return Ok(names);
        }
        let issuer = pool
            .iter()
            .find(|c| c.tbs_certificate().subject().to_der().map(|s| s == issuer_name).unwrap_or(false))
            .ok_or_else(|| anyhow!("REFUSED: no pinned issuer for {:?} (issuer {})", cur.tbs_certificate().subject().to_string(), cur.tbs_certificate().issuer()))?;
        if !is_ca(issuer) {
            bail!("REFUSED: {} is not a CA certificate", issuer.tbs_certificate().subject());
        }
        verify_signature(cur, issuer)?;
        names.push(issuer.tbs_certificate().subject().to_string());
        cur = issuer;
    }
    bail!("REFUSED: attestation chain longer than {MAX_CHAIN}")
}

/// `cert` is signed by `issuer`'s key: RSA PKCS#1 v1.5 over SHA-256 of the TBS bytes.
fn verify_signature(cert: &Certificate, issuer: &Certificate) -> Result<()> {
    use rsa::pkcs8::DecodePublicKey;
    let subject = cert.tbs_certificate().subject().to_string();
    if cert.signature_algorithm().oid.to_string() != OID_SHA256_WITH_RSA {
        bail!("REFUSED: {subject}: signature algorithm {} is not sha256WithRSAEncryption", cert.signature_algorithm().oid);
    }
    let tbs = cert.tbs_certificate().to_der()?;
    let sig = cert.signature().as_bytes().ok_or_else(|| anyhow!("{subject}: signature with unused bits"))?;
    let spki = issuer.tbs_certificate().subject_public_key_info().to_der()?;
    let pk = rsa::RsaPublicKey::from_public_key_der(&spki).map_err(|e| anyhow!("{}: issuer key: {e}", issuer.tbs_certificate().subject()))?;
    let vk = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(pk);
    let sig = rsa::pkcs1v15::Signature::try_from(sig).map_err(|e| anyhow!("{subject}: signature: {e}"))?;
    vk.verify(&tbs, &sig).map_err(|_| anyhow!("REFUSED: {subject}: signature does not verify under {}", issuer.tbs_certificate().subject()))
}

fn is_ca(cert: &Certificate) -> bool {
    ext(cert, OID_BASIC_CONSTRAINTS)
        .and_then(|v| x509_cert::ext::pkix::BasicConstraints::from_der(v).ok())
        .map(|bc| bc.ca)
        .unwrap_or(false)
}

fn ext<'a>(cert: &'a Certificate, oid: &str) -> Option<&'a [u8]> {
    cert.tbs_certificate().extensions()?.iter().find(|e| e.extn_id.to_string() == oid).map(|e| e.extn_value.as_bytes())
}

/// `02 len bytes` → u32 (the serial-number extension is a DER INTEGER).
fn der_integer_u32(v: &[u8]) -> Option<u32> {
    if v.len() < 2 || v[0] != 0x02 || v[1] as usize != v.len() - 2 {
        return None;
    }
    let mut b = &v[2..];
    while b.len() > 1 && b[0] == 0 {
        b = &b[1..];
    }
    if b.is_empty() || b.len() > 4 {
        return None;
    }
    let mut out = 0u32;
    for x in b {
        out = (out << 8) | u32::from(*x);
    }
    Some(out)
}

fn pin_policy_name(b: u8) -> &'static str {
    match b {
        1 => "NEVER",
        2 => "ONCE",
        3 => "ALWAYS",
        _ => "UNKNOWN",
    }
}

fn touch_policy_name(b: u8) -> &'static str {
    match b {
        1 => "NEVER",
        2 => "ALWAYS",
        3 => "CACHED",
        _ => "UNKNOWN",
    }
}

/// Every `-----BEGIN CERTIFICATE-----` block of a PEM bundle, DER-decoded.
pub fn pem_certs(pem: &str) -> Result<Vec<Certificate>> {
    use base64::Engine as _;
    let mut out = Vec::new();
    for block in pem.split("-----BEGIN CERTIFICATE-----").skip(1) {
        let body = block.split("-----END CERTIFICATE-----").next().ok_or_else(|| anyhow!("PEM: unterminated certificate"))?;
        let b64: String = body.chars().filter(|c| !c.is_whitespace()).collect();
        let der = base64::engine::general_purpose::STANDARD.decode(b64).map_err(|e| anyhow!("PEM base64: {e}"))?;
        out.push(Certificate::from_der(&der).map_err(|e| anyhow!("PEM certificate: {e}"))?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pinned bundle verifies against itself: every intermediate chains to the pinned root
    /// through real RSA signatures, so the chain walker and the verifier are exercised without
    /// device data (a slot certificate names the device's serial and stays out of the repo).
    #[test]
    fn pinned_intermediates_chain_to_the_pinned_root() {
        let (root, inters) = pinned().unwrap();
        assert_eq!(inters.len(), 15);
        let pool: Vec<&Certificate> = inters.iter().collect();
        for c in &inters {
            let names = build_chain(c, &pool, &root).unwrap();
            assert_eq!(names.last().unwrap(), "CN=Yubico Attestation Root 1", "{names:?}");
            assert!(names.len() == 2 || names.len() == 3, "{names:?}");
        }
    }

    #[test]
    fn a_tampered_certificate_does_not_verify() {
        let (root, inters) = pinned().unwrap();
        let mut der = inters[0].to_der().unwrap();
        // flip a byte inside the TBS (the subject), keep the signature
        let pos = der.len() / 3;
        der[pos] ^= 1;
        let tampered = Certificate::from_der(&der).unwrap();
        let pool: Vec<&Certificate> = inters.iter().collect();
        let err = build_chain(&tampered, &pool, &root).unwrap_err().to_string();
        assert!(err.starts_with("REFUSED:"), "{err}");
    }

    #[test]
    fn an_unpinned_issuer_is_refused() {
        let (root, inters) = pinned().unwrap();
        // a PIV intermediate presented with an EMPTY pool: its issuer (Intermediate B 1) is not the root
        let piv_b2 = inters.iter().find(|c| c.tbs_certificate().subject().to_string() == "CN=Yubico PIV Attestation B2 1").unwrap();
        let err = build_chain(piv_b2, &[], &root).unwrap_err().to_string();
        assert!(err.contains("no pinned issuer"), "{err}");
    }

    #[test]
    fn serial_extension_integer() {
        assert_eq!(der_integer_u32(&[0x02, 0x04, 0x02, 0x56, 0xf5, 0xc1]), Some(39253441));
        assert_eq!(der_integer_u32(&[0x02, 0x05, 0x00, 0x80, 0x00, 0x00, 0x01]), Some(0x8000_0001));
        assert_eq!(der_integer_u32(&[0x02, 0x03, 0x01]), None);
        assert_eq!(der_integer_u32(&[0x04, 0x01, 0x01]), None);
    }
}
