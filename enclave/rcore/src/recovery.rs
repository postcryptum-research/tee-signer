//! The recovery blob (`docs/ENCLAVE.md §5`): the 32 bytes of BIP39 entropy encrypted to the
//! recovery key, once, at init. ECIES: ephemeral P-256 → ECDH → HKDF-SHA256 → AES-256-GCM.

use alloc::vec::Vec;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::Sha256;
use zeroize::Zeroize;

/// HKDF salt.
pub const SALT: &[u8] = b"tee-signer/recovery/v1";

/// Derive the AES key from the shared x-coordinate and the wallet binding.
fn kdf(shared_x: &[u8], fingerprint: &[u8; 4], xpub: &[u8; 78]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(SALT), shared_x);
    let mut info = Vec::with_capacity(82);
    info.extend_from_slice(fingerprint);
    info.extend_from_slice(xpub);
    let mut key = [0u8; 32];
    hk.expand(&info, &mut key).expect("32 bytes is a valid HKDF length");
    key
}

/// Encrypt `entropy` to `recovery_pk`. Output: ephemeral public key (65, SEC1 uncompressed) ‖
/// ciphertext (32) ‖ tag (16). `None` if the recovery key is not a valid point or randomness
/// failed to yield a scalar (it retries a bounded number of times).
pub fn encrypt(recovery_pk: &[u8; 65], fingerprint: &[u8; 4], xpub: &[u8; 78], entropy: &[u8; 32]) -> Option<Vec<u8>> {
    let pk = p256::PublicKey::from_sec1_bytes(recovery_pk).ok()?;
    let mut eph: Option<p256::SecretKey> = None;
    for _ in 0..16 {
        let mut b = [0u8; 32];
        crate::sgx::read_rand(&mut b);
        if let Ok(sk) = p256::SecretKey::from_slice(&b) {
            eph = Some(sk);
        }
        b.zeroize();
        if eph.is_some() {
            break;
        }
    }
    let eph = eph?;
    let eph_pk = eph.public_key().to_encoded_point(false);
    let shared = p256::ecdh::diffie_hellman(eph.to_nonzero_scalar(), pk.as_affine());
    let mut key = kdf(shared.raw_secret_bytes().as_slice(), fingerprint, xpub);
    let cipher = Aes256Gcm::new((&key).into());
    let mut aad = Vec::with_capacity(82);
    aad.extend_from_slice(fingerprint);
    aad.extend_from_slice(xpub);
    // the key is used exactly once (fresh ephemeral ⇒ fresh key), so a constant nonce is safe
    let ct = cipher.encrypt(Nonce::from_slice(&[0u8; 12]), Payload { msg: entropy, aad: &aad }).ok()?;
    key.zeroize();
    drop(eph);
    let mut out = Vec::with_capacity(65 + ct.len());
    out.extend_from_slice(eph_pk.as_bytes());
    out.extend_from_slice(&ct);
    Some(out)
}

/// Decrypt with the recovery secret key (host side, `owner-cli recovery verify`; here for tests).
pub fn decrypt(recovery_sk: &[u8; 32], fingerprint: &[u8; 4], xpub: &[u8; 78], blob: &[u8]) -> Option<[u8; 32]> {
    if blob.len() != 65 + 32 + 16 {
        return None;
    }
    let sk = p256::SecretKey::from_slice(recovery_sk).ok()?;
    let eph_pk = p256::PublicKey::from_sec1_bytes(&blob[..65]).ok()?;
    let shared = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), eph_pk.as_affine());
    let mut key = kdf(shared.raw_secret_bytes().as_slice(), fingerprint, xpub);
    let cipher = Aes256Gcm::new((&key).into());
    let mut aad = Vec::with_capacity(82);
    aad.extend_from_slice(fingerprint);
    aad.extend_from_slice(xpub);
    let pt = cipher.decrypt(Nonce::from_slice(&[0u8; 12]), Payload { msg: &blob[65..], aad: &aad }).ok()?;
    key.zeroize();
    let mut out = [0u8; 32];
    if pt.len() != 32 {
        return None;
    }
    out.copy_from_slice(&pt);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_binding() {
        let sk = p256::SecretKey::from_slice(&[7u8; 32]).unwrap();
        let pk: [u8; 65] = sk.public_key().to_encoded_point(false).as_bytes().try_into().unwrap();
        let fp = [1, 2, 3, 4];
        let xpub = [9u8; 78];
        let entropy = [0x42u8; 32];
        let blob = encrypt(&pk, &fp, &xpub, &entropy).unwrap();
        assert_eq!(blob.len(), 113);
        assert_eq!(decrypt(&[7u8; 32], &fp, &xpub, &blob).unwrap(), entropy);
        // bound to the wallet: a different fingerprint fails to open
        assert!(decrypt(&[7u8; 32], &[0, 0, 0, 0], &xpub, &blob).is_none());
        // a different recovery key fails
        assert!(decrypt(&[8u8; 32], &fp, &xpub, &blob).is_none());
        // two blobs of the same entropy differ (fresh ephemeral)
        let blob2 = encrypt(&pk, &fp, &xpub, &entropy).unwrap();
        assert_ne!(blob, blob2);
    }
}
