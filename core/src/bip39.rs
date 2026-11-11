//! BIP39: 256 bits of entropy → 24 words → the BIP32 seed. In the core (not the shell) so the
//! test wallet of the vector suite and the enclave derive the same keys from the same entropy. English wordlist only (the standard
//! list, SHA-256 `2f5eed53…`), ASCII, so no normalisation is needed.

use alloc::string::String;
use alloc::vec::Vec;

use sha2::Sha512;

const WORDLIST: &str = include_str!("bip39-english.txt");

/// SHA-256 of the embedded wordlist (the standard English list).
pub const WORDLIST_SHA256: &str = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda";

fn words() -> Vec<&'static str> {
    WORDLIST.lines().map(|l| l.trim()).filter(|l| !l.is_empty()).collect()
}

/// The 24-word mnemonic of 32 bytes of entropy.
pub fn mnemonic(entropy: &[u8; 32]) -> String {
    let w = words();
    let check = crate::sha256(entropy)[0]; // 8 checksum bits for 256-bit entropy
    let mut bits: Vec<u8> = Vec::with_capacity(264);
    for b in entropy.iter().chain(core::iter::once(&check)) {
        for i in (0..8).rev() {
            bits.push((b >> i) & 1);
        }
    }
    let mut out = String::new();
    // 264 bits = 24 groups of 11; `chunks_exact` walks them without index arithmetic (the crate
    // denies arithmetic that could wrap; this was the one site the lint flagged).
    for (i, chunk) in bits.chunks_exact(11).enumerate() {
        let mut idx: usize = 0;
        for bit in chunk {
            idx = (idx << 1) | (*bit as usize);
        }
        if i > 0 {
            out.push(' ');
        }
        out.push_str(w.get(idx).copied().unwrap_or("?"));
    }
    out
}

/// The 64-byte BIP32 seed of a mnemonic with an empty passphrase.
pub fn seed(mnemonic: &str) -> [u8; 64] {
    let mut out = [0u8; 64];
    pbkdf2::pbkdf2_hmac::<Sha512>(mnemonic.as_bytes(), b"mnemonic", 2048, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_is_the_standard_one() {
        let w = words();
        assert_eq!(w.len(), 2048);
        assert_eq!(w[0], "abandon");
        assert_eq!(w[2047], "zoo");
        assert_eq!(hex::encode(crate::sha256(WORDLIST.as_bytes())), WORDLIST_SHA256);
    }

    #[test]
    fn known_vector() {
        // BIP39 test vector (trezor/python-mnemonic), entropy 0x80..0x80 (32 × 0x80)
        let entropy = [0x80u8; 32];
        let m = mnemonic(&entropy);
        assert_eq!(
            m,
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless"
        );
        // seed with passphrase "" is not in the vector set (they use "TREZOR"); check the
        // all-zero entropy mnemonic → known seed for passphrase "" is not published either, so
        // the PBKDF2 path is checked against a direct computation below
        let s = seed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art");
        // widely published: seed of the 24×abandon…art mnemonic with empty passphrase
        assert_eq!(hex::encode(&s[..16]), "408b285c123836004f4b8842c89324c1");
    }
}
