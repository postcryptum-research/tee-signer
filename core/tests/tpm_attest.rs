//! REQ-r9 (C-R9-A): the counter-proof verifier — the honest proof yields the counter; every
//! mutation of the attestation, the nonce, the index, the signature or the value refuses with
//! its own reason, and nothing panics on truncated or overlong input.

use p256::ecdsa::signature::hazmat::PrehashSigner;
use signer_core::reason::Reason;
use signer_core::tpm_attest::{
    build_nv_attest, parse_nv_attest, verify_nv_certify, TpmAnchor, NV_NAME_LEN,
};

struct Ak {
    sk: p256::ecdsa::SigningKey,
    pk: [u8; 65],
}

fn ak(seed: u8) -> Ak {
    let mut b = [seed; 32];
    b[0] = 7;
    let sk = p256::ecdsa::SigningKey::from_bytes((&b).into()).unwrap();
    let mut pk = [0u8; 65];
    pk.copy_from_slice(sk.verifying_key().to_encoded_point(false).as_bytes());
    Ak { sk, pk }
}

fn sign(ak: &Ak, attest: &[u8]) -> [u8; 64] {
    let d = signer_core::sha256(attest);
    let sig: p256::ecdsa::Signature = ak.sk.sign_prehash(&d).unwrap();
    let sig = sig.normalize_s().unwrap_or(sig);
    let mut out = [0u8; 64];
    out.copy_from_slice(&sig.to_bytes());
    out
}

fn name(tag: u8) -> [u8; NV_NAME_LEN] {
    let mut n = [tag; NV_NAME_LEN];
    n[0] = 0x00;
    n[1] = 0x0B;
    n
}

fn setup() -> (Ak, TpmAnchor, [u8; 32], Vec<u8>, [u8; 64]) {
    let a = ak(1);
    let anchor = TpmAnchor {
        ak_pk: a.pk,
        nv_name: name(0x11),
        expected: 42,
    };
    let nonce = [0xA5u8; 32];
    let attest = build_nv_attest(&name(0x22), &nonce, &anchor.nv_name, 42);
    let sig = sign(&a, &attest);
    (a, anchor, nonce, attest, sig)
}

#[test]
fn honest_proof_yields_the_counter() {
    let (_, anchor, nonce, attest, sig) = setup();
    assert_eq!(verify_nv_certify(&attest, &sig, &anchor, &nonce), Ok(42));
    assert!(anchor.well_formed());
}

#[test]
fn stale_value_is_state_stale() {
    let (a, mut anchor, nonce, _, _) = setup();
    // the blob expects 42, the TPM certifies 43 (a spurious increment or a rolled-back blob)
    let attest = build_nv_attest(&name(0x22), &nonce, &anchor.nv_name, 43);
    let sig = sign(&a, &attest);
    assert_eq!(
        verify_nv_certify(&attest, &sig, &anchor, &nonce),
        Err(Reason::StateStale)
    );
    // and the other way round: a blob restored from before, expecting 41
    anchor.expected = 41;
    let attest = build_nv_attest(&name(0x22), &nonce, &anchor.nv_name, 42);
    let sig = sign(&a, &attest);
    assert_eq!(
        verify_nv_certify(&attest, &sig, &anchor, &nonce),
        Err(Reason::StateStale)
    );
}

#[test]
fn replayed_proof_is_tpm_nonce() {
    let (_, anchor, _, attest, sig) = setup();
    let other = [0x5Au8; 32];
    assert_eq!(
        verify_nv_certify(&attest, &sig, &anchor, &other),
        Err(Reason::TpmNonce)
    );
}

#[test]
fn foreign_index_is_tpm_index() {
    let (a, anchor, nonce, _, _) = setup();
    let attest = build_nv_attest(&name(0x22), &nonce, &name(0x33), 42);
    let sig = sign(&a, &attest);
    assert_eq!(
        verify_nv_certify(&attest, &sig, &anchor, &nonce),
        Err(Reason::TpmIndex)
    );
}

#[test]
fn foreign_key_is_tpm_sig() {
    let (_, anchor, nonce, attest, _) = setup();
    let other = ak(2);
    let sig = sign(&other, &attest);
    assert_eq!(
        verify_nv_certify(&attest, &sig, &anchor, &nonce),
        Err(Reason::TpmSig)
    );
    // a flipped bit in a genuine signature
    let (a, _, _, _, mut sig) = setup();
    let _ = a;
    sig[10] ^= 1;
    assert_eq!(
        verify_nv_certify(&attest, &sig, &anchor, &nonce),
        Err(Reason::TpmSig)
    );
}

#[test]
fn every_structural_mutation_is_tpm_parse_and_never_panics() {
    let (a, anchor, nonce, attest, _) = setup();
    // truncations at every length
    for n in 0..attest.len() {
        let t = &attest[..n];
        let r = parse_nv_attest(t);
        assert!(r.is_err(), "truncated to {n} parsed");
    }
    // one trailing byte
    let mut long = attest.clone();
    long.push(0);
    assert_eq!(parse_nv_attest(&long), Err(Reason::TpmParse));
    // overlong
    let huge = vec![0u8; 513];
    assert_eq!(parse_nv_attest(&huge), Err(Reason::TpmParse));
    // wrong magic / type / offset / contents length / safe flag
    let mut m = attest.clone();
    m[0] ^= 1;
    assert_eq!(parse_nv_attest(&m), Err(Reason::TpmParse));
    let mut t = attest.clone();
    t[5] ^= 1;
    assert_eq!(parse_nv_attest(&t), Err(Reason::TpmParse));
    let off = attest.len() - 8 - 2 - 2; // offset field sits before nvContents (2 len + 8 bytes)
    let mut o = attest.clone();
    o[off + 1] = 1;
    assert_eq!(parse_nv_attest(&o), Err(Reason::TpmParse));
    let mut c = attest.clone();
    c[attest.len() - 9] = 7; // nvContents length 7
    assert!(parse_nv_attest(&c).is_err());
    // a wrong nonce LENGTH is a nonce refusal, a wrong index LENGTH an index refusal
    let short_nonce = {
        let mut v = Vec::new();
        v.extend_from_slice(&attest[..4 + 2]);
        v.extend_from_slice(&attest[6..6 + 2 + 34]); // signer name (34 bytes in build)
        v.extend_from_slice(&31u16.to_be_bytes());
        v.extend_from_slice(&[0u8; 31]);
        v.extend_from_slice(&attest[6 + 2 + 34 + 2 + 32..]);
        v
    };
    assert_eq!(parse_nv_attest(&short_nonce), Err(Reason::TpmNonce));
    // and a mutated-but-well-formed attest fails the signature, not the parser
    let mut v = attest.clone();
    let last = v.len() - 1;
    v[last] ^= 1; // counter byte
    let sig = sign(&a, &attest);
    assert_eq!(
        verify_nv_certify(&v, &sig, &anchor, &nonce),
        Err(Reason::TpmSig)
    );
}

#[test]
fn anchor_well_formedness() {
    let a = ak(3);
    let mut n = name(0x44);
    assert!(TpmAnchor {
        ak_pk: a.pk,
        nv_name: n,
        expected: 0
    }
    .well_formed());
    n[1] = 0x04; // SHA-1 Name
    assert!(!TpmAnchor {
        ak_pk: a.pk,
        nv_name: n,
        expected: 0
    }
    .well_formed());
    let mut bad = a.pk;
    bad[0] = 0x02;
    assert!(!TpmAnchor {
        ak_pk: bad,
        nv_name: name(0x44),
        expected: 0
    }
    .well_formed());
}
