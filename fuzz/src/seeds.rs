//! The honest objects the oracles are calibrated on. Deterministic from the vector suite's throwaway
//! keys (`fixtures::keys()`, seeds `0xa1`/`0xb2`/`0xc3`; wallets `[0x01; 32]`, `[0x02; 32]`), plus a
//! throwaway P-256 attestation key and a throwaway secp256k1 identity key that exist only here.
//! Nothing in this file has ever held value or signed anything outside tests.

use std::sync::OnceLock;

use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use p256::ecdsa::signature::hazmat::PrehashSigner;

use signer_core::mandate::{Mandate, Matcher, Network, PayjoinRule, TrustedDest};
use signer_core::proto::IdentityCard;
use signer_core::receipt::Receipt;
use signer_core::sign::sign_digest_secp;
use signer_core::state::State;
use signer_core::tpm_attest::{build_nv_attest, TpmAnchor, NV_NAME_LEN};
use signer_core::update::Message;

use crate::fixtures::{self, Keys, P256Key, Wallet, ENCLAVE_ID};

/// Everything honest the targets compare against.
pub struct Honest {
    /// Owner / recovery / witness P-256 keys (the vector suite's).
    pub keys: Keys,
    /// A throwaway TPM attestation key (P-256), harness-only.
    pub ak: P256Key,
    /// A throwaway enclave identity key (secp256k1), harness-only.
    pub identity_sk: SecretKey,
    /// Its compressed public key (what `IdentityCard.identity_pk` carries).
    pub identity_pk: [u8; 33],
    /// The hot wallet and the cold (trusted-descriptor) wallet.
    pub wallet: Wallet,
    /// The cold wallet.
    pub cold: Wallet,
    /// The base mandate of the vectors.
    pub mandate: Mandate,
    /// Named variants of the base mandate for the `compare` seeds.
    pub mandates: Vec<(&'static str, Mandate)>,
    /// Every message variant, honestly signed: (name, message, the key it verifies under).
    pub messages: Vec<(&'static str, Message, [u8; 65])>,
    /// An honest receipt and its identity signature.
    pub receipt: Receipt,
    /// Signature over `receipt.digest()`.
    pub receipt_sig: [u8; 64],
    /// An honest identity card and its identity signature.
    pub card: IdentityCard,
    /// Signature over `card.digest()`.
    pub card_sig: [u8; 64],
    /// The enclave nonce the honest attest certifies.
    pub nonce: [u8; 32],
    /// The pinned NV index Name.
    pub nv_name: [u8; NV_NAME_LEN],
    /// The qualified-signer Name the honest attest carries.
    pub signer_name: Vec<u8>,
    /// The sealed anchor (`expected = 42`).
    pub anchor: TpmAnchor,
    /// An honest `TPMS_ATTEST` for counter 42.
    pub attest: Vec<u8>,
    /// The AK's signature over `sha256(attest)`.
    pub attest_sig: [u8; 64],
    /// An honest sealed state (no secrets inside: `State` is the policy state).
    pub state: State,
}

/// The honest set, built once.
pub fn honest() -> &'static Honest {
    static H: OnceLock<Honest> = OnceLock::new();
    H.get_or_init(build)
}

/// A SHA-256 Name with the algorithm prefix (`00 0B`).
pub fn name(tag: u8) -> [u8; NV_NAME_LEN] {
    let mut n = [tag; NV_NAME_LEN];
    n[0] = 0x00;
    n[1] = 0x0B;
    n
}

/// Sign `sha256(attest)` with the AK the way the TPM does (raw `r ‖ s`, low-s).
pub fn sign_attest(ak: &P256Key, attest: &[u8]) -> [u8; 64] {
    let d = signer_core::sha256(attest);
    let sig: p256::ecdsa::Signature = ak.sk.sign_prehash(&d).expect("p256 sign");
    let sig = sig.normalize_s().unwrap_or(sig);
    let mut out = [0u8; 64];
    out.copy_from_slice(&sig.to_bytes());
    out
}

fn build() -> Honest {
    let secp = Secp256k1::new();
    let keys = fixtures::keys();
    let ak = fixtures::p256_key(0xd4);
    let wallet = fixtures::wallet(0x01);
    let cold = fixtures::wallet(0x02);
    let mandate = fixtures::base_mandate(&wallet, &cold);

    // --- mandate variants (compare seeds) ---
    let mut mandates: Vec<(&'static str, Mandate)> = vec![("base", mandate.clone())];
    {
        let mut m = mandate.clone();
        m.destinations.unlisted.max_per_tx /= 2;
        m.destinations.unlisted.max_per_window /= 2;
        m.limits.max_fee_abs /= 2;
        mandates.push(("tightened-caps", m));
        let mut m = mandate.clone();
        m.destinations.unlisted.max_per_tx *= 2;
        mandates.push(("loosened-unlisted", m));
        let mut m = mandate.clone();
        m.rules.payjoin = PayjoinRule::InflowOnly;
        mandates.push(("loosened-payjoin", m));
        let mut m = mandate.clone();
        m.destinations.trusted.clear();
        mandates.push(("tightened-no-trusted", m));
        let mut m = mandate.clone();
        m.network = Network::Testnet4;
        mandates.push(("other-network", m));
        let mut m = mandate.clone();
        m.wallet.fingerprint[0] ^= 0xff;
        mandates.push(("other-wallet", m));
        let mut m = mandate.clone();
        m.checkpoint.height += 100;
        m.not_after_height -= 100;
        mandates.push(("tightened-validity", m));
        // the encodings the fuzzer had not reached from the first seed set (coverage.sh, 2026-11-21): an
        // Address matcher, a required witness, a per-window fee cap, payjoin outflow, the regtest network
        let mut m = mandate.clone();
        m.destinations.trusted.push(TrustedDest {
            label: "exchange".into(),
            matcher: Matcher::Address { script_pubkey: cold.spk(0, 1).to_bytes() },
            max_per_tx: m.limits.max_per_tx / 2,
            max_per_window: m.limits.window_max_outflow / 2,
        });
        mandates.push(("trusted-address", m));
        let mut m = mandate.clone();
        m.freshness.required = true;
        m.freshness.witness_pk = Some(keys.witness.pk);
        mandates.push(("tightened-witness", m));
        let mut m = mandate.clone();
        m.limits.max_fee_per_window = Some(m.limits.max_fee_abs * 10);
        mandates.push(("tightened-fee-window", m));
        let mut m = mandate.clone();
        m.rules.payjoin = PayjoinRule::OutflowAllowed;
        mandates.push(("loosened-payjoin-outflow", m));
        let mut m = mandate.clone();
        m.network = Network::Regtest;
        mandates.push(("other-network-regtest", m));
    }
    // the honest set is valid by construction — the oracles calibrated on it assume so (C-R10-5 over valid mandates)
    for (name, m) in &mandates {
        assert!(m.validate().is_ok(), "honest mandate variant {name} is invalid: {:?}", m.validate());
    }

    // --- messages, one per variant, honestly signed ---
    let nv_name = name(0x11);
    let eid = ENCLAVE_ID;
    let mut messages: Vec<(&'static str, Message, [u8; 65])> = Vec::new();
    let mut add = |name: &'static str, mut m: Message, k: &P256Key| {
        k.sign(&mut m);
        assert!(m.verify(&k.pk), "seed {name} does not verify under its own key");
        messages.push((name, m, k.pk));
    };
    add(
        "policy-update",
        Message::PolicyUpdate { enclave_id: eid, nonce: 1, mandate: mandate.encode(), sig: [0; 64] },
        &keys.owner,
    );
    add("cancel-owner", Message::Cancel { enclave_id: eid, nonce: 2, sig: [0; 64] }, &keys.owner);
    add("cancel-recovery", Message::Cancel { enclave_id: eid, nonce: 2, sig: [0; 64] }, &keys.recovery);
    add("unfreeze", Message::Unfreeze { enclave_id: eid, nonce: 3, sig: [0; 64] }, &keys.owner);
    add("rearm", Message::Rearm { enclave_id: eid, nonce: 4, seq: 7, sig: [0; 64] }, &keys.owner);
    add(
        "rotate-owner",
        Message::RotateOwner { enclave_id: eid, nonce: 5, new_owner_pk: keys.witness.pk, sig: [0; 64] },
        &keys.owner,
    );
    add(
        "recover",
        Message::Recover { enclave_id: eid, nonce: 6, new_owner_pk: keys.witness.pk, sig: [0; 64] },
        &keys.recovery,
    );
    add(
        "arm",
        Message::Arm { enclave_id: eid, nonce: 7, boot_challenge: [0x11; 32], seq_seen: 7, sig: [0; 64] },
        &keys.owner,
    );
    add(
        "anchor",
        Message::Anchor {
            enclave_id: eid,
            nonce: 8,
            boot_challenge: [0x11; 32],
            ak_pk: ak.pk,
            nv_name,
            counter: 42,
            seq_seen: 7,
            sig: [0; 64],
        },
        &keys.owner,
    );
    add(
        "witness-token",
        Message::WitnessToken {
            enclave_id: eid,
            tip_hash: fixtures::header_hash(250_010),
            tip_height: 250_010,
            last_seen_seq: 7,
            issued: 250_010 * 600,
            sig: [0; 64],
        },
        &keys.witness,
    );

    // --- identity-signed objects ---
    let identity_sk = SecretKey::from_slice(&[0x55; 32]).expect("secp sk");
    let identity_pk = PublicKey::from_secret_key(&secp, &identity_sk).serialize();
    let receipt = Receipt {
        enclave_id: eid,
        seq: 1,
        txid: [0x33; 32],
        net_outflow: 1_500_000,
        unlisted: 500_000,
        trusted: vec![("cold".into(), 1_000_000)],
        fee: 1_000,
        height: 250_010,
        mandate_hash: mandate.hash(),
        pending_hash: None,
        nonce: 1,
    };
    let receipt_sig = sign_digest_secp(&secp, &identity_sk, &receipt.digest());
    let card = IdentityCard {
        mrenclave: [0; 32],
        network: 2,
        xpub: wallet.xpub_bytes(),
        fingerprint: wallet.account.fingerprint,
        identity_pk,
        tier: "T0-fuzz".into(),
    };
    let card_sig = sign_digest_secp(&secp, &identity_sk, &card.digest());

    // --- TPM counter proof ---
    let nonce = [0xA5u8; 32];
    let signer_name = name(0x22).to_vec();
    let anchor = TpmAnchor { ak_pk: ak.pk, nv_name, expected: 42 };
    let attest = build_nv_attest(&signer_name, &nonce, &nv_name, 42);
    let attest_sig = sign_attest(&ak, &attest);

    let state = fixtures::init_state(mandate.clone(), &keys, 250_010);

    Honest {
        keys,
        ak,
        identity_sk,
        identity_pk,
        wallet,
        cold,
        mandate,
        mandates,
        messages,
        receipt,
        receipt_sig,
        card,
        card_sig,
        nonce,
        nv_name,
        signer_name,
        anchor,
        attest,
        attest_sig,
        state,
    }
}

impl Honest {
    /// The P-256 keys a message may legitimately verify under, named.
    pub fn p256_keys(&self) -> [(&'static str, [u8; 65]); 4] {
        [
            ("owner", self.keys.owner.pk),
            ("recovery", self.keys.recovery.pk),
            ("witness", self.keys.witness.pk),
            ("ak", self.ak.pk),
        ]
    }
}
