//! Shared fixtures for the vector suite. Host-side only (std).
#![allow(dead_code)]

use bitcoin::absolute::LockTime;
use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpriv, Xpub};
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::transaction::Version;
use bitcoin::{Amount, Network as BNet, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use p256::ecdsa::signature::hazmat::PrehashSigner;

use signer_core::mandate::*;
use signer_core::state::{ChainState, HeaderRec, State};
use signer_core::update::Message;
use signer_core::wallet::{Account, OwnPath};

pub fn secp() -> Secp256k1<All> {
    Secp256k1::new()
}

/// Deterministic test wallet on signet. Throwaway keys, labeled as such.
pub struct Wallet {
    pub master: Xpriv,
    pub account_xpriv: Xpriv,
    pub account: Account,
}

/// Entropy `[seed_byte; 32]` → BIP39 mnemonic → BIP32 seed → master (what the enclave does).
pub fn wallet(seed_byte: u8) -> Wallet {
    let secp = secp();
    let entropy = [seed_byte; 32];
    let seed = signer_core::bip39::seed(&signer_core::bip39::mnemonic(&entropy));
    let master = Xpriv::new_master(BNet::Signet, &seed).unwrap();
    let path = DerivationPath::from(vec![
        ChildNumber::from_hardened_idx(84).unwrap(),
        ChildNumber::from_hardened_idx(1).unwrap(),
        ChildNumber::from_hardened_idx(0).unwrap(),
    ]);
    let account_xpriv = master.derive_priv(&secp, &path).unwrap();
    let xpub = Xpub::from_priv(&secp, &account_xpriv);
    let fp = master.fingerprint(&secp);
    let mut fingerprint = [0u8; 4];
    fingerprint.copy_from_slice(fp.as_bytes());
    Wallet {
        master,
        account_xpriv,
        account: Account { fingerprint, path: AccountPath { purpose: 84, coin: 1, account: 0 }, xpub },
    }
}

impl Wallet {
    pub fn spk(&self, branch: u32, index: u32) -> ScriptBuf {
        self.account.p2wpkh_at(&secp(), OwnPath { branch, index }).unwrap()
    }
    pub fn pubkey(&self, branch: u32, index: u32) -> bitcoin::secp256k1::PublicKey {
        self.account.pubkey_at(&secp(), OwnPath { branch, index }).unwrap().0
    }
    pub fn origin(&self, branch: u32, index: u32) -> (Fingerprint, DerivationPath) {
        let path = DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(84).unwrap(),
            ChildNumber::from_hardened_idx(1).unwrap(),
            ChildNumber::from_hardened_idx(0).unwrap(),
            ChildNumber::from_normal_idx(branch).unwrap(),
            ChildNumber::from_normal_idx(index).unwrap(),
        ]);
        (Fingerprint::from(self.account.fingerprint), path)
    }
    pub fn xpub_bytes(&self) -> [u8; 78] {
        self.account.xpub.encode()
    }
}

/// A P-256 key pair for owner / recovery / witness roles.
pub struct P256Key {
    pub sk: p256::ecdsa::SigningKey,
    pub pk: [u8; 65],
}

pub fn p256_key(seed_byte: u8) -> P256Key {
    let mut bytes = [seed_byte; 32];
    bytes[0] = 0x01; // keep the scalar in range
    let sk = p256::ecdsa::SigningKey::from_bytes((&bytes).into()).unwrap();
    let vk = sk.verifying_key();
    let point = vk.to_encoded_point(false);
    let mut pk = [0u8; 65];
    pk.copy_from_slice(point.as_bytes());
    P256Key { sk, pk }
}

impl P256Key {
    pub fn sign_digest(&self, digest: &[u8; 32]) -> [u8; 64] {
        let sig: p256::ecdsa::Signature = self.sk.sign_prehash(digest).unwrap();
        let mut out = [0u8; 64];
        out.copy_from_slice(&sig.to_bytes());
        out
    }
    /// Fill the signature of a message in place.
    pub fn sign(&self, msg: &mut Message) {
        let d = msg.digest();
        let s = self.sign_digest(&d);
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
    }
}

pub const SAT: u64 = 1;
pub const BTC: u64 = 100_000_000;

/// The base mandate used by most vectors: unlisted 0.01/tx 0.05/window; trusted "cold"
/// descriptor (a second throwaway wallet) 1 BTC/tx 5 BTC/window; window 144 blocks, 5 BTC.
pub fn base_mandate(w: &Wallet, cold: &Wallet) -> Mandate {
    Mandate {
        version: MANDATE_VERSION,
        network: Network::Signet,
        wallet: WalletSpec {
            fingerprint: w.account.fingerprint,
            account: AccountPath { purpose: 84, coin: 1, account: 0 },
            script_types: vec![ScriptType::P2wpkh],
        },
        destinations: Destinations {
            trusted: vec![TrustedDest {
                label: "cold".into(),
                matcher: Matcher::Descriptor { xpub: cold.xpub_bytes(), branches: vec![0], gap: 20 },
                max_per_tx: BTC,
                max_per_window: 5 * BTC,
            }],
            unlisted: ClassCaps { max_per_tx: 1_000_000, max_per_window: 5_000_000 },
        },
        limits: Limits {
            max_per_tx: BTC,
            window_blocks: 144,
            window_max_outflow: 5 * BTC,
            max_fee_abs: 100_000,
            max_fee_rate: 100,
            max_fee_per_window: None,
            max_inputs: 64,
            max_outputs: 32,
            own_index_gap: 100,
            max_reorg: 6,
        },
        rules: Rules { sighash: SighashRule::All, payjoin: PayjoinRule::None, op_return: OpReturnRule::None, rbf: true },
        checkpoint: Checkpoint { hash: header_hash(250_000), height: 250_000, time: 250_000 * 600, bits: 0x207f_ffff, period_start_time: 249_984 * 600, period_bits: 0x207f_ffff },
        freshness: Freshness { required: false, witness_pk: None, max_tip_lag: 6 },
        not_after_height: 300_000,
        timelock_blocks: 144,
    }
}

pub struct Keys {
    pub owner: P256Key,
    pub recovery: P256Key,
    pub witness: P256Key,
}

pub fn keys() -> Keys {
    Keys { owner: p256_key(0xa1), recovery: p256_key(0xb2), witness: p256_key(0xc3) }
}

pub const ENCLAVE_ID: [u8; 32] = [0xee; 32];

/// Owner-sign a mandate for the given nonce; returns the signature over the PolicyUpdate digest.
pub fn owner_sig_for(keys: &Keys, mandate: &Mandate, nonce: u64) -> [u8; 64] {
    let mut m = Message::PolicyUpdate { enclave_id: ENCLAVE_ID, nonce, mandate: mandate.encode(), sig: [0; 64] };
    keys.owner.sign(&mut m);
    *m.sig()
}

/// Initial state with a verified best header at `height` and `recent` holding the last 10.
pub fn init_state(mandate: Mandate, keys: &Keys, height: u32) -> State {
    let sig = owner_sig_for(keys, &mandate, 0);
    let mut s = State::new_at_init(ENCLAVE_ID, keys.owner.pk, keys.recovery.pk, mandate, sig);
    set_best(&mut s, height);
    s
}

pub fn header_hash(height: u32) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[..4].copy_from_slice(&height.to_le_bytes());
    h[31] = 0x42;
    h
}

/// A synthetic verified record (vectors do not go through the verifier; `tests/headers.rs` does).
pub fn rec(height: u32) -> HeaderRec {
    let mut work = [0u8; 32];
    work[..4].copy_from_slice(&height.to_le_bytes());
    HeaderRec { hash: header_hash(height), height, time: height.wrapping_mul(600), bits: 0x207f_ffff, work }
}

pub fn set_best(s: &mut State, height: u32) {
    s.chain = ChainState {
        best: Some(rec(height)),
        recent: (height.saturating_sub(10)..=height).map(rec).collect(),
        period_start_time: 0,
        prev_period_start_time: 0,
        period_bits: 0x207f_ffff,
        frozen: false,
    };
}

/// A previous transaction funding `outputs` (a synthetic coinbase-like tx).
pub fn funding_tx(outputs: &[(ScriptBuf, u64)], salt: u32) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_consensus(salt),
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: outputs.iter().map(|(s, v)| TxOut { value: Amount::from_sat(*v), script_pubkey: s.clone() }).collect(),
    }
}

/// An input spec for the PSBT builder.
pub enum In {
    /// Own key at branch/index with amount; `hint` = include the bip32 origin.
    Own { branch: u32, index: u32, amount: u64, hint: bool },
    /// Foreign script with amount.
    Foreign { spk: ScriptBuf, amount: u64 },
}

/// An output spec.
pub struct Out {
    pub spk: ScriptBuf,
    pub amount: u64,
    /// Own-output hint (branch, index), if any.
    pub hint: Option<(u32, u32)>,
}

pub struct Built {
    pub psbt: Psbt,
    pub prevs: Vec<Transaction>,
}

pub fn build_psbt(w: &Wallet, ins: &[In], outs: &[Out], version: i32, rbf: bool) -> Built {
    let mut prevs = Vec::new();
    let mut txins = Vec::new();
    let mut psbt_inputs_meta = Vec::new();
    for (i, spec) in ins.iter().enumerate() {
        let (spk, amount, own) = match spec {
            In::Own { branch, index, amount, hint } => (w.spk(*branch, *index), *amount, Some((*branch, *index, *hint))),
            In::Foreign { spk, amount } => (spk.clone(), *amount, None),
        };
        let prev = funding_tx(&[(spk, amount)], 1000 + i as u32);
        let txid = prev.compute_txid();
        txins.push(TxIn {
            previous_output: OutPoint { txid, vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: if rbf { Sequence::ENABLE_RBF_NO_LOCKTIME } else { Sequence::MAX },
            witness: Witness::new(),
        });
        prevs.push(prev);
        psbt_inputs_meta.push(own);
    }
    let tx = Transaction {
        version: Version(version),
        lock_time: LockTime::ZERO,
        input: txins,
        output: outs.iter().map(|o| TxOut { value: Amount::from_sat(o.amount), script_pubkey: o.spk.clone() }).collect(),
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    for (i, meta) in psbt_inputs_meta.iter().enumerate() {
        psbt.inputs[i].non_witness_utxo = Some(prevs[i].clone());
        if let Some((b, idx, true)) = meta {
            psbt.inputs[i].bip32_derivation.insert(w.pubkey(*b, *idx), w.origin(*b, *idx));
        }
    }
    for (i, o) in outs.iter().enumerate() {
        if let Some((b, idx)) = o.hint {
            psbt.outputs[i].bip32_derivation.insert(w.pubkey(b, idx), w.origin(b, idx));
        }
    }
    Built { psbt, prevs }
}

/// A foreign P2WPKH script (from a third throwaway wallet).
pub fn foreign_spk(index: u32) -> ScriptBuf {
    wallet(0x77).spk(0, index)
}
