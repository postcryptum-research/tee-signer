//! The mandate (`docs/POLICY.md`): types, canonical encoding, validation, hash, and the
//! tightening classifier.
//!
//! The owner signs `Mandate::hash()` of the canonical bytes; the enclave decodes those bytes with
//! the strict decoder and refuses anything non-canonical. There is no JSON here: JSON is the
//! owner-side representation, converted by `owner-cli` into exactly these bytes.

use alloc::string::String;
use alloc::vec::Vec;

use crate::encoding::{Dec, DecodeError, Enc};

/// Current mandate encoding version.
pub const MANDATE_VERSION: u16 = 1;

/// Bounds enforced by `validate` and by the decoder (the decoder's bounds are the loose ones that
/// keep allocation sane; `validate` holds the exact ones).
pub mod bounds {
    /// Max trusted destinations.
    pub const MAX_TRUSTED: usize = 64;
    /// Max label length in bytes.
    pub const MAX_LABEL: usize = 32;
    /// Max scriptPubKey length for an address matcher (P2TR/P2WSH are 34; P2SH 23; P2PKH 25).
    pub const MAX_SPK: usize = 64;
    /// Max descriptor gap.
    pub const MAX_GAP: u32 = 1000;
    /// Max `ownIndexGap` (auditor C-R4a).
    pub const MAX_OWN_INDEX_GAP: u32 = 100;
    /// Max inputs a mandate may allow (sizes the fixed enclave heap).
    pub const MAX_INPUTS: u32 = 500;
    /// Max outputs a mandate may allow.
    pub const MAX_OUTPUTS: u32 = 500;
    /// Max reorg depth a mandate may tolerate.
    pub const MAX_REORG: u32 = 1000;
    /// Max `maxTipLag`.
    pub const MAX_TIP_LAG: u32 = 144;
    /// Max window length in blocks (about a year).
    pub const MAX_WINDOW_BLOCKS: u32 = 52_560;
    /// Max script types.
    pub const MAX_SCRIPT_TYPES: usize = 4;
    /// Max branches in a descriptor matcher.
    pub const MAX_BRANCHES: usize = 2;
}

/// Bitcoin network. The numeric values are the wire encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Network {
    /// Bitcoin mainnet. Never used by anything in this repository without owner sign-off.
    Mainnet = 0,
    /// Testnet4.
    Testnet4 = 1,
    /// Signet (the dev network of this project).
    Signet = 2,
    /// Regtest.
    Regtest = 3,
}

impl Network {
    fn from_u8(v: u8) -> Result<Self, DecodeError> {
        match v {
            0 => Ok(Network::Mainnet),
            1 => Ok(Network::Testnet4),
            2 => Ok(Network::Signet),
            3 => Ok(Network::Regtest),
            _ => Err(DecodeError),
        }
    }
    /// BIP44 coin type for the account path.
    pub fn coin_type(self) -> u32 {
        match self {
            Network::Mainnet => 0,
            _ => 1,
        }
    }
    /// The `bitcoin` crate's network, for address and script work.
    pub fn to_bitcoin(self) -> bitcoin::Network {
        match self {
            Network::Mainnet => bitcoin::Network::Bitcoin,
            Network::Testnet4 => bitcoin::Network::Testnet4,
            Network::Signet => bitcoin::Network::Signet,
            Network::Regtest => bitcoin::Network::Regtest,
        }
    }
}

/// Script types the wallet may sign (v1: P2WPKH only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ScriptType {
    /// BIP84 native segwit v0 key hash.
    P2wpkh = 0,
}

impl ScriptType {
    fn from_u8(v: u8) -> Result<Self, DecodeError> {
        match v {
            0 => Ok(ScriptType::P2wpkh),
            _ => Err(DecodeError),
        }
    }
}

/// The account the mandate governs: `purpose'/coin'/account'`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountPath {
    /// BIP43 purpose (84 for P2WPKH), hardened.
    pub purpose: u32,
    /// Coin type, hardened.
    pub coin: u32,
    /// Account index, hardened.
    pub account: u32,
}

/// `wallet` section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletSpec {
    /// Master key fingerprint (BIP32).
    pub fingerprint: [u8; 4],
    /// Account path.
    pub account: AccountPath,
    /// Allowed script types.
    pub script_types: Vec<ScriptType>,
}

/// How a trusted destination is recognised.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Matcher {
    /// Exact `scriptPubKey`.
    Address {
        /// The output script bytes.
        script_pubkey: Vec<u8>,
    },
    /// `wpkh(KEY/branch/*)` for the listed branches, indices `0..=gap`.
    Descriptor {
        /// Serialized extended public key (78 bytes, BIP32).
        xpub: [u8; 78],
        /// Branches to derive (0 = external, 1 = change).
        branches: Vec<u32>,
        /// Highest index derived (inclusive bound is `gap - 1`; `gap` addresses per branch).
        gap: u32,
    },
}

/// One trusted destination.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedDest {
    /// Human label; unique within the mandate; appears in refusal reasons.
    pub label: String,
    /// The matcher.
    pub matcher: Matcher,
    /// Cap on the sum of outputs to this destination in one transaction.
    pub max_per_tx: u64,
    /// Cap on the sum over the window.
    pub max_per_window: u64,
}

/// Caps for a class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClassCaps {
    /// Per transaction.
    pub max_per_tx: u64,
    /// Per window.
    pub max_per_window: u64,
}

/// `destinations` section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Destinations {
    /// Trusted destinations.
    pub trusted: Vec<TrustedDest>,
    /// Caps for everything else.
    pub unlisted: ClassCaps,
}

/// `limits` section.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Net outflow per transaction.
    pub max_per_tx: u64,
    /// Window length in blocks.
    pub window_blocks: u32,
    /// Net outflow per window (fee included — `POLICY.md §3`).
    pub window_max_outflow: u64,
    /// Fee per transaction.
    pub max_fee_abs: u64,
    /// Fee rate in sat/vB against an upper-bound vsize.
    pub max_fee_rate: u64,
    /// Optional fee sum per window.
    pub max_fee_per_window: Option<u64>,
    /// Max inputs.
    pub max_inputs: u32,
    /// Max outputs.
    pub max_outputs: u32,
    /// Own-output index search depth beyond the sealed bound.
    pub own_index_gap: u32,
    /// Reorg depth beyond which the signer freezes.
    pub max_reorg: u32,
}

/// Sighash rule (v1: ALL only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SighashRule {
    /// `SIGHASH_ALL` only.
    All = 0,
}

/// Payjoin rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum PayjoinRule {
    /// Any foreign input refuses.
    None = 0,
    /// Foreign inputs allowed only when net outflow ≤ 0.
    InflowOnly = 1,
    /// Foreign inputs allowed; outflow judged by the caps.
    OutflowAllowed = 2,
}

/// OP_RETURN rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum OpReturnRule {
    /// Refuse any OP_RETURN output.
    None = 0,
    /// Tolerate zero-value OP_RETURN outputs.
    ZeroValue = 1,
}

/// `rules` section.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rules {
    /// Sighash.
    pub sighash: SighashRule,
    /// Payjoin.
    pub payjoin: PayjoinRule,
    /// OP_RETURN.
    pub op_return: OpReturnRule,
    /// Whether RBF-signalling inputs are accepted.
    pub rbf: bool,
}

/// `chain.checkpoint`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    /// Block hash (internal byte order, as in the `bitcoin` crate).
    pub hash: [u8; 32],
    /// Height.
    pub height: u32,
}

/// `freshness` section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Freshness {
    /// Whether a witness token is a signing precondition.
    pub required: bool,
    /// Witness P-256 public key, SEC1 uncompressed (65 bytes).
    pub witness_pk: Option<[u8; 65]>,
    /// Max tip lag in blocks.
    pub max_tip_lag: u32,
}

/// The mandate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mandate {
    /// Encoding version (`MANDATE_VERSION`).
    pub version: u16,
    /// Network.
    pub network: Network,
    /// Wallet.
    pub wallet: WalletSpec,
    /// Destinations.
    pub destinations: Destinations,
    /// Limits.
    pub limits: Limits,
    /// Rules.
    pub rules: Rules,
    /// Checkpoint.
    pub checkpoint: Checkpoint,
    /// Freshness.
    pub freshness: Freshness,
    /// `validity.notAfterHeight`.
    pub not_after_height: u32,
    /// Timelock for loosening updates, in blocks.
    pub timelock_blocks: u32,
}

/// Why a mandate is structurally invalid. Reported as `POLICY_INVALID` with this detail in logs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Invalid {
    /// Wrong version.
    Version,
    /// Account path not `84'/coin'/n'` for the network.
    AccountPath,
    /// Script types empty, duplicated, or unsupported.
    ScriptTypes,
    /// Too many trusted entries.
    TooManyTrusted,
    /// A label is empty, too long, non-printable-ASCII, or duplicated.
    Label,
    /// An address matcher is not a recognised standard output script.
    AddressScript,
    /// A descriptor matcher is malformed (xpub, branches, gap).
    Descriptor,
    /// A limit is out of range.
    Limits,
    /// Freshness is inconsistent (required without a key, bad key, bad lag).
    Freshness,
    /// `notAfterHeight` not after the checkpoint.
    Validity,
    /// Timelock zero.
    Timelock,
}

impl Mandate {
    /// Canonical bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::new();
        e.u16(self.version);
        e.u8(self.network as u8);
        e.fixed(&self.wallet.fingerprint);
        e.u32(self.wallet.account.purpose);
        e.u32(self.wallet.account.coin);
        e.u32(self.wallet.account.account);
        e.list(&self.wallet.script_types, |e, t| {
            e.u8(*t as u8);
        });
        e.list(&self.destinations.trusted, |e, t| {
            e.str(&t.label);
            match &t.matcher {
                Matcher::Address { script_pubkey } => {
                    e.u8(0);
                    e.bytes(script_pubkey);
                }
                Matcher::Descriptor { xpub, branches, gap } => {
                    e.u8(1);
                    e.fixed(xpub);
                    e.list(branches, |e, b| {
                        e.u32(*b);
                    });
                    e.u32(*gap);
                }
            }
            e.u64(t.max_per_tx);
            e.u64(t.max_per_window);
        });
        e.u64(self.destinations.unlisted.max_per_tx);
        e.u64(self.destinations.unlisted.max_per_window);
        let l = &self.limits;
        e.u64(l.max_per_tx);
        e.u32(l.window_blocks);
        e.u64(l.window_max_outflow);
        e.u64(l.max_fee_abs);
        e.u64(l.max_fee_rate);
        e.option(l.max_fee_per_window.as_ref(), |e, v| {
            e.u64(*v);
        });
        e.u32(l.max_inputs);
        e.u32(l.max_outputs);
        e.u32(l.own_index_gap);
        e.u32(l.max_reorg);
        e.u8(self.rules.sighash as u8);
        e.u8(self.rules.payjoin as u8);
        e.u8(self.rules.op_return as u8);
        e.bool(self.rules.rbf);
        e.fixed(&self.checkpoint.hash);
        e.u32(self.checkpoint.height);
        e.bool(self.freshness.required);
        e.option(self.freshness.witness_pk.as_ref(), |e, k| {
            e.fixed(k);
        });
        e.u32(self.freshness.max_tip_lag);
        e.u32(self.not_after_height);
        e.u32(self.timelock_blocks);
        e.finish()
    }

    /// Strict decode of canonical bytes. Does not validate semantics; call `validate`.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut d = Dec::new(bytes);
        let version = d.u16()?;
        if version != MANDATE_VERSION {
            return Err(DecodeError);
        }
        let network = Network::from_u8(d.u8()?)?;
        let fingerprint = d.fixed::<4>()?;
        let account = AccountPath { purpose: d.u32()?, coin: d.u32()?, account: d.u32()? };
        let script_types = d.list(bounds::MAX_SCRIPT_TYPES, |d| ScriptType::from_u8(d.u8()?))?;
        let trusted = d.list(bounds::MAX_TRUSTED, |d| {
            let label = d.str(bounds::MAX_LABEL)?;
            let matcher = match d.u8()? {
                0 => Matcher::Address { script_pubkey: d.bytes(bounds::MAX_SPK)? },
                1 => {
                    let xpub = d.fixed::<78>()?;
                    let branches = d.list(bounds::MAX_BRANCHES, |d| d.u32())?;
                    let gap = d.u32()?;
                    Matcher::Descriptor { xpub, branches, gap }
                }
                _ => return Err(DecodeError),
            };
            let max_per_tx = d.u64()?;
            let max_per_window = d.u64()?;
            Ok(TrustedDest { label, matcher, max_per_tx, max_per_window })
        })?;
        let unlisted = ClassCaps { max_per_tx: d.u64()?, max_per_window: d.u64()? };
        let limits = Limits {
            max_per_tx: d.u64()?,
            window_blocks: d.u32()?,
            window_max_outflow: d.u64()?,
            max_fee_abs: d.u64()?,
            max_fee_rate: d.u64()?,
            max_fee_per_window: d.option(|d| d.u64())?,
            max_inputs: d.u32()?,
            max_outputs: d.u32()?,
            own_index_gap: d.u32()?,
            max_reorg: d.u32()?,
        };
        let sighash = match d.u8()? {
            0 => SighashRule::All,
            _ => return Err(DecodeError),
        };
        let payjoin = match d.u8()? {
            0 => PayjoinRule::None,
            1 => PayjoinRule::InflowOnly,
            2 => PayjoinRule::OutflowAllowed,
            _ => return Err(DecodeError),
        };
        let op_return = match d.u8()? {
            0 => OpReturnRule::None,
            1 => OpReturnRule::ZeroValue,
            _ => return Err(DecodeError),
        };
        let rbf = d.bool()?;
        let checkpoint = Checkpoint { hash: d.fixed::<32>()?, height: d.u32()? };
        let freshness = Freshness {
            required: d.bool()?,
            witness_pk: d.option(|d| d.fixed::<65>())?,
            max_tip_lag: d.u32()?,
        };
        let not_after_height = d.u32()?;
        let timelock_blocks = d.u32()?;
        d.finish()?;
        Ok(Mandate {
            version,
            network,
            wallet: WalletSpec { fingerprint, account, script_types },
            destinations: Destinations { trusted, unlisted },
            limits,
            rules: Rules { sighash, payjoin, op_return, rbf },
            checkpoint,
            freshness,
            not_after_height,
            timelock_blocks,
        })
    }

    /// SHA-256 of the canonical bytes: what the owner signs (through `update::policy_digest`) and
    /// what receipts and status carry.
    pub fn hash(&self) -> [u8; 32] {
        crate::sha256(&self.encode())
    }

    /// Structural validation (`POLICY.md §3`). Independent of any sealed state; the network and
    /// wallet match against the sealed values is `update`'s job.
    pub fn validate(&self) -> Result<(), Invalid> {
        if self.version != MANDATE_VERSION {
            return Err(Invalid::Version);
        }
        let a = &self.wallet.account;
        if a.purpose != 84 || a.coin != self.network.coin_type() {
            return Err(Invalid::AccountPath);
        }
        let st = &self.wallet.script_types;
        if st.is_empty() || st.len() > bounds::MAX_SCRIPT_TYPES {
            return Err(Invalid::ScriptTypes);
        }
        for (i, t) in st.iter().enumerate() {
            if st.iter().skip(i.saturating_add(1)).any(|u| u == t) {
                return Err(Invalid::ScriptTypes);
            }
        }
        let trusted = &self.destinations.trusted;
        if trusted.len() > bounds::MAX_TRUSTED {
            return Err(Invalid::TooManyTrusted);
        }
        for (i, t) in trusted.iter().enumerate() {
            if t.label.is_empty()
                || t.label.len() > bounds::MAX_LABEL
                || !t.label.bytes().all(|b| (0x21..=0x7e).contains(&b))
            {
                return Err(Invalid::Label);
            }
            if trusted.iter().skip(i.saturating_add(1)).any(|u| u.label == t.label) {
                return Err(Invalid::Label);
            }
            match &t.matcher {
                Matcher::Address { script_pubkey } => {
                    let s = bitcoin::Script::from_bytes(script_pubkey);
                    let standard = s.is_p2wpkh()
                        || s.is_p2wsh()
                        || s.is_p2tr()
                        || s.is_p2pkh()
                        || s.is_p2sh();
                    if !standard {
                        return Err(Invalid::AddressScript);
                    }
                }
                Matcher::Descriptor { xpub, branches, gap } => {
                    if bitcoin::bip32::Xpub::decode(xpub).is_err() {
                        return Err(Invalid::Descriptor);
                    }
                    if branches.is_empty() || branches.len() > bounds::MAX_BRANCHES {
                        return Err(Invalid::Descriptor);
                    }
                    for (i, b) in branches.iter().enumerate() {
                        if *b > 1 || branches.iter().skip(i.saturating_add(1)).any(|c| c == b) {
                            return Err(Invalid::Descriptor);
                        }
                    }
                    if *gap == 0 || *gap > bounds::MAX_GAP {
                        return Err(Invalid::Descriptor);
                    }
                }
            }
        }
        let l = &self.limits;
        if l.window_blocks == 0
            || l.window_blocks > bounds::MAX_WINDOW_BLOCKS
            || l.max_inputs == 0
            || l.max_inputs > bounds::MAX_INPUTS
            || l.max_outputs == 0
            || l.max_outputs > bounds::MAX_OUTPUTS
            || l.own_index_gap == 0
            || l.own_index_gap > bounds::MAX_OWN_INDEX_GAP
            || l.max_reorg == 0
            || l.max_reorg > bounds::MAX_REORG
        {
            return Err(Invalid::Limits);
        }
        let f = &self.freshness;
        if f.max_tip_lag == 0 || f.max_tip_lag > bounds::MAX_TIP_LAG {
            return Err(Invalid::Freshness);
        }
        if f.required && f.witness_pk.is_none() {
            return Err(Invalid::Freshness);
        }
        if let Some(pk) = &f.witness_pk {
            if crate::update::parse_p256_pubkey(pk).is_none() {
                return Err(Invalid::Freshness);
            }
        }
        if self.not_after_height <= self.checkpoint.height {
            return Err(Invalid::Validity);
        }
        if self.timelock_blocks == 0 {
            return Err(Invalid::Timelock);
        }
        Ok(())
    }
}

/// The direction of an update (`POLICY.md §5`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    /// Every field provably moved in the restrictive direction: applies at once.
    Tightening,
    /// Anything else: waits the installed mandate's timelock.
    Loosening,
}

/// Why `compare` refuses to classify at all (the update is refused outright, not timelocked).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Immutable {
    /// `network` changed.
    Network,
    /// `wallet` changed.
    Wallet,
}

/// Classify `new` against `installed`.
///
/// **Fails toward loosening (auditor R6).** `tight` starts `true` and every field may only clear
/// it; a field that cannot be proven tightening — unknown shape, absent on one side, any
/// change in a matcher — clears it. There is no branch that sets it back.
pub fn compare(installed: &Mandate, new: &Mandate) -> Result<Change, Immutable> {
    if installed.network != new.network {
        return Err(Immutable::Network);
    }
    if installed.wallet != new.wallet {
        return Err(Immutable::Wallet);
    }
    let mut tight = true;
    let mut clear = |ok: bool| {
        if !ok {
            tight = false;
        }
    };
    // version: equal only (decoder already pins it; stated for completeness)
    clear(installed.version == new.version);
    // trusted: every new entry must exist in installed with the same label AND the same matcher,
    // and caps not raised. Removal is tightening; addition or any matcher change is loosening.
    for n in &new.destinations.trusted {
        match installed.destinations.trusted.iter().find(|o| o.label == n.label) {
            None => clear(false),
            Some(o) => {
                clear(matcher_tightening(&o.matcher, &n.matcher));
                clear(n.max_per_tx <= o.max_per_tx);
                clear(n.max_per_window <= o.max_per_window);
            }
        }
    }
    let (ou, nu) = (installed.destinations.unlisted, new.destinations.unlisted);
    clear(nu.max_per_tx <= ou.max_per_tx);
    clear(nu.max_per_window <= ou.max_per_window);
    let (ol, nl) = (installed.limits, new.limits);
    clear(nl.max_per_tx <= ol.max_per_tx);
    clear(nl.window_blocks >= ol.window_blocks);
    clear(nl.window_max_outflow <= ol.window_max_outflow);
    clear(nl.max_fee_abs <= ol.max_fee_abs);
    clear(nl.max_fee_rate <= ol.max_fee_rate);
    clear(match (ol.max_fee_per_window, nl.max_fee_per_window) {
        (None, None) => true,
        (None, Some(_)) => true,
        (Some(_), None) => false,
        (Some(o), Some(n)) => n <= o,
    });
    clear(nl.max_inputs <= ol.max_inputs);
    clear(nl.max_outputs <= ol.max_outputs);
    clear(nl.own_index_gap <= ol.own_index_gap);
    clear(nl.max_reorg <= ol.max_reorg);
    let (or, nr) = (installed.rules, new.rules);
    clear(nr.sighash == or.sighash);
    clear(nr.payjoin <= or.payjoin);
    clear(nr.op_return <= or.op_return);
    clear(!nr.rbf || or.rbf);
    // checkpoint: forward only (equal is fine). Whether the new checkpoint is a verified header is
    // the chain module's check at install time, not a classification question.
    clear(new.checkpoint.height >= installed.checkpoint.height);
    let (of, nf) = (&installed.freshness, &new.freshness);
    clear(nf.required || !of.required);
    clear(nf.max_tip_lag <= of.max_tip_lag);
    clear(match (&of.witness_pk, &nf.witness_pk) {
        (None, None) => true,
        (None, Some(_)) => true,
        (Some(_), None) => false,
        (Some(o), Some(n)) => o == n,
    });
    clear(new.not_after_height <= installed.not_after_height);
    clear(new.timelock_blocks >= installed.timelock_blocks);
    Ok(if tight { Change::Tightening } else { Change::Loosening })
}

/// A matcher change is tightening only when it is no change at all, or a descriptor with the
/// same key and branches and a smaller or equal gap.
fn matcher_tightening(old: &Matcher, new: &Matcher) -> bool {
    match (old, new) {
        (Matcher::Address { script_pubkey: a }, Matcher::Address { script_pubkey: b }) => a == b,
        (
            Matcher::Descriptor { xpub: xa, branches: ba, gap: ga },
            Matcher::Descriptor { xpub: xb, branches: bb, gap: gb },
        ) => xa == xb && bb.iter().all(|b| ba.contains(b)) && gb <= ga,
        _ => false,
    }
}
