//! The policy state the enclave seals (`docs/DESIGN.md §3`) — without the secrets, which the
//! enclave shell keeps beside it in the same sealed blob — and the transitions that owner,
//! recovery and witness messages cause.
//!
//! Every transition is a pure function `&State → Result<State, Refusal>`. The enclave seals the
//! returned state before acting on it (commit → seal → act).

use alloc::vec::Vec;

use crate::encoding::{Dec, DecodeError, Enc};
use crate::mandate::{self, Checkpoint, Mandate, Network, WalletSpec};
use crate::reason::{Reason, Refusal};
use crate::update::{parse_p256_pubkey, Message};

/// State encoding version.
pub const STATE_VERSION: u16 = 1;

/// Max recent headers kept for the witness tip check and reorg detection.
pub const MAX_RECENT: usize = 2048;

/// Max trusted usage entries (= max trusted destinations).
const MAX_TRUSTED_USAGE: usize = mandate::bounds::MAX_TRUSTED;

/// A pending (timelocked) mandate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pending {
    /// The mandate to install.
    pub mandate: Mandate,
    /// The owner signature that authorised it.
    pub sig: [u8; 64],
    /// The nonce it was accepted under.
    pub nonce: u64,
    /// Height at or after which it installs.
    pub activation_height: u32,
}

/// A pending owner rotation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingOwner {
    /// The key that becomes owner.
    pub new_owner_pk: [u8; 65],
    /// Height at or after which it applies.
    pub activation_height: u32,
}

/// What the enclave knows about the chain. Filled by the header verifier (R4); in R1 it is set by
/// the caller and treated as already verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainState {
    /// Best verified header, if any.
    pub best: Option<Checkpoint>,
    /// Recent verified headers, most recent last, bounded by `MAX_RECENT`.
    pub recent: Vec<Checkpoint>,
}

/// Usage counters for the current window.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Window {
    /// Window start height.
    pub start_height: u32,
    /// Σ net outflow (fee included).
    pub outflow: u64,
    /// Σ unlisted outputs.
    pub unlisted: u64,
    /// Σ fees.
    pub fees: u64,
    /// Σ per trusted label (index into the installed mandate's `trusted`, label copied so a
    /// tightening that removes an entry does not misattribute usage).
    pub trusted: Vec<(alloc::string::String, u64)>,
}

/// The sealed policy state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    /// `SHA-256(identity public key)`; every message names it.
    pub enclave_id: [u8; 32],
    /// Network fixed at init.
    pub network: Network,
    /// Wallet fixed at init.
    pub wallet: WalletSpec,
    /// Owner public key.
    pub owner_pk: [u8; 65],
    /// Recovery public key.
    pub recovery_pk: [u8; 65],
    /// Installed mandate.
    pub mandate: Mandate,
    /// Its owner signature.
    pub mandate_sig: [u8; 64],
    /// Last accepted owner/recovery nonce.
    pub nonce: u64,
    /// Pending mandate.
    pub pending: Option<Pending>,
    /// Pending owner rotation.
    pub pending_owner: Option<PendingOwner>,
    /// Frozen: no signing until `Unfreeze`.
    pub frozen: bool,
    /// Armed: false after a suspected rollback until `Rearm`.
    pub armed: bool,
    /// Chain view.
    pub chain: ChainState,
    /// Current window.
    pub window: Window,
    /// Highest own index seen + 1, per branch (0 = receive, 1 = change).
    pub own_index_bound: [u32; 2],
    /// Receipt sequence: number of signatures produced.
    pub seq: u64,
}

impl State {
    /// A fresh state at init. The caller has validated `mandate` and verified `mandate_sig`.
    pub fn new_at_init(
        enclave_id: [u8; 32],
        owner_pk: [u8; 65],
        recovery_pk: [u8; 65],
        mandate: Mandate,
        mandate_sig: [u8; 64],
    ) -> Self {
        let start = mandate.checkpoint.height;
        State {
            enclave_id,
            network: mandate.network,
            wallet: mandate.wallet.clone(),
            owner_pk,
            recovery_pk,
            mandate,
            mandate_sig,
            nonce: 0,
            pending: None,
            pending_owner: None,
            frozen: false,
            armed: true,
            chain: ChainState { best: None, recent: Vec::new() },
            window: Window { start_height: start, ..Default::default() },
            own_index_bound: [0, 0],
            seq: 0,
        }
    }

    /// Canonical bytes for sealing.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::new();
        e.u16(STATE_VERSION);
        e.fixed(&self.enclave_id);
        e.u8(self.network as u8);
        // wallet is re-derived from the mandate's wallet at decode; it is sealed via the mandate
        // of record at init, so encode it explicitly to make the state self-contained.
        e.fixed(&self.wallet.fingerprint);
        e.u32(self.wallet.account.purpose);
        e.u32(self.wallet.account.coin);
        e.u32(self.wallet.account.account);
        e.list(&self.wallet.script_types, |e, t| {
            e.u8(*t as u8);
        });
        e.fixed(&self.owner_pk);
        e.fixed(&self.recovery_pk);
        e.bytes(&self.mandate.encode());
        e.fixed(&self.mandate_sig);
        e.u64(self.nonce);
        e.option(self.pending.as_ref(), |e, p| {
            e.bytes(&p.mandate.encode()).fixed(&p.sig).u64(p.nonce).u32(p.activation_height);
        });
        e.option(self.pending_owner.as_ref(), |e, p| {
            e.fixed(&p.new_owner_pk).u32(p.activation_height);
        });
        e.bool(self.frozen);
        e.bool(self.armed);
        e.option(self.chain.best.as_ref(), |e, c| {
            e.fixed(&c.hash).u32(c.height);
        });
        e.list(&self.chain.recent, |e, c| {
            e.fixed(&c.hash).u32(c.height);
        });
        e.u32(self.window.start_height);
        e.u64(self.window.outflow);
        e.u64(self.window.unlisted);
        e.u64(self.window.fees);
        e.list(&self.window.trusted, |e, (l, v)| {
            e.str(l).u64(*v);
        });
        e.u32(self.own_index_bound[0]);
        e.u32(self.own_index_bound[1]);
        e.u64(self.seq);
        e.finish()
    }

    /// Strict decode.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut d = Dec::new(bytes);
        if d.u16()? != STATE_VERSION {
            return Err(DecodeError);
        }
        let enclave_id = d.fixed()?;
        let network = match d.u8()? {
            0 => Network::Mainnet,
            1 => Network::Testnet4,
            2 => Network::Signet,
            3 => Network::Regtest,
            _ => return Err(DecodeError),
        };
        let fingerprint = d.fixed()?;
        let account = mandate::AccountPath { purpose: d.u32()?, coin: d.u32()?, account: d.u32()? };
        let script_types = d.list(mandate::bounds::MAX_SCRIPT_TYPES, |d| match d.u8()? {
            0 => Ok(mandate::ScriptType::P2wpkh),
            _ => Err(DecodeError),
        })?;
        let owner_pk = d.fixed()?;
        let recovery_pk = d.fixed()?;
        let mandate = Mandate::decode(&d.bytes(crate::update::MAX_MANDATE_BYTES)?)?;
        let mandate_sig = d.fixed()?;
        let nonce = d.u64()?;
        let pending = d.option(|d| {
            Ok(Pending {
                mandate: Mandate::decode(&d.bytes(crate::update::MAX_MANDATE_BYTES)?)?,
                sig: d.fixed()?,
                nonce: d.u64()?,
                activation_height: d.u32()?,
            })
        })?;
        let pending_owner =
            d.option(|d| Ok(PendingOwner { new_owner_pk: d.fixed()?, activation_height: d.u32()? }))?;
        let frozen = d.bool()?;
        let armed = d.bool()?;
        let best = d.option(|d| Ok(Checkpoint { hash: d.fixed()?, height: d.u32()? }))?;
        let recent = d.list(MAX_RECENT, |d| Ok(Checkpoint { hash: d.fixed()?, height: d.u32()? }))?;
        let window = Window {
            start_height: d.u32()?,
            outflow: d.u64()?,
            unlisted: d.u64()?,
            fees: d.u64()?,
            trusted: d.list(MAX_TRUSTED_USAGE, |d| {
                Ok((d.str(mandate::bounds::MAX_LABEL)?, d.u64()?))
            })?,
        };
        let own_index_bound = [d.u32()?, d.u32()?];
        let seq = d.u64()?;
        d.finish()?;
        Ok(State {
            enclave_id,
            network,
            wallet: WalletSpec { fingerprint, account, script_types },
            owner_pk,
            recovery_pk,
            mandate,
            mandate_sig,
            nonce,
            pending,
            pending_owner,
            frozen,
            armed,
            chain: ChainState { best, recent },
            window,
            own_index_bound,
            seq,
        })
    }

    /// Best verified height, or `ChainStale`.
    pub fn best_height(&self) -> Result<u32, Refusal> {
        self.chain.best.map(|c| c.height).ok_or_else(|| Refusal::one(Reason::ChainStale))
    }

    /// Install anything pending whose activation height has passed. Called at the start of every
    /// operation; idempotent.
    pub fn activate_pending(&mut self) {
        let Some(best) = self.chain.best.map(|c| c.height) else { return };
        if let Some(p) = &self.pending {
            if best >= p.activation_height {
                let p = p.clone();
                self.mandate = p.mandate;
                self.mandate_sig = p.sig;
                self.pending = None;
            }
        }
        if let Some(p) = &self.pending_owner {
            if best >= p.activation_height {
                self.owner_pk = p.new_owner_pk;
                self.pending_owner = None;
            }
        }
    }

    /// Roll the fixed window forward by whole window lengths until it contains `best`.
    /// Usage resets only when the window actually moves. Never moves backwards.
    pub fn roll_window(&mut self) {
        let Some(best) = self.chain.best.map(|c| c.height) else { return };
        let len = self.mandate.limits.window_blocks;
        if len == 0 {
            return;
        }
        if best < self.window.start_height {
            return;
        }
        let elapsed = best.saturating_sub(self.window.start_height);
        if elapsed >= len {
            let k = elapsed.checked_div(len).unwrap_or(0);
            let advance = k.saturating_mul(len);
            let new_start = self.window.start_height.saturating_add(advance);
            self.window = Window { start_height: new_start, ..Default::default() };
        }
    }

    /// Freeze (unauthenticated; fail-closed).
    pub fn freeze(&mut self) {
        self.frozen = true;
    }

    /// Apply an owner / recovery message. `WitnessToken` is not a transition (see `judge`).
    pub fn apply_message(&self, msg: &Message) -> Result<State, Refusal> {
        if msg.enclave_id() != &self.enclave_id {
            return Err(Reason::PolicySig.into());
        }
        let mut s = self.clone();
        s.activate_pending();
        let best = s.best_height()?;
        let next = s.nonce.checked_add(1).ok_or_else(|| Refusal::one(Reason::Overflow))?;
        let check_nonce = |n: u64| if n == next { Ok(()) } else { Err(Refusal::one(Reason::PolicyNonce)) };
        match msg {
            Message::PolicyUpdate { nonce, mandate, .. } => {
                if !msg.verify(&s.owner_pk) {
                    return Err(Reason::PolicySig.into());
                }
                check_nonce(*nonce)?;
                if s.pending.is_some() {
                    return Err(Reason::PolicyPending.into());
                }
                let new = Mandate::decode(mandate).map_err(|_| Refusal::one(Reason::PolicyInvalid))?;
                new.validate().map_err(|_| Refusal::one(Reason::PolicyInvalid))?;
                if new.network != s.network {
                    return Err(Reason::PolicyNetwork.into());
                }
                if new.wallet != s.wallet {
                    return Err(Reason::PolicyWallet.into());
                }
                if new.checkpoint.height > best {
                    // a checkpoint ahead of what the enclave has verified is not a checkpoint
                    return Err(Reason::PolicyInvalid.into());
                }
                let change = match mandate::compare(&s.mandate, &new) {
                    Ok(c) => c,
                    Err(mandate::Immutable::Network) => return Err(Reason::PolicyNetwork.into()),
                    Err(mandate::Immutable::Wallet) => return Err(Reason::PolicyWallet.into()),
                };
                s.nonce = next;
                match change {
                    mandate::Change::Tightening => {
                        s.mandate = new;
                        s.mandate_sig = *msg.sig();
                    }
                    mandate::Change::Loosening => {
                        let activation_height = best
                            .checked_add(s.mandate.timelock_blocks)
                            .ok_or_else(|| Refusal::one(Reason::Overflow))?;
                        s.pending = Some(Pending {
                            mandate: new,
                            sig: *msg.sig(),
                            nonce: next,
                            activation_height,
                        });
                    }
                }
                Ok(s)
            }
            Message::Cancel { nonce, .. } => {
                if !(msg.verify(&s.owner_pk) || msg.verify(&s.recovery_pk)) {
                    return Err(Reason::PolicySig.into());
                }
                check_nonce(*nonce)?;
                s.nonce = next;
                s.pending = None;
                s.pending_owner = None;
                Ok(s)
            }
            Message::Unfreeze { nonce, .. } => {
                if !msg.verify(&s.owner_pk) {
                    return Err(Reason::PolicySig.into());
                }
                check_nonce(*nonce)?;
                s.nonce = next;
                s.frozen = false;
                Ok(s)
            }
            Message::Rearm { nonce, seq, .. } => {
                if !msg.verify(&s.owner_pk) {
                    return Err(Reason::PolicySig.into());
                }
                check_nonce(*nonce)?;
                s.nonce = next;
                s.armed = true;
                if *seq > s.seq {
                    s.seq = *seq;
                }
                Ok(s)
            }
            Message::RotateOwner { nonce, new_owner_pk, .. } => {
                if !msg.verify(&s.owner_pk) {
                    return Err(Reason::PolicySig.into());
                }
                check_nonce(*nonce)?;
                if s.pending_owner.is_some() {
                    return Err(Reason::PolicyPending.into());
                }
                if parse_p256_pubkey(new_owner_pk).is_none() || new_owner_pk == &s.recovery_pk {
                    return Err(Reason::PolicyInvalid.into());
                }
                let activation_height = best
                    .checked_add(s.mandate.timelock_blocks)
                    .ok_or_else(|| Refusal::one(Reason::Overflow))?;
                s.nonce = next;
                s.pending_owner = Some(PendingOwner { new_owner_pk: *new_owner_pk, activation_height });
                Ok(s)
            }
            Message::Recover { nonce, new_owner_pk, .. } => {
                if !msg.verify(&s.recovery_pk) {
                    return Err(Reason::PolicySig.into());
                }
                check_nonce(*nonce)?;
                if parse_p256_pubkey(new_owner_pk).is_none() || new_owner_pk == &s.recovery_pk {
                    return Err(Reason::PolicyInvalid.into());
                }
                s.nonce = next;
                s.owner_pk = *new_owner_pk;
                // a recovery voids everything in flight: the old owner key may be the thief's
                s.pending = None;
                s.pending_owner = None;
                Ok(s)
            }
            Message::WitnessToken { .. } => Err(Reason::PolicyInvalid.into()),
        }
    }
}
