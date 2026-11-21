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

/// State encoding version 1: no TPM anchor (every state before REQ-r9, and every unanchored one).
pub const STATE_VERSION: u16 = 1;
/// State encoding version 2 (REQ-r9): version 1's fields followed by the TPM anchor. The version
/// *is* the presence of the anchor — an unanchored state is a v1 state, an anchored one a v2 state —
/// so each value has exactly one encoding and the R1 vectors (v1 blobs) stay valid.
pub const STATE_VERSION_TPM: u16 = 2;

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

/// One verified header, as the chain view keeps it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeaderRec {
    /// Block hash (internal byte order).
    pub hash: [u8; 32],
    /// Height.
    pub height: u32,
    /// Timestamp.
    pub time: u32,
    /// `nBits`.
    pub bits: u32,
    /// Cumulative work from the checkpoint, `Work::to_le_bytes()`.
    pub work: [u8; 32],
}

/// What the enclave knows about the chain. Written only by `headers::apply_headers` (and reset
/// from a checkpoint at init or at a re-pin); never from a host assertion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainState {
    /// Best verified header, if any.
    pub best: Option<HeaderRec>,
    /// Recent verified headers of the main chain, oldest first, bounded by `MAX_RECENT`.
    pub recent: Vec<HeaderRec>,
    /// Timestamp of the first block of the current retarget period.
    pub period_start_time: u32,
    /// Timestamp of the first block of the previous period (needed when a fork point lies
    /// before the current period's first block).
    pub prev_period_start_time: u32,
    /// `nBits` of the current period's first block.
    pub period_bits: u32,
    /// Frozen by a reorg deeper than `maxReorg`; cleared by a mandate update that re-pins.
    pub frozen: bool,
}

impl ChainState {
    /// A chain view that starts from a checkpoint.
    pub fn from_checkpoint(c: &Checkpoint) -> Self {
        let work = bitcoin::pow::Target::from_compact(bitcoin::pow::CompactTarget::from_consensus(c.bits))
            .to_work()
            .to_le_bytes();
        let rec = HeaderRec { hash: c.hash, height: c.height, time: c.time, bits: c.bits, work };
        ChainState {
            best: Some(rec),
            recent: alloc::vec![rec],
            period_start_time: c.period_start_time,
            prev_period_start_time: 0,
            period_bits: c.period_bits,
            frozen: false,
        }
    }
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
    /// REQ-r9: the TPM counter this state is bound to, if any. `None` = R7 behaviour unchanged.
    pub tpm: Option<crate::tpm_attest::TpmAnchor>,
}

impl State {
    /// A fresh state at init. Validates `mandate` itself and refuses an invalid one (RESP-r10-F01,
    /// C-F01-3: "the installed mandate is always validated" is enforced at the write site, not by
    /// caller discipline — `compare` relies on it). The caller has verified `mandate_sig`.
    pub fn new_at_init(
        enclave_id: [u8; 32],
        owner_pk: [u8; 65],
        recovery_pk: [u8; 65],
        mandate: Mandate,
        mandate_sig: [u8; 64],
    ) -> Result<Self, mandate::Invalid> {
        mandate.validate()?;
        let start = mandate.checkpoint.height;
        let chain = ChainState::from_checkpoint(&mandate.checkpoint);
        Ok(State {
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
            chain,
            window: Window { start_height: start, ..Default::default() },
            own_index_bound: [0, 0],
            seq: 0,
            tpm: None,
        })
    }

    /// REQ-r9 (C-R9-B): the one place the expected counter moves by `+1` — called by the shell's
    /// single seal helper for every blob it seals, never per path. Saturating: a counter at
    /// `u64::MAX` can never be matched again, which is a refusal, not a wrap.
    pub fn bump_tpm(&mut self) {
        if let Some(t) = self.tpm.as_mut() {
            t.expected = t.expected.saturating_add(1);
        }
    }

    /// Canonical bytes for sealing.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::new();
        e.u16(if self.tpm.is_some() { STATE_VERSION_TPM } else { STATE_VERSION });
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
        let rec = |e: &mut Enc, c: &HeaderRec| {
            e.fixed(&c.hash).u32(c.height).u32(c.time).u32(c.bits).fixed(&c.work);
        };
        e.option(self.chain.best.as_ref(), |e, c| rec(e, c));
        e.list(&self.chain.recent, |e, c| rec(e, c));
        e.u32(self.chain.period_start_time);
        e.u32(self.chain.prev_period_start_time);
        e.u32(self.chain.period_bits);
        e.bool(self.chain.frozen);
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
        if let Some(t) = self.tpm.as_ref() {
            e.fixed(&t.ak_pk).fixed(&t.nv_name).u64(t.expected);
        }
        e.finish()
    }

    /// Strict decode.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut d = Dec::new(bytes);
        let version = d.u16()?;
        if version != STATE_VERSION && version != STATE_VERSION_TPM {
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
        let pending_owner = d.option(|d| Ok(PendingOwner { new_owner_pk: d.fixed()?, activation_height: d.u32()? }))?;
        let frozen = d.bool()?;
        let armed = d.bool()?;
        let rec = |d: &mut Dec| -> Result<HeaderRec, DecodeError> {
            Ok(HeaderRec { hash: d.fixed()?, height: d.u32()?, time: d.u32()?, bits: d.u32()?, work: d.fixed()? })
        };
        let best = d.option(rec)?;
        let recent = d.list(MAX_RECENT, rec)?;
        let period_start_time = d.u32()?;
        let prev_period_start_time = d.u32()?;
        let period_bits = d.u32()?;
        let chain_frozen = d.bool()?;
        let window = Window {
            start_height: d.u32()?,
            outflow: d.u64()?,
            unlisted: d.u64()?,
            fees: d.u64()?,
            trusted: d.list(MAX_TRUSTED_USAGE, |d| Ok((d.str(mandate::bounds::MAX_LABEL)?, d.u64()?)))?,
        };
        let own_index_bound = [d.u32()?, d.u32()?];
        let seq = d.u64()?;
        let tpm = if version == STATE_VERSION_TPM {
            Some(crate::tpm_attest::TpmAnchor { ak_pk: d.fixed()?, nv_name: d.fixed()?, expected: d.u64()? })
        } else {
            None
        };
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
            chain: ChainState {
                best,
                recent,
                period_start_time,
                prev_period_start_time,
                period_bits,
                frozen: chain_frozen,
            },
            window,
            own_index_bound,
            seq,
            tpm,
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
                if self.chain.frozen && p.mandate.checkpoint != self.mandate.checkpoint {
                    self.chain = ChainState::from_checkpoint(&p.mandate.checkpoint);
                }
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
                // REQ-r10-O01: while the chain is frozen by a deep reorg the only policy update that helps
                // is a checkpoint re-pin (below). Anything else is refused: a tightening would be a no-op
                // behind CHAIN_REORG, a loosening would park in `pending` for ever (`best` cannot move
                // while frozen — `apply_headers` refuses every header) and block the re-pin itself behind
                // POLICY_PENDING. Refused before the nonce is consumed.
                if s.chain.frozen && new.checkpoint == s.mandate.checkpoint {
                    return Err(Reason::ChainReorg.into());
                }
                // the checkpoint is the trust root: unchanged, or a header this enclave verified
                // itself with every field as recorded (RESP-r10-F01 leg 2), or — only while the chain
                // is frozen by a deep reorg — a fresh re-pin, which applies at once (C-F01-1)
                if new.checkpoint != s.mandate.checkpoint {
                    if s.chain.frozen {
                        // Frozen re-pin. The deep reorg invalidated the local view, so there is no
                        // header to validate the checkpoint against and the owner's signature is the
                        // root of trust for recovery (THREAT-MODEL.md, V5 ∧ frozen). It applies AT
                        // ONCE, forward or same-height: the block-height timelock cannot run while
                        // `apply_headers` refuses every header, so a re-pin routed through `pending`
                        // would never activate and the signer would stay frozen for good. Checkpoint-
                        // only (C-F01-2): nothing else may change in the same step, so the recovery
                        // path is not a policy-change path.
                        let mut rest = new.clone();
                        rest.checkpoint = s.mandate.checkpoint;
                        if rest != s.mandate {
                            return Err(Reason::PolicyInvalid.into());
                        }
                        s.nonce = next;
                        s.chain = ChainState::from_checkpoint(&new.checkpoint);
                        s.mandate = new;
                        s.mandate_sig = *msg.sig();
                        return Ok(s);
                    }
                    checkpoint_pinned(&s.chain, &new.checkpoint, best)?;
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
                        s.pending = Some(Pending { mandate: new, sig: *msg.sig(), nonce: next, activation_height });
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
                let activation_height =
                    best.checked_add(s.mandate.timelock_blocks).ok_or_else(|| Refusal::one(Reason::Overflow))?;
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
            // Arm is a statement about a process, not about the sealed state alone: only `apply_arm`,
            // which takes this load's challenge as data, may accept it.
            Message::Arm { .. } => Err(Reason::PolicyInvalid.into()),
            Message::Anchor { .. } => Err(Reason::PolicyInvalid.into()),
            Message::WitnessToken { .. } => Err(Reason::PolicyInvalid.into()),
        }
    }

    /// The boot-arm transition (REQ-r7). Verified like every owner message — signature, enclave
    /// id, next nonce (consumed) — plus the two checks that bind it to THIS process: the challenge
    /// the enclave drew at this load, handed in by the shell as data (the core holds no volatile
    /// state), and the sequence the owner last saw, which an enclave that was rolled back cannot
    /// reach. Whether the process is then armed is the shell's volatile fact, never sealed.
    pub fn apply_arm(&self, msg: &Message, boot_challenge: &[u8; 32]) -> Result<State, Refusal> {
        let Message::Arm { nonce, boot_challenge: c, seq_seen, .. } = msg else {
            return Err(Reason::PolicyInvalid.into());
        };
        // REQ-r10-F02 (F-2026-11-21-01): a due rotation activates FIRST, so the signature is verified against
        // the owner at the operation — as every `apply_message` arm does — never against a key being retired
        let mut s = self.clone();
        s.activate_pending();
        if msg.enclave_id() != &s.enclave_id || !msg.verify(&s.owner_pk) {
            return Err(Reason::PolicySig.into());
        }
        let next = s.nonce.checked_add(1).ok_or_else(|| Refusal::one(Reason::Overflow))?;
        if *nonce != next {
            return Err(Reason::PolicyNonce.into());
        }
        if c != boot_challenge {
            return Err(Reason::ArmChallenge.into());
        }
        if *seq_seen > s.seq {
            return Err(Reason::ArmSeqBehind.into());
        }
        s.nonce = next;
        Ok(s)
    }

    /// REQ-r9a C1: the TPM identity an `Anchor`'s proof must be verified against. A TPM-bound state
    /// answers with the SEALED key and Name — the identity bound at this wallet's first anchor, inside
    /// the blob the host cannot change — and the message must name the same two values, otherwise
    /// `ANCHOR_TPM_MISMATCH`: the owner builds the Anchor from a host-supplied `tpm-info`, so a host
    /// could hand the owner the identity of a TPM it controls plus a valid proof from that TPM and
    /// re-point the anti-rollback counter to itself. Only an unbound state (the first, binding
    /// anchor) takes the message's identity: trust-on-first-use, the labeled residual.
    pub fn anchor_identity(&self, msg: &Message) -> Result<([u8; 65], [u8; crate::tpm_attest::NV_NAME_LEN]), Refusal> {
        let Message::Anchor { ak_pk, nv_name, .. } = msg else {
            return Err(Reason::PolicyInvalid.into());
        };
        match self.tpm.as_ref() {
            Some(bound) => {
                if bound.ak_pk != *ak_pk || bound.nv_name != *nv_name {
                    return Err(Reason::AnchorTpmMismatch.into());
                }
                Ok((bound.ak_pk, bound.nv_name))
            }
            None => Ok((*ak_pk, *nv_name)),
        }
    }

    /// The anchor transition (REQ-r9 §2.5, REQ-r9a): every check of `apply_arm` — owner signature,
    /// enclave id, next nonce (consumed), this load's challenge, the sequence the owner saw — plus the
    /// structural check of the pinned material and the identity rule of `anchor_identity`; then the
    /// state pins the TPM and expects `live_counter` — the value the shell verified in the proof the
    /// host deposited for THIS call (REQ-r9a C3), never the message's static snapshot: between the
    /// owner's `tpm-certify` and this apply the daemon's own persists may have moved the counter. The
    /// owner's attested `counter` is the LOWER BOUND: a live value below it is a lying host or a
    /// replaced TPM (`ANCHOR_COUNTER_BEHIND`). The shell seals the result (which bumps `expected` to
    /// `live_counter + 1`) and arms the load.
    pub fn apply_anchor(&self, msg: &Message, boot_challenge: &[u8; 32], live_counter: u64) -> Result<State, Refusal> {
        let Message::Anchor { nonce, boot_challenge: c, counter, seq_seen, .. } = msg else {
            return Err(Reason::PolicyInvalid.into());
        };
        // REQ-r10-F02 (F-2026-11-21-01): a due rotation activates FIRST, so the signature is verified against
        // the owner at the operation — as every `apply_message` arm does — never against a key being retired
        let mut s = self.clone();
        s.activate_pending();
        if msg.enclave_id() != &s.enclave_id || !msg.verify(&s.owner_pk) {
            return Err(Reason::PolicySig.into());
        }
        let next = s.nonce.checked_add(1).ok_or_else(|| Refusal::one(Reason::Overflow))?;
        if *nonce != next {
            return Err(Reason::PolicyNonce.into());
        }
        if c != boot_challenge {
            return Err(Reason::ArmChallenge.into());
        }
        if *seq_seen > s.seq {
            return Err(Reason::ArmSeqBehind.into());
        }
        let (ak_pk, nv_name) = s.anchor_identity(msg)?;
        if live_counter < *counter {
            return Err(Reason::AnchorCounterBehind.into());
        }
        let anchor = crate::tpm_attest::TpmAnchor { ak_pk, nv_name, expected: live_counter };
        if !anchor.well_formed() {
            return Err(Reason::PolicyInvalid.into());
        }
        s.nonce = next;
        s.tpm = Some(anchor);
        Ok(s)
    }
}

/// RESP-r10-F01 leg 2: on the unfrozen path a changed checkpoint is accepted only if **every** field
/// is pinned by this enclave's own chain view — validate or refuse, never document-and-trust.
/// `hash`/`height` must be a verified recent header `r` at or below `best`; `time` and `bits` must be
/// `r`'s; `period_start_time`/`period_bits` must be the current period's values, which the enclave
/// knows exactly only while `r` lies in the current retarget period (`apply_headers` keeps the
/// previous period's start time but not its bits exactly on every network) — a header of an earlier
/// period is not re-pinnable while unfrozen. Anything else is `POLICY_INVALID`.
fn checkpoint_pinned(chain: &ChainState, c: &Checkpoint, best: u32) -> Result<(), Refusal> {
    let invalid = || Refusal::one(Reason::PolicyInvalid);
    if c.height > best {
        return Err(invalid());
    }
    let r = chain.recent.iter().find(|r| r.hash == c.hash && r.height == c.height).ok_or_else(invalid)?;
    if c.time != r.time || c.bits != r.bits {
        return Err(invalid());
    }
    let period_start_height = best.saturating_sub(best.checked_rem(crate::headers::INTERVAL).unwrap_or(0));
    if r.height < period_start_height
        || c.period_start_time != chain.period_start_time
        || c.period_bits != chain.period_bits
    {
        return Err(invalid());
    }
    Ok(())
}
