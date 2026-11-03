//! The policy engine (invariants I5–I9): classified transaction + state → verdict, and the
//! state the verdict charges.
//!
//! Order: freshness and liveness gates → structure rules → arithmetic (checked, overflow refuses)
//! → per-transaction caps → per-window caps → commit. A refusal charges nothing, with one
//! deliberate exception: a witness token that reveals a rollback **disarms** the signer, and that
//! change is returned so the enclave seals it.

use alloc::string::String;
use alloc::vec::Vec;

use crate::classify::{Classified, InputClass, OutputClass};
use crate::mandate::PayjoinRule;
use crate::reason::{Reason, Refusal};
use crate::state::State;
use crate::update::Message;

/// What a signature will be a receipt for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Summary {
    /// Sequence number this signature takes.
    pub seq: u64,
    /// Txid of the unsigned transaction.
    pub txid: [u8; 32],
    /// Net outflow (Σ own in − Σ own out; 0 when receiving).
    pub net_outflow: u64,
    /// Σ unlisted.
    pub unlisted: u64,
    /// Σ per trusted label.
    pub trusted: Vec<(String, u64)>,
    /// Fee (Σ all in − Σ all out).
    pub fee: u64,
    /// Best height at judgement.
    pub height: u32,
    /// Installed mandate hash.
    pub mandate_hash: [u8; 32],
    /// Pending mandate hash, if any.
    pub pending_hash: Option<[u8; 32]>,
    /// Owner nonce at judgement.
    pub nonce: u64,
}

/// The verdict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Sign. `state` is the charged state to seal **before** signing.
    Accept {
        /// Charged state.
        state: State,
        /// Receipt material.
        summary: Summary,
    },
    /// Refuse. `disarm` is `Some` when the refusal itself changed the state (rollback suspected).
    Refuse {
        /// Reasons.
        refusal: Refusal,
        /// State to seal, if the refusal changed it.
        disarm: Option<State>,
    },
}

#[cfg(feature = "hollow-test")]
/// Guard knobs for the hollow-test suite only. Every field defaults to `true`; a test flips one
/// to prove the matching vector goes red. Absent from every non-test build.
#[derive(Clone, Copy, Debug)]
pub struct Guards {
    /// I5/I11: charge the window before signing.
    pub commit_before_sign: bool,
    /// window caps enforced
    pub window_caps: bool,
}

#[cfg(feature = "hollow-test")]
impl Default for Guards {
    fn default() -> Self {
        Guards { commit_before_sign: true, window_caps: true }
    }
}

fn add(a: u64, b: u64) -> Result<u64, Refusal> {
    a.checked_add(b).ok_or_else(|| Refusal::one(Reason::Overflow))
}

/// Judge `c` against `state` with an optional witness token.
pub fn judge(state: &State, c: &Classified, witness: Option<&Message>) -> Verdict {
    #[cfg(feature = "hollow-test")]
    let guards = Guards::default();
    judge_inner(
        state,
        c,
        witness,
        #[cfg(feature = "hollow-test")]
        guards,
    )
}

#[cfg(feature = "hollow-test")]
/// Judge with explicit guard knobs (hollow-test suite only).
pub fn judge_with_guards(state: &State, c: &Classified, witness: Option<&Message>, g: Guards) -> Verdict {
    judge_inner(state, c, witness, g)
}

fn judge_inner(
    state: &State,
    c: &Classified,
    witness: Option<&Message>,
    #[cfg(feature = "hollow-test")] g: Guards,
) -> Verdict {
    let mut s = state.clone();
    s.activate_pending();
    s.roll_window();
    match judge_checks(
        &mut s,
        c,
        witness,
        #[cfg(feature = "hollow-test")]
        g,
    ) {
        Ok(summary) => Verdict::Accept { state: s, summary },
        Err((refusal, disarm)) => Verdict::Refuse { refusal, disarm: if disarm { Some(s) } else { None } },
    }
}

fn judge_checks(
    s: &mut State,
    c: &Classified,
    witness: Option<&Message>,
    #[cfg(feature = "hollow-test")] g: Guards,
) -> Result<Summary, (Refusal, bool)> {
    let m = s.mandate.clone();
    let l = m.limits;
    let no = |r: Reason| (Refusal::one(r), false);

    // --- liveness gates ---
    if s.frozen {
        return Err(no(Reason::Frozen));
    }
    if !s.armed {
        return Err(no(Reason::FreshnessSeqBehind));
    }
    let best = s.chain.best.ok_or_else(|| no(Reason::ChainStale))?;
    if best.height > m.not_after_height {
        return Err(no(Reason::MandateExpired));
    }

    // --- freshness witness (R13: two checks, tip and sequence) ---
    if m.freshness.required {
        let Some(tok) = witness else { return Err(no(Reason::FreshnessMissing)) };
        let Message::WitnessToken { enclave_id, tip_hash, tip_height, last_seen_seq, .. } = tok else {
            return Err(no(Reason::FreshnessSig));
        };
        let Some(pk) = &m.freshness.witness_pk else { return Err(no(Reason::FreshnessMissing)) };
        if enclave_id != &s.enclave_id || !tok.verify(pk) {
            return Err(no(Reason::FreshnessSig));
        }
        let lag = best.height.checked_sub(*tip_height).ok_or_else(|| no(Reason::FreshnessTip))?;
        if lag > m.freshness.max_tip_lag {
            return Err(no(Reason::FreshnessTip));
        }
        let known = (best.height == *tip_height && best.hash == *tip_hash)
            || s.chain.recent.iter().any(|h| h.height == *tip_height && h.hash == *tip_hash);
        if !known {
            return Err(no(Reason::FreshnessTip));
        }
        if *last_seen_seq > s.seq {
            // the world has seen receipts this enclave does not remember: rollback suspected
            s.armed = false;
            return Err((Refusal::one(Reason::FreshnessSeqBehind), true));
        }
    }

    // --- structure rules ---
    let mut reasons: Vec<Reason> = Vec::new();
    if c.version != 1 && c.version != 2 {
        reasons.push(Reason::TxVersion);
    }
    if c.rbf && !m.rules.rbf {
        reasons.push(Reason::RbfForbidden);
    }
    let foreign_present = c.inputs.iter().any(|i| matches!(i, InputClass::Foreign { .. }));
    if foreign_present && m.rules.payjoin == PayjoinRule::None {
        reasons.push(Reason::InputForeignForbidden);
    }
    if !c.inputs.iter().any(|i| matches!(i, InputClass::Own { .. })) {
        // nothing to sign: not a refusal class of its own; the host asked for nothing
        reasons.push(Reason::InputNotOwn);
    }

    // --- sums (checked) ---
    let mut own_in = 0u64;
    let mut all_in = 0u64;
    for i in &c.inputs {
        match i {
            InputClass::Own { amount, .. } => {
                own_in = add(own_in, *amount).map_err(|r| (r, false))?;
                all_in = add(all_in, *amount).map_err(|r| (r, false))?;
            }
            InputClass::Foreign { amount } => {
                all_in = add(all_in, *amount).map_err(|r| (r, false))?;
            }
        }
    }
    let mut own_out = 0u64;
    let mut all_out = 0u64;
    let mut unlisted = 0u64;
    let mut trusted: Vec<(String, u64)> = Vec::new();
    let mut new_bound = s.own_index_bound;
    for o in &c.outputs {
        match o {
            OutputClass::Own { path, amount } => {
                own_out = add(own_out, *amount).map_err(|r| (r, false))?;
                all_out = add(all_out, *amount).map_err(|r| (r, false))?;
                let b = &mut new_bound[path.branch as usize];
                let next = path.index.saturating_add(1);
                if next > *b {
                    *b = next;
                }
            }
            OutputClass::Trusted { dest, amount } => {
                all_out = add(all_out, *amount).map_err(|r| (r, false))?;
                let label = m.destinations.trusted.get(*dest).map(|d| d.label.clone()).unwrap_or_default();
                match trusted.iter_mut().find(|(l, _)| *l == label) {
                    Some((_, v)) => *v = add(*v, *amount).map_err(|r| (r, false))?,
                    None => trusted.push((label, *amount)),
                }
            }
            OutputClass::Unlisted { amount } => {
                all_out = add(all_out, *amount).map_err(|r| (r, false))?;
                unlisted = add(unlisted, *amount).map_err(|r| (r, false))?;
            }
            OutputClass::OpReturn => {}
        }
    }
    // own inputs raise the receive/change bound too (the enclave learns used indices from spends)
    for i in &c.inputs {
        if let InputClass::Own { path, .. } = i {
            let b = &mut new_bound[path.branch as usize];
            let next = path.index.saturating_add(1);
            if next > *b {
                *b = next;
            }
        }
    }
    if all_out > all_in {
        return Err(no(Reason::PsbtParse));
    }
    let fee = all_in.saturating_sub(all_out);
    let net_outflow = own_in.saturating_sub(own_out);
    let inflow = own_out > own_in;

    if foreign_present && m.rules.payjoin == PayjoinRule::InflowOnly && !inflow && net_outflow > 0 {
        reasons.push(Reason::InputForeignForbidden);
    }

    // --- per-transaction caps ---
    if net_outflow > l.max_per_tx {
        reasons.push(Reason::CapTx);
    }
    if unlisted > m.destinations.unlisted.max_per_tx {
        reasons.push(Reason::CapUnlistedTx);
    }
    for (label, v) in &trusted {
        if let Some(d) = m.destinations.trusted.iter().find(|d| &d.label == label) {
            if *v > d.max_per_tx {
                reasons.push(Reason::CapTrustedTx(label.clone()));
            }
        }
    }
    if fee > l.max_fee_abs {
        reasons.push(Reason::FeeAbs);
    }
    // a rate cap too large to multiply is no cap at all; `max_fee_abs` still binds
    if let Some(max_fee) = l.max_fee_rate.checked_mul(c.vsize_lower_bound) {
        if fee > max_fee {
            reasons.push(Reason::FeeRate);
        }
    }

    // --- per-window caps ---
    let w = &s.window;
    let w_outflow = add(w.outflow, net_outflow).map_err(|r| (r, false))?;
    let w_unlisted = add(w.unlisted, unlisted).map_err(|r| (r, false))?;
    let w_fees = add(w.fees, fee).map_err(|r| (r, false))?;
    #[cfg(feature = "hollow-test")]
    let window_caps = g.window_caps;
    #[cfg(not(feature = "hollow-test"))]
    let window_caps = true;
    if window_caps {
        if w_outflow > l.window_max_outflow {
            reasons.push(Reason::CapWindow);
        }
        if w_unlisted > m.destinations.unlisted.max_per_window {
            reasons.push(Reason::CapUnlistedWindow);
        }
        if let Some(cap) = l.max_fee_per_window {
            if w_fees > cap {
                reasons.push(Reason::FeeWindow);
            }
        }
    }
    let mut w_trusted = w.trusted.clone();
    for (label, v) in &trusted {
        let d = m.destinations.trusted.iter().find(|d| &d.label == label);
        let entry = match w_trusted.iter_mut().find(|(l, _)| l == label) {
            Some(e) => e,
            None => {
                w_trusted.push((label.clone(), 0));
                w_trusted.last_mut().expect("just pushed")
            }
        };
        entry.1 = add(entry.1, *v).map_err(|r| (r, false))?;
        if window_caps {
            if let Some(d) = d {
                if entry.1 > d.max_per_window {
                    reasons.push(Reason::CapTrustedWindow(label.clone()));
                }
            }
        }
    }

    if !reasons.is_empty() {
        return Err((Refusal(reasons), false));
    }

    // --- commit ---
    let seq = s.seq.checked_add(1).ok_or_else(|| no(Reason::Overflow))?;
    #[cfg(feature = "hollow-test")]
    let commit = g.commit_before_sign;
    #[cfg(not(feature = "hollow-test"))]
    let commit = true;
    if commit {
        s.window.outflow = w_outflow;
        s.window.unlisted = w_unlisted;
        s.window.fees = w_fees;
        s.window.trusted = w_trusted;
        s.own_index_bound = new_bound;
        s.seq = seq;
    }
    Ok(Summary {
        seq,
        txid: c.txid,
        net_outflow,
        unlisted,
        trusted,
        fee,
        height: best.height,
        mandate_hash: m.hash(),
        pending_hash: s.pending.as_ref().map(|p| p.mandate.hash()),
        nonce: s.nonce,
    })
}
