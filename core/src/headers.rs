//! The header-chain verifier — the enclave's only clock (`docs/DESIGN.md §5`, `docs/ENCLAVE.md
//! §6`). Consensus-critical: the retarget math is the `bitcoin` crate's own
//! (`CompactTarget::from_next_work_required`, `Target`, `Work`), never hand-rolled.
//!
//! A batch of headers is accepted as a whole or not at all: it must attach to the best header
//! (extension) or to a recent header (a fork), every header must link, carry exactly the required
//! `nBits`, meet its target, and have a timestamp above the median of the previous eleven; the
//! resulting chain is adopted only if its cumulative work exceeds the current best. A fork deeper
//! than the mandate's `maxReorg` freezes the chain view (`CHAIN_REORG`) until the owner re-pins.
//!
//! No wall clock exists here. The median-time-past rule consumes header timestamps only, and no
//! policy decision anywhere consults a time: windows, timelocks, validity and freshness are heights.

use alloc::vec::Vec;

use bitcoin::block::Header;
use bitcoin::consensus::deserialize;
use bitcoin::params::Params;
use bitcoin::pow::{CompactTarget, Target, Work};

use crate::mandate::Network;
use crate::reason::{Reason, Refusal};
use crate::state::{HeaderRec, State};

/// Retarget interval, blocks.
pub const INTERVAL: u32 = 2016;
/// Headers kept beyond `maxReorg` for the median-time-past rule and the witness tip check.
pub const RECENT_EXTRA: u32 = 12;

fn params(n: Network) -> Params {
    match n {
        Network::Mainnet => Params::MAINNET,
        Network::Testnet4 => Params::TESTNET4,
        Network::Signet => Params::SIGNET,
        Network::Regtest => Params::REGTEST,
    }
}

fn work_of(rec: &HeaderRec) -> Work {
    Work::from_le_bytes(rec.work)
}

/// 256-bit little-endian addition with carry; `None` on overflow (a chain with 2^256 work does not
/// exist, but the arithmetic discipline is the same everywhere: checked, or refuse).
fn add_work_le(a: &[u8; 32], b: &[u8; 32]) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    let mut carry: u16 = 0;
    for i in 0..32 {
        let s: u16 = u16::from(a[i]).checked_add(u16::from(b[i]))?.checked_add(carry)?;
        out[i] = (s & 0xff) as u8;
        carry = s >> 8;
    }
    if carry != 0 {
        return None;
    }
    Some(out)
}

fn median_time(chain: &[HeaderRec]) -> u32 {
    let n = chain.len().min(11);
    if n == 0 {
        return 0;
    }
    let mut times: Vec<u32> = chain[chain.len().saturating_sub(n)..].iter().map(|r| r.time).collect();
    times.sort_unstable();
    times[n.checked_div(2).unwrap_or(0)]
}

/// The `nBits` the next header must carry, given the chain it extends.
fn required_bits(
    p: &Params,
    parent: &HeaderRec,
    next_height: u32,
    next_time: u32,
    period_start_time: u32,
    period_bits: u32,
) -> u32 {
    if p.no_pow_retargeting {
        return parent.bits;
    }
    let boundary = next_height.checked_rem(INTERVAL) == Some(0);
    if boundary {
        // Core: CalculateNextWorkRequired(pindexLast, nFirstBlockTime) — from the LAST header's
        // bits (whatever they are) and the timespan since the period's first block.
        let timespan = u64::from(parent.time.saturating_sub(period_start_time));
        return CompactTarget::from_next_work_required(CompactTarget::from_consensus(parent.bits), timespan, p)
            .to_consensus();
    }
    if p.allow_min_difficulty_blocks {
        let limit = p.max_attainable_target.to_compact_lossy().to_consensus();
        let spacing2 = u32::try_from(p.pow_target_spacing.saturating_mul(2)).unwrap_or(u32::MAX);
        if next_time > parent.time.saturating_add(spacing2) {
            return limit;
        }
        // Core walks back to the last header that is not min-difficulty, stopping at the period
        // boundary; every such header carries the period's bits.
        return period_bits;
    }
    parent.bits
}

/// Apply a batch of 80-byte headers. Returns the number of headers now on the main chain that
/// were not before (0 when a fork with less work was offered). Mutates `state.chain`; on a
/// too-deep reorg it sets `chain.frozen` **and** returns `CHAIN_REORG` — the caller seals either
/// way.
pub fn apply_headers(state: &mut State, raw: &[[u8; 80]]) -> Result<u32, Refusal> {
    if raw.is_empty() {
        return Ok(0);
    }
    if state.chain.frozen {
        return Err(Reason::ChainReorg.into());
    }
    let p = params(state.network);
    let best = state.chain.best.ok_or_else(|| Refusal::one(Reason::ChainStale))?;
    let max_reorg = state.mandate.limits.max_reorg;

    let mut headers: Vec<Header> = Vec::with_capacity(raw.len());
    for h in raw {
        headers.push(deserialize::<Header>(h).map_err(|_| Refusal::one(Reason::HeaderInvalid))?);
    }

    // --- attachment point ---
    let first_prev: [u8; 32] = *headers[0].prev_blockhash.as_ref();
    let fork_index = if first_prev == best.hash {
        state.chain.recent.len().checked_sub(1).ok_or_else(|| Refusal::one(Reason::ChainStale))?
    } else {
        match state.chain.recent.iter().position(|r| r.hash == first_prev) {
            Some(i) => i,
            None => return Err(Reason::HeaderInvalid.into()),
        }
    };
    let fork_point = state.chain.recent[fork_index];
    let depth = best.height.saturating_sub(fork_point.height);
    if depth > max_reorg {
        state.chain.frozen = true;
        return Err(Reason::ChainReorg.into());
    }

    // --- period data for the chain being extended ---
    let cur_period_start_height = best.height.saturating_sub(best.height.checked_rem(INTERVAL).unwrap_or(0));
    let (mut period_start_time, mut prev_period_start_time, mut period_bits) =
        if fork_point.height >= cur_period_start_height {
            (state.chain.period_start_time, state.chain.prev_period_start_time, state.chain.period_bits)
        } else {
            // the fork point lies in the previous period; the candidate will re-cross the boundary
            (state.chain.prev_period_start_time, 0, state.chain.period_bits)
        };
    if fork_point.height < cur_period_start_height {
        // period_bits of the previous period: the bits of the fork point's period — every
        // non-min-difficulty header carries them; take the fork point's own bits as the best
        // available value (exact on mainnet/signet, where all headers of a period agree)
        period_bits = fork_point.bits;
    }

    // --- verify the candidate ---
    let mut chain: Vec<HeaderRec> = state.chain.recent[..=fork_index].to_vec();
    for h in &headers {
        let parent = *chain.last().ok_or_else(|| Refusal::one(Reason::ChainStale))?;
        let prev: [u8; 32] = *h.prev_blockhash.as_ref();
        if prev != parent.hash {
            return Err(Reason::HeaderInvalid.into());
        }
        let height = parent.height.checked_add(1).ok_or_else(|| Refusal::one(Reason::Overflow))?;
        let bits = h.bits.to_consensus();
        let required = required_bits(&p, &parent, height, h.time, period_start_time, period_bits);
        if bits != required {
            return Err(Reason::HeaderInvalid.into());
        }
        let target = Target::from_compact(h.bits);
        if target > p.max_attainable_target {
            return Err(Reason::HeaderInvalid.into());
        }
        if h.validate_pow(target).is_err() {
            return Err(Reason::HeaderInvalid.into());
        }
        if h.time <= median_time(&chain) {
            return Err(Reason::HeaderInvalid.into());
        }
        let work =
            add_work_le(&parent.work, &target.to_work().to_le_bytes()).ok_or_else(|| Refusal::one(Reason::Overflow))?;
        let rec = HeaderRec { hash: *h.block_hash().as_ref(), height, time: h.time, bits, work };
        if height.checked_rem(INTERVAL) == Some(0) {
            prev_period_start_time = period_start_time;
            period_start_time = h.time;
            period_bits = bits;
        }
        chain.push(rec);
    }

    // --- fork choice: most cumulative work, strictly ---
    let tip = *chain.last().ok_or_else(|| Refusal::one(Reason::ChainStale))?;
    if work_of(&tip) <= work_of(&best) {
        return Ok(0);
    }
    let added = tip.height.saturating_sub(best.height).saturating_add(depth);
    let keep = max_reorg.saturating_add(RECENT_EXTRA) as usize;
    if chain.len() > keep {
        chain.drain(..chain.len().saturating_sub(keep));
    }
    state.chain.best = Some(tip);
    state.chain.recent = chain;
    state.chain.period_start_time = period_start_time;
    state.chain.prev_period_start_time = prev_period_start_time;
    state.chain.period_bits = period_bits;
    Ok(added)
}
