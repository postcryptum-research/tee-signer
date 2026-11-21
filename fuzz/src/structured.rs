//! Structured targets (REQ-r10 phase 2, pass i): `work_add` (C-R10P2-2 / C-R10-6), `headers` (F6) and
//! `state_ops` (F4). Inputs are scripted — fixed-size step records read byte by byte — so every seed is
//! hand-writable and every injected defect has a deterministic reproducer; libFuzzer mutates the records.
//! Every assertion names its oracle.

use core::cmp::Ordering;
use std::sync::OnceLock;

use arbitrary::Unstructured;
use bitcoin::block::Header;
use bitcoin::hashes::Hash;
use signer_core::headers::{add_work_le, apply_headers, INTERVAL, RECENT_EXTRA};
use signer_core::mandate::{compare, Change, Checkpoint, Mandate, Network};
use signer_core::reason::{Reason, Refusal};
use signer_core::state::{State, MAX_RECENT};
use signer_core::tpm_attest::TpmAnchor;
use signer_core::update::Message;

use crate::fixtures::{self, P256Key, ENCLAVE_ID};
use crate::gen;
use crate::seeds::honest;
use crate::targets::mutate_mandate;

// ------------------------------------------------------------------------------------------------
// work_add — C-R10-6 directly: the 256-bit accumulator never wraps (C-R10P2-2)
// ------------------------------------------------------------------------------------------------

/// Two 256-bit little-endian operands; `add_work_le` against an independent reference adder.
pub fn work_add(data: &[u8]) {
    if data.len() < 64 {
        return;
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&data[..32]);
    let mut b = [0u8; 32];
    b.copy_from_slice(&data[32..64]);
    let (sum, overflow) = gen::add256_ref(&a, &b);
    let got = add_work_le(&a, &b);
    assert_eq!(got, add_work_le(&b, &a), "C-R10-6: add_work_le is not commutative");
    match got {
        None => assert!(overflow, "C-R10-6: add_work_le refused a sum that fits below 2^256"),
        Some(s) => {
            assert!(!overflow, "C-R10-6: add_work_le WRAPPED — a + b >= 2^256 yet it returned Some");
            assert_eq!(s, sum, "C-R10-6: add_work_le differs from the reference sum");
            assert!(
                gen::le_cmp(&s, &a) != Ordering::Less && gen::le_cmp(&s, &b) != Ordering::Less,
                "C-R10-6: a sum below one of its operands"
            );
        }
    }
}

// ------------------------------------------------------------------------------------------------
// headers — F6
// ------------------------------------------------------------------------------------------------

fn code(r: &Refusal) -> &'static str {
    r.0.first().map(|x| x.code()).unwrap_or("")
}

/// The chain-view invariants that hold after every `apply_headers` call, accepted or refused.
fn chain_invariants(before: &State, after: &State, result: &Result<u32, Refusal>) {
    let b = before.chain.best.expect("fixture has a best");
    let a = after.chain.best.expect("best never disappears");
    assert!(gen::le_cmp(&a.work, &b.work) != Ordering::Less, "F6: best moved to LESS cumulative work");
    let r = &after.chain.recent;
    assert!(!r.is_empty() && r.last().unwrap().hash == a.hash, "F6: recent does not end at best");
    for w in r.windows(2) {
        assert_eq!(w[1].height, w[0].height + 1, "F6: recent is not contiguous");
        assert!(
            gen::le_cmp(&w[1].work, &w[0].work) == Ordering::Greater,
            "C-R10-6: work not strictly increasing along recent"
        );
    }
    let keep = (after.mandate.limits.max_reorg + RECENT_EXTRA) as usize;
    assert!(r.len() <= keep.max(1) && r.len() <= MAX_RECENT, "F6: recent exceeds its bound");
    match result {
        Err(e) if code(e) == Reason::ChainReorg.code() => {
            assert!(after.chain.frozen, "F6: CHAIN_REORG returned but the chain is not frozen")
        }
        Err(_) => assert_eq!(after.chain, before.chain, "F6: a refused batch changed the chain view"),
        Ok(0) => assert_eq!(after.chain.best, before.chain.best, "F6: Ok(0) but best moved"),
        Ok(n) => assert!(a.height > b.height || *n > 0, "F6: Ok(n>0) without growth"),
    }
    if before.chain.frozen {
        assert!(
            after.chain.frozen && after.chain == before.chain,
            "F6: a frozen chain changed or thawed on a header batch"
        );
        assert!(
            matches!(result, Err(e) if code(e) == Reason::ChainReorg.code()),
            "F6: a frozen chain accepted headers"
        );
    }
}

fn apply(s: &mut State, batch: &[Header]) -> Result<u32, Refusal> {
    let raw: Vec<[u8; 80]> = batch.iter().map(gen::raw).collect();
    apply_headers(s, &raw)
}

fn signet_headers() -> &'static Vec<[u8; 80]> {
    static H: OnceLock<Vec<[u8; 80]>> = OnceLock::new();
    H.get_or_init(|| {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../vectors/headers/signet-322560-324700.hex"
        ))
        .expect("the signet header vector");
        text.lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                let v = hex::decode(l.trim()).expect("hex");
                let mut a = [0u8; 80];
                a.copy_from_slice(&v);
                a
            })
            .collect()
    })
}

/// The signet fixture: checkpoint = the vector's first header (322 560, a retarget boundary).
fn signet_state() -> State {
    let (w, cold, k) = (fixtures::wallet(0x01), fixtures::wallet(0x02), fixtures::keys());
    let h: Header = bitcoin::consensus::deserialize(&signet_headers()[0]).expect("header");
    let mut m = fixtures::base_mandate(&w, &cold);
    m.network = Network::Signet;
    m.limits.max_reorg = 6;
    m.checkpoint = Checkpoint {
        hash: h.block_hash().to_byte_array(),
        height: 322_560,
        time: h.time,
        bits: h.bits.to_consensus(),
        period_start_time: h.time,
        period_bits: h.bits.to_consensus(),
    };
    m.not_after_height = 400_000;
    let sig = fixtures::owner_sig_for(&k, &m, 0);
    State::new_at_init(ENCLAVE_ID, k.owner.pk, k.recovery.pk, m, sig).expect("fixture mandate valid")
}

/// `mode ‖ max_reorg ‖ …`:
/// - mode 0: a raw batch of 80-byte headers on the regtest fixture (anything goes; the invariants hold);
/// - mode 1: scripted records `[op, d, k]` on the regtest fixture against a model chain — op 0 extend by
///   k, op 1 fork at depth d with k blocks, op 2 extend by k delivered as two batches split at d;
/// - mode 2: the real signet chain (first 64 headers) with one byte mutated at an arbitrary position;
/// - mode 3: the no-wrap boundary at the call site — the fixture's work set to the 32 input bytes, then
///   one mined header: `OVERFLOW` iff the reference sum reaches 2^256, else exactly the reference sum;
/// - mode 4: the real signet chain ACROSS its retarget boundary (header 2016 of the vector = 324 576) —
///   2016 + n headers in two batches split at an arbitrary point, optional one-byte mutation in the tail.
pub fn headers(data: &[u8]) {
    let Some((&mode, rest)) = data.split_first() else { return };
    let Some((&mr, rest)) = rest.split_first() else { return };
    let max_reorg = 1 + u32::from(mr % 8);
    match mode % 5 {
        0 => {
            let (mut s, _cp) = gen::regtest_state(max_reorg);
            let hs: Vec<Header> = rest
                .chunks_exact(80)
                .take(64)
                .filter_map(|c| bitcoin::consensus::deserialize::<Header>(c).ok())
                .collect();
            let raw: Vec<[u8; 80]> = rest.chunks_exact(80).take(64).map(|c| c.try_into().unwrap()).collect();
            let before = s.clone();
            let r = apply_headers(&mut s, &raw);
            if hs.len() == raw.len() {
                chain_invariants(&before, &s, &r);
            } else {
                assert!(r.is_err() && s == before, "F6: an undecodable header was accepted or changed the state");
            }
            let before2 = s.clone();
            let r2 = apply_headers(&mut s, &raw);
            chain_invariants(&before2, &s, &r2);
        }
        1 => scripted_regtest(max_reorg, rest),
        2 => {
            // header 0 of the vector is the fixture's checkpoint; the chain to feed starts after it
            let hs = &signet_headers()[1..65];
            let n = 1 + usize::from(rest.first().copied().unwrap_or(31)) % hs.len();
            let mut raw: Vec<[u8; 80]> = hs[..n].to_vec();
            let mutated = rest.len() >= 4;
            if mutated {
                let pos = (usize::from(rest[1]) << 8 | usize::from(rest[2])) % (n * 80);
                raw[pos / 80][pos % 80] ^= rest[3].max(1);
            }
            let mut s = signet_state();
            let before = s.clone();
            let r = apply_headers(&mut s, &raw);
            chain_invariants(&before, &s, &r);
            if let Ok(k) = r {
                assert!(k as usize <= n, "F6: more growth than headers fed");
            }
            if !mutated {
                assert_eq!(r.as_ref().ok(), Some(&(n as u32)), "F6: the real signet chain was refused: {r:?}");
                assert_eq!(s.chain.best.unwrap().height as usize, 322_560 + n);
            }
        }
        4 => {
            let hs = &signet_headers()[1..]; // after the checkpoint header
            let n = 2016 + 1 + usize::from(rest.first().copied().unwrap_or(31)) % 64;
            let mut raw: Vec<[u8; 80]> = hs[..n.min(hs.len())].to_vec();
            if rest.len() >= 4 && rest[3] != 0 {
                let pos = (usize::from(rest[1]) << 8 | usize::from(rest[2])) % (64 * 80);
                let idx = raw.len() - 64 + pos / 80; // the mutation lands in the last 64 headers
                raw[idx][pos % 80] ^= rest[3];
            }
            let split = (usize::from(rest.get(4).copied().unwrap_or(0)) * 9) % raw.len();
            let mut s = signet_state();
            let before = s.clone();
            let r1 = apply_headers(&mut s, &raw[..split]);
            chain_invariants(&before, &s, &r1);
            let mid = s.clone();
            let r2 = apply_headers(&mut s, &raw[split..]);
            chain_invariants(&mid, &s, &r2);
            if rest.len() < 4 || rest[3] == 0 {
                // the untouched real chain is accepted whole, across the boundary
                assert_eq!(
                    (r1.as_ref().ok(), r2.as_ref().ok()),
                    (Some(&(split as u32)), Some(&((raw.len() - split) as u32))),
                    "F6: the real signet chain was refused: {r1:?} / {r2:?}"
                );
                assert_eq!(s.chain.best.unwrap().height as usize, 322_560 + raw.len());
            }
        }
        _ => {
            if rest.len() < 32 {
                return;
            }
            let (mut s, cp) = gen::regtest_state(max_reorg);
            let mut w = [0u8; 32];
            w.copy_from_slice(&rest[..32]);
            if let Some(b) = s.chain.best.as_mut() {
                b.work = w;
            }
            for r in s.chain.recent.iter_mut() {
                r.work = w;
            }
            let before = s.clone();
            let h = gen::mine(&cp, cp.time + 10, 7);
            let (sum, overflow) = gen::add256_ref(&w, &gen::work_of_bits(gen::REGTEST_BITS));
            let r = apply(&mut s, &[h]);
            if overflow {
                assert!(
                    matches!(&r, Err(e) if code(e) == Reason::Overflow.code()) && s == before,
                    "C-R10-6: the work accumulator reached 2^256 and did not refuse OVERFLOW (got {r:?})"
                );
            } else {
                assert_eq!(r.as_ref().ok(), Some(&1), "F6: a valid extension on a sane state was refused: {r:?}");
                assert_eq!(s.chain.best.unwrap().work, sum, "C-R10-6: accumulated work is not the reference sum");
            }
        }
    }
}

fn scripted_regtest(max_reorg: u32, script: &[u8]) {
    let (mut s, cp) = gen::regtest_state(max_reorg);
    let mut chain: Vec<Header> = vec![cp]; // the model main chain; index i = height CP_HEIGHT + i
    let mut frozen = false;
    let mut salt: u32 = 1;
    let keep = (max_reorg + RECENT_EXTRA) as usize;
    let height_of = |i: usize| gen::CP_HEIGHT + i as u32;
    for rec in script.chunks_exact(3).take(12) {
        let (op, d, k) = (rec[0] % 3, usize::from(rec[1]), usize::from(rec[2] % 16));
        let before = s.clone();
        // mine the batch against the model
        let (batch, expect): (Vec<Header>, Result<u32, Reason>) = match op {
            0 | 2 => {
                let mut v = Vec::new();
                let mut prev = *chain.last().unwrap();
                for _ in 0..k {
                    prev = gen::mine(&prev, prev.time + 10, salt);
                    salt += 1;
                    v.push(prev);
                }
                (v, if frozen && k > 0 { Err(Reason::ChainReorg) } else { Ok(k as u32) })
            }
            _ => {
                let recent_len = chain.len().min(keep); // the enclave keeps a suffix of the model chain
                let d = d % (chain.len().max(1));
                let attach = chain[chain.len() - 1 - d];
                let mut v = Vec::new();
                let mut prev = attach;
                for _ in 0..k {
                    prev = gen::mine(&prev, prev.time + 10, salt);
                    salt += 1;
                    v.push(prev);
                }
                let exp = if k == 0 {
                    Ok(0)
                } else if frozen {
                    Err(Reason::ChainReorg)
                } else if d >= recent_len {
                    Err(Reason::HeaderInvalid) // attach point fell out of `recent`
                } else if d as u32 > max_reorg {
                    Err(Reason::ChainReorg)
                } else if k > d {
                    Ok(k as u32)
                } else {
                    Ok(0)
                };
                (v, exp)
            }
        };
        if batch.is_empty() {
            continue;
        }
        let result = if op == 2 && k > 1 {
            let split = d % k;
            let r1 = apply(&mut s, &batch[..split]);
            if split > 0 && r1.is_err() {
                r1
            } else {
                let mid = s.clone();
                let r2 = apply(&mut s, &batch[split..]);
                chain_invariants(&mid, &s, &r2);
                r2.map(|n| n + r1.unwrap_or(0))
            }
        } else {
            apply(&mut s, &batch)
        };
        if !(op == 2 && k > 1) {
            chain_invariants(&before, &s, &result);
        }
        match (&expect, &result) {
            (Ok(n), Ok(m)) => assert_eq!(n, m, "F6: growth {m} returned, model says {n} (op {op}, d {d}, k {k})"),
            (Err(e), Err(r)) => assert_eq!(
                code(r),
                e.code(),
                "F6: refusal {} returned, model says {} (op {op}, d {d}, k {k})",
                code(r),
                e.code()
            ),
            (e, r) => panic!("F6: model {e:?} vs enclave {r:?} (op {op}, d {d}, k {k}, frozen {frozen})"),
        }
        // advance the model
        match (op, &expect) {
            (_, Err(Reason::ChainReorg)) => frozen = true,
            (0 | 2, Ok(n)) if *n > 0 => chain.extend_from_slice(&batch),
            (1, Ok(n)) if *n > 0 => {
                let d = usize::from(rec[1]) % chain.len();
                chain.truncate(chain.len() - d);
                chain.extend_from_slice(&batch);
            }
            _ => {}
        }
        let best = s.chain.best.unwrap();
        assert_eq!(best.height, height_of(chain.len() - 1), "F6: best height differs from the model");
        assert_eq!(best.hash, gen::hash32(chain.last().unwrap()), "F6: best hash differs from the model");
        assert_eq!(s.chain.frozen, frozen, "F6: frozen flag differs from the model");
    }
}

// ------------------------------------------------------------------------------------------------
// state_ops — F4
// ------------------------------------------------------------------------------------------------

const HONEST_CHALLENGE: [u8; 32] = [0x11; 32];
const WRONG_CHALLENGE: [u8; 32] = [0x22; 32];

struct Keyring {
    owner: P256Key,
    recovery: P256Key,
    witness: P256Key,
    ak: P256Key,
}

impl Keyring {
    fn by_pk(&self, pk: &[u8; 65]) -> Option<&P256Key> {
        [&self.owner, &self.recovery, &self.witness, &self.ak].into_iter().find(|k| &k.pk == pk)
    }
    /// A key that is neither the current owner nor the recovery key.
    fn stranger(&self, owner_pk: &[u8; 65]) -> &P256Key {
        if &self.witness.pk != owner_pk {
            &self.witness
        } else {
            &self.ak
        }
    }
}

/// Leg 2 of F-01 as the REQ's table states it (written independently of `state.rs`).
fn pinned(s: &State, c: &Checkpoint) -> bool {
    let Some(best) = s.chain.best else { return false };
    if c.height > best.height {
        return false;
    }
    let Some(r) = s.chain.recent.iter().find(|r| r.hash == c.hash && r.height == c.height) else { return false };
    let period_start = best.height - best.height % INTERVAL;
    c.time == r.time
        && c.bits == r.bits
        && r.height >= period_start
        && c.period_start_time == s.chain.period_start_time
        && c.period_bits == s.chain.period_bits
}

fn checkpoint_only(new: &Mandate, installed: &Mandate) -> bool {
    let mut rest = new.clone();
    rest.checkpoint = installed.checkpoint;
    rest == *installed
}

fn pinned_checkpoint(s: &State, height: u32) -> Option<Checkpoint> {
    let r = s.chain.recent.iter().find(|r| r.height == height)?;
    Some(Checkpoint {
        hash: r.hash,
        height: r.height,
        time: r.time,
        bits: r.bits,
        period_start_time: s.chain.period_start_time,
        period_bits: s.chain.period_bits,
    })
}

/// What the install path must do with `new` (the REQ-r10-F01 / REQ-r10-O01 rules), given a state whose
/// pending (if due) has already activated.
enum Outcome {
    Now,
    Pending(u32),
    Repin,
    Refuse(Reason),
}

fn expected_update(s: &State, new: &Mandate) -> Outcome {
    if s.pending.is_some() {
        return Outcome::Refuse(Reason::PolicyPending);
    }
    if new.validate().is_err() {
        return Outcome::Refuse(Reason::PolicyInvalid);
    }
    if new.network != s.network {
        return Outcome::Refuse(Reason::PolicyNetwork);
    }
    if new.wallet != s.wallet {
        return Outcome::Refuse(Reason::PolicyWallet);
    }
    let installed = &s.mandate;
    if s.chain.frozen && new.checkpoint == installed.checkpoint {
        return Outcome::Refuse(Reason::ChainReorg); // REQ-r10-O01
    }
    if new.checkpoint != installed.checkpoint {
        if s.chain.frozen {
            return if checkpoint_only(new, installed) {
                Outcome::Repin
            } else {
                Outcome::Refuse(Reason::PolicyInvalid)
            };
        }
        if !pinned(s, &new.checkpoint) {
            return Outcome::Refuse(Reason::PolicyInvalid);
        }
    }
    match compare(installed, new) {
        Ok(Change::Tightening) => Outcome::Now,
        Ok(Change::Loosening) => {
            // the activation height is checked arithmetic in the enclave: a timelock that does not fit the
            // chain's height space is refused OVERFLOW rather than wrapped (the owner chose that timelock)
            let best = s.chain.best.map(|b| b.height).unwrap_or(0);
            match best.checked_add(installed.timelock_blocks) {
                Some(act) => Outcome::Pending(act),
                None => Outcome::Refuse(Reason::Overflow),
            }
        }
        Err(_) => unreachable!("network and wallet were checked equal"),
    }
}

/// What the accepted operation itself does to what is in flight (the activation of a DUE pending happens
/// first, on every operation): `Clears` voids both pendings (Cancel, Recover); `Installs` puts a new mandate in
/// place (a tightening or a re-pin — only possible once no pending is left, so after a due one activated);
/// `Queues` leaves a new pending mandate; `QueuesOwner` leaves a new pending owner; `Plain` touches neither.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Effect {
    Plain,
    Clears,
    Installs,
    Queues,
    QueuesOwner,
}

/// The invariants every accepted operation leaves behind. `before` is the state as it was (nothing
/// activated). The timelock model is the harness's own: a pending is due iff `best >= activation_height`,
/// and nothing else may install it early or hold it back.
fn state_invariants(before: &State, after: &State, nonce_consumed: bool, effect: Effect) {
    assert!(after.mandate.validate().is_ok(), "F4: the installed mandate is invalid");
    let best = before.chain.best.map(|b| b.height).unwrap_or(0);
    if let Some(p) = &before.pending {
        if best >= p.activation_height {
            match effect {
                Effect::Queues => assert!(
                    after.pending.as_ref().is_some_and(|q| q != p),
                    "F4: a due pending mandate did not activate before the new loosening was queued"
                ),
                _ => assert!(
                    after.pending.is_none(),
                    "F4: a due pending mandate did not activate on an accepted operation"
                ),
            }
            if matches!(effect, Effect::Plain | Effect::QueuesOwner) {
                assert_eq!(
                    after.mandate, p.mandate,
                    "F4: a due pending mandate activated but is not the installed one"
                );
            }
        } else {
            // not due: a PolicyUpdate cannot be accepted with it in flight (POLICY_PENDING)
            assert!(
                !matches!(effect, Effect::Installs | Effect::Queues),
                "F4: a policy update was accepted while a pending mandate was in flight"
            );
            if effect != Effect::Clears {
                assert_eq!(
                    after.pending.as_ref(),
                    Some(p),
                    "F4: a pending mandate changed before its activation height"
                );
                assert_eq!(
                    after.mandate, before.mandate,
                    "F4: the installed mandate changed while a loosening was pending and not yet due"
                );
            }
        }
    }
    if let Some(p) = &before.pending_owner {
        if best >= p.activation_height {
            match effect {
                Effect::QueuesOwner => assert!(
                    after.pending_owner.as_ref().is_some_and(|q| q != p),
                    "F4: a due pending owner did not activate before the new rotation was queued"
                ),
                _ => assert!(
                    after.pending_owner.is_none(),
                    "F4: a due pending owner did not activate on an accepted operation"
                ),
            }
            if effect != Effect::Clears {
                assert_eq!(after.owner_pk, p.new_owner_pk, "F4: a due pending owner activated but is not the owner");
            }
        } else {
            assert!(effect != Effect::QueuesOwner, "F4: a rotation was accepted while one was in flight");
            if effect != Effect::Clears {
                assert_eq!(
                    after.pending_owner.as_ref(),
                    Some(p),
                    "F4: a pending owner changed before its activation height"
                );
                assert_eq!(
                    after.owner_pk, before.owner_pk,
                    "F4: the owner changed while a rotation was pending and not yet due"
                );
            }
        }
    }
    let bytes = after.encode();
    assert_eq!(State::decode(&bytes).as_ref(), Ok(after), "C-R10-2: the live state does not round-trip");
    assert_eq!(
        after.nonce,
        before.nonce + u64::from(nonce_consumed),
        "F4: nonce moved by other than exactly one per accepted owner message"
    );
    if let (Some(b), Some(p)) = (after.chain.best, &after.pending) {
        assert!(
            b.height < p.activation_height,
            "F4: a pending update stayed pending past its activation height after an accepted operation"
        );
    }
    if let (Some(b), Some(p)) = (after.chain.best, &after.pending_owner) {
        assert!(
            b.height < p.activation_height,
            "F4: a pending owner stayed pending past its activation height after an accepted operation"
        );
    }
}

fn check_err(result: &Result<State, Refusal>, want: Reason, what: &str) {
    match result {
        Err(r) => assert_eq!(code(r), want.code(), "F4: {what}: refused {} , expected {}", code(r), want.code()),
        Ok(_) => panic!("F4: {what}: accepted, expected refusal {}", want.code()),
    }
}

/// Scripted 8-byte records `[kind, flags, a, b, c, d, e, f]` over the honest fixture state (the vector
/// suite's keys and mandate; the chain driven through the fixture helpers — the header path is F6).
/// kinds: 0 PolicyUpdate (a structured mutation of the installed mandate; flags: 1 wrong key, 2 wrong
/// nonce, 4 identical, 8 re-pin to recent header `best - a % 11` (a = 0xff: one above best), 16 frozen-style
/// checkpoint-only re-pin, 32 a deterministic loosening, 64 another network, 128 another wallet),
/// 1 Cancel (flags 1: recovery key, 2 wrong key, 4 wrong nonce, 8 another enclave's id), 2 Unfreeze, 3 Rearm (seq = a‖b),
/// 4 RotateOwner (a % 4: witness / AK / garbage / the recovery key), 5 Recover (same targets),
/// 6 Arm (flags 1 wrong challenge, 2 wrong key, 4 wrong nonce, 32 a Cancel handed to apply_arm; seq_seen = e),
/// 7 Anchor (counter a, live counter b, seq_seen = e; flags 8 a foreign AK — the witness key, 16 a non-point AK,
/// 32 a Cancel handed to apply_anchor), 8 WitnessToken / Arm / Anchor through apply_message (a % 3; always
/// refused), 9 advance the chain by 1 + 8·a blocks,
/// 10 freeze the chain (a deep reorg happened), 11 the owner's freeze.
pub fn state_ops(data: &[u8]) {
    let h = honest();
    let fx = fixtures::keys();
    let ring = Keyring {
        owner: P256Key { sk: fx.owner.sk.clone(), pk: fx.owner.pk },
        recovery: P256Key { sk: fx.recovery.sk.clone(), pk: fx.recovery.pk },
        witness: P256Key { sk: fx.witness.sk.clone(), pk: fx.witness.pk },
        ak: P256Key { sk: h.ak.sk.clone(), pk: h.ak.pk },
    };
    let mut s = h.state.clone();
    for rec in data.chunks_exact(8).take(24) {
        let (kind, flags, a, b) = (rec[0] % 12, rec[1], rec[2], rec[3]);
        let wrong_key = flags & 2 != 0;
        let wrong_nonce = flags & 4 != 0;
        let eid = ENCLAVE_ID;
        let best = s.chain.best.map(|r| r.height).unwrap_or(0);
        // the state as the operation will see it: a due pending (mandate or owner) activates first
        let mut proj = s.clone();
        proj.activate_pending();
        let owner_key = ring.by_pk(&proj.owner_pk).expect("the owner key is always one we hold");
        let nonce = proj.nonce + 1 + u64::from(wrong_nonce);
        let before = s.clone();
        match kind {
            0 => {
                let mut new = if flags & 4 != 0 {
                    proj.mandate.clone()
                } else {
                    let mut u = Unstructured::new(&rec[2..]);
                    mutate_mandate(&proj.mandate, &mut u).unwrap_or_else(|| proj.mandate.clone())
                };
                if flags & 8 != 0 {
                    if let Some(mut cp) = pinned_checkpoint(&proj, best.saturating_sub(u32::from(a % 11))) {
                        if a == 0xff {
                            cp.height = best + 1; // one above the verified chain: not pinnable
                        }
                        new = proj.mandate.clone();
                        new.checkpoint = cp;
                    }
                }
                if flags & 64 != 0 {
                    new.network = if new.network == Network::Regtest { Network::Testnet4 } else { Network::Regtest };
                }
                if flags & 128 != 0 {
                    new.wallet.fingerprint[0] ^= 0xff;
                }
                if flags & 16 != 0 {
                    new = proj.mandate.clone();
                    new.checkpoint.hash = [a; 32];
                    new.checkpoint.time = new.checkpoint.time.wrapping_add(600);
                }
                if flags & 32 != 0 {
                    new = proj.mandate.clone();
                    new.destinations.unlisted.max_per_tx =
                        new.destinations.unlisted.max_per_tx.saturating_mul(2).max(1);
                    // a loosening
                }
                let signer = if flags & 1 != 0 { ring.stranger(&proj.owner_pk) } else { owner_key };
                let mut m = Message::PolicyUpdate { enclave_id: eid, nonce, mandate: new.encode(), sig: [0; 64] };
                signer.sign(&mut m);
                let r = s.apply_message(&m);
                if flags & 1 != 0 {
                    check_err(&r, Reason::PolicySig, "update signed by a stranger");
                } else if wrong_nonce {
                    check_err(&r, Reason::PolicyNonce, "update with the wrong nonce");
                } else {
                    match expected_update(&proj, &new) {
                        Outcome::Refuse(want) => check_err(&r, want, "update the rules refuse"),
                        Outcome::Now => {
                            let after = r.expect("F4: a tightening (or identical) update by the owner was refused");
                            assert!(
                                after.pending.is_none() && after.mandate == new,
                                "F4: a tightening did not apply at once"
                            );
                            assert_eq!(
                                after.chain.best, proj.chain.best,
                                "F4: a non-re-pin update moved the chain view"
                            );
                            state_invariants(&before, &after, true, Effect::Installs);
                            s = after;
                        }
                        Outcome::Pending(act) => {
                            let after = r.expect("F4: a loosening update by the owner was refused");
                            let p = after.pending.as_ref().expect("F4: a loosening did not become pending");
                            assert_eq!(
                                p.activation_height, act,
                                "F4: pending activation height is not best + timelock"
                            );
                            assert_eq!(p.mandate, new);
                            assert_eq!(
                                after.mandate, proj.mandate,
                                "F4: a loosening changed the installed mandate before its timelock"
                            );
                            state_invariants(&before, &after, true, Effect::Queues);
                            s = after;
                        }
                        Outcome::Repin => {
                            let after = r.expect("F4: a checkpoint-only re-pin while frozen was refused (C-F01-1)");
                            assert!(!after.chain.frozen, "C-F01-1: the re-pin did not clear the freeze");
                            assert_eq!(
                                after.chain.best.unwrap().hash,
                                new.checkpoint.hash,
                                "C-F01-1: the chain did not restart from the re-pin"
                            );
                            assert!(
                                after.pending.is_none() && after.mandate == new,
                                "C-F01-1: the re-pin did not install at once"
                            );
                            state_invariants(&before, &after, true, Effect::Installs);
                            s = after;
                        }
                    }
                }
            }
            1 => {
                let signer = if wrong_key {
                    ring.stranger(&proj.owner_pk)
                } else if flags & 1 != 0 {
                    &ring.recovery
                } else {
                    owner_key
                };
                let cancel_eid = if flags & 8 != 0 { [0x5c; 32] } else { eid };
                let mut m = Message::Cancel { enclave_id: cancel_eid, nonce, sig: [0; 64] };
                signer.sign(&mut m);
                let r = s.apply_message(&m);
                if flags & 8 != 0 {
                    check_err(&r, Reason::PolicySig, "cancel addressed to another enclave");
                } else if wrong_key {
                    check_err(&r, Reason::PolicySig, "cancel by a stranger");
                } else if wrong_nonce {
                    check_err(&r, Reason::PolicyNonce, "cancel with the wrong nonce");
                } else {
                    let after = r.expect("F4: an honest cancel was refused");
                    assert!(
                        after.pending.is_none() && after.pending_owner.is_none(),
                        "F4: cancel left something pending"
                    );
                    state_invariants(&before, &after, true, Effect::Clears);
                    s = after;
                }
            }
            2 | 3 => {
                let signer = if wrong_key { ring.stranger(&proj.owner_pk) } else { owner_key };
                let seq = u64::from(u16::from_le_bytes([a, b]));
                let mut m = if kind == 2 {
                    Message::Unfreeze { enclave_id: eid, nonce, sig: [0; 64] }
                } else {
                    Message::Rearm { enclave_id: eid, nonce, seq, sig: [0; 64] }
                };
                signer.sign(&mut m);
                let r = s.apply_message(&m);
                if wrong_key {
                    check_err(&r, Reason::PolicySig, "owner message by a stranger");
                } else if wrong_nonce {
                    check_err(&r, Reason::PolicyNonce, "owner message with the wrong nonce");
                } else {
                    let after = r.expect("F4: an honest unfreeze/rearm was refused");
                    if kind == 2 {
                        assert!(!after.frozen, "F4: unfreeze left the signer frozen");
                    } else {
                        assert!(
                            after.armed && after.seq == proj.seq.max(seq),
                            "F4: rearm did not arm or moved seq wrongly"
                        );
                    }
                    state_invariants(&before, &after, true, Effect::Plain);
                    s = after;
                }
            }
            4 | 5 => {
                let target: [u8; 65] = match a % 4 {
                    0 => ring.witness.pk,
                    1 => ring.ak.pk,
                    2 => [b; 65],
                    _ => ring.recovery.pk,
                };
                let honest_signer = if kind == 4 { owner_key } else { &ring.recovery };
                let signer = if wrong_key {
                    if kind == 4 {
                        ring.stranger(&proj.owner_pk)
                    } else {
                        owner_key
                    }
                } else {
                    honest_signer
                };
                let mut m = if kind == 4 {
                    Message::RotateOwner { enclave_id: eid, nonce, new_owner_pk: target, sig: [0; 64] }
                } else {
                    Message::Recover { enclave_id: eid, nonce, new_owner_pk: target, sig: [0; 64] }
                };
                signer.sign(&mut m);
                let r = s.apply_message(&m);
                let bad_target = a % 4 >= 2; // a non-point, or the recovery key itself
                if wrong_key {
                    check_err(&r, Reason::PolicySig, "rotate/recover by the wrong key");
                } else if wrong_nonce {
                    check_err(&r, Reason::PolicyNonce, "rotate/recover with the wrong nonce");
                } else if kind == 4 && proj.pending_owner.is_some() {
                    check_err(&r, Reason::PolicyPending, "rotate while a rotation is pending");
                } else if bad_target {
                    check_err(&r, Reason::PolicyInvalid, "rotate/recover to a non-key or the recovery key");
                } else if kind == 4 && best.checked_add(proj.mandate.timelock_blocks).is_none() {
                    check_err(&r, Reason::Overflow, "rotate whose activation height does not fit u32");
                } else {
                    let after = r.expect("F4: an honest rotate/recover was refused");
                    if kind == 4 {
                        let p = after.pending_owner.as_ref().expect("F4: rotate did not queue a pending owner");
                        assert_eq!(
                            (p.new_owner_pk, p.activation_height),
                            (target, best + proj.mandate.timelock_blocks)
                        );
                        assert_eq!(after.owner_pk, proj.owner_pk, "F4: rotate changed the owner before its timelock");
                    } else {
                        assert_eq!(after.owner_pk, target, "F4: recover did not install the new owner");
                        assert!(
                            after.pending.is_none() && after.pending_owner.is_none(),
                            "F4: recover left something in flight"
                        );
                    }
                    state_invariants(
                        &before,
                        &after,
                        true,
                        if kind == 5 { Effect::Clears } else { Effect::QueuesOwner },
                    );
                    s = after;
                }
            }
            6 | 7 => {
                let challenge = if flags & 1 != 0 { WRONG_CHALLENGE } else { HONEST_CHALLENGE };
                let signer = if wrong_key { ring.stranger(&proj.owner_pk) } else { owner_key };
                let seq_seen = u64::from(rec[4]);
                let (counter, live) = (u64::from(a), u64::from(b));
                let ak_pk: [u8; 65] = if flags & 16 != 0 {
                    [b; 65]
                } else if flags & 8 != 0 {
                    ring.witness.pk
                } else {
                    h.ak.pk
                };
                let mut m = if flags & 32 != 0 {
                    Message::Cancel { enclave_id: eid, nonce, sig: [0; 64] } // the wrong message type for apply_arm/apply_anchor
                } else if kind == 6 {
                    Message::Arm { enclave_id: eid, nonce, boot_challenge: challenge, seq_seen, sig: [0; 64] }
                } else {
                    Message::Anchor {
                        enclave_id: eid,
                        nonce,
                        boot_challenge: challenge,
                        ak_pk,
                        nv_name: h.anchor.nv_name,
                        counter,
                        seq_seen,
                        sig: [0; 64],
                    }
                };
                signer.sign(&mut m);
                let r = if kind == 6 {
                    s.apply_arm(&m, &HONEST_CHALLENGE)
                } else {
                    s.apply_anchor(&m, &HONEST_CHALLENGE, live)
                };
                let ak_ok = signer_core::update::parse_p256_pubkey(&ak_pk).is_some();
                if flags & 32 != 0 {
                    check_err(&r, Reason::PolicyInvalid, "a non-Arm/Anchor message handed to apply_arm/apply_anchor");
                } else if wrong_key {
                    check_err(&r, Reason::PolicySig, "arm/anchor by a stranger");
                } else if wrong_nonce {
                    check_err(&r, Reason::PolicyNonce, "arm/anchor with the wrong nonce");
                } else if flags & 1 != 0 {
                    check_err(&r, Reason::ArmChallenge, "arm/anchor with another load's challenge");
                } else if seq_seen > proj.seq {
                    check_err(&r, Reason::ArmSeqBehind, "arm/anchor claiming a seq the enclave never reached");
                } else if kind == 7 && proj.tpm.as_ref().is_some_and(|t| t.ak_pk != ak_pk) {
                    check_err(&r, Reason::AnchorTpmMismatch, "anchor naming another AK than the bound one");
                } else if kind == 7 && live < counter {
                    check_err(&r, Reason::AnchorCounterBehind, "anchor whose certified counter is behind the live one");
                } else if kind == 7 && !ak_ok {
                    check_err(&r, Reason::PolicyInvalid, "anchor whose AK is not a point");
                } else {
                    let after = r.expect("F4: an honest arm/anchor was refused");
                    assert_eq!(after.frozen, proj.frozen, "C-R7-6: arm/anchor changed the owner's freeze");
                    assert_eq!(
                        after.armed, proj.armed,
                        "F4: the sealed armed flag changed on arm/anchor (it is the shell's volatile fact)"
                    );
                    if kind == 7 {
                        assert_eq!(
                            after.tpm,
                            Some(TpmAnchor { ak_pk, nv_name: h.anchor.nv_name, expected: live }),
                            "R9: the anchor did not pin the live counter under the named AK"
                        );
                    }
                    state_invariants(&before, &after, true, Effect::Plain);
                    s = after;
                }
            }
            8 => {
                // the three messages apply_message never accepts, whoever signs them
                let mut m = match a % 3 {
                    0 => Message::WitnessToken {
                        enclave_id: eid,
                        tip_hash: s.chain.best.map(|r| r.hash).unwrap_or([0; 32]),
                        tip_height: best,
                        last_seen_seq: u64::from(b),
                        issued: u64::from(b) * 600,
                        sig: [0; 64],
                    },
                    1 => Message::Arm {
                        enclave_id: eid,
                        nonce,
                        boot_challenge: HONEST_CHALLENGE,
                        seq_seen: 0,
                        sig: [0; 64],
                    },
                    _ => Message::Anchor {
                        enclave_id: eid,
                        nonce,
                        boot_challenge: HONEST_CHALLENGE,
                        ak_pk: h.ak.pk,
                        nv_name: h.anchor.nv_name,
                        counter: u64::from(b),
                        seq_seen: 0,
                        sig: [0; 64],
                    },
                };
                if a % 3 == 0 {
                    ring.witness.sign(&mut m)
                } else {
                    owner_key.sign(&mut m)
                }
                check_err(
                    &s.apply_message(&m),
                    Reason::PolicyInvalid,
                    "a witness token / arm / anchor through apply_message",
                );
                assert_eq!(s, before, "F4: a refused message changed the state");
            }
            9 => {
                let fz = s.chain.frozen;
                fixtures::set_best(&mut s, best + 1 + 8 * u32::from(a));
                s.chain.frozen = fz;
            }
            10 => s.chain.frozen = true,
            _ => s.frozen = true,
        }
        assert!(s.mandate.validate().is_ok(), "F4: the installed mandate is invalid after step {kind}");
    }
}
