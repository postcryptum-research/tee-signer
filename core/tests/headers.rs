//! The header verifier, both directions: real signet headers across a retarget (accept), tampered
//! and mislinked headers (refuse), synthetic regtest chains for forks, most-work choice, the
//! median-time rule and the deep-reorg freeze.

mod common;

use bitcoin::block::Header;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::pow::{CompactTarget, Target};
use common::*;
use signer_core::headers::{apply_headers, INTERVAL};
use signer_core::mandate::{Checkpoint, Mandate, Network};
use signer_core::reason::Reason;
use signer_core::state::State;

fn load_signet() -> Vec<[u8; 80]> {
    let text =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors/headers/signet-322560-324700.hex"))
            .unwrap();
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let v = hex::decode(l.trim()).unwrap();
            let mut a = [0u8; 80];
            a.copy_from_slice(&v);
            a
        })
        .collect()
}

fn header(raw: &[u8; 80]) -> Header {
    deserialize::<Header>(raw).unwrap()
}

/// A mandate whose checkpoint is the given header at `height` (must be a period boundary here).
fn signet_mandate(w: &Wallet, cold: &Wallet, raw: &[u8; 80], height: u32) -> Mandate {
    let h = header(raw);
    let mut m = base_mandate(w, cold);
    m.limits.max_reorg = 6;
    m.checkpoint = Checkpoint {
        hash: h.block_hash().to_byte_array(),
        height,
        time: h.time,
        bits: h.bits.to_consensus(),
        period_start_time: h.time,
        period_bits: h.bits.to_consensus(),
    };
    m.not_after_height = 400_000;
    m
}

fn signet_state() -> (State, Vec<[u8; 80]>) {
    let (w, cold, k) = (wallet(0x01), wallet(0x02), keys());
    let hs = load_signet();
    let m = signet_mandate(&w, &cold, &hs[0], 322_560);
    let sig = owner_sig_for(&k, &m, 0);
    let s = State::new_at_init(ENCLAVE_ID, k.owner.pk, k.recovery.pk, m, sig).unwrap();
    (s, hs)
}

#[test]
fn signet_real_chain_accepts_across_retarget() {
    let (mut s, hs) = signet_state();
    assert_eq!(s.chain.best.unwrap().height, 322_560);
    // feed in batches of 100 (the daemon's shape)
    let mut height = 322_560u32;
    for chunk in hs[1..].chunks(100) {
        let n = apply_headers(&mut s, chunk).unwrap();
        assert_eq!(n as usize, chunk.len());
        height = height.checked_add(u32::try_from(chunk.len()).expect("chunk")).expect("height");
        assert_eq!(s.chain.best.unwrap().height, height);
    }
    assert_eq!(s.chain.best.unwrap().height, 324_700);
    // the retarget at 324_576 happened: the period data moved and the bits changed or stayed per the real chain
    assert_eq!(s.chain.period_start_time, header(&hs[(324_576 - 322_560) as usize]).time);
    assert_eq!(s.chain.period_bits, header(&hs[(324_576 - 322_560) as usize]).bits.to_consensus());
    // the retarget math, checked independently of acceptance: the boundary header's bits equal
    // the crate's own computation from the last header of the period and the period's first time
    let last = header(&hs[(324_575 - 322_560) as usize]);
    let first = header(&hs[0]);
    let expected = CompactTarget::from_next_work_required(
        last.bits,
        u64::from(last.time - first.time),
        bitcoin::params::Params::SIGNET,
    );
    assert_eq!(header(&hs[(324_576 - 322_560) as usize]).bits, expected);
    // recent is bounded by maxReorg + 12 and ends at best
    assert!(s.chain.recent.len() <= 6 + 12);
    assert_eq!(s.chain.recent.last().unwrap().hash, s.chain.best.unwrap().hash);
    // the state round-trips through the sealed encoding with the chain view
    assert_eq!(State::decode(&s.encode()).unwrap(), s);
    // an empty batch is a no-op; replaying the last batch is a fork with equal work → not adopted
    assert_eq!(apply_headers(&mut s, &[]).unwrap(), 0);
    let last = *hs.last().unwrap();
    assert_eq!(
        apply_headers(&mut s, &[last]).unwrap(),
        0,
        "the tip again: a fork of equal work from the tip's parent ⇒ not adopted"
    );
    assert_eq!(s.chain.best.unwrap().height, 324_700);
}

#[test]
fn signet_tampered_headers_refuse() {
    let (base, hs) = signet_state();
    // nonce changed: PoW fails
    let mut bad = hs[1];
    bad[76] ^= 0x01;
    let mut s = base.clone();
    assert_eq!(apply_headers(&mut s, &[bad]).unwrap_err().0, vec![Reason::HeaderInvalid]);
    assert_eq!(s.chain.best.unwrap().height, 322_560, "nothing adopted");
    // bits changed to an easier target with PoW re-satisfied trivially? the required-bits check fires first
    let mut h = header(&hs[1]);
    h.bits = CompactTarget::from_consensus(0x207f_ffff);
    let raw: [u8; 80] = serialize(&h).try_into().unwrap();
    let mut s = base.clone();
    assert_eq!(apply_headers(&mut s, &[raw]).unwrap_err().0, vec![Reason::HeaderInvalid]);
    // mislinked: header 3 right after the checkpoint
    let mut s = base.clone();
    assert_eq!(apply_headers(&mut s, &[hs[3]]).unwrap_err().0, vec![Reason::HeaderInvalid]);
    // a valid prefix followed by a bad header: the whole batch refuses, nothing adopted
    let mut s = base.clone();
    let mut batch = hs[1..5].to_vec();
    batch[3][76] ^= 0x01;
    assert_eq!(apply_headers(&mut s, &batch).unwrap_err().0, vec![Reason::HeaderInvalid]);
    assert_eq!(s.chain.best.unwrap().height, 322_560);
    // timestamp at or below the median time past: take a real header and push its time back
    let mut s = base.clone();
    apply_headers(&mut s, &hs[1..20]).unwrap();
    let mut h = header(&hs[20]);
    h.time = 0;
    let raw: [u8; 80] = serialize(&h).try_into().unwrap();
    assert_eq!(apply_headers(&mut s, &[raw]).unwrap_err().0, vec![Reason::HeaderInvalid]);
    // a wrong retarget at the boundary: replace the boundary header's bits with the previous bits
    let mut s = base.clone();
    let boundary = (324_576 - 322_560) as usize;
    apply_headers(&mut s, &hs[1..boundary]).unwrap();
    let mut h = header(&hs[boundary]);
    let prev_bits = header(&hs[boundary - 1]).bits;
    if h.bits != prev_bits {
        h.bits = prev_bits;
        let raw: [u8; 80] = serialize(&h).try_into().unwrap();
        assert_eq!(
            apply_headers(&mut s, &[raw]).unwrap_err().0,
            vec![Reason::HeaderInvalid],
            "boundary header must carry the retargeted bits"
        );
    }
    // the real boundary header is accepted
    assert_eq!(apply_headers(&mut s, &[hs[boundary]]).unwrap(), 1);
}

// ---------------- regtest synthetic chains: forks, most-work, deep reorg freeze ----------------

fn regtest_limit() -> Target {
    bitcoin::params::Params::REGTEST.max_attainable_target
}

/// Mine a regtest header on `prev` with the given time (PoW limit 0x207fffff: a few tries).
fn mine(prev: &Header, time: u32, salt: u32) -> Header {
    let mut h = Header {
        version: bitcoin::block::Version::TWO,
        prev_blockhash: prev.block_hash(),
        merkle_root: bitcoin::TxMerkleNode::from_byte_array([salt.to_le_bytes()[0]; 32]),
        time,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        nonce: 0,
    };
    loop {
        if h.validate_pow(regtest_limit()).is_ok() {
            return h;
        }
        h.nonce = h.nonce.checked_add(1).expect("a regtest header is mined within the nonce space");
    }
}

fn raw(h: &Header) -> [u8; 80] {
    serialize(h).try_into().unwrap()
}

fn hash32(h: &Header) -> [u8; 32] {
    h.block_hash().to_byte_array()
}

fn regtest_state(max_reorg: u32) -> (State, Header) {
    let (w, cold, k) = (wallet(0x01), wallet(0x02), keys());
    let genesis_like = Header {
        version: bitcoin::block::Version::TWO,
        prev_blockhash: bitcoin::BlockHash::all_zeros(),
        merkle_root: bitcoin::TxMerkleNode::all_zeros(),
        time: 1_000_000,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        nonce: 0,
    };
    let cp = mine(&genesis_like, 1_000_000, 0); // any valid header works as a checkpoint
    let mut m = base_mandate(&w, &cold);
    m.network = Network::Regtest;
    m.limits.max_reorg = max_reorg;
    m.checkpoint = Checkpoint {
        hash: cp.block_hash().to_byte_array(),
        height: 100,
        time: cp.time,
        bits: 0x207f_ffff,
        period_start_time: cp.time,
        period_bits: 0x207f_ffff,
    };
    m.not_after_height = 10_000;
    let sig = owner_sig_for(&k, &m, 0);
    (State::new_at_init(ENCLAVE_ID, k.owner.pk, k.recovery.pk, m, sig).unwrap(), cp)
}

fn chain_from(start: &Header, n: usize, t0: u32, salt: u32) -> Vec<Header> {
    let mut v = Vec::new();
    let mut prev = *start;
    for i in 0..n {
        let k = u32::try_from(i).expect("chain length");
        let t = t0.checked_add(k.checked_add(1).and_then(|x| x.checked_mul(10)).expect("time")).expect("time");
        let h = mine(&prev, t, salt.checked_add(k).expect("salt"));
        v.push(h);
        prev = h;
    }
    v
}

#[test]
fn regtest_fork_choice_and_deep_reorg_freeze() {
    let (base, cp) = regtest_state(3);
    // main: 6 blocks
    let main = chain_from(&cp, 6, cp.time, 100);
    let mut s = base.clone();
    assert_eq!(apply_headers(&mut s, &main.iter().map(raw).collect::<Vec<_>>()).unwrap(), 6);
    assert_eq!(s.chain.best.unwrap().height, 106);
    // a fork from main[3] (height 104) with 2 blocks: tip 106, equal work → not adopted
    let fork2 = chain_from(&main[3], 2, main[3].time, 200);
    let mut s2 = s.clone();
    assert_eq!(apply_headers(&mut s2, &fork2.iter().map(raw).collect::<Vec<_>>()).unwrap(), 0);
    assert_eq!(s2.chain.best.unwrap().hash, s.chain.best.unwrap().hash);
    // a fork from main[3] with 3 blocks: more work, depth 2 ≤ maxReorg 3 → adopted
    let fork3 = chain_from(&main[3], 3, main[3].time, 300);
    let mut s3 = s.clone();
    assert_eq!(
        apply_headers(&mut s3, &fork3.iter().map(raw).collect::<Vec<_>>()).unwrap(),
        3,
        "three headers now on the main chain that were not: (107 − 106) + depth 2"
    );
    assert_eq!(s3.chain.best.unwrap().height, 107);
    assert_eq!(s3.chain.best.unwrap().hash, hash32(&fork3[2]));
    assert!(!s3.chain.frozen);
    // a fork from main[1] (height 102) with 6 blocks: depth 4 > maxReorg 3 → FREEZE, not switch
    let fork_deep = chain_from(&main[1], 6, main[1].time, 400);
    let mut s4 = s.clone();
    let e = apply_headers(&mut s4, &fork_deep.iter().map(raw).collect::<Vec<_>>()).unwrap_err();
    assert_eq!(e.0, vec![Reason::ChainReorg]);
    assert!(s4.chain.frozen, "frozen, to be sealed");
    assert_eq!(s4.chain.best.unwrap().height, 106, "best untouched");
    // frozen: further headers refuse, and the judge refuses CHAIN_REORG
    let more = chain_from(&main[5], 1, main[5].time, 500);
    assert_eq!(apply_headers(&mut s4, &[raw(&more[0])]).unwrap_err().0, vec![Reason::ChainReorg]);
    // unknown parent refuses
    let orphan = mine(&fork_deep[5], fork_deep[5].time + 10, 600);
    let mut s5 = s.clone();
    assert_eq!(apply_headers(&mut s5, &[raw(&orphan)]).unwrap_err().0, vec![Reason::HeaderInvalid]);
    // regtest has no retarget: a header with other bits refuses even if its PoW is fine
    let mut odd = mine(&main[5], main[5].time + 10, 700);
    odd.bits = CompactTarget::from_consensus(0x1d00_ffff);
    let mut s6 = s.clone();
    assert_eq!(apply_headers(&mut s6, &[raw(&odd)]).unwrap_err().0, vec![Reason::HeaderInvalid]);
    // the INTERVAL constant is the consensus one
    assert_eq!(INTERVAL, 2016);
}

#[test]
fn repin_after_freeze_through_a_mandate_update() {
    use signer_core::update::Message;
    let (base, cp) = regtest_state(2);
    let k = keys();
    let main = chain_from(&cp, 5, cp.time, 100);
    let mut s = base.clone();
    apply_headers(&mut s, &main.iter().map(raw).collect::<Vec<_>>()).unwrap();
    let deep = chain_from(&main[0], 6, main[0].time, 900);
    assert!(apply_headers(&mut s, &deep.iter().map(raw).collect::<Vec<_>>()).is_err());
    assert!(s.chain.frozen);
    // the owner re-pins to the deep fork's tip (a fresh checkpoint, allowed only while frozen);
    // the re-pin is a loosening (checkpoint moves forward → tightening on that field; but to make
    // it apply at once we also tighten nothing else, so it is a pure checkpoint move = tightening)
    let tip = deep[5];
    let mut m = s.mandate.clone();
    m.checkpoint = Checkpoint {
        hash: hash32(&tip),
        height: 101 + 6,
        time: tip.time,
        bits: 0x207f_ffff,
        period_start_time: tip.time,
        period_bits: 0x207f_ffff,
    };
    let mut msg = Message::PolicyUpdate { enclave_id: ENCLAVE_ID, nonce: 1, mandate: m.encode(), sig: [0; 64] };
    k.owner.sign(&mut msg);
    let s2 = s.apply_message(&msg).unwrap();
    assert!(!s2.chain.frozen);
    assert_eq!(s2.chain.best.unwrap().hash, hash32(&tip));
    assert_eq!(s2.chain.recent.len(), 1);
    // and the chain continues from there
    let next = mine(&tip, tip.time + 10, 1000);
    let mut s3 = s2.clone();
    assert_eq!(apply_headers(&mut s3, &[raw(&next)]).unwrap(), 1);
}
