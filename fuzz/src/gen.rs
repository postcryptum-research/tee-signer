//! Generators for the structured targets (REQ-r10 phase 2): a regtest header miner on the fixture
//! checkpoint, the regtest fixture state, and the 256-bit little-endian reference arithmetic the
//! no-wrap oracle compares `headers::add_work_le` against.

use bitcoin::block::{Header, Version};
use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash;
use bitcoin::pow::{CompactTarget, Target};
use bitcoin::{BlockHash, TxMerkleNode};
use signer_core::mandate::{Checkpoint, Network};
use signer_core::state::State;

use crate::fixtures::{self, ENCLAVE_ID};

/// Regtest proof-of-work limit as `nBits` (every header here carries it: no retargeting).
pub const REGTEST_BITS: u32 = 0x207f_ffff;
/// Height the regtest fixture checkpoint sits at.
pub const CP_HEIGHT: u32 = 100;

fn regtest_limit() -> Target {
    bitcoin::params::Params::REGTEST.max_attainable_target
}

/// Mine a regtest header on `prev` with the given time; `salt` makes the merkle root (and so the
/// hash) distinct for forks. Two tries on average at the regtest limit.
pub fn mine(prev: &Header, time: u32, salt: u32) -> Header {
    let mut root = [0u8; 32];
    root[..4].copy_from_slice(&salt.to_le_bytes());
    let mut h = Header {
        version: Version::TWO,
        prev_blockhash: prev.block_hash(),
        merkle_root: TxMerkleNode::from_byte_array(root),
        time,
        bits: CompactTarget::from_consensus(REGTEST_BITS),
        nonce: 0,
    };
    loop {
        if h.validate_pow(regtest_limit()).is_ok() {
            return h;
        }
        h.nonce = h.nonce.wrapping_add(1);
    }
}

/// The 80 consensus bytes of a header.
pub fn raw(h: &Header) -> [u8; 80] {
    serialize(h).try_into().expect("80 bytes")
}

/// The block hash as 32 bytes (the chain's internal byte order).
pub fn hash32(h: &Header) -> [u8; 32] {
    h.block_hash().to_byte_array()
}

/// The regtest fixture: a mined checkpoint at height `CP_HEIGHT`, a mandate on the regtest network
/// with `max_reorg`, and the state at init (the chain view = the checkpoint alone).
pub fn regtest_state(max_reorg: u32) -> (State, Header) {
    let (w, cold, k) = (fixtures::wallet(0x01), fixtures::wallet(0x02), fixtures::keys());
    let genesis_like = Header {
        version: Version::TWO,
        prev_blockhash: BlockHash::all_zeros(),
        merkle_root: TxMerkleNode::all_zeros(),
        time: 1_000_000,
        bits: CompactTarget::from_consensus(REGTEST_BITS),
        nonce: 0,
    };
    let cp = mine(&genesis_like, 1_000_000, 0);
    let mut m = fixtures::base_mandate(&w, &cold);
    m.network = Network::Regtest;
    m.limits.max_reorg = max_reorg;
    m.checkpoint = Checkpoint {
        hash: hash32(&cp),
        height: CP_HEIGHT,
        time: cp.time,
        bits: REGTEST_BITS,
        period_start_time: cp.time,
        period_bits: REGTEST_BITS,
    };
    m.not_after_height = 10_000;
    let sig = fixtures::owner_sig_for(&k, &m, 0);
    let s = State::new_at_init(ENCLAVE_ID, k.owner.pk, k.recovery.pk, m, sig).expect("fixture mandate valid");
    (s, cp)
}

/// Work of one header at `bits`, little-endian 256-bit (what `HeaderRec.work` accumulates).
pub fn work_of_bits(bits: u32) -> [u8; 32] {
    Target::from_compact(CompactTarget::from_consensus(bits)).to_work().to_le_bytes()
}

/// Reference 256-bit little-endian addition, written independently of `headers::add_work_le`:
/// the exact sum modulo nothing — `(sum, overflow)` with `overflow` set iff the mathematical sum
/// is at least 2^256 (then `sum` holds the low 256 bits).
pub fn add256_ref(a: &[u8; 32], b: &[u8; 32]) -> ([u8; 32], bool) {
    let mut out = [0u8; 32];
    let mut carry: u32 = 0;
    for i in 0..32 {
        let s = u32::from(a[i]) + u32::from(b[i]) + carry;
        out[i] = (s & 0xff) as u8;
        carry = s >> 8;
    }
    (out, carry != 0)
}

/// Little-endian 256-bit comparison.
pub fn le_cmp(a: &[u8; 32], b: &[u8; 32]) -> core::cmp::Ordering {
    for i in (0..32).rev() {
        match a[i].cmp(&b[i]) {
            core::cmp::Ordering::Equal => continue,
            o => return o,
        }
    }
    core::cmp::Ordering::Equal
}
