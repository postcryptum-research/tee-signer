//! The fuzz target bodies. Each is `fn(&[u8])`, takes the fuzzer's bytes and panics only when an
//! oracle fails; every panic message names the oracle (REQ-r10 §1, RESP-r10 C-R10-1…6). Nothing
//! here reads a file, the clock or randomness, so a reproducer replays byte for byte on stable.
//!
//! Oracles in force in every target:
//! - **no panic / no abort** inside `signer-core` on any input (REQ-r10 §1.1);
//! - **strict canonicality** (C-R10-2): for every `b` that decodes `Ok`, `encode(decode(b)) == b`;
//! - **signature covers the full canonical encoding** (C-R10-3): a decoded object that verifies
//!   stays the only object those bytes can mean — every single-field change breaks the signature;
//! - **cross-type non-confusion** (C-R10-1): one blob never verifies as two types or two roles.

use arbitrary::Unstructured;
use bitcoin::secp256k1::Secp256k1;

use signer_core::encoding::Dec;
use signer_core::mandate::{compare, Change, Immutable, Mandate, Matcher, OpReturnRule, PayjoinRule, SighashRule};
use signer_core::proto::{
    limits, HeadersResponse, IdentityCard, InitRequest, InitResponse, JudgeResponse, PolicyResponse, ReportResponse,
    Response, SealedResponse, SealedWith, SignResponse, StatusResponse, TestInitRequest, TpmProof,
};
use signer_core::reason::Reason;
use signer_core::receipt::Receipt;
use signer_core::sign::verify_digest_secp;
use signer_core::state::State;
use signer_core::tpm_attest::{
    build_nv_attest, certified_counter, parse_nv_attest, verify_nv_certify, MAX_ATTEST_LEN, NV_NAME_LEN,
};
use signer_core::update::{verify_p256, Message};

use crate::seeds::{self, honest};

fn selector(data: &[u8]) -> Option<(u8, &[u8])> {
    data.split_first().map(|(s, r)| (*s, r))
}

/// C-R10-2 for one type: decode, and if it decodes, the canonical re-encoding is the input.
macro_rules! strict {
    ($ty:ty, $b:expr) => {
        if let Ok(x) = <$ty>::decode($b) {
            assert_eq!(x.encode(), $b, concat!("C-R10-2: ", stringify!($ty), " accepted non-canonical bytes"));
        }
    };
}

// ------------------------------------------------------------------------------------------------
// F1 — proto: every request/response type the daemon and the enclave exchange
// ------------------------------------------------------------------------------------------------

/// Selector byte, then the bytes. Every type in `signer_core::proto` with a `decode`.
pub fn proto_decode(data: &[u8]) {
    let Some((s, b)) = selector(data) else { return };
    match s % 14 {
        0 => strict!(TpmProof, b),
        1 => strict!(Response, b),
        2 => strict!(InitRequest, b),
        3 => strict!(SealedResponse, b),
        4 => strict!(TestInitRequest, b),
        5 => strict!(InitResponse, b),
        6 => {
            if let Ok(c) = IdentityCard::decode(b) {
                assert_eq!(c.encode(), b, "C-R10-2: IdentityCard accepted non-canonical bytes");
                let _ = c.digest();
            }
        }
        7 => strict!(StatusResponse, b),
        8 => strict!(PolicyResponse, b),
        9 => strict!(ReportResponse, b),
        10 => {
            // the per-op bound on `data`: PSBT, message, or small
            let max = match s / 14 % 3 {
                0 => limits::MAX_PSBT,
                1 => limits::MAX_MESSAGE,
                _ => limits::MAX_SMALL,
            };
            if let Ok(x) = SealedWith::decode(b, max) {
                assert_eq!(x.encode(), b, "C-R10-2: SealedWith accepted non-canonical bytes");
                assert!(x.data.len() <= max, "SealedWith: data above the op bound");
            }
        }
        11 => strict!(JudgeResponse, b),
        12 => strict!(SignResponse, b),
        _ => strict!(HeadersResponse, b),
    }
}

// ------------------------------------------------------------------------------------------------
// F2 — mandate: decode / validate / hash / compare
// ------------------------------------------------------------------------------------------------

/// Raw bytes → `Mandate`.
///
/// C-R10-5 (the partial order) is asserted over **valid** mandates: the enclave calls `compare` only
/// after `validate` (`state.rs`, the `PolicyUpdate` arm), and on an invalid mandate with duplicated
/// trusted labels `compare` is not reflexive (it matches the first entry with a label) — found by the
/// fuzzer 2026-11-20, `regressions/mandate_decode/REG-2026-11-20-01-*`, reported to the auditor as an
/// observation on the contract, not a finding. Decoding and `validate` stay total on every input.
pub fn mandate_decode(data: &[u8]) {
    let Ok(m) = Mandate::decode(data) else { return };
    assert_eq!(m.encode(), data, "C-R10-2: Mandate accepted non-canonical bytes");
    let _ = m.hash();
    let valid = m.validate().is_ok();
    let refl = compare(&m, &m); // total on any decoded mandate
    if valid {
        assert_eq!(refl, Ok(Change::Tightening), "C-R10-5: compare is not reflexive on a valid mandate");
    }
}

/// One field of a mandate moved by the fuzzer's choice (`arbitrary` drives which and how).
pub fn mutate_mandate(a: &Mandate, u: &mut Unstructured) -> Option<Mandate> {
    let mut b = a.clone();
    match u.int_in_range(0u8..=26).ok()? {
        0 => b.limits.max_per_tx = u.arbitrary().ok()?,
        1 => b.limits.window_blocks = u.arbitrary().ok()?,
        2 => b.limits.window_max_outflow = u.arbitrary().ok()?,
        3 => b.limits.max_fee_abs = u.arbitrary().ok()?,
        4 => b.limits.max_fee_rate = u.arbitrary().ok()?,
        5 => b.limits.max_fee_per_window = u.arbitrary().ok()?,
        6 => b.limits.max_inputs = u.arbitrary().ok()?,
        7 => b.limits.max_outputs = u.arbitrary().ok()?,
        8 => b.limits.own_index_gap = u.arbitrary().ok()?,
        9 => b.limits.max_reorg = u.arbitrary().ok()?,
        10 => b.destinations.unlisted.max_per_tx = u.arbitrary().ok()?,
        11 => b.destinations.unlisted.max_per_window = u.arbitrary().ok()?,
        12 => b.destinations.trusted.first_mut()?.max_per_tx = u.arbitrary().ok()?,
        13 => b.destinations.trusted.first_mut()?.max_per_window = u.arbitrary().ok()?,
        14 => {
            if let Matcher::Descriptor { gap, .. } = &mut b.destinations.trusted.first_mut()?.matcher {
                *gap = u.arbitrary().ok()?;
            }
        }
        15 => {
            if let Matcher::Descriptor { branches, .. } = &mut b.destinations.trusted.first_mut()?.matcher {
                *branches = u.arbitrary::<Vec<u32>>().ok()?;
                branches.truncate(2);
            }
        }
        16 => {
            b.destinations.trusted.pop();
        }
        17 => {
            let mut t = b.destinations.trusted.first()?.clone();
            t.label = u.arbitrary::<String>().ok()?;
            b.destinations.trusted.push(t);
        }
        18 => b.rules.rbf = u.arbitrary().ok()?,
        19 => b.rules.sighash = SighashRule::All,
        20 => {
            b.rules.payjoin = match u.int_in_range(0u8..=2).ok()? {
                0 => PayjoinRule::None,
                1 => PayjoinRule::InflowOnly,
                _ => PayjoinRule::OutflowAllowed,
            }
        }
        21 => b.rules.op_return = if u.arbitrary().ok()? { OpReturnRule::ZeroValue } else { OpReturnRule::None },
        22 => b.checkpoint.height = u.arbitrary().ok()?,
        23 => {
            // the checkpoint's other fields: hash, time, bits, period fields
            match u.int_in_range(0u8..=4).ok()? {
                0 => b.checkpoint.hash[0] ^= 1,
                1 => b.checkpoint.time = u.arbitrary().ok()?,
                2 => b.checkpoint.bits = u.arbitrary().ok()?,
                3 => b.checkpoint.period_start_time = u.arbitrary().ok()?,
                _ => b.checkpoint.period_bits = u.arbitrary().ok()?,
            }
        }
        24 => {
            b.freshness.required = u.arbitrary().ok()?;
            b.freshness.max_tip_lag = u.arbitrary().ok()?;
            b.freshness.witness_pk = if u.arbitrary().ok()? { Some(honest().keys.witness.pk) } else { None };
        }
        25 => b.not_after_height = u.arbitrary().ok()?,
        _ => b.timelock_blocks = u.arbitrary().ok()?,
    }
    Some(b)
}

/// The fields in which two mandates differ, by name — for oracle messages and `examples/explain.rs`.
pub fn mandate_diff(a: &Mandate, b: &Mandate) -> Vec<String> {
    let mut d: Vec<String> = Vec::new();
    macro_rules! f {
        ($name:expr, $x:expr, $y:expr) => {
            if $x != $y {
                d.push($name.to_string());
            }
        };
    }
    f!("version", a.version, b.version);
    f!("network", a.network, b.network);
    f!("wallet", a.wallet, b.wallet);
    let (ta, tb) = (&a.destinations.trusted, &b.destinations.trusted);
    if ta.len() != tb.len() {
        d.push(format!("trusted.len({}->{})", ta.len(), tb.len()));
    } else {
        for (i, (x, y)) in ta.iter().zip(tb).enumerate() {
            f!(format!("trusted[{i}].label"), x.label, y.label);
            f!(format!("trusted[{i}].matcher"), x.matcher, y.matcher);
            f!(format!("trusted[{i}].max_per_tx"), x.max_per_tx, y.max_per_tx);
            f!(format!("trusted[{i}].max_per_window"), x.max_per_window, y.max_per_window);
        }
    }
    f!("unlisted.max_per_tx", a.destinations.unlisted.max_per_tx, b.destinations.unlisted.max_per_tx);
    f!("unlisted.max_per_window", a.destinations.unlisted.max_per_window, b.destinations.unlisted.max_per_window);
    let (la, lb) = (&a.limits, &b.limits);
    f!("limits.max_per_tx", la.max_per_tx, lb.max_per_tx);
    f!("limits.window_blocks", la.window_blocks, lb.window_blocks);
    f!("limits.window_max_outflow", la.window_max_outflow, lb.window_max_outflow);
    f!("limits.max_fee_abs", la.max_fee_abs, lb.max_fee_abs);
    f!("limits.max_fee_rate", la.max_fee_rate, lb.max_fee_rate);
    f!("limits.max_fee_per_window", la.max_fee_per_window, lb.max_fee_per_window);
    f!("limits.max_inputs", la.max_inputs, lb.max_inputs);
    f!("limits.max_outputs", la.max_outputs, lb.max_outputs);
    f!("limits.own_index_gap", la.own_index_gap, lb.own_index_gap);
    f!("limits.max_reorg", la.max_reorg, lb.max_reorg);
    f!("rules.sighash", a.rules.sighash, b.rules.sighash);
    f!("rules.payjoin", a.rules.payjoin, b.rules.payjoin);
    f!("rules.op_return", a.rules.op_return, b.rules.op_return);
    f!("rules.rbf", a.rules.rbf, b.rules.rbf);
    let (ca, cb) = (&a.checkpoint, &b.checkpoint);
    f!("checkpoint.hash", ca.hash, cb.hash);
    f!("checkpoint.height", ca.height, cb.height);
    f!("checkpoint.time", ca.time, cb.time);
    f!("checkpoint.bits", ca.bits, cb.bits);
    f!("checkpoint.period_start_time", ca.period_start_time, cb.period_start_time);
    f!("checkpoint.period_bits", ca.period_bits, cb.period_bits);
    f!("freshness.required", a.freshness.required, b.freshness.required);
    f!("freshness.witness_pk", a.freshness.witness_pk, b.freshness.witness_pk);
    f!("freshness.max_tip_lag", a.freshness.max_tip_lag, b.freshness.max_tip_lag);
    f!("not_after_height", a.not_after_height, b.not_after_height);
    f!("timelock_blocks", a.timelock_blocks, b.timelock_blocks);
    d
}

/// C-R10-5: `compare` is a proper partial order between two **valid** mandates (see `mandate_decode`
/// for why validity is the precondition). On an invalid pair only totality is exercised.
fn check_compare_pair(a: &Mandate, b: &Mandate) {
    let ab = compare(a, b);
    let ba = compare(b, a);
    if a.validate().is_err() || b.validate().is_err() {
        return;
    }
    if a.network != b.network {
        assert_eq!(ab, Err(Immutable::Network), "C-R10-5: network change not refused as Immutable");
        assert_eq!(ba, Err(Immutable::Network), "C-R10-5: network change not refused as Immutable (reverse)");
        return;
    }
    if a.wallet != b.wallet {
        assert_eq!(ab, Err(Immutable::Wallet), "C-R10-5: wallet change not refused as Immutable");
        assert_eq!(ba, Err(Immutable::Wallet), "C-R10-5: wallet change not refused as Immutable (reverse)");
        return;
    }
    assert!(ab.is_ok() && ba.is_ok(), "C-R10-5: Immutable reported without a network/wallet change");
    if a == b {
        assert_eq!(ab, Ok(Change::Tightening), "C-R10-5: equal mandates not Tightening");
        return;
    }
    if ab == Ok(Change::Tightening) && ba == Ok(Change::Tightening) {
        panic!(
            "C-R10-5: two distinct mandates classify as mutual Tightening; they differ in {:?}\n a = {}\n b = {}",
            mandate_diff(a, b),
            hex::encode(a.encode()),
            hex::encode(b.encode())
        );
    }
}

/// `u16 LE len(a)` ‖ `a` ‖ `b`: two raw mandates, then `a` against a structured mutation of itself.
pub fn mandate_compare(data: &[u8]) {
    let Some((la, rest)) = data.split_at_checked(2) else { return };
    let la = u16::from_le_bytes([la[0], la[1]]) as usize;
    let Some((a_bytes, b_bytes)) = rest.split_at_checked(la) else { return };
    let Ok(a) = Mandate::decode(a_bytes) else { return };
    if let Ok(b) = Mandate::decode(b_bytes) {
        check_compare_pair(&a, &b);
    }
    let mut u = Unstructured::new(b_bytes);
    if let Some(b) = mutate_mandate(&a, &mut u) {
        check_compare_pair(&a, &b);
        // and a second step away
        if let Some(c) = mutate_mandate(&b, &mut u) {
            check_compare_pair(&a, &c);
            check_compare_pair(&b, &c);
        }
    }
}

// ------------------------------------------------------------------------------------------------
// F3 — owner / recovery / witness messages
// ------------------------------------------------------------------------------------------------

fn flip<const N: usize>(mut a: [u8; N]) -> [u8; N] {
    a[0] ^= 1;
    a
}

/// Every single-field change of a message (never the signature), plus the same bytes re-tagged as
/// the variant with the same layout — the C-R10-1 within-key confusion (Cancel ↔ Unfreeze,
/// RotateOwner ↔ Recover share a layout and the owner key; only the domain tells them apart).
pub fn message_tweaks(m: &Message) -> Vec<Message> {
    use Message::*;
    let mut out = Vec::new();
    match m.clone() {
        PolicyUpdate { enclave_id, nonce, mandate, sig } => {
            out.push(PolicyUpdate { enclave_id: flip(enclave_id), nonce, mandate: mandate.clone(), sig });
            out.push(PolicyUpdate { enclave_id, nonce: nonce.wrapping_add(1), mandate: mandate.clone(), sig });
            let mut m2 = mandate.clone();
            m2.push(0);
            out.push(PolicyUpdate { enclave_id, nonce, mandate: m2, sig });
            if let Some(&b0) = mandate.first() {
                let mut m3 = mandate.clone();
                m3[0] = b0 ^ 1;
                out.push(PolicyUpdate { enclave_id, nonce, mandate: m3, sig });
            }
        }
        Cancel { enclave_id, nonce, sig } => {
            out.push(Cancel { enclave_id: flip(enclave_id), nonce, sig });
            out.push(Cancel { enclave_id, nonce: nonce.wrapping_add(1), sig });
            out.push(Unfreeze { enclave_id, nonce, sig });
        }
        Unfreeze { enclave_id, nonce, sig } => {
            out.push(Unfreeze { enclave_id: flip(enclave_id), nonce, sig });
            out.push(Unfreeze { enclave_id, nonce: nonce.wrapping_add(1), sig });
            out.push(Cancel { enclave_id, nonce, sig });
        }
        Rearm { enclave_id, nonce, seq, sig } => {
            out.push(Rearm { enclave_id: flip(enclave_id), nonce, seq, sig });
            out.push(Rearm { enclave_id, nonce: nonce.wrapping_add(1), seq, sig });
            out.push(Rearm { enclave_id, nonce, seq: seq.wrapping_add(1), sig });
        }
        RotateOwner { enclave_id, nonce, new_owner_pk, sig } => {
            out.push(RotateOwner { enclave_id: flip(enclave_id), nonce, new_owner_pk, sig });
            out.push(RotateOwner { enclave_id, nonce: nonce.wrapping_add(1), new_owner_pk, sig });
            out.push(RotateOwner { enclave_id, nonce, new_owner_pk: flip(new_owner_pk), sig });
            out.push(Recover { enclave_id, nonce, new_owner_pk, sig });
        }
        Recover { enclave_id, nonce, new_owner_pk, sig } => {
            out.push(Recover { enclave_id: flip(enclave_id), nonce, new_owner_pk, sig });
            out.push(Recover { enclave_id, nonce: nonce.wrapping_add(1), new_owner_pk, sig });
            out.push(Recover { enclave_id, nonce, new_owner_pk: flip(new_owner_pk), sig });
            out.push(RotateOwner { enclave_id, nonce, new_owner_pk, sig });
        }
        Arm { enclave_id, nonce, boot_challenge, seq_seen, sig } => {
            out.push(Arm { enclave_id: flip(enclave_id), nonce, boot_challenge, seq_seen, sig });
            out.push(Arm { enclave_id, nonce: nonce.wrapping_add(1), boot_challenge, seq_seen, sig });
            out.push(Arm { enclave_id, nonce, boot_challenge: flip(boot_challenge), seq_seen, sig });
            out.push(Arm { enclave_id, nonce, boot_challenge, seq_seen: seq_seen.wrapping_add(1), sig });
        }
        Anchor { enclave_id, nonce, boot_challenge, ak_pk, nv_name, counter, seq_seen, sig } => {
            let base = |f: &dyn Fn(&mut Message)| {
                let mut m = Anchor { enclave_id, nonce, boot_challenge, ak_pk, nv_name, counter, seq_seen, sig };
                f(&mut m);
                m
            };
            out.push(base(&|m| {
                if let Anchor { enclave_id, .. } = m {
                    enclave_id[0] ^= 1
                }
            }));
            out.push(base(&|m| {
                if let Anchor { nonce, .. } = m {
                    *nonce = nonce.wrapping_add(1)
                }
            }));
            out.push(base(&|m| {
                if let Anchor { boot_challenge, .. } = m {
                    boot_challenge[0] ^= 1
                }
            }));
            out.push(base(&|m| {
                if let Anchor { ak_pk, .. } = m {
                    ak_pk[1] ^= 1
                }
            }));
            out.push(base(&|m| {
                if let Anchor { nv_name, .. } = m {
                    nv_name[2] ^= 1
                }
            }));
            out.push(base(&|m| {
                if let Anchor { counter, .. } = m {
                    *counter = counter.wrapping_add(1)
                }
            }));
            out.push(base(&|m| {
                if let Anchor { seq_seen, .. } = m {
                    *seq_seen = seq_seen.wrapping_add(1)
                }
            }));
        }
        WitnessToken { enclave_id, tip_hash, tip_height, last_seen_seq, issued, sig } => {
            out.push(WitnessToken { enclave_id: flip(enclave_id), tip_hash, tip_height, last_seen_seq, issued, sig });
            out.push(WitnessToken { enclave_id, tip_hash: flip(tip_hash), tip_height, last_seen_seq, issued, sig });
            out.push(WitnessToken {
                enclave_id,
                tip_hash,
                tip_height: tip_height.wrapping_add(1),
                last_seen_seq,
                issued,
                sig,
            });
            out.push(WitnessToken {
                enclave_id,
                tip_hash,
                tip_height,
                last_seen_seq: last_seen_seq.wrapping_add(1),
                issued,
                sig,
            });
            out.push(WitnessToken {
                enclave_id,
                tip_hash,
                tip_height,
                last_seen_seq,
                issued: issued.wrapping_add(1),
                sig,
            });
        }
    }
    out
}

/// C-R10-3 on a message that verifies under `pk`: no field change keeps the signature.
pub fn check_message_binding(m: &Message, pk: &[u8; 65]) {
    for t in message_tweaks(m) {
        assert_ne!(&t, m, "harness: a tweak produced the same message");
        assert!(
            !t.verify(pk),
            "C-R10-3: a message with a changed field still verifies under the same key\n orig = {:?}\n tweak = {:?}",
            m,
            t
        );
    }
}

/// Raw bytes → `Message`; a verifying message is held to C-R10-3.
pub fn message_decode(data: &[u8]) {
    let Ok(m) = Message::decode(data) else { return };
    assert_eq!(m.encode(), data, "C-R10-2: Message accepted non-canonical bytes");
    let _ = m.digest();
    let _ = m.enclave_id();
    for (_, pk) in honest().p256_keys() {
        if m.verify(&pk) {
            check_message_binding(&m, &pk);
        }
    }
}

// ------------------------------------------------------------------------------------------------
// F4 (decode half) — the sealed policy state
// ------------------------------------------------------------------------------------------------

/// Raw bytes → `State`.
pub fn state_decode(data: &[u8]) {
    let Ok(s) = State::decode(data) else { return };
    assert_eq!(s.encode(), data, "C-R10-2: State accepted non-canonical bytes");
    let _ = s.best_height();
    let _ = s.mandate.hash();
    if let Some(t) = &s.tpm {
        let _ = t.well_formed();
    }
}

// ------------------------------------------------------------------------------------------------
// F5 — the TPM counter proof (`TPMS_ATTEST`), C-R9-A reason order
// ------------------------------------------------------------------------------------------------

/// Field classes of the honest attest by byte offset (the fixed layout `build_nv_attest` writes).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum AttestField {
    /// magic, type, every TPM2B length, the `offset` field: a structural byte.
    Structure,
    /// bytes the signature covers but the verifier does not compare: signer name, clock, counts, firmware.
    DontCare,
    /// the `safe` byte (0/1 accepted, else parse error)
    Safe,
    /// the enclave nonce (extraData value)
    Nonce,
    /// the index Name value
    Index,
    /// the counter value (nvContents)
    Counter,
}

fn attest_field(signer_len: usize, pos: usize) -> AttestField {
    use AttestField::*;
    // 4 magic | 2 type | 2 signer len | signer | 2 extra len | 32 extra | 8 clock | 4 reset | 4 restart | 1 safe
    // | 8 firmware | 2 name len | 34 name | 2 offset | 2 contents len | 8 contents
    let mut o = 0usize;
    let mut span = |n: usize, f: AttestField| -> Option<AttestField> {
        let end = o + n;
        let hit = pos >= o && pos < end;
        o = end;
        hit.then_some(f)
    };
    span(4, Structure)
        .or_else(|| span(2, Structure))
        .or_else(|| span(2, Structure))
        .or_else(|| span(signer_len, DontCare))
        .or_else(|| span(2, Structure))
        .or_else(|| span(32, Nonce))
        .or_else(|| span(8, DontCare))
        .or_else(|| span(4, DontCare))
        .or_else(|| span(4, DontCare))
        .or_else(|| span(1, Safe))
        .or_else(|| span(8, DontCare))
        .or_else(|| span(2, Structure))
        .or_else(|| span(NV_NAME_LEN, Index))
        .or_else(|| span(2, Structure))
        .or_else(|| span(2, Structure))
        .or_else(|| span(8, Counter))
        .unwrap_or(Structure)
}

/// Mode byte, then:
/// - `0`: raw bytes are the attest — parse never panics; under the honest signature only the honest
///   attest verifies;
/// - `1`: one byte of the honest attest (or of its signature) is changed — the reason is the one
///   C-R9-A fixes for that field, never `Ok`;
/// - `2`: an honest proof for a fuzzer-chosen counter — `Ok` exactly when it equals the anchor's
///   `expected`, `STATE_STALE` otherwise.
pub fn tpm_attest(data: &[u8]) {
    let h = honest();
    let Some((mode, rest)) = selector(data) else { return };
    match mode % 3 {
        0 => {
            if let Ok(a) = parse_nv_attest(rest) {
                assert!(rest.len() <= MAX_ATTEST_LEN, "TPM_PARSE: accepted an attest above MAX_ATTEST_LEN");
                let _ = a.counter;
            }
            let r = verify_nv_certify(rest, &h.attest_sig, &h.anchor, &h.nonce);
            if r.is_ok() {
                assert_eq!(rest, &h.attest[..], "C-R10-3: a different attest verified under the honest signature");
            }
            let _ = certified_counter(rest, &h.attest_sig, &h.ak.pk, &h.nv_name, &h.nonce);
        }
        1 => {
            let Some((&which, r2)) = rest.split_first() else { return };
            let Some((pos_b, r3)) = r2.split_at_checked(2) else { return };
            let Some((&val, _)) = r3.split_first() else { return };
            let pos = u16::from_le_bytes([pos_b[0], pos_b[1]]) as usize;
            let delta = val | 1; // XOR with a non-zero value: the byte always changes
            if which % 4 == 0 {
                let mut sig = h.attest_sig;
                sig[pos % 64] ^= delta;
                assert_eq!(
                    verify_nv_certify(&h.attest, &sig, &h.anchor, &h.nonce),
                    Err(Reason::TpmSig),
                    "C-R9-A: a changed signature byte is not TPM_SIG"
                );
            } else {
                let mut attest = h.attest.clone();
                let p = pos % attest.len();
                attest[p] ^= delta;
                let r = verify_nv_certify(&attest, &h.attest_sig, &h.anchor, &h.nonce);
                assert!(r.is_err(), "C-R10-3: a changed attest byte still verifies (offset {p})");
                let expected = match attest_field(h.signer_name.len(), p) {
                    AttestField::DontCare | AttestField::Counter => Some(Reason::TpmSig),
                    AttestField::Nonce => Some(Reason::TpmNonce),
                    AttestField::Index => Some(Reason::TpmIndex),
                    AttestField::Safe => Some(if attest[p] > 1 { Reason::TpmParse } else { Reason::TpmSig }),
                    AttestField::Structure => None, // any refusal; which one depends on how the walk re-aligns
                };
                if let Some(e) = expected {
                    assert_eq!(
                        r,
                        Err(e),
                        "C-R9-A: byte {p} ({:?}) refused with the wrong reason",
                        attest_field(h.signer_name.len(), p)
                    );
                } else {
                    assert!(
                        matches!(
                            r,
                            Err(Reason::TpmParse) | Err(Reason::TpmNonce) | Err(Reason::TpmIndex) | Err(Reason::TpmSig)
                        ),
                        "C-R9-A: structural byte {p} refused with a reason outside the TPM set: {r:?}"
                    );
                }
            }
        }
        _ => {
            let Some((c, _)) = rest.split_at_checked(8) else { return };
            let counter = u64::from_le_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]);
            let attest = build_nv_attest(&h.signer_name, &h.nonce, &h.nv_name, counter);
            let sig = seeds::sign_attest(&h.ak, &attest);
            assert_eq!(
                certified_counter(&attest, &sig, &h.ak.pk, &h.nv_name, &h.nonce),
                Ok(counter),
                "honest proof refused"
            );
            let r = verify_nv_certify(&attest, &sig, &h.anchor, &h.nonce);
            if counter == h.anchor.expected {
                assert_eq!(r, Ok(counter), "honest proof for the expected counter refused");
            } else {
                assert_eq!(r, Err(Reason::StateStale), "a counter other than expected is not STATE_STALE");
            }
        }
    }
}

// ------------------------------------------------------------------------------------------------
// F9 — receipt, the encoding primitives, BIP39
// ------------------------------------------------------------------------------------------------

/// Raw bytes → `Receipt`.
pub fn receipt_decode(data: &[u8]) {
    let Ok(r) = Receipt::decode(data) else { return };
    assert_eq!(r.encode(), data, "C-R10-2: Receipt accepted non-canonical bytes");
    let _ = r.digest();
}

/// Op count, op bytes, then the bytes to decode: a random walk over `Dec`. Every bound is honoured,
/// `remaining` is exact, `finish` accepts exactly the empty tail.
pub fn encoding_dec(data: &[u8]) {
    let Some((n_ops, rest)) = selector(data) else { return };
    let n_ops = (n_ops % 32) as usize;
    let Some((ops, payload)) = rest.split_at_checked(n_ops) else { return };
    let mut d = Dec::new(payload);
    let mut consumed = 0usize;
    for &op in ops {
        let max = (op >> 4) as usize; // 0..16: a small bound, so the bound checks fire often
        let before = d.remaining();
        let took: Option<usize> = match (op & 0x0f) % 10 {
            0 => d.u8().ok().map(|_| 1),
            1 => d.u16().ok().map(|_| 2),
            2 => d.u32().ok().map(|_| 4),
            3 => d.u64().ok().map(|_| 8),
            4 => d.bool().ok().map(|_| 1),
            5 => d.fixed::<7>().ok().map(|_| 7),
            6 => d.bytes(max).ok().map(|v| {
                assert!(v.len() <= max, "Dec::bytes: length above the bound");
                4 + v.len()
            }),
            7 => d.str(max).ok().map(|s| {
                assert!(s.len() <= max, "Dec::str: length above the bound");
                2 + s.len()
            }),
            8 => d.list(max, |d| d.u8()).ok().map(|v| {
                assert!(v.len() <= max, "Dec::list: count above the bound");
                4 + v.len()
            }),
            _ => d.option(|d| d.u8()).ok().map(|v| 1 + usize::from(v.is_some())),
        };
        match took {
            Some(n) => {
                consumed += n;
                assert_eq!(
                    before - d.remaining(),
                    n,
                    "Dec: consumed {n} but remaining moved by {}",
                    before - d.remaining()
                );
            }
            None => {
                // a failed read: the primitives consume nothing they could not complete, except the
                // length-prefixed ones, which may have taken their prefix — only "no overshoot" is asserted
                assert!(d.remaining() <= before, "Dec: remaining grew");
                consumed += before - d.remaining();
            }
        }
    }
    assert_eq!(d.remaining(), payload.len() - consumed, "Dec::remaining is not exact");
    let tail_empty = d.remaining() == 0;
    assert_eq!(d.finish().is_ok(), tail_empty, "Dec::finish disagrees with remaining()");
}

/// 32 bytes of entropy → 24 words → seed, deterministic; any string → `seed` never panics.
pub fn bip39(data: &[u8]) {
    if data.len() >= 32 {
        let mut e = [0u8; 32];
        e.copy_from_slice(&data[..32]);
        let m = signer_core::bip39::mnemonic(&e);
        let words: Vec<&str> = m.split(' ').collect();
        assert_eq!(words.len(), 24, "bip39: not 24 words");
        assert!(!words.contains(&"?"), "bip39: a word index outside the list");
        assert_eq!(signer_core::bip39::seed(&m), signer_core::bip39::seed(&m), "bip39: seed not deterministic");
    } else if let Ok(s) = std::str::from_utf8(data) {
        let _ = signer_core::bip39::seed(s);
    }
}

// ------------------------------------------------------------------------------------------------
// C-R10-1 — cross-type / cross-role confusion
// ------------------------------------------------------------------------------------------------

/// `sig (64)` ‖ `blob`: the blob is decoded as every signed or hashed type and the signature tried
/// under every role key. One blob may verify as at most one (type, role).
pub fn cross_type(data: &[u8]) {
    let h = honest();
    let Some((sig_b, blob)) = data.split_at_checked(64) else { return };
    let mut sig = [0u8; 64];
    sig.copy_from_slice(sig_b);
    let secp = Secp256k1::verification_only();
    let mut hits: Vec<String> = Vec::new();

    if let Ok(m) = Message::decode(blob) {
        for (role, pk) in h.p256_keys() {
            if m.verify(&pk) {
                hits.push(format!("message:{}/{role}", message_tag_name(&m)));
            }
        }
    }
    if let Ok(r) = Receipt::decode(blob) {
        let d = r.digest();
        if verify_digest_secp(&secp, &h.identity_pk, &d, &sig) {
            hits.push("receipt/identity".into());
        }
        for (role, pk) in h.p256_keys() {
            if verify_p256(&pk, &d, &sig) {
                hits.push(format!("receipt/{role}"));
            }
        }
    }
    if let Ok(c) = IdentityCard::decode(blob) {
        let d = c.digest();
        if verify_digest_secp(&secp, &h.identity_pk, &d, &sig) {
            hits.push("card/identity".into());
        }
        for (role, pk) in h.p256_keys() {
            if verify_p256(&pk, &d, &sig) {
                hits.push(format!("card/{role}"));
            }
        }
    }
    if certified_counter(blob, &sig, &h.ak.pk, &h.nv_name, &h.nonce).is_ok() {
        hits.push("attest/ak".into());
    }
    // the attest's undomained digest form under every P-256 role key
    let raw = signer_core::sha256(blob);
    for (role, pk) in h.p256_keys() {
        if role != "ak" && verify_p256(&pk, &raw, &sig) {
            hits.push(format!("rawsha/{role}"));
        }
    }
    // a mandate or a state parsing as something signed is itself worth knowing about
    if Mandate::decode(blob).is_ok() && !hits.is_empty() {
        hits.push("mandate(parses)".into());
    }
    assert!(hits.len() <= 1, "C-R10-1: one blob verifies as more than one type/role: {hits:?}");
}

/// The variant name of a message (for oracle messages).
pub fn message_tag_name(m: &Message) -> &'static str {
    match m {
        Message::PolicyUpdate { .. } => "PolicyUpdate",
        Message::Cancel { .. } => "Cancel",
        Message::Unfreeze { .. } => "Unfreeze",
        Message::Rearm { .. } => "Rearm",
        Message::RotateOwner { .. } => "RotateOwner",
        Message::Recover { .. } => "Recover",
        Message::Arm { .. } => "Arm",
        Message::Anchor { .. } => "Anchor",
        Message::WitnessToken { .. } => "WitnessToken",
    }
}

/// A target body.
pub type Target = fn(&[u8]);

/// Every target by name — the replay test and the seed writer iterate this table.
pub const TARGETS: &[(&str, Target)] = &[
    ("proto_decode", proto_decode),
    ("mandate_decode", mandate_decode),
    ("mandate_compare", mandate_compare),
    ("message_decode", message_decode),
    ("state_decode", state_decode),
    ("tpm_attest", tpm_attest),
    ("receipt_decode", receipt_decode),
    ("encoding_dec", encoding_dec),
    ("bip39", bip39),
    ("cross_type", cross_type),
    // phase 2, pass (i)
    ("work_add", crate::structured::work_add),
    ("headers", crate::structured::headers),
    ("state_ops", crate::structured::state_ops),
    // phase 2, pass (ii)
    ("classify", crate::policy::classify_target),
    ("judge", crate::policy::judge_target),
];
