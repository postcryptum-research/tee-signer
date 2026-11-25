//! The stable replay gate (REQ-r10 §3, RESP-r10 Q5): every committed corpus file and every
//! regression reproducer goes through its target body on the repo's stable toolchain, with no
//! libFuzzer and no sanitizer. Red here blocks the merge like `cargo test` in `core/`.
//!
//! Also here: the calibration of the oracles on the honest set (an oracle that rejects an honest
//! object is a harness bug, not a finding), the C-R10-1 re-tag vectors, and the seed writer.

use std::fs;
use std::path::{Path, PathBuf};

use signer_core::encoding::Enc;
use signer_core::mandate::{Mandate, Network};
use signer_core::proto::{
    HeadersResponse, InitRequest, InitResponse, JudgeResponse, PolicyResponse, ReportResponse, Response,
    SealedResponse, SealedWith, SignResponse, StatusResponse, TestInitRequest, TpmProof,
};
use signer_core::state::{Pending, PendingOwner};
use signer_core::update::Message;
use tee_signer_fuzz::seeds::honest;
use tee_signer_fuzz::targets::{self, TARGETS};
use tee_signer_fuzz::{dispatch, gen, policy, structured};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn files(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = fs::read_dir(dir)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .collect();
    v.sort();
    v
}

#[test]
fn every_target_replays_its_corpus_and_regressions() {
    let mut total = 0usize;
    for (name, f) in TARGETS {
        let mut n = 0usize;
        // seeds (hand-written, `write_seeds`) + corpus (fuzzer-grown, minimised) + regressions: every input passes
        for dir in ["seeds", "corpus", "regressions"] {
            for p in files(&root().join(dir).join(name)) {
                let bytes = fs::read(&p).unwrap();
                let ok = std::panic::catch_unwind(|| f(&bytes)).is_ok();
                assert!(ok, "{name}: {} fails its oracle (the message above names it)", p.display());
                n += 1;
            }
        }
        assert!(n > 0, "{name}: no corpus — a target without seeds is a hollow target (C-R10-7)");
        total += n;
        // findings: an OPEN finding's reproducer must still fire its oracle. When it stops firing, the
        // core fix (or the auditor's oracle ruling) has landed: move the file to `regressions/<target>/`
        // with the RESP reference in `findings/<target>/FINDING.md`. Nothing is fixed quietly (REQ-r10 §3).
        for p in files(&root().join("findings").join(name)) {
            if p.file_name().map(|f| f == "FINDING.md").unwrap_or(false) {
                continue;
            }
            let bytes = fs::read(&p).unwrap();
            let prev = std::panic::take_hook();
            std::panic::set_hook(Box::new(|_| {})); // the oracle message is expected here; keep the log clean
            let fired = std::panic::catch_unwind(|| f(&bytes)).is_err();
            std::panic::set_hook(prev);
            assert!(
                fired,
                "{name}: {} no longer fires its oracle — the finding is resolved; move it to regressions/ with the RESP reference",
                p.display()
            );
        }
    }
    eprintln!("replayed {total} inputs over {} targets", TARGETS.len());
}

#[test]
fn honest_messages_verify_and_are_bound_to_every_field() {
    let h = honest();
    for (name, m, pk) in &h.messages {
        assert!(m.verify(pk), "{name}: honest message does not verify");
        targets::check_message_binding(m, pk);
        targets::message_decode(&m.encode());
        // the other role keys never verify it (one role per message)
        for (role, other) in h.p256_keys() {
            if other != *pk {
                assert!(!m.verify(&other), "{name}: verifies under the {role} key too");
            }
        }
    }
}

/// C-R10-1 within one key: the same bytes re-tagged as the variant with the same layout carry a
/// signature made under another domain and must not verify. Cancel ↔ Unfreeze, RotateOwner ↔ Recover.
#[test]
fn retagged_message_does_not_verify() {
    let h = honest();
    let owner = h.keys.owner.pk;
    let recovery = h.keys.recovery.pk;
    let cases: &[(&str, u8, [u8; 65])] =
        &[("cancel-owner", 3, owner), ("unfreeze", 2, owner), ("rotate-owner", 6, owner), ("recover", 5, recovery)];
    for (name, new_tag, pk) in cases {
        let (_, m, _) = h.messages.iter().find(|(n, _, _)| n == name).unwrap();
        let mut bytes = m.encode();
        bytes[0] = *new_tag;
        let re = Message::decode(&bytes).expect("same layout decodes");
        assert_ne!(&re, m);
        assert!(!re.verify(pk), "{name} re-tagged as {} still verifies", targets::message_tag_name(&re));
        // and through the cross-type target: zero hits, no panic
        let mut input = m.sig().to_vec();
        input.extend_from_slice(&bytes);
        targets::cross_type(&input);
    }
}

#[test]
fn honest_objects_pass_their_targets() {
    let h = honest();
    for (sel, bytes) in proto_seeds() {
        let mut v = vec![sel];
        v.extend_from_slice(&bytes);
        targets::proto_decode(&v);
    }
    for (_, m) in &h.mandates {
        targets::mandate_decode(&m.encode());
    }
    targets::state_decode(&h.state.encode());
    targets::receipt_decode(&h.receipt.encode());
    for input in tpm_seeds() {
        targets::tpm_attest(&input);
    }
    for input in cross_type_seeds() {
        targets::cross_type(&input);
    }
    targets::encoding_dec(&encoding_seed());
    for input in bip39_seeds() {
        targets::bip39(&input);
    }
    for input in work_add_seeds() {
        structured::work_add(&input);
    }
    for input in headers_seeds() {
        structured::headers(&input);
    }
    for input in state_ops_seeds() {
        structured::state_ops(&input);
    }
    for input in classify_seeds() {
        policy::classify_target(&input);
    }
    for input in judge_seeds() {
        policy::judge_target(&input);
    }
    for input in dispatch_seeds() {
        dispatch::dispatch_target(&input);
    }
}

#[test]
fn compare_over_the_seed_pairs() {
    let h = honest();
    for (_, a) in &h.mandates {
        for (_, b) in &h.mandates {
            targets::mandate_compare(&pair(a, b));
        }
    }
}

// ------------------------------------------------------------------------------------------------
// seeds
// ------------------------------------------------------------------------------------------------

fn pair(a: &Mandate, b: &Mandate) -> Vec<u8> {
    let ab = a.encode();
    let mut v = (ab.len() as u16).to_le_bytes().to_vec();
    v.extend_from_slice(&ab);
    v.extend_from_slice(&b.encode());
    v
}

fn proto_seeds() -> Vec<(u8, Vec<u8>)> {
    let h = honest();
    let sealed = vec![0xC0u8; 96];
    let init = InitRequest { network: 2, owner_pk: h.keys.owner.pk, recovery_pk: h.keys.recovery.pk };
    let card = h.card.encode();
    let status = StatusResponse {
        installed: true,
        tier: "T0-fuzz".into(),
        mrenclave: [0; 32],
        session_id: [7; 16],
        network: 2,
        xpub: h.wallet.xpub_bytes(),
        fingerprint: h.wallet.account.fingerprint,
        identity_pk: h.identity_pk,
        nonce: 1,
        seq: 1,
        frozen: false,
        armed: true,
        chain_frozen: false,
        best_height: 250_010,
        best_hash: tee_signer_fuzz::fixtures::header_hash(250_010),
        window_start: 250_000,
        window_outflow: 1_500_000,
        window_unlisted: 500_000,
        window_fees: 1_000,
        mandate_hash: h.mandate.hash(),
        pending: Some(([9; 32], 250_200)),
        pending_owner: None,
        clock_label: "signet: weak PoW".into(),
        boot_armed: true,
        boot_challenge: [0x11; 32],
        auto_arm: false,
        tpm_bound: true,
        tpm_expected: 42,
        tpm_last_fresh: true,
    };
    vec![
        (0, TpmProof { attest: h.attest.clone(), sig: h.attest_sig }.encode()),
        (1, Response::ok(b"payload".to_vec()).encode()),
        (1, Response::refuse(vec!["PSBT_PARSE".into(), "OVERFLOW".into()], sealed.clone()).encode()),
        (2, init.encode()),
        (3, SealedResponse { sealed: sealed.clone() }.encode()),
        (
            4,
            TestInitRequest { init: init.clone(), seed: [1; 32], identity_sk: [0x55; 32], state: h.state.encode() }
                .encode(),
        ),
        (
            5,
            InitResponse {
                sealed: sealed.clone(),
                xpub: h.wallet.xpub_bytes(),
                fingerprint: h.wallet.account.fingerprint,
                identity_pk: h.identity_pk,
                card: card.clone(),
                card_sig: h.card_sig,
                recovery_blob: vec![0xAB; 48],
            }
            .encode(),
        ),
        (6, card.clone()),
        (7, status.encode()),
        (8, PolicyResponse { mandate: h.mandate.encode(), sig: h.state.mandate_sig, nonce: 1, pending: None }.encode()),
        (
            8,
            PolicyResponse {
                mandate: h.mandate.encode(),
                sig: h.state.mandate_sig,
                nonce: 1,
                pending: Some((h.mandates[2].1.encode(), [0x5A; 64], 2, 250_200)),
            }
            .encode(),
        ),
        (9, ReportResponse { report: [0x42; 432], card: h.card.clone() }.encode()),
        (10, SealedWith { sealed: sealed.clone(), data: h.messages[0].1.encode(), extra: None }.encode()),
        (
            10,
            SealedWith { sealed: sealed.clone(), data: vec![0xAA; 300], extra: Some(h.messages[9].1.encode()) }
                .encode(),
        ),
        (11, JudgeResponse { sealed: sealed.clone(), receipt: h.receipt.encode() }.encode()),
        (
            12,
            SignResponse {
                psbt: vec![0x70, 0x73, 0x62, 0x74, 0xff],
                receipt: h.receipt.encode(),
                receipt_sig: h.receipt_sig,
                session_id: [7; 16],
            }
            .encode(),
        ),
        (13, HeadersResponse { sealed, accepted: 3, best_height: 250_013 }.encode()),
    ]
}

fn tpm_seeds() -> Vec<Vec<u8>> {
    let h = honest();
    let mut raw = vec![0u8];
    raw.extend_from_slice(&h.attest);
    let mut v = vec![raw];
    // mode 1: a signature byte, then one byte of each field class
    // (which, pos, val): a signature byte, then one byte of each field class of the honest attest —
    // magic 0, signer 10/20, nonce 60, safe 92 (val 2 ⇒ XOR 3 ⇒ 2 > 1 ⇒ TPM_PARSE), firmware 100,
    // index name 110, the offset field 138, the counter 145, and 150 (wraps to the magic)
    for (which, pos, val) in [
        (0u8, 0u16, 0x01u8),
        (1, 0, 0x01),
        (1, 10, 0x01),
        (1, 20, 0x01),
        (1, 60, 0x01),
        (1, 92, 0x02),
        (1, 92, 0x01),
        (1, 100, 0x01),
        (1, 110, 0x01),
        (1, 138, 0x01),
        (1, 145, 0x01),
        (1, 150, 0x01),
    ] {
        v.push(vec![1, which, pos as u8, (pos >> 8) as u8, val]);
    }
    for counter in [42u64, 43, 41, 0, u64::MAX] {
        let mut s = vec![2u8];
        s.extend_from_slice(&counter.to_le_bytes());
        v.push(s);
    }
    v
}

fn cross_type_seeds() -> Vec<Vec<u8>> {
    let h = honest();
    let mut v = Vec::new();
    for (_, m, _) in &h.messages {
        let mut s = m.sig().to_vec();
        s.extend_from_slice(&m.encode());
        v.push(s);
    }
    let mut s = h.receipt_sig.to_vec();
    s.extend_from_slice(&h.receipt.encode());
    v.push(s);
    let mut s = h.card_sig.to_vec();
    s.extend_from_slice(&h.card.encode());
    v.push(s);
    let mut s = h.attest_sig.to_vec();
    s.extend_from_slice(&h.attest);
    v.push(s);
    v
}

fn encoding_seed() -> Vec<u8> {
    // low nibble: the primitive (0..=9), high nibble: the bound — as `targets::encoding_dec` reads an op
    let ops: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6 | (3 << 4), 7 | (2 << 4), 8 | (4 << 4), 9, 9];
    let mut e = Enc::new();
    e.u8(7).u16(513).u32(1 << 20).u64(u64::MAX).bool(true).fixed(&[9u8; 7]).bytes(b"abc").str("hi");
    e.list(&[1u8, 2, 3, 4], |e, v| {
        e.u8(*v);
    });
    e.option(Some(&0x2au8), |e, v| {
        e.u8(*v);
    });
    e.option(None::<&u8>, |e, v| {
        e.u8(*v);
    });
    let mut v = vec![ops.len() as u8];
    v.extend_from_slice(&ops);
    v.extend_from_slice(&e.finish());
    v
}

fn bip39_seeds() -> Vec<Vec<u8>> {
    vec![vec![0x80; 32], vec![0x00; 32], vec![0xff; 32], b"abandon abandon art".to_vec()]
}

/// C-R10P2-2: the no-wrap boundary, deterministically on both sides.
fn work_add_seeds() -> Vec<Vec<u8>> {
    let one = {
        let mut v = [0u8; 32];
        v[0] = 1;
        v
    };
    let top = {
        let mut v = [0u8; 32];
        v[31] = 0x80;
        v
    }; // 2^255
    let almost = {
        let mut v = [0xffu8; 32];
        v[31] = 0x7f;
        v
    }; // 2^255 - 1
    let cat = |a: [u8; 32], b: [u8; 32]| [a.as_slice(), b.as_slice()].concat();
    vec![
        cat([0xff; 32], one), // 2^256 - 1 + 1 = 2^256 → None
        cat(top, top),        // 2^255 + 2^255 = 2^256 → None
        cat([0xff; 32], [0xff; 32]),
        cat(almost, top), // 2^256 - 1 → Some
        cat([0xff; 32], [0; 32]),
        cat([0; 32], [0; 32]),
        cat(gen::work_of_bits(gen::REGTEST_BITS), gen::work_of_bits(gen::REGTEST_BITS)),
    ]
}

/// F6: raw regtest batches, scripted regtest sessions, the signet chain (clean and mutated), the no-wrap
/// boundary at the call site.
fn headers_seeds() -> Vec<Vec<u8>> {
    let (_s, cp) = gen::regtest_state(3);
    let mut raw5 = vec![0u8, 2]; // mode 0, max_reorg 3
    let mut prev = cp;
    for i in 0..5u32 {
        prev = gen::mine(&prev, prev.time + 10, 100 + i);
        raw5.extend_from_slice(&gen::raw(&prev));
    }
    let mut raw_garbage = vec![0u8, 2];
    raw_garbage.extend_from_slice(&[0x5a; 80]);
    let script = |mr: u8, ops: &[[u8; 3]]| {
        let mut v = vec![1u8, mr];
        for o in ops {
            v.extend_from_slice(o);
        }
        v
    };
    vec![
        raw5,
        raw_garbage,
        // extend 5; fork d2 k3 (adopted); fork d1 k1 (equal work, not adopted); fork d5 (> max_reorg 4) → frozen; then extend → CHAIN_REORG
        script(3, &[[0, 0, 5], [1, 2, 3], [1, 1, 1], [1, 5, 2], [0, 0, 2]]),
        // extend 12 in two halves; fork d0 k1 (a sibling tip, equal work); fork d3 k4 adopted
        script(7, &[[2, 6, 12], [1, 0, 1], [1, 3, 4]]),
        // the attach point fell out of recent: max_reorg 1 keeps 13, extend 20 then fork at depth 15
        script(0, &[[0, 0, 15], [0, 0, 5], [1, 15, 1]]),
        vec![2, 6, 31],                        // the real signet chain, 32 headers, clean
        vec![2, 6, 31, 0x10, 0x00, 0x01],      // one bit flipped in header 5
        vec![2, 6, 63, 0x13, 0x00, 0x80],      // 64 headers, a flip in header 61
        vec![2, 6, 31, 0x03, 0x4c, 0x01],      // header 10, a merkle-root byte: the proof of work no longer holds
        vec![4, 6, 31],                        // across the signet retarget boundary (2016 + 32 headers), one batch
        vec![4, 6, 31, 0, 0, 0, 7],            // the same, split in two at header 63
        vec![4, 6, 63, 0x05, 0x4c, 0x01, 200], // across the boundary, a flip in the tail, split late
        vec![2, 6, 31, 0x03, 0x68, 0x01],      // header 10, a bits byte: bits != required
        vec![5, 2, 1, 2, 4], // regtest past the boundary (+1); fork from the previous period, 4 blocks: adopted
        vec![5, 2, 0, 1, 1], // at the boundary; fork depth 2 with 1 block: equal work, not adopted
        vec![5, 0, 3, 7, 2], // max_reorg 1: a fork depth 2 → CHAIN_REORG, frozen
        [vec![3, 0], vec![0xff; 32]].concat(), // work at 2^256 - 1 → OVERFLOW
        [vec![3, 0], vec![0; 32]].concat(), // sane → Ok(1), work = the header's
        [vec![3, 0], {
            let mut w = vec![0u8; 32];
            w[31] = 0x80;
            w
        }]
        .concat(), // 2^255 + a header's work → fits
    ]
}

/// F4: scripted sessions over the honest state — one per invariant, incl. the negatives.
fn state_ops_seeds() -> Vec<Vec<u8>> {
    let r = |k: u8, f: u8, a: u8, b: u8| vec![k, f, a, b, 0, 0, 0, 0];
    let cat = |rs: &[Vec<u8>]| rs.concat();
    vec![
        cat(&[r(0, 4, 0, 0)]),                                 // identical update: tightening, applies now
        cat(&[r(0, 32, 0, 0)]),                                // a loosening: pending at best + 144
        cat(&[r(0, 32, 0, 0), r(9, 0, 0, 0), r(2, 0, 0, 0)]), // pending, +1 block (not due), unfreeze: pending untouched
        cat(&[r(0, 32, 0, 0), r(9, 0, 20, 0), r(2, 0, 0, 0)]), // pending, +161 blocks (due), unfreeze: it activates
        cat(&[r(0, 32, 0, 0), r(1, 0, 0, 0)]),                // pending, cancel by the owner
        cat(&[r(0, 32, 0, 0), r(1, 1, 0, 0)]),                // pending, cancel by the recovery key
        cat(&[r(0, 32, 0, 0), r(0, 4, 0, 0)]),                // a second update while pending: POLICY_PENDING
        cat(&[r(0, 1, 0, 0)]),                                // signed by a stranger
        cat(&[r(0, 2, 0, 0)]),                                // wrong nonce
        cat(&[r(0, 8, 3, 0)]),                                // re-pin to a verified recent header (pinned, forward)
        cat(&[r(0, 8, 0xff, 0)]),                             // a checkpoint one above the verified chain: refused
        cat(&[r(0, 64, 0, 0)]),                               // another network: POLICY_NETWORK
        cat(&[r(0, 128, 0, 0)]),                              // another wallet: POLICY_WALLET
        cat(&[r(10, 0, 0, 0), r(0, 16 | 32, 0xaa, 0)]), // frozen: a re-pin that also loosens: POLICY_INVALID (C-F01-2)
        cat(&[r(1, 8, 0, 0)]),                          // cancel addressed to another enclave: POLICY_SIG
        cat(&[r(0, 16, 0xaa, 0)]),                      // a checkpoint change nobody verified, unfrozen: refused
        cat(&[r(10, 0, 0, 0), r(0, 4, 0, 0)]),          // frozen: an identical update → CHAIN_REORG (O01)
        cat(&[r(10, 0, 0, 0), r(0, 32, 0, 0)]),         // frozen: a loosening → CHAIN_REORG (O01)
        cat(&[r(10, 0, 0, 0), r(0, 16, 0xaa, 0)]),      // frozen: checkpoint-only re-pin → applies, clears the freeze
        cat(&[r(10, 0, 0, 0), r(0, 16, 0xaa, 0), r(0, 4, 0, 0)]), // and the next ordinary update goes through again
        cat(&[r(2, 0, 0, 0)]),                          // unfreeze
        cat(&[r(3, 0, 7, 0)]),                          // rearm with seq 7
        cat(&[r(4, 0, 0, 0)]),                          // rotate to the witness key (pending owner)
        cat(&[r(4, 0, 0, 0), r(4, 0, 1, 0)]),           // a second rotation while one is pending
        cat(&[r(4, 0, 0, 0), r(9, 0, 30, 0), r(1, 0, 0, 0)]), // rotation due: the witness key is the owner; it cancels
        cat(&[r(4, 0, 2, 0x33)]),                       // rotate to a non-point: refused
        cat(&[r(4, 0, 3, 0)]),                          // rotate to the recovery key: refused
        cat(&[r(5, 0, 1, 0), r(0, 4, 0, 0)]),           // recover to the AK key; it updates
        cat(&[r(5, 2, 1, 0)]),                          // recover signed by the owner: refused
        cat(&[r(6, 0, 0, 0)]),                          // arm
        cat(&[r(6, 1, 0, 0)]),                          // arm with another load's challenge
        cat(&[r(6, 0, 9, 0)]),                          // arm claiming seq 9 the enclave never reached
        cat(&[r(11, 0, 0, 0), r(6, 0, 0, 0)]),          // the owner's freeze persists through arm (C-R7-6)
        cat(&[r(7, 0, 5, 6)]),                          // anchor counter 5, live 6
        cat(&[r(7, 0, 9, 3)]),                          // anchor counter 9, live 3: behind
        cat(&[r(7, 0, 5, 6), r(7, 0, 6, 8)]),           // re-anchor on the same objects
        cat(&[r(7, 0, 5, 6), r(7, 8, 6, 8)]),           // re-anchor naming another AK: ANCHOR_TPM_MISMATCH
        cat(&[r(7, 8, 5, 6)]),                          // first anchor under a foreign (valid) AK: accepted
        cat(&[r(7, 16, 5, 0x33)]),                      // an AK that is not a point: refused
        cat(&[r(7, 32, 0, 0)]),                         // a Cancel handed to apply_anchor: refused
        cat(&[r(6, 32, 0, 0)]),                         // a Cancel handed to apply_arm: refused
        cat(&[r(6, 2, 0, 0)]),                          // arm by a stranger: POLICY_SIG
        cat(&[r(6, 4, 0, 0)]),                          // arm with the wrong nonce: POLICY_NONCE
        cat(&[r(7, 4, 5, 6)]),                          // anchor with the wrong nonce: POLICY_NONCE
        cat(&[r(8, 0, 1, 0)]),                          // an Arm through apply_message: refused
        cat(&[r(8, 0, 2, 0)]),                          // an Anchor through apply_message: refused
        cat(&[r(8, 0, 0, 0)]),                          // a witness token through apply_message: refused
        cat(&[r(9, 0, 1, 0), r(0, 8, 0, 0)]),           // advance, then re-pin to the new best
        vec![],
    ]
}

/// The scripted spec of a sane payout: own(0,5) 2 000 000 in; unlisted 900 000 + own change (branch 1, index 0)
/// 1 098 000 out; fee 2 000. `[n_in, n_out, version, flags, lie, target] ‖ [kind, index, lo, hi]…` (amount =
/// 1000 + u16·1000 sat).
fn spend_spec(version: u8, flags: u8, lie: u8, target: u8) -> Vec<u8> {
    let mut v = vec![0, 1, version, flags, lie, target];
    v.extend_from_slice(&[0, 5, 0xcf, 0x07]); // own hinted, index 5, 2 000 000
    v.extend_from_slice(&[3, 1, 0x83, 0x03]); // unlisted (foreign) 900 000
    v.extend_from_slice(&[0, 1, 0x49, 0x04]); // own change: idx 1 → branch 1 index 0, 1 098 000
    v
}

/// F7: raw PSBTs (the honest build and garbage), the scripted build with every lie, the differential mode.
fn classify_seeds() -> Vec<Vec<u8>> {
    let mut v = Vec::new();
    let honest = policy::seed_psbt(&spend_spec(1, 0, 0, 0)).unwrap();
    v.push([vec![0u8], honest].concat());
    v.push([vec![0u8], vec![0x70, 0x73, 0x62, 0x74, 0xff, 0x00, 0x00]].concat()); // "psbt\xff" and nothing else
    v.push([vec![0u8], vec![0x5a; 64]].concat());
    v.push([vec![1u8, 0], spend_spec(1, 0, 0, 0)].concat()); // version 2, no rbf
    v.push([vec![1u8, 0], spend_spec(0, 1, 0, 0)].concat()); // version 1, rbf
    v.push([vec![1u8, 0], spend_spec(3, 0, 0, 0)].concat()); // version 3 (classify accepts; judge refuses)
    let mut cold = spend_spec(1, 0, 0, 0);
    cold[10] = 1;
    cold[11] = 3; // out 0 → trusted cold, index 3
    v.push([vec![1u8, 0], cold.clone()].concat());
    let mut beyond = spend_spec(1, 0, 0, 0);
    beyond[10] = 2; // out 0 → the cold wallet beyond the descriptor's gap: unlisted
    v.push([vec![1u8, 0], beyond].concat());
    let mut opret = spend_spec(1, 0, 0, 0);
    opret[1] = 2;
    opret.extend_from_slice(&[4, 0, 0, 0]); // + an OP_RETURN
    v.push([vec![1u8, 0], opret.clone()].concat()); // rule None: refused
    v.push([vec![1u8, 1], opret].concat()); // rule ZeroValue: accepted
    let mut unhinted = spend_spec(1, 0, 0, 0);
    unhinted[6] = 1; // own input without a hint: foreign class
    v.push([vec![1u8, 0], unhinted].concat());
    let mut foreign = spend_spec(1, 0, 0, 0);
    foreign[0] = 1;
    foreign.splice(10..10, [2u8, 9, 0xe8, 0x03]); // + a foreign input of 1 001 000
    v.push([vec![1u8, 0], foreign.clone()].concat());
    let mut far = spend_spec(1, 0, 0, 0);
    far[15] = 0xff; // own change idx 255 → branch 1 index 127: beyond gap 100
    v.push([vec![1u8, 0], far].concat());
    for lie in 1..=13u8 {
        v.push([vec![1u8, 0], spend_spec(1, 0, lie, 0)].concat());
        v.push([vec![1u8, 0], spend_spec(1, 0, lie, 1)].concat());
    }
    v.push(
        [vec![1u8, 0], {
            let mut d = foreign.clone();
            d[4] = 9;
            d[5] = 1;
            d
        }]
        .concat(),
    ); // the duplicate outpoint on input 1
    v.push(
        [vec![1u8, 0], {
            let mut d = foreign;
            d[4] = 5;
            d[5] = 1;
            d
        }]
        .concat(),
    ); // a foreign input dressed as ours
       // knobs: counts against the mandate (max 2), no script type allowed, an explicit SIGHASH_ALL; a raw PSBT without outputs
    let mut three_in = spend_spec(1, 0, 0, 0);
    three_in[0] = 2;
    three_in.splice(10..10, [2u8, 9, 0xe8, 0x03, 0u8, 12, 0xe8, 0x03]); // + a foreign and an own input
    v.push([vec![1u8, 2], three_in].concat()); // TOO_MANY_INPUTS
    let mut three_out = spend_spec(1, 0, 0, 0);
    three_out[1] = 2;
    three_out.extend_from_slice(&[3, 4, 0xe8, 0x03]); // + a third output
    v.push([vec![1u8, 2], three_out].concat()); // TOO_MANY_OUTPUTS
    v.push([vec![1u8, 4], spend_spec(1, 0, 0, 0)].concat()); // INPUT_SCRIPT_TYPE
    v.push([vec![1u8, 0], spend_spec(1, 2, 0, 0)].concat()); // an explicit SIGHASH_ALL: accepted
    v.push([vec![0u8], policy::seed_no_outputs()].concat()); // PSBT_PARSE
    v.push([vec![2u8], spend_spec(1, 0, 0, 0)].concat());
    v.push([vec![2u8], cold].concat());
    v
}

/// F8: `[flags, witness, seq, fill, best_delta, payjoin, scale] ‖ spec`.
fn judge_seeds() -> Vec<Vec<u8>> {
    let j = |flags: u8, witness: u8, seq: u8, fill: u8, delta: u8, payjoin: u8, scale: u8, spec: Vec<u8>| {
        [vec![flags, witness, seq, fill, delta, payjoin, scale], spec].concat()
    };
    let spend = spend_spec(1, 0, 0, 0);
    let mut big = spend_spec(1, 0, 0, 0);
    big[8] = 0x1f;
    big[9] = 0x4e; // in 20 000 000
    big[12] = 0x8f;
    big[13] = 0x38; // unlisted 14 480 000
    big[16] = 0x00;
    big[17] = 0x13; // change 4 865 000 → fee 655 000
    let mut huge = spend_spec(1, 0, 0, 0);
    huge[0] = 1;
    huge.splice(10..10, [0u8, 6, 0xff, 0xff]);
    huge[8] = 0xff;
    huge[9] = 0xff; // two own inputs near u64::MAX: the sum wraps
    let mut foreign = spend_spec(1, 0, 0, 0);
    foreign[0] = 1;
    foreign.splice(10..10, [2u8, 9, 0xe8, 0x03]);
    let mut all_foreign = spend_spec(1, 0, 0, 0);
    all_foreign[6] = 2;
    let mut opret = spend_spec(1, 0, 0, 0);
    opret[1] = 2;
    opret.extend_from_slice(&[4, 0, 0, 0]); // + an OP_RETURN
    let mut midfee = spend_spec(1, 0, 0, 0);
    midfee[16] = 0x19;
    midfee[17] = 0x04; // change 1 050 000 → fee 50 000
    let mut cold_big = spend_spec(1, 0, 0, 0);
    cold_big[8] = 0x60;
    cold_big[9] = 0xea; // in 60 001 000
    cold_big[10] = 1;
    cold_big[11] = 2;
    cold_big[12] = 0x5f;
    cold_big[13] = 0xea; // cold index 2, 60 000 000
    cold_big[16] = 0;
    cold_big[17] = 0; // change 1 000 → fee 0
    vec![
        j(0, 0, 0, 0, 0, 0, 0, spend.clone()),           // accept: the baseline spend
        j(1, 0, 0, 0, 0, 0, 0, spend.clone()),           // FROZEN
        j(2, 0, 0, 0, 0, 0, 0, spend.clone()),           // unarmed → FRESHNESS_SEQ_BEHIND, no disarm
        j(4, 0, 0, 0, 0, 0, 0, spend.clone()),           // chain frozen → CHAIN_REORG
        j(8, 0, 0, 0, 0, 0, 0, spend.clone()),           // expired
        j(16, 0, 0, 0, 0, 0, 0, spend.clone()),          // freshness required, no token → FRESHNESS_MISSING
        j(16, 1, 3, 0, 0, 0, 0, spend.clone()), // fresh token, last_seen == seq → accept, NO disarm (the C-R10-4 boundary)
        j(16, 1, 3, 1, 0, 0, 0, spend.clone()), // fresh token, last_seen below seq → accept
        j(16, 2, 3, 0, 0, 0, 0, spend.clone()), // verified, seq behind → FRESHNESS_SEQ_BEHIND WITH disarm (C-R10-4 positive)
        j(16, 3, 3, 0, 0, 0, 0, spend.clone()), // unverified token with a high seq → FRESHNESS_SIG, no disarm (C-R10-4 negative)
        j(16, 4, 3, 0, 0, 0, 0, spend.clone()), // tip lagging → FRESHNESS_TIP, no disarm
        j(16, 5, 3, 0, 0, 0, 0, spend.clone()), // unknown tip hash → FRESHNESS_TIP
        j(16, 6, 3, 0, 0, 0, 0, spend.clone()), // another enclave's token → FRESHNESS_SIG
        j(16, 7, 3, 0, 0, 0, 0, spend.clone()), // tip above best → FRESHNESS_TIP
        j(1 | 16, 2, 3, 0, 0, 0, 0, spend.clone()), // frozen wins over a seq-behind token: FROZEN, no disarm
        j(0, 0, 0, 0, 0, 0, 7, big.clone()), // caps scaled by 8: CAP_TX, CAP_UNLISTED_TX, FEE_ABS, CAP_WINDOW, CAP_UNLISTED_WINDOW
        j(0, 0, 0, 0, 0, 0, 0, big), // full caps: unlisted 14.48M > 1M → CAP_UNLISTED_TX, CAP_UNLISTED_WINDOW, FEE_ABS
        j(0, 0, 0, 250, 0, 0, 0, spend.clone()), // the window nearly spent: CAP_WINDOW / CAP_UNLISTED_WINDOW
        j(64, 0, 0, 250, 0, 0, 0, spend.clone()), // + a fee window cap, nearly spent → FEE_WINDOW too
        j(0, 0, 0, 0, 0, 0, 0, huge), // the sum wraps → OVERFLOW
        j(0, 0, 0, 0, 0, 0, 0, spend_spec(3, 0, 0, 0)), // version 3 → TX_VERSION
        j(32, 0, 0, 0, 0, 0, 0, spend_spec(1, 1, 0, 0)), // rbf while the mandate forbids it
        j(0, 0, 0, 0, 0, 0, 0, foreign.clone()), // a foreign input, payjoin None → INPUT_FOREIGN_FORBIDDEN
        j(0, 0, 0, 0, 0, 1, 0, foreign.clone()), // payjoin InflowOnly, net outflow > 0 → INPUT_FOREIGN_FORBIDDEN
        j(0, 0, 0, 0, 0, 2, 0, foreign), // payjoin OutflowAllowed → accept
        j(0, 0, 0, 0, 0, 2, 0, all_foreign), // nothing of ours to sign → INPUT_NOT_OWN
        j(0, 0, 7, 0, 200, 0, 0, spend.clone()), // best advanced 200 blocks, seq 7 → accept, seq 8
        j(16, 8, 3, 0, 0, 0, 0, spend), // a Cancel message offered as the witness → FRESHNESS_SIG, no disarm
        j(128, 0, 0, 0, 0, 0, 0, opret.clone()), // OP_RETURN allowed (ZeroValue) → accept; it charges nothing
        j(0, 0, 0, 0, 0, 0, 0, opret), // OP_RETURN under rule None: classify refuses, judge never runs
        j(0, 0, 0, 0, 0, 0, 8, midfee.clone()), // fee 50 000 with max_fee_rate = u64::MAX: no FEE_RATE; FEE_ABS (100k) does not bind → accept
        j(0, 0, 0, 0, 0, 0, 0, midfee),         // the same fee under the 100 sat/vB cap → FEE_RATE
        j(0, 0, 0, 0, 0, 0, 7, cold_big), // cold 60M with caps /128: CAP_TRUSTED_TX, CAP_TRUSTED_WINDOW (+ CAP_TX, CAP_WINDOW)
    ]
}

/// One scripted `dispatch` input: `[1, flags] ‖ steps` (`dispatch::dispatch_target` documents the record).
fn script(flags: u8, steps: &[[u8; 8]]) -> Vec<u8> {
    let mut v = vec![1u8, flags];
    for s in steps {
        v.extend_from_slice(s);
    }
    v
}

/// `dispatch` (F10) seeds: the honest requests of every op as raw inputs (mode 0), and scripted sequences (mode 1)
/// that reach every refusal of the shell — the two-phase rule, the boot-arm after a reload, the session mark on an
/// older blob, every TPM gate verdict, the anchor's own refusals, INSTALL's checks, the headers verifier's refusals
/// through the dispatcher, the witness token's disarm, mutated blobs and requests, the raw op surface.
fn dispatch_seeds() -> Vec<Vec<u8>> {
    const STATUS: u8 = 0;
    const POLICY: u8 = 1;
    const REPORT: u8 = 2;
    const FREEZE: u8 = 3;
    const HEADERS: u8 = 4;
    const APPLY: u8 = 5;
    const JUDGE: u8 = 6;
    const SIGN: u8 = 7;
    const NONCE: u8 = 8;
    const PROOF: u8 = 9;
    const RELOAD: u8 = 10;
    const RAW: u8 = 11;
    const INSTALL: u8 = 12;
    const TEST_INIT: u8 = 13;
    // step helpers: [kind, a, b (blob), c, d, e, f, g]
    let st = |kind: u8, a: u8| [kind, a, 0, 0, 0, 0, 0, 0];
    let judge_payout = [JUDGE, 4, 0, 0, 0, 0, 0, 0];
    let sign_last = [SIGN, 0, 0, 0, 0, 0, 0, 0];
    let headers = |n: u8, variant: u8, depth: u8| [HEADERS, n.saturating_sub(1), 0, variant, depth, 1, 0, 0];
    // APPLY: a = message kind (0 same mandate, 1 tighten, 2 loosen, 3 require freshness, 4 Cancel, 5 Unfreeze,
    // 6 Rearm, 7 Arm, 8 Anchor, 9 RotateOwner, 10 Recover, 11 WitnessToken, 12 max_outputs = 1), c = signer flags (1 stranger,
    // 2 wrong nonce, 4 wrong enclave id), d = message knobs (1 stale challenge, 2 seq ahead, 4 counter+1,
    // 8 other AK, 16 seq_seen-1, 32 other network, 64 other fingerprint, 128 a SHA-1 index Name), e = deposit variant (0x80 none)
    let apply = |kind: u8, c: u8, d: u8, e: u8| [APPLY, kind, 0, c, d, e, 0, 0];
    let mut v: Vec<Vec<u8>> = Vec::new();
    // --- mode 0: every op's honest request on a fresh regtest signer, plus the empty/unknown/garbage edges ---
    for (op_code, bytes) in dispatch::honest_requests() {
        let sel = dispatch::OPS.iter().position(|o| *o == op_code).expect("a known op") as u8;
        let mut s = vec![0u8, sel];
        s.extend_from_slice(&bytes);
        v.push(s);
    }
    v.push(vec![0, 1]); // STATUS with no bytes: STATE_UNSEALABLE
    v.push(vec![0, 14, 0xff, 0xff, 0xff, 0xff]); // an unknown op code
    v.push(vec![0, 0, 9, 9, 9]); // INIT on garbage: POLICY_INVALID
    v.push(vec![0, 12, 1, 2, 3]); // TEST_INIT on garbage
                                  // --- mode 1 ---
                                  // S1 the full flow: status, policy, headers, judge → sign, sign again (idempotent), a second payout
    v.push(script(
        0,
        &[
            st(STATUS, 0),
            st(POLICY, 0),
            headers(3, 0, 0),
            judge_payout,
            sign_last,
            st(STATUS, 0),
            sign_last,
            judge_payout,
            sign_last,
            st(POLICY, 0),
        ],
    ));
    // S2 the two-phase rule: another PSBT, a changed byte, garbage, the pre-charge blob, then the right one
    v.push(script(
        0,
        &[
            judge_payout,
            [SIGN, 1, 0, 0, 0, 0, 0, 0],
            [SIGN, 2, 0, 0x40, 0x11, 0, 0, 0],
            [SIGN, 3, 0, 0, 0, 0, 0, 0],
            [SIGN, 0, 1, 0, 0, 0, 0, 0],
            sign_last,
        ],
    ));
    // S3 REQ-r7: a reload is unarmed; Arm negatives (stale challenge, seq ahead, stranger, wrong nonce), the Arm,
    // then the ratcheted mark refuses the old blob
    v.push(script(
        0,
        &[
            judge_payout,
            st(RELOAD, 0),
            judge_payout,
            sign_last,
            apply(7, 0, 1, 0),
            apply(7, 0, 2, 0),
            apply(7, 1, 0, 0),
            apply(7, 2, 0, 0),
            apply(7, 0, 0, 0),
            st(STATUS, 0),
            judge_payout,
            sign_last,
            [JUDGE, 4, 3, 0, 0, 0, 0, 0],
        ],
    ));
    // S4 FREEZE / Unfreeze, and C-R7-6: a freeze taken while unarmed persists into the armed state
    v.push(script(
        0,
        &[
            st(FREEZE, 0),
            judge_payout,
            apply(5, 0, 0, 0),
            judge_payout,
            st(RELOAD, 0),
            st(FREEZE, 0),
            apply(7, 0, 0, 0),
            st(STATUS, 0),
            judge_payout,
            apply(5, 0, 0, 0),
            judge_payout,
            sign_last,
        ],
    ));
    // S5 owner messages: rotate (pending owner), a second rotate, cancel, a loosening (pending), a tightening (at once),
    // Recover by the recovery key, Rearm on an armed state, a WitnessToken as an owner message
    v.push(script(
        0,
        &[
            apply(9, 0, 0, 0),
            st(STATUS, 0),
            apply(9, 0, 0, 0),
            apply(4, 0, 0, 0),
            apply(2, 0, 0, 0),
            st(STATUS, 0),
            st(POLICY, 0),
            apply(1, 0, 0, 0),
            st(STATUS, 0),
            apply(10, 0, 0, 0),
            apply(6, 0, 0, 0),
            apply(11, 0, 0, 0),
            apply(0, 0, 0, 0),
            apply(3, 2, 0, 0),
            apply(1, 4, 0, 0),
        ],
    ));
    // S6 REQ-r9: Anchor, then the TPM gate on every Fresh op — no deposit, honest, stale counter, another AK, another
    // index, another nonce, a malformed attest, the host forgetting the increment; Stale ops need nothing
    v.push(script(
        0,
        &[
            apply(8, 0, 0, 0),
            st(STATUS, 0),
            [JUDGE, 4, 0, 0, 0, 0, 0, 7],
            [JUDGE, 4, 0, 0, 0, 0, 0, 0],
            [SIGN, 0, 0, 0, 0, 0, 0, 0],
            [FREEZE, 2, 0, 0, 0, 0, 0, 0],
            [HEADERS, 1, 0, 0, 0, 1, 3, 0],
            [HEADERS, 1, 0, 0, 0, 1, 4, 0],
            [HEADERS, 1, 0, 0, 0, 1, 5, 0],
            [HEADERS, 1, 0, 0, 0, 1, 6, 0],
            [HEADERS, 1, 0, 0, 0, 1, 0, 0x40],
            [FREEZE, 0, 0, 0, 0, 0, 0, 0],
            st(STATUS, 0),
            st(POLICY, 0),
            [FREEZE, 0, 0, 0, 0, 0, 0, 0],
        ],
    ));
    // S7 the anchor's own refusals: stale challenge, no deposit, the owner's counter above the live one, another AK in
    // the message, the honest anchor, a re-anchor naming another AK, a reload then a fresh proof arms the load
    v.push(script(
        0,
        &[
            apply(8, 0, 1, 0),
            apply(8, 0, 0, 0x80),
            apply(8, 0, 4, 0),
            apply(8, 0, 8, 0),
            apply(8, 0, 0, 0),
            apply(8, 0, 8, 0),
            st(RELOAD, 0),
            st(STATUS, 0),
            [JUDGE, 4, 0, 0, 0, 0, 0, 0],
            st(STATUS, 0),
            [SIGN, 0, 0, 0, 0, 0, 0, 0],
        ],
    ));
    // S8 a keys-only blob: STATUS says uninstalled, everything else refuses; INSTALL's refusals, the install, twice
    v.push(script(
        1,
        &[
            st(STATUS, 0),
            st(POLICY, 0),
            judge_payout,
            st(INSTALL, 1),
            st(INSTALL, 2),
            st(INSTALL, 3),
            st(INSTALL, 4),
            st(INSTALL, 5),
            st(INSTALL, 0),
            st(INSTALL, 0),
            headers(2, 0, 0),
            judge_payout,
            sign_last,
        ],
    ));
    // S9 headers through the dispatcher: a fork, bad bits, bad prev, bad time, not a multiple of 80, empty, a duplicate,
    // then a fork deeper than max_reorg: CHAIN_REORG and the frozen chain refuses the judge
    v.push(script(
        0,
        &[
            headers(4, 0, 0),
            headers(3, 1, 2),
            headers(2, 2, 1),
            headers(2, 3, 0),
            headers(2, 4, 1),
            headers(2, 5, 0),
            headers(1, 6, 0),
            headers(2, 7, 0),
            headers(8, 0, 0),
            headers(8, 1, 7),
            st(STATUS, 0),
            judge_payout,
        ],
    ));
    // S10 the witness token: freshness required, missing, fresh, seq-behind (disarm, the blob changes on a refusal),
    // unarmed judge, Rearm, a Cancel offered as the token, garbage extra, then scripted lies
    v.push(script(
        0,
        &[
            apply(3, 0, 0, 0),
            judge_payout,
            [JUDGE, 4, 0, 0, 0, 0, 1, 0],
            [JUDGE, 4, 0, 0, 0, 0, 2, 0],
            st(STATUS, 0),
            [JUDGE, 4, 0, 0, 0, 0, 1, 0],
            apply(6, 0, 0, 0),
            [JUDGE, 4, 0, 0, 0, 0, 1, 0],
            [JUDGE, 4, 0, 0, 0, 0, 3, 0],
            [JUDGE, 4, 0, 0, 0, 0, 4, 0],
            [JUDGE, 1, 0, 1, 2, 3, 1, 0],
            [JUDGE, 3, 0, 4, 5, 6, 1, 0],
            [JUDGE, 1, 0, 7, 8, 9, 1, 0],
            [JUDGE, 0, 0, 1, 1, 1, 1, 0],
        ],
    ));
    // S11 mutations: a flipped and a truncated blob on STATUS/POLICY, a changed request byte, REPORT's edges
    v.push(script(
        0,
        &[
            [STATUS, 0, 8, 0x80, 0x01, 0, 0, 0],
            [STATUS, 0, 9, 0, 3, 0, 0, 0],
            [POLICY, 0, 10, 0x40, 0x55, 0, 0, 0],
            [STATUS, 0, 11, 0x20, 0x80, 0, 0, 0],
            [JUDGE, 4, 0, 0x30, 0, 0x7f, 0, 0x80],
            [APPLY, 7, 0, 0, 0, 0, 0, 0x81],
            st(REPORT, 0),
            st(REPORT, 1),
            st(REPORT, 2),
            st(REPORT, 3),
            [REPORT, 0, 9, 0, 1, 0, 0, 0],
        ],
    ));
    // S12 the signet fixture state: judge → sign; a foreign header batch
    v.push(script(2, &[st(STATUS, 0), judge_payout, sign_last, headers(2, 0, 0), st(POLICY, 0)]));
    // S13 the cold wallet's seed under the hot wallet's mandate: nothing is ours
    v.push(script(4, &[st(STATUS, 0), judge_payout, [JUDGE, 1, 0, 2, 2, 2, 0, 0]]));
    // S14 an invalid identity key: KEY_DERIVATION and no blob at all
    v.push(script(8, &[st(STATUS, 0), judge_payout, st(POLICY, 0)]));
    // S15 the ABI checks and the recovery blob's mutation
    v.push(script(16, &[[STATUS, 0x33, 0, 0x77, 0, 0, 0, 0], judge_payout, sign_last]));
    // S16 raw ops: unknown, INIT honest, the reset through the raw route, TEST_INIT on garbage, STATUS on blob+junk
    v.push(script(
        0,
        &[
            [RAW, 14, 0, 0xfe, 0xff, 0, 0, 0],
            [RAW, 0, 0, 2, 3, 0, 0, 0],
            st(STATUS, 0),
            [RAW, 13, 0, 0, 0, 0, 0, 0],
            judge_payout,
            [RAW, 12, 0, 3, 1, 2, 3, 0],
            [RAW, 1, 0, 3, 1, 2, 3, 0],
            [RAW, 1, 0, 1, 0, 0, 0, 0],
            apply(7, 0, 0, 0),
            judge_payout,
        ],
    ));
    // S18 other networks: a testnet4 keys-only signer (the regtest mandate fails INSTALL's network check; judging a
    // keys-only blob is STATE_UNSEALABLE), an INIT request on testnet4 through the raw route, a network byte that is
    // no network (POLICY_NETWORK at TEST_INIT, so no blob at all)
    v.push(script(
        32,
        &[st(STATUS, 0), st(INSTALL, 0), judge_payout, [RAW, 0, 0, 2, 0, 0, 0, 0], st(STATUS, 0), judge_payout],
    ));
    v.push(script(64, &[st(STATUS, 0), st(POLICY, 0)]));
    // S19 keys-only: INSTALL with a mandate that decodes but fails validate (timelock 0), the install, a payout judged,
    // then a tightening classify feels (max_outputs = 1) — SIGN of the two-output PSBT refuses at its re-classification,
    // and so does the next JUDGE
    v.push(script(
        1,
        &[st(INSTALL, 6), st(INSTALL, 0), judge_payout, apply(12, 0, 0, 0), st(STATUS, 0), sign_last, judge_payout],
    ));
    // S20 an Anchor naming a SHA-1 index Name (POLICY_INVALID before any proof is read), the honest anchor, then the
    // same malformed name against the bound state (ANCHOR_TPM_MISMATCH first)
    v.push(script(0, &[apply(8, 0, 128, 0), st(STATUS, 0), apply(8, 0, 0, 0), apply(8, 0, 128, 0), st(STATUS, 0)]));
    // S17 the TPM ops alone: a proof before any nonce, two nonces (the first forgotten), a truncated proof, a deposit
    // nobody consumes, a proof with a MAX_ATTEST_LEN attest (580 bytes: refused at the 576-byte store), then a
    // mid-sequence TEST_INIT with the keys-only variant
    v.push(script(
        0,
        &[
            [PROOF, 0, 0, 1, 0, 0, 0, 0],
            st(NONCE, 0),
            st(NONCE, 0),
            [PROOF, 0x80, 0, 0, 3, 0, 0, 0],
            [PROOF, 0, 0, 0, 0, 0, 0, 0],
            judge_payout,
            st(NONCE, 0),
            [PROOF, 7, 0, 0, 0x11, 0, 0, 0],
            [TEST_INIT, 1, 0, 0, 0, 0, 0, 0],
            st(STATUS, 0),
            st(INSTALL, 0),
            judge_payout,
        ],
    ));
    v
}

fn vectors() -> Vec<serde_json::Value> {
    files(&root().join("../vectors/r1"))
        .into_iter()
        .filter(|p| p.extension().map(|e| e == "json").unwrap_or(false))
        .map(|p| serde_json::from_slice(&fs::read(p).unwrap()).unwrap())
        .collect()
}

/// Writes the deterministic hand-written seeds. Re-run after changing them, commit the result:
/// `TEE_FUZZ_SEEDS_OUT=seeds cargo test --no-default-features --test replay -- --ignored write_seeds`
/// (`corpus/<target>/` is the fuzzer-grown, minimised corpus and is never written by this test.)
#[test]
#[ignore]
fn write_seeds() {
    let Ok(out) = std::env::var("TEE_FUZZ_SEEDS_OUT") else {
        eprintln!("TEE_FUZZ_SEEDS_OUT not set; nothing written");
        return;
    };
    let out = root().join(out);
    let h = honest();
    let put = |target: &str, name: &str, bytes: &[u8]| {
        let dir = out.join(target);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(name), bytes).unwrap();
    };
    // proto
    for (i, (sel, bytes)) in proto_seeds().into_iter().enumerate() {
        let mut v = vec![sel];
        v.extend_from_slice(&bytes);
        put("proto_decode", &format!("seed-{i:02}-type-{sel}"), &v);
    }
    // mandates (own variants + every distinct mandate of the vector suite)
    let mut seen = std::collections::BTreeSet::new();
    for (name, m) in &h.mandates {
        let b = m.encode();
        if seen.insert(b.clone()) {
            put("mandate_decode", &format!("fixture-{name}"), &b);
        }
    }
    let vs = vectors();
    for v in &vs {
        let b = hex::decode(v["mandate_hex"].as_str().unwrap()).unwrap();
        if seen.insert(b.clone()) {
            put("mandate_decode", &format!("vector-{}", v["name"].as_str().unwrap()), &b);
        }
    }
    for (na, a) in &h.mandates {
        for (nb, b) in &h.mandates {
            put("mandate_compare", &format!("{na}--{nb}"), &pair(a, b));
        }
    }
    // messages (own variants + the vectors' witness tokens)
    for (name, m, _) in &h.messages {
        put("message_decode", &format!("fixture-{name}"), &m.encode());
    }
    for v in &vs {
        if let Some(w) = v["witness_hex"].as_str() {
            put("message_decode", &format!("vector-{}", v["name"].as_str().unwrap()), &hex::decode(w).unwrap());
        }
    }
    // states
    put("state_decode", "fixture-init-state", &h.state.encode());
    // a pending mandate and a pending owner, and the regtest network: the arms of `State::decode` the
    // fuzzer had not completed from the first seed set (coverage.sh, 2026-11-21 — no vector state carries a
    // pending mandate, and the fuzzer never assembled a whole inner mandate on its own)
    let mut s = h.state.clone();
    s.pending =
        Some(Pending { mandate: h.mandates[1].1.clone(), sig: [0x5a; 64], nonce: 9, activation_height: 250_200 });
    s.pending_owner = Some(PendingOwner { new_owner_pk: h.keys.witness.pk, activation_height: 250_200 });
    put("state_decode", "fixture-state-pending", &s.encode());
    let mut s = h.state.clone();
    s.network = Network::Regtest;
    put("state_decode", "fixture-state-regtest", &s.encode());
    let mut seen = std::collections::BTreeSet::new();
    for v in &vs {
        let b = hex::decode(v["state_hex"].as_str().unwrap()).unwrap();
        if seen.insert(b.clone()) {
            put("state_decode", &format!("vector-{}", v["name"].as_str().unwrap()), &b);
        }
    }
    for (i, s) in tpm_seeds().into_iter().enumerate() {
        put("tpm_attest", &format!("seed-{i:02}"), &s);
    }
    put("receipt_decode", "fixture-receipt", &h.receipt.encode());
    let mut r = h.receipt.clone();
    r.pending_hash = Some([0x77; 32]);
    put("receipt_decode", "fixture-receipt-pending", &r.encode());
    put("encoding_dec", "seed-walk", &encoding_seed());
    for (i, s) in bip39_seeds().into_iter().enumerate() {
        put("bip39", &format!("seed-{i:02}"), &s);
    }
    for (i, s) in cross_type_seeds().into_iter().enumerate() {
        put("cross_type", &format!("seed-{i:02}"), &s);
    }
    // phase 2, pass (i)
    for (i, s) in work_add_seeds().into_iter().enumerate() {
        put("work_add", &format!("seed-{i:02}"), &s);
    }
    for (i, s) in headers_seeds().into_iter().enumerate() {
        put("headers", &format!("seed-{i:02}"), &s);
    }
    for (i, s) in state_ops_seeds().into_iter().enumerate() {
        put("state_ops", &format!("seed-{i:02}"), &s);
    }
    // phase 2, pass (ii)
    for (i, s) in classify_seeds().into_iter().enumerate() {
        put("classify", &format!("seed-{i:02}"), &s);
    }
    for (i, s) in judge_seeds().into_iter().enumerate() {
        put("judge", &format!("seed-{i:02}"), &s);
    }
    // phase 2, pass (iii)
    for (i, s) in dispatch_seeds().into_iter().enumerate() {
        put("dispatch", &format!("seed-{i:02}"), &s);
    }
    // negative seeds: non-canonical and re-tagged inputs that must be REFUSED. They make the stable
    // replay itself a mutation detector (C-R10-7b): drop a `finish()`, a bound or a domain tag in
    // core and one of these turns the gate red without a fuzzer in the loop.
    let with_tail = |b: &[u8]| {
        let mut v = b.to_vec();
        v.push(0);
        v
    };
    put("mandate_decode", "negative-trailing-byte", &with_tail(&h.mandate.encode()));
    // validate's refusal arms the fuzzer had not reached on its own (coverage.sh, 2026-11-21): decode accepts,
    // validate refuses, the target stays total and skips C-R10-5 (the duplicate-label defence is validate's —
    // auditor, 2026-11-20)
    let mut m = h.mandate.clone();
    let dup = m.destinations.trusted[0].clone();
    m.destinations.trusted.push(dup);
    put("mandate_decode", "negative-invalid-dup-label", &m.encode());
    let mut m = h.mandate.clone();
    m.timelock_blocks = 0;
    put("mandate_decode", "negative-invalid-timelock-zero", &m.encode());
    put("state_decode", "negative-trailing-byte", &with_tail(&h.state.encode()));
    put("receipt_decode", "negative-trailing-byte", &with_tail(&h.receipt.encode()));
    for (name, m, _) in &h.messages {
        put("message_decode", &format!("negative-trailing-{name}"), &with_tail(&m.encode()));
    }
    for (name, new_tag) in [("cancel-owner", 3u8), ("unfreeze", 2), ("rotate-owner", 6), ("recover", 5)] {
        let (_, m, _) = h.messages.iter().find(|(n, _, _)| *n == name).unwrap();
        let mut b = m.encode();
        b[0] = new_tag;
        put("message_decode", &format!("negative-retagged-{name}"), &b);
        let mut c = m.sig().to_vec();
        c.extend_from_slice(&b);
        put("cross_type", &format!("negative-retagged-{name}"), &c);
    }
    for (i, (sel, bytes)) in proto_seeds().into_iter().enumerate() {
        let mut v = vec![sel];
        v.extend_from_slice(&with_tail(&bytes));
        put("proto_decode", &format!("negative-trailing-{i:02}-type-{sel}"), &v);
    }
    // a list whose count exceeds the bound (max 4, count 5) and a string above its bound (max 2, len 3)
    let mut e = Enc::new();
    e.list(&[1u8, 2, 3, 4, 5], |e, v| {
        e.u8(*v);
    });
    let mut v = vec![1u8, 8 | (4 << 4)];
    v.extend_from_slice(&e.finish());
    put("encoding_dec", "negative-list-over-bound", &v);
    // a count within the bound but beyond the bytes that remain: refused before the allocation
    let mut v = vec![1, 0xf8]; // one op: list, bound 15
    v.extend_from_slice(&10u32.to_le_bytes());
    v.extend_from_slice(&[1, 2]);
    put("encoding_dec", "negative-list-count-beyond-remaining", &v);
    let mut e = Enc::new();
    e.str("abc");
    let mut v = vec![1u8, 7 | (2 << 4)];
    v.extend_from_slice(&e.finish());
    put("encoding_dec", "negative-str-over-bound", &v);
    // an attest with a trailing byte (strict at_end) and one above MAX_ATTEST_LEN
    let mut a = vec![0u8];
    a.extend_from_slice(&with_tail(&h.attest));
    put("tpm_attest", "negative-trailing-byte", &a);
    let mut a = vec![0u8];
    a.extend_from_slice(&h.attest);
    a.extend_from_slice(&[0u8; 600]);
    put("tpm_attest", "negative-overlong", &a);
}
