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
use tee_signer_fuzz::{gen, structured};

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
        [vec![3, 0], vec![0xff; 32]].concat(), // work at 2^256 - 1 → OVERFLOW
        [vec![3, 0], vec![0; 32]].concat(),    // sane → Ok(1), work = the header's
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
        cat(&[r(10, 0, 0, 0), r(0, 16 | 32, 0xaa, 0)]),       // frozen: a re-pin that also loosens: refused
        cat(&[r(1, 8, 0, 0)]),                                // cancel addressed to another enclave: POLICY_SIG
        cat(&[r(0, 16, 0xaa, 0)]),                            // a checkpoint change nobody verified, unfrozen: refused
        cat(&[r(10, 0, 0, 0), r(0, 4, 0, 0)]),                // frozen: an identical update → CHAIN_REORG (O01)
        cat(&[r(10, 0, 0, 0), r(0, 32, 0, 0)]),               // frozen: a loosening → CHAIN_REORG (O01)
        cat(&[r(10, 0, 0, 0), r(0, 16, 0xaa, 0)]), // frozen: checkpoint-only re-pin → applies, clears the freeze
        cat(&[r(10, 0, 0, 0), r(0, 16, 0xaa, 0), r(0, 4, 0, 0)]), // and the next ordinary update goes through again
        cat(&[r(2, 0, 0, 0)]),                     // unfreeze
        cat(&[r(3, 0, 7, 0)]),                     // rearm with seq 7
        cat(&[r(4, 0, 0, 0)]),                     // rotate to the witness key (pending owner)
        cat(&[r(4, 0, 0, 0), r(4, 0, 1, 0)]),      // a second rotation while one is pending
        cat(&[r(4, 0, 0, 0), r(9, 0, 30, 0), r(1, 0, 0, 0)]), // rotation due: the witness key is the owner; it cancels
        cat(&[r(4, 0, 2, 0x33)]),                  // rotate to a non-point: refused
        cat(&[r(4, 0, 3, 0)]),                     // rotate to the recovery key: refused
        cat(&[r(5, 0, 1, 0), r(0, 4, 0, 0)]),      // recover to the AK key; it updates
        cat(&[r(5, 2, 1, 0)]),                     // recover signed by the owner: refused
        cat(&[r(6, 0, 0, 0)]),                     // arm
        cat(&[r(6, 1, 0, 0)]),                     // arm with another load's challenge
        cat(&[r(6, 0, 9, 0)]),                     // arm claiming seq 9 the enclave never reached
        cat(&[r(11, 0, 0, 0), r(6, 0, 0, 0)]),     // the owner's freeze persists through arm (C-R7-6)
        cat(&[r(7, 0, 5, 6)]),                     // anchor counter 5, live 6
        cat(&[r(7, 0, 9, 3)]),                     // anchor counter 9, live 3: behind
        cat(&[r(7, 0, 5, 6), r(7, 0, 6, 8)]),      // re-anchor on the same objects
        cat(&[r(7, 0, 5, 6), r(7, 8, 6, 8)]),      // re-anchor naming another AK: ANCHOR_TPM_MISMATCH
        cat(&[r(7, 8, 5, 6)]),                     // first anchor under a foreign (valid) AK: accepted
        cat(&[r(7, 16, 5, 0x33)]),                 // an AK that is not a point: refused
        cat(&[r(7, 32, 0, 0)]),                    // a Cancel handed to apply_anchor: refused
        cat(&[r(6, 32, 0, 0)]),                    // a Cancel handed to apply_arm: refused
        cat(&[r(8, 0, 1, 0)]),                     // an Arm through apply_message: refused
        cat(&[r(8, 0, 2, 0)]),                     // an Anchor through apply_message: refused
        cat(&[r(8, 0, 0, 0)]),                     // a witness token through apply_message: refused
        cat(&[r(9, 0, 1, 0), r(0, 8, 0, 0)]),      // advance, then re-pin to the new best
        vec![],
    ]
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
