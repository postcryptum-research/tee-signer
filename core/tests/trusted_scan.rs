//! R11 (C-EXT1-4): the one-pass trusted-destination scan (`wallet::match_trusted_outputs`) held against the
//! per-output reference (`wallet::matches_trusted`) — the same destination per output in every order, the
//! derivation count, the cap refusing during the scan and never at the exact boundary, the Address matcher
//! both ways, first-match-in-list-order, and the validated worst case fitting `DERIVATION_CAP` exactly.
mod common;

use bitcoin::{Script, ScriptBuf};
use common::{secp, wallet, Wallet};
use signer_core::mandate::{Matcher, TrustedDest};
use signer_core::reason::Reason;
use signer_core::wallet::{derivation_cap_from_bounds, match_trusted_outputs, matches_trusted, DERIVATION_CAP};

fn desc(w: &Wallet, branches: &[u32], gap: u32, label: &str) -> TrustedDest {
    TrustedDest {
        label: label.into(),
        matcher: Matcher::Descriptor { xpub: w.xpub_bytes(), branches: branches.to_vec(), gap },
        max_per_tx: 1,
        max_per_window: 1,
    }
}

fn addr(spk: ScriptBuf, label: &str) -> TrustedDest {
    TrustedDest {
        label: label.into(),
        matcher: Matcher::Address { script_pubkey: spk.to_bytes() },
        max_per_tx: 1,
        max_per_window: 1,
    }
}

/// The reference: per output, the first destination (list order) whose matcher matches it.
fn reference(trusted: &[TrustedDest], scripts: &[&Script]) -> Vec<Option<usize>> {
    let secp = secp();
    scripts.iter().map(|s| trusted.iter().position(|d| matches_trusted(&secp, &d.matcher, s))).collect()
}

#[test]
fn one_pass_equals_the_per_output_walk_in_every_order() {
    let secp = secp();
    let (a, b, c, cold) = (wallet(1), wallet(2), wallet(3), wallet(4));
    let trusted = vec![
        desc(&a, &[0], 5, "a"),
        addr(cold.spk(0, 7), "cold"),
        desc(&b, &[0, 1], 7, "b"),
        desc(&a, &[1], 3, "a-change"),
        desc(&c, &[1], 4, "c"),
    ];
    let scripts: Vec<ScriptBuf> = vec![
        a.spk(0, 0),                      // a, inside the gap
        a.spk(0, 4),                      // a, the last index inside
        a.spk(0, 5),                      // a, one beyond the gap: unlisted
        a.spk(1, 2),                      // a's change branch: the fourth destination
        a.spk(1, 3),                      // beyond its gap
        b.spk(0, 6),                      // b, branch 0
        b.spk(1, 0),                      // b, branch 1
        b.spk(1, 7),                      // beyond
        c.spk(1, 3),                      // c, inside
        c.spk(0, 0),                      // c's branch 0 is not listed
        cold.spk(0, 7),                   // the address
        cold.spk(0, 8),                   // the cold wallet's next address: not the listed one
        wallet(9).spk(0, 0),              // a stranger
        ScriptBuf::new_op_return([1, 2]), // not P2WPKH
        a.spk(0, 0),                      // a duplicate of the first
    ];
    let refs: Vec<&Script> = scripts.iter().map(|s| s.as_script()).collect();
    let want = reference(&trusted, &refs);
    assert_eq!(
        want,
        vec![
            Some(0),
            Some(0),
            None,
            Some(3),
            None,
            Some(2),
            Some(2),
            None,
            Some(4),
            None,
            Some(1),
            None,
            None,
            None,
            Some(0)
        ]
    );
    let got = match_trusted_outputs(&secp, &trusted, &refs, DERIVATION_CAP).unwrap();
    assert_eq!(got.dest, want, "the one pass disagrees with the per-output walk");
    // every descriptor is scanned fully (an unmatched P2WPKH output remains throughout): 5 + 2·7 + 3 + 4
    assert_eq!(got.derivations, 26);
    for rot in 1..refs.len() {
        let mut r = refs.clone();
        r.rotate_left(rot);
        let mut w = want.clone();
        w.rotate_left(rot);
        assert_eq!(match_trusted_outputs(&secp, &trusted, &r, DERIVATION_CAP).unwrap().dest, w, "rotation {rot}");
    }
}

#[test]
fn the_cap_refuses_during_the_scan_and_never_at_the_boundary() {
    let secp = secp();
    let (a, b) = (wallet(1), wallet(2));
    let trusted = vec![desc(&a, &[0], 10, "a"), desc(&b, &[0, 1], 6, "b")]; // 10 + 2·6 = 22 candidates
    let stranger = wallet(9).spk(0, 0);
    let refs = vec![stranger.as_script()];
    let exact = match_trusted_outputs(&secp, &trusted, &refs, 22).unwrap();
    assert_eq!((exact.derivations, exact.dest), (22, vec![None]), "the cap at the exact count passes");
    assert_eq!(match_trusted_outputs(&secp, &trusted, &refs, 21).unwrap_err(), Reason::PolicyTooExpensive);
    // during the scan: with a cap below the first descriptor's gap the refusal comes inside that descriptor,
    // before the second — the one that would match — is touched
    let hit = b.spk(1, 0);
    let refs2 = vec![hit.as_script()];
    assert_eq!(match_trusted_outputs(&secp, &trusted, &refs2, DERIVATION_CAP).unwrap().dest, vec![Some(1)]);
    assert_eq!(match_trusted_outputs(&secp, &trusted, &refs2, 5).unwrap_err(), Reason::PolicyTooExpensive);
    // and it is fast: sixty-four descriptors of gap 1000 against a cap of 5 refuse after six derivations, not
    // after 128 000 — a generous wall-clock bound tells the two apart (128 000 derivations take seconds even in release)
    let big: Vec<TrustedDest> = (10u8..74).map(|s| desc(&wallet(s), &[0, 1], 1000, "d")).collect();
    let started = std::time::Instant::now();
    assert_eq!(match_trusted_outputs(&secp, &big, &refs, 5).unwrap_err(), Reason::PolicyTooExpensive);
    assert!(started.elapsed() < std::time::Duration::from_secs(2), "the refusal did not come during the scan");
}

#[test]
fn address_matcher_both_directions_and_no_derivation() {
    let secp = secp();
    let (a, cold) = (wallet(1), wallet(4));
    let trusted = vec![addr(cold.spk(0, 1), "cold")];
    let scripts = [cold.spk(0, 1), cold.spk(0, 2), a.spk(0, 0)];
    let refs: Vec<&Script> = scripts.iter().map(|s| s.as_script()).collect();
    let got = match_trusted_outputs(&secp, &trusted, &refs, DERIVATION_CAP).unwrap();
    assert_eq!(got.dest, vec![Some(0), None, None]);
    assert_eq!(got.derivations, 0, "an Address matcher derives nothing");
    assert_eq!(got.dest, reference(&trusted, &refs));
}

#[test]
fn first_match_in_list_order_wins() {
    let secp = secp();
    let a = wallet(1);
    let two = vec![desc(&a, &[0], 5, "first"), desc(&a, &[0], 5, "second")];
    let s = a.spk(0, 1);
    let refs = vec![s.as_script()];
    assert_eq!(match_trusted_outputs(&secp, &two, &refs, DERIVATION_CAP).unwrap().dest, vec![Some(0)]);
    let addr_after = vec![desc(&a, &[0], 5, "d"), addr(a.spk(0, 1), "same key as an address")];
    assert_eq!(match_trusted_outputs(&secp, &addr_after, &refs, DERIVATION_CAP).unwrap().dest, vec![Some(0)]);
    let addr_before = vec![addr(a.spk(0, 1), "address first"), desc(&a, &[0], 5, "d")];
    assert_eq!(match_trusted_outputs(&secp, &addr_before, &refs, DERIVATION_CAP).unwrap().dest, vec![Some(0)]);
    assert_eq!(reference(&addr_before, &refs), vec![Some(0)]);
    // a descriptor whose xpub does not decode matches nothing and stops nothing else
    let mut broken = desc(&a, &[0], 5, "broken");
    if let Matcher::Descriptor { xpub, .. } = &mut broken.matcher {
        xpub[0] ^= 0xff;
    }
    let with_broken = vec![broken, desc(&a, &[0], 5, "d")];
    assert_eq!(match_trusted_outputs(&secp, &with_broken, &refs, DERIVATION_CAP).unwrap().dest, vec![Some(1)]);
    assert_eq!(reference(&with_broken, &refs), vec![Some(1)]);
}

#[test]
fn cap_is_the_bounds_product() {
    assert_eq!(
        derivation_cap_from_bounds(),
        Some(DERIVATION_CAP),
        "DERIVATION_CAP must be MAX_TRUSTED × MAX_BRANCHES × MAX_GAP"
    );
}

/// The validated worst case — 64 descriptors × 2 branches × gap 1000 against 500 outputs — derives exactly
/// `DERIVATION_CAP` candidates and is not refused. Slow (128 000 derivations): run with
/// `cargo test --release --test trusted_scan -- --ignored`; the wall time is recorded in the R11 impl REQ.
#[test]
#[ignore = "128 000 derivations: cargo test --release --test trusted_scan -- --ignored"]
fn the_validated_worst_case_fits_the_cap_exactly() {
    let secp = secp();
    let trusted: Vec<TrustedDest> = (10u8..74).map(|s| desc(&wallet(s), &[0, 1], 1000, "d")).collect();
    assert_eq!(trusted.len(), 64);
    let stranger = wallet(200);
    let scripts: Vec<ScriptBuf> = (0..500u32).map(|i| stranger.spk(0, i)).collect();
    let refs: Vec<&Script> = scripts.iter().map(|s| s.as_script()).collect();
    let started = std::time::Instant::now();
    let got = match_trusted_outputs(&secp, &trusted, &refs, DERIVATION_CAP).expect("the worst case is not refused");
    let took = started.elapsed();
    assert_eq!(got.derivations, DERIVATION_CAP);
    assert!(got.dest.iter().all(Option::is_none));
    eprintln!("worst case: {} derivations in {took:?}", got.derivations);
}
