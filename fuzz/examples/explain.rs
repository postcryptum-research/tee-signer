//! Explain a fuzz input: `cargo run --no-default-features --example explain -- <target> <file>`.
//! Decodes what the target sees and prints it, then runs the target body (so the oracle message, if
//! any, follows). For `mandate_compare` it prints both mandates and every field that differs — the
//! form a C-R10-5 finding is reported in.

use std::fs;

use arbitrary::Unstructured;
use signer_core::mandate::{compare, Change, Mandate};
use signer_core::update::Message;
use tee_signer_fuzz::targets::{self, TARGETS};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: explain <target> <file>");
        std::process::exit(2);
    }
    let target = args[1].as_str();
    let data = fs::read(&args[2]).expect("read input");
    println!("{} bytes for target {target}", data.len());
    match target {
        "mandate_compare" => {
            let la = u16::from_le_bytes([data[0], data[1]]) as usize;
            let (a_bytes, b_bytes) = data[2..].split_at(la);
            let a = Mandate::decode(a_bytes).expect("a decodes");
            println!("a: validate = {:?}", a.validate());
            // the same pairs the target checks, in the same order; a pair FIRES when both are valid,
            // distinct, and classify as Tightening in both directions
            let mut pairs: Vec<(String, Mandate, Mandate)> = Vec::new();
            if let Ok(b) = Mandate::decode(b_bytes) {
                pairs.push(("raw (a,b)".into(), a.clone(), b));
            }
            let mut u = Unstructured::new(b_bytes);
            if let Some(m1) = targets::mutate_mandate(&a, &mut u) {
                pairs.push(("(a,m1)".into(), a.clone(), m1.clone()));
                if let Some(m2) = targets::mutate_mandate(&m1, &mut u) {
                    pairs.push(("(a,m2)".into(), a.clone(), m2.clone()));
                    pairs.push(("(m1,m2)".into(), m1, m2));
                }
            }
            for (name, x, y) in &pairs {
                let (xy, yx) = (compare(x, y), compare(y, x));
                let valid = x.validate().is_ok() && y.validate().is_ok();
                let fires = valid && x != y && xy == Ok(Change::Tightening) && yx == Ok(Change::Tightening);
                println!(
                    "pair {name}: compare(x,y)={xy:?} compare(y,x)={yx:?} valid={valid} diff={:?}{}",
                    targets::mandate_diff(x, y),
                    if fires { "  FIRES" } else { "" }
                );
            }
        }
        "mandate_decode" => match Mandate::decode(&data) {
            Ok(m) => {
                let labels: Vec<&str> = m.destinations.trusted.iter().map(|t| t.label.as_str()).collect();
                println!(
                    "validate: {:?}; trusted labels: {labels:?}; compare(m,m) = {:?}",
                    m.validate(),
                    compare(&m, &m)
                );
            }
            Err(_) => println!("does not decode as a Mandate"),
        },
        "message_decode" => match Message::decode(&data) {
            Ok(m) => println!("{m:#?}"),
            Err(_) => println!("does not decode as a Message"),
        },
        _ => {}
    }
    let Some((_, f)) = TARGETS.iter().find(|(n, _)| *n == target) else {
        eprintln!("unknown target {target}");
        std::process::exit(2);
    };
    println!("running the target body …");
    f(&data);
    println!("no oracle fired");
}
