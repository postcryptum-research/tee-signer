//! R4 §5 negative vector (`SPEND_WITHOUT_RECEIPT`): the monitor must alarm when the wallet's coins
//! move without the enclave's receipt, i.e. when someone else holds the seed. This plays that
//! someone, from the mnemonic the OWNER printed with `recovery-verify --print-mnemonic`.
use std::io::Read;

use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::Network;

fn main() {
    let mut words = String::new();
    std::io::stdin().read_to_string(&mut words).expect("stdin");
    let network = std::env::args().nth(1).unwrap_or_else(|| "signet".into());
    let (net, coin) = match network.as_str() {
        "mainnet" => (Network::Bitcoin, 0u32),
        "regtest" => (Network::Regtest, 1u32),
        _ => (Network::Signet, 1u32),
    };
    let seed = signer_core::bip39::seed(words.trim());
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let master = Xpriv::new_master(net, &seed).expect("master");
    let path: DerivationPath = format!("m/84'/{coin}'/0'").parse().expect("path");
    let account = master.derive_priv(&secp, &path).expect("derive");
    println!("fingerprint {}", master.fingerprint(&secp));
    for branch in 0..2 {
        println!("wpkh({account}/{branch}/*)");
    }
}
