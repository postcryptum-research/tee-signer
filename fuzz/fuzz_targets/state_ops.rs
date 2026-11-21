#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| tee_signer_fuzz::structured::state_ops(data));
