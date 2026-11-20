# Study: Rust no_std staticlib inside an Intel SGX SDK enclave on SGX1 hardware (lab, 2026-11-03)

> Produced by a lab sub-session on the SGX build box in `~/btcpay-tee-lab/` (working tree left in place for inspection). HW mode, debug launch only (the box has no FLC). Every number below was measured that day; nothing was assumed.


Date: 2026-11-03T12:44Z - host: <build-box> (Intel(R) Xeon(R) CPU E3-1275 v6 @ 3.80GHz), kernel 5.15.0-138-generic, Ubuntu 22.04
Working tree: /home/andrey/btcpay-tee-lab/ (nothing written outside it except ~/.cargo registry cache)

## 0. Outcome summary

| Step | Result |
|---|---|
| 1. SDK sanity: SampleEnclave, SGX_MODE=HW SGX_DEBUG=1, ./app | PASS ("SampleEnclave successfully returned.") |
| 2. Rust #![no_std] staticlib (sha2 over alloc::Vec) linked into a C enclave, SHA-256 == sha256sum | PASS (3 vectors incl. 300,000-byte file) |
| 3. bitcoin 0.32 + secp256k1 0.29 no_std in the enclave: PSBT deserialize + BIP143 P2WPKH sighash + RFC6979 ECDSA DER | PASS (host verify_ecdsa OK, byte-identical to host signature) |
| Extra: Rust panic inside enclave | panic_handler -> abort() -> ecall returns 0x1006 SGX_ERROR_ENCLAVE_CRASHED |

## 1. Environment / versions (facts)

- SGX SDK: no /opt/intel/sgxsdk/version.txt; `strings libsgx_trts.a` -> `SGX_TRTS_VERSION_2.25.100.3`; PSW debs libsgx-urts/enclave-common/launch/aesm-launch-plugin = 2.25.100.3-jammy1
- Devices: /dev/isgx (legacy driver, 0666), /dev/sgx_provision, /dev/sgx_vepc; NO /dev/sgx_enclave. aesm_service running (pid 2580774). CPU flags: sgx (no sgx_lc => no FLC => debug launch only).
- Compiler/linker: gcc 11.4.0; the SDK buildenv.mk passes `-B/usr/local/bin` so the enclave is linked with **/usr/local/bin/ld = GNU ld 2.36.1** (system /usr/bin/ld is 2.38). GNU Make 4.3, OpenSSL 3.0.2.
- Rust: rustc 1.92.0 (ded5c06cf 2025-12-08), cargo 1.92.0, default toolchain, target x86_64-unknown-linux-gnu only. `cc` crate 1.11.0.
- Box load average was ~11 on 8 cores during the lab; builds used -j2 or default cargo.

## 2. Step 1 - SDK sanity

```
cd /home/andrey/btcpay-tee-lab && cp -r /opt/intel/sgxsdk/SampleCode/SampleEnclave ./SampleEnclave
source /opt/intel/sgxsdk/environment && cd SampleEnclave && make SGX_MODE=HW SGX_DEBUG=1 -j2 && ./app
```
Output (tail): `The project has been built in debug hardware mode.` then
```
Checksum(0x0x7ffc47071160, 100) = 0xfffd4143
Info: executing thread synchronization, please wait...
Info: SampleEnclave successfully returned.
Enter a character before exit ...
```
enclave.so = 470,280 B. sgx_sign "required memory 0x3fa000".

## 3. Step 2 / 3 - layout

```
btcpay-tee-lab/
  SampleEnclave/                 untouched copy, built (step 1)
  rcore/                         Rust staticlib (Cargo.toml, .cargo/config.toml, src/lib.rs, build-vv.log)
  enclave-lab/                   minimal C enclave + app derived from SampleEnclave (Makefile, App/App.c, Enclave/{Enclave.edl,Enclave.c,Enclave.lds,Enclave.config.xml})
  hostverify/                    std helper: generates the PSBT fixture (psbt.b64) and verifies the enclave signature
  scratch/                       extracted secp256k1 objects, sgx_sign dump, cc wrapper + cc-calls.log
  Makefile-vs-SampleEnclave.diff
  REPORT.md
```
Build/run:
```
source /opt/intel/sgxsdk/environment
cd /home/andrey/btcpay-tee-lab/enclave-lab && make SGX_MODE=HW SGX_DEBUG=1     # runs cargo build --release for ../rcore, links, signs
./app selftest | ./app panic | ./app hash [string] | ./app hash-file <path> | ./app psbt | ./app sign
cd ../hostverify && cargo build --release && ./target/release/hostverify verify <DER hex from ./app sign>
```

### 3.1 rcore/Cargo.toml (final)
```toml
[package]
name = "rcore"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["staticlib"]

[dependencies]
sha2 = { version = "0.10", default-features = false, features = ["force-soft"] }
bitcoin = { version = "0.32", default-features = false }
secp256k1 = { version = "0.29", default-features = false, features = ["alloc", "lowmemory"] }

[profile.dev]
panic = "abort"
opt-level = 2

[profile.release]
panic = "abort"
opt-level = 2
lto = true
codegen-units = 1
```

### 3.2 rcore/.cargo/config.toml
```toml
[build]
target = "x86_64-unknown-linux-gnu"
rustflags = ["-C", "relocation-model=pic"]
```
(rustc already defaults to relocation-model=pic for x86_64-unknown-linux-gnu staticlibs; the flag is explicit documentation, not a fix.)

### 3.3 rcore/src/lib.rs (final)
```rust
#![no_std]
extern crate alloc;

use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
use sha2::{Digest, Sha256};

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::key::CompressedPublicKey;
use bitcoin::psbt::Psbt;
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};

// Provided inside the enclave by libsgx_tstdc (malloc/free/memalign, weak) and libsgx_trts (abort).
extern "C" {
    fn malloc(size: usize) -> *mut u8;
    fn free(p: *mut u8);
    fn memalign(align: usize, size: usize) -> *mut u8;
    fn abort() -> !;
}

struct SgxTlibcAlloc;

unsafe impl GlobalAlloc for SgxTlibcAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // tlibc dlmalloc guarantees 16-byte alignment on x86_64.
        if layout.align() <= 16 {
            malloc(layout.size())
        } else {
            memalign(layout.align(), layout.size())
        }
    }
    unsafe fn dealloc(&self, p: *mut u8, _layout: Layout) {
        free(p)
    }
}

#[global_allocator]
static GLOBAL: SgxTlibcAlloc = SgxTlibcAlloc;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { abort() }
}

/// SHA-256 over a heap copy of `input`; writes 32 bytes to `out32`; returns 0 on success.
#[no_mangle]
pub extern "C" fn rcore_hash(input: *const u8, len: usize, out32: *mut u8) -> i32 {
    if out32.is_null() || (input.is_null() && len != 0) {
        return -1;
    }
    let src: &[u8] = if len == 0 { &[] } else { unsafe { core::slice::from_raw_parts(input, len) } };
    let copy: Vec<u8> = src.to_vec(); // exercises the global allocator
    let digest = Sha256::digest(&copy);
    unsafe { core::ptr::copy_nonoverlapping(digest.as_ptr(), out32, 32) };
    0
}

/// Bisect helper: 0 = no-op, 1 = heap alloc/free only, 2 = SHA-256 of a small constant.
#[no_mangle]
pub extern "C" fn rcore_selftest(stage: i32) -> i32 {
    match stage {
        0 => 0,
        1 => {
            let mut v: Vec<u8> = Vec::with_capacity(4096);
            for i in 0..4096u32 { v.push((i & 0xff) as u8); }
            let s: u32 = v.iter().map(|&b| b as u32).sum();
            if s == 4096 * 255 / 2 { 0 } else { 1 }
        }
        2 => {
            let d = Sha256::digest(b"abc");
            if d[0] == 0xba && d[31] == 0xad { 0 } else { 2 }
        }
        3 => panic!("deliberate panic inside the enclave"), // -> panic_handler -> abort() -> #UD -> SGX_ERROR_ENCLAVE_CRASHED
        _ => -1,
    }
}

// ---------------------------------------------------------------------------------------------
// Step 3: bitcoin + secp256k1 (no_std). TEST VECTOR ONLY - fixed key, fake outpoint.
// Must match hostverify/src/main.rs.
// ---------------------------------------------------------------------------------------------
const SK: [u8; 32] = [0x11; 32];
const PREV_TXID: [u8; 32] = [0xab; 32];
const PREV_VOUT: u32 = 1;
const PREV_VALUE_SAT: u64 = 100_000;
const SEND_SAT: u64 = 90_000;

/// Produced by `hostverify psbt` (bitcoin 0.32, std): unsigned 1-in/1-out tx + witness_utxo.
const PSBT_B64: &str = "cHNidP8BAFICAAAAAaurq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urAQAAAAD9////AZBfAQAAAAAAFgAU/HJQohHe3ccO5aJzjeXweBc1HO8AAAAAAAEBH6CGAQAAAAAAFgAU/HJQohHe3ccO5aJzjeXweBc1HO8AAA==";

/// Minimal standard-alphabet base64 decoder (bitcoin's `base64` feature pulls the std-enabled
/// `base64` crate, so we decode by hand in no_std).
fn b64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a') as u32 + 26),
            b'0'..=b'9' => Some((c - b'0') as u32 + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &c in s.as_bytes() {
        if c == b'=' { break; }
        if c == b'\n' || c == b'\r' || c == b' ' { continue; }
        acc = (acc << 6) | val(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

fn fixture(secp: &Secp256k1<secp256k1::SignOnly>) -> (SecretKey, Transaction, ScriptBuf, Amount) {
    let sk = SecretKey::from_slice(&SK).expect("valid test key");
    let pk = PublicKey::from_secret_key(secp, &sk);
    let spk = ScriptBuf::new_p2wpkh(&CompressedPublicKey(pk).wpubkey_hash());
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: alloc::vec![TxIn {
            previous_output: OutPoint { txid: Txid::from_byte_array(PREV_TXID), vout: PREV_VOUT },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::default(),
        }],
        output: alloc::vec![TxOut { value: Amount::from_sat(SEND_SAT), script_pubkey: spk.clone() }],
    };
    (sk, tx, spk, Amount::from_sat(PREV_VALUE_SAT))
}

/// Parses the embedded base64 PSBT with `bitcoin::psbt::Psbt::deserialize` and reports
/// out5 = [raw_len, n_inputs, n_outputs, witness_utxo.value_sat, unsigned_tx.output[0].value_sat].
#[no_mangle]
pub extern "C" fn rcore_psbt_test(out5: *mut u64) -> i32 {
    if out5.is_null() { return -1; }
    let raw = match b64_decode(PSBT_B64) { Some(v) => v, None => return -2 };
    let psbt = match Psbt::deserialize(&raw) { Ok(p) => p, Err(_) => return -3 };
    let wutxo_sat = psbt.inputs.get(0).and_then(|i| i.witness_utxo.as_ref()).map(|o| o.value.to_sat()).unwrap_or(0);
    let out0_sat = psbt.unsigned_tx.output.get(0).map(|o| o.value.to_sat()).unwrap_or(0);
    let vals = [raw.len() as u64, psbt.inputs.len() as u64, psbt.outputs.len() as u64, wutxo_sat, out0_sat];
    unsafe { core::ptr::copy_nonoverlapping(vals.as_ptr(), out5, 5) };
    0
}

/// Builds the 1-in/1-out P2WPKH spend, cross-checks it against the embedded PSBT, computes the
/// BIP143 sighash with SighashCache, signs ECDSA (RFC6979, deterministic) and writes the DER
/// signature. `*out_len` is IN: capacity of out_sig, OUT: bytes written. Returns 0 on success.
#[no_mangle]
pub extern "C" fn rcore_sign_p2wpkh_test(out_sig: *mut u8, out_len: *mut usize) -> i32 {
    if out_sig.is_null() || out_len.is_null() { return -1; }
    let cap = unsafe { *out_len };

    let secp = Secp256k1::signing_only(); // needs secp256k1 feature "alloc"; no rand needed
    let (sk, tx, spk, value) = fixture(&secp);

    // PSBT cross-check: the embedded PSBT must describe exactly this spend.
    let raw = match b64_decode(PSBT_B64) { Some(v) => v, None => return -2 };
    let psbt = match Psbt::deserialize(&raw) { Ok(p) => p, Err(_) => return -3 };
    if psbt.unsigned_tx != tx { return -4; }
    match psbt.inputs.get(0).and_then(|i| i.witness_utxo.as_ref()) {
        Some(w) if w.script_pubkey == spk && w.value == value => {}
        _ => return -5,
    }

    let sighash = match SighashCache::new(&tx).p2wpkh_signature_hash(0, &spk, value, EcdsaSighashType::All) {
        Ok(h) => h,
        Err(_) => return -6,
    };
    let msg = Message::from_digest(sighash.to_byte_array());
    let sig = secp.sign_ecdsa(&msg, &sk);
    let der = sig.serialize_der();
    if der.len() > cap { return -7; }
    unsafe {
        core::ptr::copy_nonoverlapping(der.as_ptr(), out_sig, der.len());
        *out_len = der.len();
    }
    0
}
```

### 3.4 enclave-lab/Enclave/Enclave.edl
```
enclave {
    trusted {
        public int ecall_rust_selftest(int stage);
        public int ecall_rust_hash([in, size=len] const uint8_t* in, size_t len, [out] uint8_t out32[32]);
        public int ecall_rust_psbt_test([out] uint64_t out5[5]);
        public int ecall_rust_sign_test([out, size=cap] uint8_t* out_sig, size_t cap, [out] size_t* out_len);
    };
    untrusted {
        void ocall_print_string([in, string] const char *str);
    };
};
```

### 3.5 enclave-lab/Enclave/Enclave.c
```c
#include <stdint.h>
#include <stddef.h>
#include "Enclave_t.h"

/* exported by librcore.a (Rust no_std staticlib) */
extern int rcore_hash(const uint8_t* input, size_t len, uint8_t* out32);
extern int rcore_selftest(int stage);
extern int rcore_psbt_test(uint64_t* out5);
extern int rcore_sign_p2wpkh_test(uint8_t* out_sig, size_t* out_len);

int ecall_rust_selftest(int stage) { return rcore_selftest(stage); }

int ecall_rust_hash(const uint8_t* in, size_t len, uint8_t out32[32])
{
    return rcore_hash(in, len, out32);
}

int ecall_rust_psbt_test(uint64_t out5[5]) { return rcore_psbt_test(out5); }

int ecall_rust_sign_test(uint8_t* out_sig, size_t cap, size_t* out_len)
{
    *out_len = cap;                               /* in: capacity, out: DER length */
    return rcore_sign_p2wpkh_test(out_sig, out_len);
}
```
Enclave.lds and Enclave.config.xml are byte-identical copies of SampleEnclave's (HeapMaxSize 0x100000 = 1 MiB, StackMaxSize 0x40000 = 256 KiB, TCSNum 10, DisableDebug 0). No tuning was needed.

### 3.6 enclave-lab/App/App.c
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "sgx_urts.h"
#include "Enclave_u.h"

#define ENCLAVE_FILENAME "enclave.signed.so"

void ocall_print_string(const char *str) { printf("%s", str); }

static void hex(const uint8_t *p, size_t n) { for (size_t i = 0; i < n; i++) printf("%02x", p[i]); }

static uint8_t *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb"); if (!f) { perror("fopen"); exit(2); }
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t *b = malloc((size_t)n + 1); if (fread(b, 1, (size_t)n, f) != (size_t)n) { perror("fread"); exit(2); }
    fclose(f); *len = (size_t)n; return b;
}

int main(int argc, char **argv)
{
    sgx_enclave_id_t eid = 0;
    sgx_status_t ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &eid, NULL);
    if (ret != SGX_SUCCESS) { printf("sgx_create_enclave failed: 0x%x\n", ret); return 1; }
    printf("enclave created, eid=%llu (SGX_DEBUG_FLAG=%d)\n", (unsigned long long)eid, SGX_DEBUG_FLAG);

    const char *mode = argc > 1 ? argv[1] : "hash";
    int rc = 0;
    if (strcmp(mode, "hash") == 0) {
        const char *s = argc > 2 ? argv[2] : "hello sgx";
        uint8_t out[32]; int r = -99;
        ret = ecall_rust_hash(eid, &r, (const uint8_t*)s, strlen(s), out);
        printf("ecall_rust_hash: status=0x%x rc=%d\nsha256(\"%s\") = ", ret, r, s); hex(out, 32); printf("\n");
        rc = (ret == SGX_SUCCESS && r == 0) ? 0 : 3;
    } else if (strcmp(mode, "hash-file") == 0 && argc > 2) {
        size_t n; uint8_t *buf = read_file(argv[2], &n);
        uint8_t out[32]; int r = -99;
        ret = ecall_rust_hash(eid, &r, buf, n, out);
        printf("ecall_rust_hash(file %s, %zu bytes): status=0x%x rc=%d\n", argv[2], n, ret, r); hex(out, 32); printf("  %s\n", argv[2]);
        free(buf);
        rc = (ret == SGX_SUCCESS && r == 0) ? 0 : 3;
    } else if (strcmp(mode, "selftest") == 0) {
        for (int st = 0; st <= 2; st++) { int r = -99; ret = ecall_rust_selftest(eid, &r, st); printf("selftest stage %d: status=0x%x rc=%d\n", st, ret, r); if (ret != SGX_SUCCESS) { rc = 3; break; } }
    } else if (strcmp(mode, "panic") == 0) {
        int r = -99; ret = ecall_rust_selftest(eid, &r, 3);
        printf("ecall_rust_selftest(3=panic): status=0x%x rc=%d (0x1006 = SGX_ERROR_ENCLAVE_CRASHED)\n", ret, r);
        rc = (ret == SGX_ERROR_ENCLAVE_CRASHED) ? 0 : 3;
    } else if (strcmp(mode, "psbt") == 0) {
        uint64_t o[5] = {0}; int r = -99;
        ret = ecall_rust_psbt_test(eid, &r, o);
        printf("ecall_rust_psbt_test: status=0x%x rc=%d raw_len=%llu inputs=%llu outputs=%llu witness_utxo_sat=%llu out0_sat=%llu\n", ret, r,
               (unsigned long long)o[0], (unsigned long long)o[1], (unsigned long long)o[2], (unsigned long long)o[3], (unsigned long long)o[4]);
        rc = (ret == SGX_SUCCESS && r == 0) ? 0 : 3;
    } else if (strcmp(mode, "sign") == 0) {
        uint8_t sig[80]; size_t n = 0; int r = -99;
        ret = ecall_rust_sign_test(eid, &r, sig, sizeof sig, &n);
        printf("ecall_rust_sign_test: status=0x%x rc=%d der_len=%zu\n", ret, r, n);
        if (ret == SGX_SUCCESS && r == 0) { printf("DER="); hex(sig, n); printf("\n"); }
        rc = (ret == SGX_SUCCESS && r == 0) ? 0 : 3;
    } else {
        printf("usage: %s selftest | panic | hash [string] | hash-file <path> | psbt | sign\n", argv[0]); rc = 1;
    }
    sgx_destroy_enclave(eid);
    return rc;
}
```

### 3.7 Makefile diff vs SampleEnclave (full file also at Makefile-vs-SampleEnclave.diff)
Key hunks: C-only App/Enclave; single EDL; `-L$(RCORE_DIR) -lrcore` inserted inside `--start-group ... --end-group` right after `-lsgx_tstdc`; a phony `rcore` target that runs `cargo build --release`; enclave link driven by `$(CC)` not `$(CXX)`; `.o` rules made to depend on the edger8r-generated `.h` (see error #3).
```diff
--- /home/andrey/btcpay-tee-lab/SampleEnclave/Makefile	2026-11-03 12:26:18.112069359 +0000
+++ /home/andrey/btcpay-tee-lab/enclave-lab/Makefile	2026-11-03 12:40:38.866521839 +0000
@@ -1,66 +1,19 @@
-#
-# Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
-#
-# Redistribution and use in source and binary forms, with or without
-# modification, are permitted provided that the following conditions
-# are met:
-#
-#   * Redistributions of source code must retain the above copyright
-#     notice, this list of conditions and the following disclaimer.
-#   * Redistributions in binary form must reproduce the above copyright
-#     notice, this list of conditions and the following disclaimer in
-#     the documentation and/or other materials provided with the
-#     distribution.
-#   * Neither the name of Intel Corporation nor the names of its
-#     contributors may be used to endorse or promote products derived
-#     from this software without specific prior written permission.
-#
-# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
-# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
-# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
-# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
-# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
-# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
-# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
-# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
-# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
-# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
-# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
-#
-#
-
-######## SGX SDK Settings ########
-
+# Derived from /opt/intel/sgxsdk/SampleCode/SampleEnclave/Makefile (SGX SDK 2.25).
+# Changes: pure-C App/Enclave, single EDL, Rust staticlib librcore.a linked into the enclave.
 SGX_SDK ?= /opt/intel/sgxsdk
 SGX_MODE ?= HW
 SGX_ARCH ?= x64
 SGX_DEBUG ?= 1
+CARGO ?= $(HOME)/.cargo/bin/cargo
+RCORE_SRC ?= ../rcore
+RCORE_DIR ?= $(RCORE_SRC)/target/x86_64-unknown-linux-gnu/release
 
 include $(SGX_SDK)/buildenv.mk
 
-ifeq ($(shell getconf LONG_BIT), 32)
-    SGX_ARCH := x86
-else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
-    SGX_ARCH := x86
-endif
-
-ifeq ($(SGX_ARCH), x86)
-    SGX_COMMON_FLAGS := -m32
-    SGX_LIBRARY_PATH := $(SGX_SDK)/lib
-    SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
-    SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
-else
-    SGX_COMMON_FLAGS := -m64
-    SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
-    SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
-    SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
-endif
-
-ifeq ($(SGX_DEBUG), 1)
-ifeq ($(SGX_PRERELEASE), 1)
-$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
-endif
-endif
+SGX_COMMON_FLAGS := -m64
+SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
+SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
+SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
 
 ifeq ($(SGX_DEBUG), 1)
         SGX_COMMON_FLAGS += -O0 -g
@@ -73,42 +26,27 @@
                     -Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow \
                     -Wcast-align -Wcast-qual -Wconversion -Wredundant-decls
 SGX_COMMON_CFLAGS := $(SGX_COMMON_FLAGS) -Wjump-misses-init -Wstrict-prototypes -Wunsuffixed-float-constants
-SGX_COMMON_CXXFLAGS := $(SGX_COMMON_FLAGS) -Wnon-virtual-dtor -std=c++11
 
 ######## App Settings ########
-
 ifneq ($(SGX_MODE), HW)
     Urts_Library_Name := sgx_urts_sim
 else
     Urts_Library_Name := sgx_urts
 endif
 
-App_Cpp_Files := App/App.cpp $(wildcard App/Edger8rSyntax/*.cpp) $(wildcard App/TrustedLibrary/*.cpp)
-App_Include_Paths := -IInclude -IApp -I$(SGX_SDK)/include
-
+App_C_Files := App/App.c
+App_Include_Paths := -IApp -I$(SGX_SDK)/include
 App_C_Flags := -fPIC -Wno-attributes $(App_Include_Paths)
-
-# Three configuration modes - Debug, prerelease, release
-#   Debug - Macro DEBUG enabled.
-#   Prerelease - Macro NDEBUG and EDEBUG enabled.
-#   Release - Macro NDEBUG enabled.
 ifeq ($(SGX_DEBUG), 1)
         App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
-else ifeq ($(SGX_PRERELEASE), 1)
-        App_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
 else
         App_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
 endif
-
-App_Cpp_Flags := $(App_C_Flags)
-App_Link_Flags := -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -lpthread 
-
-App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)
-
+App_Link_Flags := -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -lpthread
+App_C_Objects := $(App_C_Files:.c=.o)
 App_Name := app
 
 ######## Enclave Settings ########
-
 ifneq ($(SGX_MODE), HW)
     Trts_Library_Name := sgx_trts_sim
     Service_Library_Name := sgx_tservice_sim
@@ -118,40 +56,23 @@
 endif
 Crypto_Library_Name := sgx_tcrypto
 
-Enclave_Cpp_Files := Enclave/Enclave.cpp $(wildcard Enclave/Edger8rSyntax/*.cpp) $(wildcard Enclave/TrustedLibrary/*.cpp)
-Enclave_Include_Paths := -IInclude -IEnclave -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx
-
-Enclave_C_Flags := $(Enclave_Include_Paths) -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections $(MITIGATION_CFLAGS)
-CC_BELOW_4_9 := $(shell expr "`$(CC) -dumpversion`" \< "4.9")
-ifeq ($(CC_BELOW_4_9), 1)
-    Enclave_C_Flags += -fstack-protector
-else
-    Enclave_C_Flags += -fstack-protector-strong
-endif
+Enclave_C_Files := Enclave/Enclave.c
+Enclave_Include_Paths := -IEnclave -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc
+Enclave_C_Flags := $(Enclave_Include_Paths) -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections $(MITIGATION_CFLAGS) -fstack-protector-strong
 
-Enclave_Cpp_Flags := $(Enclave_C_Flags) -nostdinc++
-
-# Enable the security flags
 Enclave_Security_Link_Flags := -Wl,-z,relro,-z,now,-z,noexecstack
 
-# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
-#    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
-#       so that the whole content of trts is included in the enclave.
-#    2. For other libraries, you just need to pull the required symbols.
-#       Use `--start-group' and `--end-group' to link these libraries.
-# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
-# Otherwise, you may get some undesirable errors.
+# librcore.a is added inside the --start-group/--end-group, right after -lsgx_tstdc.
 Enclave_Link_Flags := $(MITIGATION_LDFLAGS) $(Enclave_Security_Link_Flags) \
     -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_TRUSTED_LIBRARY_PATH) \
 	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
-	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
+	-Wl,--start-group -lsgx_tstdc -L$(RCORE_DIR) -lrcore -lsgx_tcxx -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
 	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
 	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
 	-Wl,--defsym,__ImageBase=0 -Wl,--gc-sections   \
 	-Wl,--version-script=Enclave/Enclave.lds
 
-Enclave_Cpp_Objects := $(sort $(Enclave_Cpp_Files:.cpp=.o))
-
+Enclave_C_Objects := $(Enclave_C_Files:.c=.o)
 Enclave_Name := enclave.so
 Signed_Enclave_Name := enclave.signed.so
 Enclave_Config_File := Enclave/Enclave.config.xml
@@ -160,112 +81,70 @@
 ifeq ($(SGX_MODE), HW)
 ifeq ($(SGX_DEBUG), 1)
     Build_Mode = HW_DEBUG
-else ifeq ($(SGX_PRERELEASE), 1)
-    Build_Mode = HW_PRERELEASE
 else
     Build_Mode = HW_RELEASE
 endif
 else
-ifeq ($(SGX_DEBUG), 1)
     Build_Mode = SIM_DEBUG
-else ifeq ($(SGX_PRERELEASE), 1)
-    Build_Mode = SIM_PRERELEASE
-else
-    Build_Mode = SIM_RELEASE
-endif
 endif
 
-
-.PHONY: all target run
+.PHONY: all target run rcore clean
 all: .config_$(Build_Mode)_$(SGX_ARCH)
 	@$(MAKE) target
 
-ifeq ($(Build_Mode), HW_RELEASE)
-target:  $(App_Name) $(Enclave_Name)
-	@echo "The project has been built in release hardware mode."
-	@echo "Please sign the $(Enclave_Name) first with your signing key before you run the $(App_Name) to launch and access the enclave."
-	@echo "To sign the enclave use the command:"
-	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(Enclave_Name) -out <$(Signed_Enclave_Name)> -config $(Enclave_Config_File)"
-	@echo "You can also sign the enclave using an external signing tool."
-	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."
-
-
-else
 target: $(App_Name) $(Signed_Enclave_Name)
-ifeq ($(Build_Mode), HW_DEBUG)
-	@echo "The project has been built in debug hardware mode."
-else ifeq ($(Build_Mode), SIM_DEBUG)
-	@echo "The project has been built in debug simulation mode."
-else ifeq ($(Build_Mode), HW_PRERELEASE)
-	@echo "The project has been built in pre-release hardware mode."
-else ifeq ($(Build_Mode), SIM_PRERELEASE)
-	@echo "The project has been built in pre-release simulation mode."
-else
-	@echo "The project has been built in release simulation mode."
-endif
-
-endif
+	@echo "The project has been built in $(Build_Mode) mode."
 
 run: all
-ifneq ($(Build_Mode), HW_RELEASE)
 	@$(CURDIR)/$(App_Name)
-	@echo "RUN  =>  $(App_Name) [$(SGX_MODE)|$(SGX_ARCH), OK]"
-endif
 
 .config_$(Build_Mode)_$(SGX_ARCH):
-	@rm -f .config_* $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) $(App_Cpp_Objects) App/Enclave_u.* $(Enclave_Cpp_Objects) Enclave/Enclave_t.*
+	@rm -f .config_* $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) $(App_C_Objects) App/Enclave_u.* $(Enclave_C_Objects) Enclave/Enclave_t.*
 	@touch .config_$(Build_Mode)_$(SGX_ARCH)
 
-######## App Objects ########
+######## Rust staticlib ########
+# 'rcore' is phony so cargo (incremental) always gets a chance to rebuild the staticlib.
+rcore:
+	cd $(RCORE_SRC) && $(CARGO) build --release
+	@echo "RUST =>  $(RCORE_DIR)/librcore.a"
+$(RCORE_DIR)/librcore.a: rcore
 
+######## App Objects ########
 App/Enclave_u.h: $(SGX_EDGER8R) Enclave/Enclave.edl
 	@cd App && $(SGX_EDGER8R) --untrusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include
 	@echo "GEN  =>  $@"
-
 App/Enclave_u.c: App/Enclave_u.h
-
-App/Enclave_u.o: App/Enclave_u.c
+App/Enclave_u.o: App/Enclave_u.c App/Enclave_u.h
 	@$(CC) $(SGX_COMMON_CFLAGS) $(App_C_Flags) -c $< -o $@
 	@echo "CC   <=  $<"
-
-App/%.o: App/%.cpp  App/Enclave_u.h
-	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(App_Cpp_Flags) -c $< -o $@
-	@echo "CXX  <=  $<"
-
-$(App_Name): App/Enclave_u.o $(App_Cpp_Objects)
-	@$(CXX) $^ -o $@ $(App_Link_Flags)
+App/%.o: App/%.c App/Enclave_u.h
+	@$(CC) $(SGX_COMMON_CFLAGS) $(App_C_Flags) -c $< -o $@
+	@echo "CC   <=  $<"
+$(App_Name): App/Enclave_u.o $(App_C_Objects)
+	@$(CC) $^ -o $@ $(App_Link_Flags)
 	@echo "LINK =>  $@"
 
 ######## Enclave Objects ########
-
 Enclave/Enclave_t.h: $(SGX_EDGER8R) Enclave/Enclave.edl
 	@cd Enclave && $(SGX_EDGER8R) --trusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include
 	@echo "GEN  =>  $@"
-
 Enclave/Enclave_t.c: Enclave/Enclave_t.h
-
-Enclave/Enclave_t.o: Enclave/Enclave_t.c
+Enclave/Enclave_t.o: Enclave/Enclave_t.c Enclave/Enclave_t.h
 	@$(CC) $(SGX_COMMON_CFLAGS) $(Enclave_C_Flags) -c $< -o $@
 	@echo "CC   <=  $<"
-
-Enclave/%.o: Enclave/%.cpp Enclave/Enclave_t.h
-	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(Enclave_Cpp_Flags) -c $< -o $@
-	@echo "CXX  <=  $<"
-
-$(Enclave_Name): Enclave/Enclave_t.o $(Enclave_Cpp_Objects)
-	@$(CXX) $^ -o $@ $(Enclave_Link_Flags)
+Enclave/%.o: Enclave/%.c Enclave/Enclave_t.h
+	@$(CC) $(SGX_COMMON_CFLAGS) $(Enclave_C_Flags) -c $< -o $@
+	@echo "CC   <=  $<"
+$(Enclave_Name): Enclave/Enclave_t.o $(Enclave_C_Objects) $(RCORE_DIR)/librcore.a
+	$(CC) Enclave/Enclave_t.o $(Enclave_C_Objects) -o $@ $(Enclave_Link_Flags)
 	@echo "LINK =>  $@"
-
 $(Signed_Enclave_Name): $(Enclave_Name)
 ifeq ($(wildcard $(Enclave_Test_Key)),)
-	@echo "There is no enclave test key<Enclave_private_test.pem>."
-	@echo "The project will generate a key<Enclave_private_test.pem> for test."
+	@echo "No enclave test key; generating $(Enclave_Test_Key)"
 	@openssl genrsa -out $(Enclave_Test_Key) -3 3072
 endif
 	@$(SGX_ENCLAVE_SIGNER) sign -key $(Enclave_Test_Key) -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)
 	@echo "SIGN =>  $@"
 
-.PHONY: clean
-
 clean:
-	@rm -f .config_* $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) $(App_Cpp_Objects) App/Enclave_u.* $(Enclave_Cpp_Objects) Enclave/Enclave_t.* $(Enclave_Test_Key)
+	@rm -f .config_* $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) $(App_C_Objects) App/Enclave_u.* $(Enclave_C_Objects) Enclave/Enclave_t.*
```

### 3.8 hostverify/src/main.rs (std, host side)
```rust
//! Host-side (std) helper: builds the PSBT fixture embedded in rcore, and verifies the
//! DER signature produced inside the enclave against the same fixed test vector.
use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::key::CompressedPublicKey;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use base64::Engine;

// Same constants as rcore/src/lib.rs (TEST ONLY).
const SK: [u8; 32] = [0x11; 32];
const PREV_TXID: [u8; 32] = [0xab; 32];
const PREV_VOUT: u32 = 1;
const PREV_VALUE_SAT: u64 = 100_000;
const SEND_SAT: u64 = 90_000;

fn fixture() -> (SecretKey, PublicKey, Transaction, ScriptBuf, Amount) {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&SK).unwrap();
    let pk = PublicKey::from_secret_key(&secp, &sk);
    let spk = ScriptBuf::new_p2wpkh(&CompressedPublicKey(pk).wpubkey_hash());
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: Txid::from_byte_array(PREV_TXID), vout: PREV_VOUT },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::default(),
        }],
        output: vec![TxOut { value: Amount::from_sat(SEND_SAT), script_pubkey: spk.clone() }],
    };
    (sk, pk, tx, spk, Amount::from_sat(PREV_VALUE_SAT))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (sk, pk, tx, spk, value) = fixture();
    match args.get(1).map(String::as_str) {
        Some("psbt") => {
            let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
            psbt.inputs[0].witness_utxo = Some(TxOut { value, script_pubkey: spk });
            let raw = psbt.serialize();
            let b64 = base64::engine::general_purpose::STANDARD.encode(&raw);
            println!("{}", b64);
            eprintln!("psbt raw len={} b64 len={} inputs={} outputs={}", raw.len(), b64.len(), psbt.inputs.len(), psbt.outputs.len());
        }
        Some("verify") => {
            let der = hex::decode(args.get(2).expect("der hex")).expect("hex");
            let sighash = SighashCache::new(&tx)
                .p2wpkh_signature_hash(0, &spk, value, EcdsaSighashType::All)
                .unwrap();
            let msg = Message::from_digest(sighash.to_byte_array());
            let secp = Secp256k1::new();
            let sig = Signature::from_der(&der).expect("DER parse");
            let ok = secp.verify_ecdsa(&msg, &sig, &pk).is_ok();
            let host_sig = secp.sign_ecdsa(&msg, &sk);
            let same = host_sig.serialize_der().as_ref() == der.as_slice();
            println!("sighash(BIP143) = {}", hex::encode(sighash.to_byte_array()));
            println!("pubkey          = {}", hex::encode(pk.serialize()));
            println!("enclave DER     = {}", hex::encode(&der));
            println!("host DER        = {}", hex::encode(host_sig.serialize_der()));
            println!("verify_ecdsa    = {}", if ok { "OK" } else { "FAIL" });
            println!("byte-identical (RFC6979 deterministic) = {}", same);
            std::process::exit(if ok && same { 0 } else { 1 });
        }
        _ => { eprintln!("usage: hostverify psbt | verify <der-hex>"); std::process::exit(2); }
    }
}
```
hostverify/Cargo.toml deps: bitcoin = "0.32", base64 = "0.22", hex = "0.4". `hostverify psbt` printed (raw 127 B, base64 172 chars):
```
cHNidP8BAFICAAAAAaurq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urAQAAAAD9////AZBfAQAAAAAAFgAU/HJQohHe3ccO5aJzjeXweBc1HO8AAAAAAAEBH6CGAQAAAAAAFgAU/HJQohHe3ccO5aJzjeXweBc1HO8AAA==
```

## 4. Every error hit, in order, and the fix

1. **Link: `undefined reference to rust_eh_personality`** (first enclave link, Step 2)
   `librcore.a(alloc-06039bcfba61f665.alloc...rcgu.o):(.data.DW.ref.rust_eh_personality+0x0)`.
   Cause: the sysroot `alloc`/`core` rlibs are compiled with panic=unwind; their `.eh_frame`-referenced personality pointer survives `--gc-sections`.
   Fix (stable, no -Z): `lto = true` + `codegen-units = 1` in `[profile.release]`. After fat LTO the LTO'd object no longer references it (`nm -u` still shows 11 references inside unused compiler_builtins archive members, which the linker never pulls). A dummy `#[no_mangle] rust_eh_personality` was prepared as fallback but NOT needed. `_Unwind_Resume`: referenced only by never-pulled members, never an error. `__rust_probestack`: not referenced at all (inline stack probes); final enclave.so has no probestack/unwind symbols (only `rust_begin_unwind`, which is the panic entry point).
2. **Runtime: ecall returned 0x1006 SGX_ERROR_ENCLAVE_CRASHED** for every input (Step 2 first run).
   Diagnosis: `objdump -d enclave.so` showed the `cpuid` instruction inside `sha2::sha256::x86::shani_cpuid::init_get::init_inner::cpuid` / `cpuid_count` (the `cpufeatures` crate's runtime SHA-NI/AVX2 detection). CPUID is illegal inside an SGX enclave (#UD).
   Fix: `sha2 = { ..., features = ["force-soft"] }`. Verified: 0 `cpuid` instructions in the final enclave.so; staged selftest (no-op / alloc only / sha2) all return 0. Note: `cpufeatures` stays in the dependency graph but is not linked. **Any crate doing runtime CPU detection will crash the enclave the same way.** bitcoin_hashes/secp256k1 do no such detection (verified: 0 cpuid in final .so).
3. **`undefined reference to ecall_rust_selftest` when linking app, then status 0x3 / 0x1001 (SGX_ERROR_INVALID_FUNCTION)** after adding an ecall.
   Cause: ecall-table mismatch between app and enclave: edger8r regenerated Enclave_u.c/Enclave_t.c during the make run, but the `.o` rules only depended on the `.c` whose timestamp make had already stat'ed, so stale objects were linked (the same latent quirk exists in SampleEnclave's Makefile; a second `make` or `make clean` masks it).
   Fix: `App/Enclave_u.o: App/Enclave_u.c App/Enclave_u.h` and `Enclave/Enclave_t.o: Enclave/Enclave_t.c Enclave/Enclave_t.h`; `make clean`.
4. **Panic demo returned rc=-1 instead of crashing**: my Makefile's `librcore.a` rule had no prerequisites, so cargo was not re-run after editing lib.rs. Fix: phony `rcore` target as prerequisite of `librcore.a` (cargo is incremental, ~0.5 s when unchanged). After that: status=0x1006 as expected.
5. **Capturing secp256k1-sys cc flags**: `cargo build -vv` and `CC_ENABLE_DEBUG_OUTPUT=1` (cc 1.11.0) produced no "running:" lines (build-script stderr 0 bytes). Captured instead with a CC wrapper (scratch/cc-wrapper.sh) that logs argv and execs gcc.

Things that did NOT happen (checked, not assumed):
- No duplicate-symbol conflicts. compiler_builtins for x86_64-unknown-linux-gnu defines no `memcpy/memset/memcmp/memmove/bcmp` (nm on the sysroot rlib and on librcore.a: none; `mem` feature off). The enclave uses libsgx_tstdc's memcpy/memset (present in enclave.so). compiler_builtins' libm-style symbols (`floor sqrt fma ceil fmod trunc round rint fabs __udivti3 __umodti3 __divti3`) are **weak** in librcore.a vs **strong** in libsgx_tstdc.a -> no clash; `__popcountdi2` is strong in both but never pulled from both. `--allow-multiple-definition` was never used.
- No TEXTREL. librcore.a `.text` relocations are only R_X86_64_PC32/PLT32/GOTPCREL(X) (0 absolute relocs in .text; the 34k R_X86_64_32 are in non-alloc debug sections). secp256k1.o (compiled by cc) likewise: text relocs = 691 PC32, 94 PLT32, 11 REX_GOTPCRELX. Final enclave.so dynamic relocs:       2 R_X86_64_GLOB_DAT;     45 R_X86_64_RELATIVE; TEXTREL entries: 0. sgx_sign accepted it.
- No undefined symbols from the secp256k1 C code beyond what tstdc/trts provide: it needs `malloc free calloc memcpy memset memcmp memmove bcmp abort __stack_chk_fail` (+ `__memcpy_chk`-style fortify symbols which tstdc also exports). Default callbacks: secp256k1-sys defines `rustsecp256k1_v0_10_0_default_{illegal,error}_callback_fn` in Rust (lib.rs:958 ff., they panic -> abort), C side built with `-DUSE_EXTERNAL_DEFAULT_CALLBACKS=1` and `-Dprintf(...)=` so no libc I/O.

## 5. secp256k1-sys C build (facts)

Exact compiler invocation for secp256k1.c as issued by the `cc` crate (captured via scratch/cc-wrapper.sh; identical flags for lax_der_parsing.c, precomputed_ecmult.c, precomputed_ecmult_gen.c; 9 gcc invocations total incl. -E probes):
```
gcc -O2 -ffunction-sections -fdata-sections -fPIC -m64 -march=x86-64 -I depend/secp256k1/ -I depend/secp256k1/include -I depend/secp256k1/src -Wall -Wextra -fPIC -Wno-unused-function -Wno-unused-parameter -DSECP256K1_API= -DENABLE_MODULE_ECDH=1 -DENABLE_MODULE_SCHNORRSIG=1 -DENABLE_MODULE_EXTRAKEYS=1 -DENABLE_MODULE_ELLSWIFT=1 -Dprintf(...)= -DECMULT_WINDOW_SIZE=4 -DECMULT_GEN_PREC_BITS=2 -DUSE_EXTERNAL_DEFAULT_CALLBACKS=1 -o /home/andrey/btcpay-tee-lab/rcore/target/x86_64-unknown-linux-gnu/release/build/secp256k1-sys-e8a3bdcfd2d6899f/out/d41651a13ca9c479-secp256k1.o -c depend/secp256k1/src/secp256k1.c
```
Ubuntu's gcc 11 defaults add `-fstack-protector-strong`, `-fcf-protection=full`, `-fstack-clash-protection`, and `-D_FORTIFY_SOURCE=2` at -O2; all resulting symbols (`__stack_chk_fail`, `__*_chk`) exist in libsgx_tstdc.a. The SDK's own Enclave_C_Flags (`-nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections -fstack-protector-strong`) were NOT applied to the cc-built objects; they compile against the host glibc headers (header-only use) and link cleanly under `--no-undefined`.
lowmemory => `-DECMULT_WINDOW_SIZE=4 -DECMULT_GEN_PREC_BITS=2` (build.rs lines 35-36).

## 6. Crate graph, features, std exposure

`cargo tree -e normal -f "{p} [{f}]"` for rcore:
```
rcore v0.1.0 (/home/andrey/btcpay-tee-lab/rcore) []
├── bitcoin v0.32.102 []
│   ├── base58ck v0.1.101 []
│   │   └── bitcoin_hashes v0.14.101 [alloc,bitcoin-io,io]
│   │       ├── bitcoin-io v0.1.101 [alloc]
│   │       └── hex-conservative v0.2.3 [alloc]
│   │           └── arrayvec v0.7.8 []
│   ├── bech32 v0.11.1 [alloc]
│   ├── bitcoin-io v0.1.101 [alloc]
│   ├── bitcoin-units v0.1.101 [alloc]
│   ├── bitcoin_hashes v0.14.101 [alloc,bitcoin-io,io] (*)
│   ├── hex-conservative v0.2.3 [alloc] (*)
│   ├── hex_lit v0.1.1 []
│   └── secp256k1 v0.29.1 [alloc,hashes,lowmemory]
│       ├── bitcoin_hashes v0.14.101 [alloc,bitcoin-io,io] (*)
│       └── secp256k1-sys v0.10.1 [alloc,lowmemory]
├── secp256k1 v0.29.1 [alloc,hashes,lowmemory] (*)
└── sha2 v0.10.9 [force-soft]
    ├── cfg-if v1.0.5 []
    ├── cpufeatures v0.2.17 []
    └── digest v0.10.7 [block-buffer,core-api,default]
        ├── block-buffer v0.10.4 []
        │   └── generic-array v0.14.7 [more_lengths]
        │       └── typenum v1.20.1 []
        └── crypto-common v0.1.7 []
            ├── generic-array v0.14.7 [more_lengths] (*)
            └── typenum v1.20.1 []
```
- bitcoin 0.32.102 (what cargo resolved for "0.32" on 2026-11-03) depends on secp256k1 ^0.29.0 with features [hashes, alloc] and default-features=false -> resolved secp256k1 0.29.1 / secp256k1-sys 0.10.1. Our direct `secp256k1 = "0.29"` with [alloc, lowmemory] unifies with it.
- **rand**: NOT needed. `cargo tree` contains no rand/rand_core/getrandom. Signing uses `Secp256k1::signing_only()` (requires feature `alloc`) and `sign_ecdsa` (RFC6979). Context randomization (`Secp256k1::randomize`) would need feature `rand` + an in-enclave entropy source (sgx_read_rand via an ocall-free RngCore) - not done.
- Features that WOULD pull std if enabled (from the registry Cargo.toml files):
  - bitcoin: `std` = base58/std, bech32/std, hashes/std, hex/std, io/std, secp256k1/std, units/std; `rand-std`, `bitcoinconsensus-std` (= std); `base64` -> dep base64 0.21.3 declared WITHOUT default-features=false (base64 0.21 features: (base64 0.21 not in local registry; bitcoin 0.32.102 Cargo.toml declares [dependencies.base64] version=0.21.3 optional=true WITHOUT default-features=false)) so it brings std; `serde` -> serde default (std).
  - secp256k1 0.29.1: `std` = alloc + secp256k1-sys/std; `global-context` = std; `global-context-less-secure` -> global-context; `rand-std` = std + rand/std; `hashes-std` = std + hashes/std.
  - sha2: `std`; `asm` (not used).
- **bitcoin::psbt in no_std**: `pub mod psbt;` is unconditional (lib.rs:118) and `Psbt::deserialize` / `Psbt::from_unsigned_tx` / field access compile and run no_std (proved by ecall_rust_psbt_test). Items in src/psbt/mod.rs gated on `std`:
    21:#[cfg(feature = "std")]
    22-use std::collections::{HashMap, HashSet};
    829:#[cfg(feature = "std")]
    830-impl_get_key_for_set!(HashSet);
    867:#[cfg(feature = "std")]
    868-impl_get_key_for_pubkey_map!(HashMap);
    905:#[cfg(feature = "std")]
    906-impl_get_key_for_xonly_map!(HashMap);
    934:#[cfg(feature = "std")]
    935-impl std::error::Error for GetKeyError {
    1063:#[cfg(feature = "std")]
    1064-impl std::error::Error for SignError {
    1147:#[cfg(feature = "std")]
    1148-impl std::error::Error for ExtractTxError {
    1201:#[cfg(feature = "std")]
    1202-impl std::error::Error for IndexOutOfBoundsError {
    1249:    #[cfg(feature = "std")]
    1250-    impl std::error::Error for PsbtParseError {
    1949:            #[cfg(feature = "std")]
    1950-            assert_eq!(err.to_string(), "invalid taproot signature");
    1963:            #[cfg(feature = "std")]
    1964-            assert_eq!(err.to_string(), "invalid hash when parsing slice");
    1971:            #[cfg(feature = "std")]
    1972-            assert_eq!(err.to_string(), "invalid taproot signature");
    1979:            #[cfg(feature = "std")]
    1980-            assert_eq!(err.to_string(), "invalid taproot signature");
  Items gated on `base64` (the FromStr/Display base64 text form, which pulls std via the base64 crate):
    1212:#[cfg(feature = "base64")]
    1213-mod display_from_str {
    1214-    use core::convert::Infallible;
    --
    1276:#[cfg(feature = "base64")]
    1277-pub use self::display_from_str::PsbtParseError;
    1278-
    --
    1650:        #[cfg(feature = "base64")]
    1651-        use std::str::FromStr;
    1652-
    --
    1662:        #[cfg(feature = "base64")]
    1663-        #[test]
    1664-        #[should_panic(expected = "InvalidMagic")]
    --
    1676:        #[cfg(feature = "base64")]
    1677-        #[test]
    1678-        #[should_panic(expected = "ConsensusEncoding")]
    --
    1690:        #[cfg(feature = "base64")]
    1691-        #[test]
    1692-        #[should_panic(expected = "UnsignedTxHasScriptSigs")]
    --
    1703:        #[cfg(feature = "base64")]
    1704-        #[test]
    1705-        #[should_panic(expected = "MustHaveUnsignedTx")]
    --
    1716:        #[cfg(feature = "base64")]
    1717-        #[test]
    1718-        #[should_panic(expected = "DuplicateKey(Key { type_value: 0, key: [] })")]
    --
    1816:            #[cfg(feature = "base64")]
    1817-            {
    1818-                let base64str = "cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAAAA";
  => the enclave decodes base64 with a 20-line hand-written decoder and calls `Psbt::deserialize(&bytes)`.

## 7. Final run output (verbatim, HW mode, debug launch)

```
enclave created, eid=2 (SGX_DEBUG_FLAG=1)
selftest stage 0: status=0x0 rc=0
selftest stage 1: status=0x0 rc=0
selftest stage 2: status=0x0 rc=0
exit=0
enclave created, eid=2 (SGX_DEBUG_FLAG=1)
ecall_rust_selftest(3=panic): status=0x1006 rc=-99 (0x1006 = SGX_ERROR_ENCLAVE_CRASHED)
exit=0
enclave created, eid=2 (SGX_DEBUG_FLAG=1)
ecall_rust_hash: status=0x0 rc=0
sha256("hello sgx") = f368ef2e611d5301a2cbb29323ac5a261fce554471704f3af9698ce915b24676
exit=0
f368ef2e611d5301a2cbb29323ac5a261fce554471704f3af9698ce915b24676  -
enclave created, eid=2 (SGX_DEBUG_FLAG=1)
ecall_rust_hash: status=0x0 rc=0
sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  -
enclave created, eid=2 (SGX_DEBUG_FLAG=1)
ecall_rust_hash(file big.bin, 300000 bytes): status=0x0 rc=0
a85f2969bf734d96a2087ec0c13bfc7a34392f117f3e716293aca1c9d661b1cc  big.bin
a85f2969bf734d96a2087ec0c13bfc7a34392f117f3e716293aca1c9d661b1cc  big.bin
enclave created, eid=2 (SGX_DEBUG_FLAG=1)
ecall_rust_psbt_test: status=0x0 rc=0 raw_len=127 inputs=1 outputs=1 witness_utxo_sat=100000 out0_sat=90000
exit=0
enclave created, eid=2 (SGX_DEBUG_FLAG=1)
ecall_rust_sign_test: status=0x0 rc=0 der_len=70
DER=30440220653a8d9981fce77cccb20249b8481ba5115f93e279452d1b2e058477ee9f5ecc0220613e2299c97b13179700cb185f1216c6f5af603600264e46fd08c58e2b75172e
exit=0
sighash(BIP143) = 95f46345b2d9587d752498e0340c5fdca8f534059353d6fd0103bf1258bb61b4
pubkey          = 034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa
enclave DER     = 30440220653a8d9981fce77cccb20249b8481ba5115f93e279452d1b2e058477ee9f5ecc0220613e2299c97b13179700cb185f1216c6f5af603600264e46fd08c58e2b75172e
host DER        = 30440220653a8d9981fce77cccb20249b8481ba5115f93e279452d1b2e058477ee9f5ecc0220613e2299c97b13179700cb185f1216c6f5af603600264e46fd08c58e2b75172e
verify_ecdsa    = OK
byte-identical (RFC6979 deterministic) = true
hostverify exit=0
```
Test vector: sk = 0x11*32, prev outpoint ab..ab:1 (100,000 sat P2WPKH), 1 output 90,000 sat to the same P2WPKH, version 2, locktime 0, sequence 0xfffffffd, SIGHASH_ALL. Pubkey 034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa. BIP143 sighash 95f46345b2d9587d752498e0340c5fdca8f534059353d6fd0103bf1258bb61b4. DER length 70.

## 8. Sizes

```
28000 /home/andrey/btcpay-tee-lab/enclave-lab/app
410608 /home/andrey/btcpay-tee-lab/enclave-lab/enclave.signed.so
410608 /home/andrey/btcpay-tee-lab/enclave-lab/enclave.so
4699908 /home/andrey/btcpay-tee-lab/rcore/target/x86_64-unknown-linux-gnu/release/librcore.a
470280 /home/andrey/btcpay-tee-lab/SampleEnclave/enclave.so
```
- librcore.a history: 8,077,286 B (sha2 only, no LTO) -> 4,271,652 B (sha2 force-soft, LTO) -> 4,699,908 B (+ bitcoin + secp256k1, LTO). The archive carries the whole compiler_builtins rlib (297 members); only referenced members are linked.
- enclave.so history: 147,912 B (Step 2, sha2 only) -> 410,608 B (Step 3). SampleEnclave's enclave.so (C++ libcxx demo) is 470,280 B for comparison. Step-3 section sizes:
```
.text                251697     4128
.rodata               35840   262144
.eh_frame             18260   301496
.data.rel.ro            400   326656
.data                  8544   327680
.bss                  69264   338048
```
- sgx_sign "required memory": 0x40c000 (4,243,456 B) with the unchanged 1 MiB heap / 256 KiB stack / 10 TCS config. Signed enclave metadata:
```
metadata->enclave_size: 0x1000000
metadata->attributes.flags: 0x4
metadata->attributes.xfrm: 0xe7
metadata->enclave_css.body.misc_select: 0x0
metadata->enclave_css.body.misc_mask: 0xffffffff
metadata->enclave_css.body.attributes.flags: 0x4
metadata->enclave_css.body.attributes.xfrm: 0x3
metadata->enclave_css.body.attribute_mask.flags: 0xff00fffffffffffd
metadata->enclave_css.body.attribute_mask.xfrm: 0xffffffffffffff1b
```
(attributes.flags 0x4 = MODE64BIT; the DEBUG bit is set at load time by SGX_DEBUG_FLAG=1 because attribute_mask.flags leaves bit 1 unmasked. xfrm 0xe7 = x87|SSE|AVX|AVX-512 state allowed.)

## 9. What remains unproven / not done

- Only SGX_MODE=HW SGX_DEBUG=1 (debug launch via Intel LE) - production/pre-release launch is impossible on this SGX1-no-FLC box; nothing here says anything about a release-signed enclave.
- No attestation, no sealing, no key management: the secret key is a constant in the enclave binary (test vector only).
- secp256k1 context not randomized (no rand feature, no sgx_read_rand wiring) - side-channel blinding is off.
- Heap/stack limits untested beyond this workload (default 1 MiB / 256 KiB sufficed; no measurement of peak heap).
- Multi-threaded ecalls (TCSNum 10) with the Rust allocator untested (tlibc malloc is lock-protected but not exercised concurrently here).
- The C side was compiled -O0 -g (SGX_DEBUG=1); SGX_DEBUG=0 (HW_RELEASE needs a real signing flow) not built. Rust side is always release/LTO.
- sha2 runs the software path (force-soft); performance of SHA-NI paths and any crate using cpufeatures/is_x86_feature_detected is a hard crash, not a slowdown.
- bitcoin's base64 PSBT text form (FromStr/Display) not usable no_std (would pull std via base64 0.21 default features); a hand decoder was used. Psbt::sign() was not exercised (only deserialize + manual sighash/sign).
- Simulation mode (SGX_MODE=SIM) never tried.
- Not verified: behaviour of the enclave on a kernel/driver with /dev/sgx_enclave (only /dev/isgx here).

## 10. Reproduce from scratch
```
ssh <build-box>
source /opt/intel/sgxsdk/environment
cd /home/andrey/btcpay-tee-lab/enclave-lab && make clean && make SGX_MODE=HW SGX_DEBUG=1 && ./app selftest && ./app sign
cd ../hostverify && ~/.cargo/bin/cargo build --release && ./target/release/hostverify verify $(cd ../enclave-lab && ./app sign | grep ^DER= | cut -d= -f2)
```
