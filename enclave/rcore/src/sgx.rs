//! The SDK calls this crate makes, declared by hand (no bindgen in the TCB), and their `nosgx`
//! stand-ins for host-side tests of the dispatcher. Every `unsafe` block in the crate that
//! touches the SDK is in this file.

use alloc::vec::Vec;

/// `sgx_status_t` success.
#[cfg(not(feature = "nosgx"))]
const SGX_SUCCESS: u32 = 0;

#[cfg(not(feature = "nosgx"))]
mod ffi {
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct SgxAttributes {
        pub flags: u64,
        pub xfrm: u64,
    }
    extern "C" {
        pub fn sgx_read_rand(rand: *mut u8, len: usize) -> u32;
        pub fn sgx_calc_sealed_data_size(add_mac_txt_size: u32, txt_encrypt_size: u32) -> u32;
        pub fn sgx_seal_data_ex(
            key_policy: u16,
            attribute_mask: SgxAttributes,
            misc_mask: u32,
            add_mac_txt_len: u32,
            add_mac_txt: *const u8,
            txt_len: u32,
            txt: *const u8,
            sealed_size: u32,
            sealed: *mut u8,
        ) -> u32;
        pub fn sgx_get_add_mac_txt_len(sealed: *const u8) -> u32;
        pub fn sgx_get_encrypt_txt_len(sealed: *const u8) -> u32;
        pub fn sgx_unseal_data(
            sealed: *const u8,
            add_mac_txt: *mut u8,
            add_mac_txt_len: *mut u32,
            txt: *mut u8,
            txt_len: *mut u32,
        ) -> u32;
        pub fn sgx_create_report(target_info: *const u8, report_data: *const u8, report: *mut u8) -> u32;
    }
    /// `SGX_KEYPOLICY_MRENCLAVE`.
    pub const KEYPOLICY_MRENCLAVE: u16 = 0x0001;
    /// The SDK's `TSEAL_DEFAULT_FLAGSMASK`: every security-relevant attribute bit is bound.
    pub const FLAGS_MASK: u64 = 0xFF00_0000_0000_000B;
    /// The SDK's `TSEAL_DEFAULT_MISCMASK`.
    pub const MISC_MASK: u32 = 0xF000_0000;
    /// `sizeof(sgx_report_t)`.
    pub const REPORT_SIZE: usize = 432;
    /// `sizeof(sgx_target_info_t)`.
    pub const TARGET_INFO_SIZE: usize = 512;
    /// Offset of `mr_enclave` inside `sgx_report_body_t`.
    pub const MRENCLAVE_OFFSET: usize = 64;
}

/// Fill `buf` from the hardware source. Aborts the enclave on failure: there is no acceptable
/// fallback for randomness (REQ-prover-randomness discipline, carried).
pub fn read_rand(buf: &mut [u8]) {
    #[cfg(not(feature = "nosgx"))]
    {
        // SAFETY: buf is a valid, writable slice; the SDK writes exactly len bytes.
        let rc = unsafe { ffi::sgx_read_rand(buf.as_mut_ptr(), buf.len()) };
        if rc != SGX_SUCCESS {
            abort();
        }
    }
    #[cfg(feature = "nosgx")]
    {
        // deterministic stand-in for host tests: SHA-256 counter stream, NEVER used in an enclave
        use core::sync::atomic::{AtomicU64, Ordering};
        static CTR: AtomicU64 = AtomicU64::new(0x5eed);
        let mut off = 0usize;
        while off < buf.len() {
            let c = CTR.fetch_add(1, Ordering::SeqCst);
            let block = signer_core::sha256(&c.to_le_bytes());
            let n = (buf.len() - off).min(32);
            buf[off..off + n].copy_from_slice(&block[..n]);
            off += n;
        }
    }
}

mod libc_abort {
    extern "C" {
        pub fn abort() -> !;
    }
}

/// Abort the enclave (`SGX_ERROR_ENCLAVE_CRASHED` at the host); the host's libc `abort` under
/// `nosgx`.
#[allow(dead_code)]
pub fn abort() -> ! {
    // SAFETY: never returns.
    unsafe { libc_abort::abort() }
}

/// Seal `plain` with `aad` under the MRENCLAVE policy.
pub fn seal(aad: &[u8], plain: &[u8]) -> Option<Vec<u8>> {
    #[cfg(not(feature = "nosgx"))]
    {
        let aad_len = u32::try_from(aad.len()).ok()?;
        let txt_len = u32::try_from(plain.len()).ok()?;
        // SAFETY: pure computation on lengths.
        let size = unsafe { ffi::sgx_calc_sealed_data_size(aad_len, txt_len) };
        if size == u32::MAX {
            return None;
        }
        let mut out = alloc::vec![0u8; size as usize];
        let mask = ffi::SgxAttributes { flags: ffi::FLAGS_MASK, xfrm: 0 };
        // SAFETY: all buffers are sized as the SDK requires; `out` has `size` bytes.
        let rc = unsafe {
            ffi::sgx_seal_data_ex(
                ffi::KEYPOLICY_MRENCLAVE,
                mask,
                ffi::MISC_MASK,
                aad_len,
                aad.as_ptr(),
                txt_len,
                plain.as_ptr(),
                size,
                out.as_mut_ptr(),
            )
        };
        if rc != SGX_SUCCESS {
            return None;
        }
        Some(out)
    }
    #[cfg(feature = "nosgx")]
    {
        // host stand-in: a tagged, UNENCRYPTED container; tests only
        let mut out = alloc::vec::Vec::new();
        out.extend_from_slice(b"NOSGX-SEAL-V1");
        out.extend_from_slice(&(aad.len() as u32).to_le_bytes());
        out.extend_from_slice(aad);
        out.extend_from_slice(&(plain.len() as u32).to_le_bytes());
        out.extend_from_slice(plain);
        Some(out)
    }
}

/// Unseal; returns `(aad, plain)`. The sealed bytes are untrusted host input: a MAC failure is
/// `None`, never a partial result.
pub fn unseal(sealed: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    #[cfg(not(feature = "nosgx"))]
    {
        // sgx_sealed_data_t header is 560 bytes; the SDK validates the full structure
        if sealed.len() < 560 {
            return None;
        }
        // SAFETY: `sealed` is a readable buffer the bridge copied into the enclave; the SDK
        // bounds-checks its own structure before trusting any length in it.
        let aad_len = unsafe { ffi::sgx_get_add_mac_txt_len(sealed.as_ptr()) };
        let txt_len = unsafe { ffi::sgx_get_encrypt_txt_len(sealed.as_ptr()) };
        if aad_len == u32::MAX || txt_len == u32::MAX {
            return None;
        }
        let mut aad = alloc::vec![0u8; aad_len as usize];
        let mut txt = alloc::vec![0u8; txt_len as usize];
        let mut aad_out = aad_len;
        let mut txt_out = txt_len;
        // SAFETY: output buffers sized from the SDK's own accessors.
        let rc = unsafe {
            ffi::sgx_unseal_data(sealed.as_ptr(), aad.as_mut_ptr(), &mut aad_out, txt.as_mut_ptr(), &mut txt_out)
        };
        if rc != SGX_SUCCESS || aad_out != aad_len || txt_out != txt_len {
            return None;
        }
        Some((aad, txt))
    }
    #[cfg(feature = "nosgx")]
    {
        let tag = b"NOSGX-SEAL-V1";
        if sealed.len() < tag.len() + 8 || &sealed[..tag.len()] != tag {
            return None;
        }
        let mut p = tag.len();
        let al = u32::from_le_bytes(sealed[p..p + 4].try_into().ok()?) as usize;
        p += 4;
        let aad = sealed.get(p..p + al)?.to_vec();
        p += al;
        let tl = u32::from_le_bytes(sealed.get(p..p + 4)?.try_into().ok()?) as usize;
        p += 4;
        let txt = sealed.get(p..p + tl)?.to_vec();
        if p + tl != sealed.len() {
            return None;
        }
        Some((aad, txt))
    }
}

/// This enclave's MRENCLAVE from a self-report (zeros under `nosgx`).
pub fn mrenclave() -> [u8; 32] {
    #[cfg(not(feature = "nosgx"))]
    {
        let target = [0u8; ffi::TARGET_INFO_SIZE];
        let data = [0u8; 64];
        let mut report = [0u8; ffi::REPORT_SIZE];
        // SAFETY: buffers are the SDK's documented sizes; a null target yields a self-report.
        let rc = unsafe { ffi::sgx_create_report(target.as_ptr(), data.as_ptr(), report.as_mut_ptr()) };
        if rc != SGX_SUCCESS {
            abort();
        }
        let mut m = [0u8; 32];
        m.copy_from_slice(&report[ffi::MRENCLAVE_OFFSET..ffi::MRENCLAVE_OFFSET + 32]);
        m
    }
    #[cfg(feature = "nosgx")]
    {
        [0u8; 32]
    }
}

/// The tier label this build runs under.
pub fn tier() -> &'static str {
    #[cfg(feature = "nosgx")]
    {
        "T0-nosgx"
    }
    #[cfg(not(feature = "nosgx"))]
    {
        // The launch mode is decided by the host flag and the signed config; the binary cannot see
        // the DEBUG attribute without a report — the report's attributes carry it.
        if debug_attribute_set() {
            "T1-debug"
        } else {
            "T2-release"
        }
    }
}

#[cfg(not(feature = "nosgx"))]
fn debug_attribute_set() -> bool {
    let target = [0u8; ffi::TARGET_INFO_SIZE];
    let data = [0u8; 64];
    let mut report = [0u8; ffi::REPORT_SIZE];
    // SAFETY: as in `mrenclave`.
    let rc = unsafe { ffi::sgx_create_report(target.as_ptr(), data.as_ptr(), report.as_mut_ptr()) };
    if rc != SGX_SUCCESS {
        abort();
    }
    // sgx_report_body_t: cpu_svn[16] misc_select[4] reserved1[12] isv_ext_prod_id[16] attributes{flags u64, xfrm u64}
    let flags = u64::from_le_bytes(report[48..56].try_into().unwrap_or([0; 8]));
    flags & 0x2 != 0
}
