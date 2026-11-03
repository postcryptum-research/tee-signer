//! The enclave behind one trait. `Sgx` is the real thing (ecall through the edger8r bridge);
//! `InProcess` is rcore in host simulation for laptop tests. Both are called under one mutex by
//! the daemon — the enclave is stateless between calls, so serialization is the whole story.

use anyhow::{anyhow, Result};
use signer_core::proto::Response;

/// One ecall.
pub trait Enclave: Send {
    /// `rcore_call` semantics: op + canonical request → canonical response.
    fn call(&mut self, op: u32, input: &[u8]) -> Result<Response>;
    /// A label for status.
    fn kind(&self) -> &'static str;
}

const OUT_CAP: usize = 2 * 1024 * 1024;

#[cfg(feature = "nosgx")]
pub struct InProcess;

#[cfg(feature = "nosgx")]
impl Enclave for InProcess {
    fn call(&mut self, op: u32, input: &[u8]) -> Result<Response> {
        let mut out = vec![0u8; OUT_CAP];
        let mut out_len = 0usize;
        // SAFETY: buffers are valid for the lengths given; rcore copies into `out` within cap.
        let rc = unsafe { rcore::rcore_call(op, input.as_ptr(), input.len(), out.as_mut_ptr(), out.len(), &mut out_len) };
        if rc != 0 {
            return Err(anyhow!("rcore_call status {rc}"));
        }
        Response::decode(&out[..out_len]).map_err(|_| anyhow!("undecodable response"))
    }
    fn kind(&self) -> &'static str {
        "in-process (nosgx)"
    }
}

#[cfg(feature = "sgx")]
pub mod sgx {
    use super::*;

    #[allow(non_camel_case_types)]
    type sgx_enclave_id_t = u64;

    extern "C" {
        fn sgx_create_enclave(
            file_name: *const std::os::raw::c_char,
            debug: i32,
            launch_token: *mut [u8; 1024],
            launch_token_updated: *mut i32,
            enclave_id: *mut sgx_enclave_id_t,
            misc_attr: *mut u8,
        ) -> u32;
        fn sgx_destroy_enclave(enclave_id: sgx_enclave_id_t) -> u32;
        fn ecall_call(
            eid: sgx_enclave_id_t,
            retval: *mut i32,
            op: u32,
            input: *const u8,
            in_len: usize,
            out: *mut u8,
            out_cap: usize,
            out_len: *mut usize,
        ) -> u32;
    }

    pub struct Sgx {
        eid: sgx_enclave_id_t,
        debug: bool,
    }

    impl Sgx {
        /// Load `path`. `debug` must be true on hardware without launch control (T1); the
        /// enclave itself reports which attributes it actually got.
        pub fn load(path: &str, debug: bool) -> Result<Self> {
            let c = std::ffi::CString::new(path)?;
            let mut token = [0u8; 1024];
            let mut updated = 0i32;
            let mut eid: sgx_enclave_id_t = 0;
            // SAFETY: all pointers are to valid locals; the SDK fills them.
            let rc = unsafe {
                sgx_create_enclave(c.as_ptr(), i32::from(debug), &mut token, &mut updated, &mut eid, std::ptr::null_mut())
            };
            if rc != 0 {
                return Err(anyhow!("sgx_create_enclave failed: 0x{rc:x}"));
            }
            Ok(Sgx { eid, debug })
        }
    }

    impl Drop for Sgx {
        fn drop(&mut self) {
            // SAFETY: eid came from sgx_create_enclave.
            unsafe {
                sgx_destroy_enclave(self.eid);
            }
        }
    }

    impl Enclave for Sgx {
        fn call(&mut self, op: u32, input: &[u8]) -> Result<Response> {
            let mut out = vec![0u8; OUT_CAP];
            let mut out_len = 0usize;
            let mut retval = 0i32;
            // SAFETY: buffers valid for their lengths; the bridge copies in/out.
            let rc = unsafe {
                ecall_call(self.eid, &mut retval, op, input.as_ptr(), input.len(), out.as_mut_ptr(), out.len(), &mut out_len)
            };
            if rc != 0 {
                return Err(anyhow!("ecall failed: sgx status 0x{rc:x} (0x1006 = enclave crashed: a panic inside; nothing was charged)"));
            }
            if retval != 0 {
                return Err(anyhow!("rcore_call status {retval}"));
            }
            Response::decode(&out[..out_len]).map_err(|_| anyhow!("undecodable response"))
        }
        fn kind(&self) -> &'static str {
            if self.debug {
                "sgx (debug launch)"
            } else {
                "sgx"
            }
        }
    }
}
