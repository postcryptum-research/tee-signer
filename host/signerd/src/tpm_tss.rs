//! REQ-r9 — the `tss` transport: a local TPM 2.0 (the node's vTPM, or an operator's physical one)
//! reached through the TSS stack, with the attestation key and the counter index at handles the
//! operator names **explicitly** (C-R9-E: nothing is ever picked, probed or evicted for you).
//!
//! Two halves:
//! * the **runtime** (`TssTpm`): `NV_Certify` / `NV_Increment` / the reads behind `tpm-info`, on a
//!   raw ESAPI context (`tss-esapi` 7.7 has no safe `nv_certify`; the `unsafe` is confined here and
//!   every out-buffer is copied and freed before returning);
//! * the **setup** (`tpm-setup` / `tpm-teardown`): a restricted P-256 attestation key under the owner
//!   hierarchy persisted at `--ak-handle`, and a `TPMA_NV_COUNTER` index at `--nv-index`. Setup
//!   refuses an occupied handle or index; teardown removes exactly the two objects `tpm-setup`
//!   recorded in its `--out` file (the key's public point and the index Name must match — a
//!   destructive operation resolves its exact target, RESP-r9 Q8) and only if they also match this
//!   module's own templates (another project's key or index is refused, not touched).
//!
//! Authorization: `SIGNERD_TPM_AUTH` (any string) becomes the authValue of both objects
//! (SHA-256 of the string, so the length is free). Unset = empty auth: fine for an isolated test
//! TPM; on a shared TPM a co-tenant could increment the counter (a liveness denial, never a
//! rollback) or ask for certifies — set it on the product path (RESP-r9 tss note).
//!
//! All of this is host-side plumbing: a lying transport only makes the enclave refuse.

use std::ffi::{c_void, CString};
use std::ptr::null_mut;
use std::str::FromStr as _;

use anyhow::{anyhow, bail, Context as _, Result};
use signer_core::proto::TpmProof;
use signer_core::tpm_attest::NV_NAME_LEN;
use tss_esapi::constants::tss::{TPM2_ALG_ECC, TPM2_ALG_ECDSA, TPM2_ALG_NULL, TPM2_ALG_SHA256};
use tss_esapi::tss2_esys as sys;

use crate::tpm::{TpmInfo, TpmTransport};

/// Persistent object handles (`TPM2_HT_PERSISTENT`).
pub const PERSISTENT_FIRST: u32 = 0x8100_0000;
pub const PERSISTENT_LAST: u32 = 0x81FF_FFFF;
/// NV index handles (`TPM2_HT_NV_INDEX`).
pub const NV_FIRST: u32 = 0x0100_0000;
pub const NV_LAST: u32 = 0x01FF_FFFF;
/// The default TCTI: the kernel resource manager.
pub const DEFAULT_TCTI: &str = "device:/dev/tpmrm0";

/// `tss:<tcti>?ak=0x81......&nv=0x01......` — the TCTI may be empty (= `device:/dev/tpmrm0`); both
/// handles are mandatory, in their ranges, hex with `0x`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TssSpec {
    pub tcti: String,
    pub ak: u32,
    pub nv: u32,
}

impl TssSpec {
    pub fn parse(rest: &str) -> Result<Self> {
        let (tcti, query) = rest.split_once('?').ok_or_else(|| anyhow!("tss: missing `?ak=0x…&nv=0x…`"))?;
        let tcti = if tcti.is_empty() { DEFAULT_TCTI.to_string() } else { tcti.to_string() };
        let (mut ak, mut nv) = (None, None);
        for kv in query.split('&').filter(|s| !s.is_empty()) {
            match kv.split_once('=') {
                Some(("ak", v)) => ak = Some(parse_handle(v, "ak")?),
                Some(("nv", v)) => nv = Some(parse_handle(v, "nv")?),
                _ => bail!("tss: unknown parameter `{kv}` (ak=, nv= only)"),
            }
        }
        let spec = TssSpec {
            tcti,
            ak: ak.ok_or_else(|| anyhow!("tss: `ak=0x81……` (the attestation key's persistent handle) is mandatory"))?,
            nv: nv.ok_or_else(|| anyhow!("tss: `nv=0x01……` (the counter's NV index) is mandatory"))?,
        };
        spec.check_ranges()?;
        Ok(spec)
    }

    pub fn check_ranges(&self) -> Result<()> {
        if !(PERSISTENT_FIRST..=PERSISTENT_LAST).contains(&self.ak) {
            bail!(
                "ak handle 0x{:08x} is not in the persistent range 0x{PERSISTENT_FIRST:08x}–0x{PERSISTENT_LAST:08x}",
                self.ak
            );
        }
        if !(NV_FIRST..=NV_LAST).contains(&self.nv) {
            bail!("nv index 0x{:08x} is not in the NV range 0x{NV_FIRST:08x}–0x{NV_LAST:08x}", self.nv);
        }
        Ok(())
    }

    pub fn describe(&self) -> String {
        format!("tss:{}?ak=0x{:08x}&nv=0x{:08x}", self.tcti, self.ak, self.nv)
    }
}

/// `0x81000200` → 0x81000200. Hex with the prefix only: a handle is never a decimal.
pub fn parse_handle(s: &str, what: &str) -> Result<u32> {
    let hex = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .ok_or_else(|| anyhow!("{what}: `{s}` must be hex with 0x"))?;
    u32::from_str_radix(hex, 16).map_err(|_| anyhow!("{what}: `{s}` is not a 32-bit hex handle"))
}

/// `SIGNERD_TPM_AUTH` → the 32-byte authValue shared by the key and the index; `None` when unset or
/// empty.
fn auth_value() -> Option<[u8; 32]> {
    std::env::var("SIGNERD_TPM_AUTH").ok().filter(|s| !s.is_empty()).map(|s| signer_core::sha256(s.as_bytes()))
}

// ---------------------------------------------------------------------------------------------
// raw ESAPI context (runtime)

/// One ESAPI context over one TCTI. Not thread-safe by construction; the daemon holds its
/// transport behind its state mutex and never calls it from two threads at once.
struct Esys {
    ctx: *mut sys::ESYS_CONTEXT,
    tcti: *mut sys::TSS2_TCTI_CONTEXT,
}

// SAFETY: raw pointers to heap objects owned by this struct; the ESAPI contract is "one call at a
// time", which the owning `Daemon` guarantees through its mutex. Moving the struct between threads
// is fine.
unsafe impl Send for Esys {}

fn rc(code: sys::TSS2_RC, what: &str) -> Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(anyhow!("TPM {what}: rc 0x{code:08x} (`tpm2_rc_decode 0x{code:x}`)"))
    }
}

impl Esys {
    fn connect(tcti_conf: &str) -> Result<Self> {
        let c = CString::new(tcti_conf).context("tcti string")?;
        let mut tcti: *mut sys::TSS2_TCTI_CONTEXT = null_mut();
        // SAFETY: a valid NUL-terminated string and an out-pointer; on success `tcti` is a context
        // this struct owns and finalizes in `drop`.
        rc(unsafe { sys::Tss2_TctiLdr_Initialize(c.as_ptr(), &mut tcti) }, &format!("tcti `{tcti_conf}`"))?;
        let mut ctx: *mut sys::ESYS_CONTEXT = null_mut();
        // SAFETY: `tcti` is the context just initialized; a NULL ABI version means "default".
        let r = unsafe { sys::Esys_Initialize(&mut ctx, tcti, null_mut()) };
        if r != 0 {
            // SAFETY: finalizing the context we own, exactly once.
            unsafe { sys::Tss2_TctiLdr_Finalize(&mut tcti) };
            rc(r, "Esys_Initialize")?;
        }
        Ok(Esys { ctx, tcti })
    }

    /// An ESYS object for a handle that already exists in the TPM (persistent or NV).
    fn tr_from_handle(&mut self, handle: u32) -> Result<sys::ESYS_TR> {
        let mut tr: sys::ESYS_TR = 0;
        // SAFETY: valid context; `tr` is an out-param.
        let r = unsafe {
            sys::Esys_TR_FromTPMPublic(
                self.ctx,
                handle,
                sys::ESYS_TR_NONE,
                sys::ESYS_TR_NONE,
                sys::ESYS_TR_NONE,
                &mut tr,
            )
        };
        rc(r, &format!("object 0x{handle:08x} (not in the TPM? run `signerd tpm-setup`)"))?;
        Ok(tr)
    }

    fn set_auth(&mut self, tr: sys::ESYS_TR, auth: &[u8; 32]) -> Result<()> {
        // SAFETY: a fully initialized TPM2B with size ≤ buffer.
        let mut a: sys::TPM2B_AUTH = unsafe { std::mem::zeroed() };
        a.size = 32;
        a.buffer[..32].copy_from_slice(auth);
        // SAFETY: valid context, a resolved ESYS_TR, a pointer to a live struct.
        rc(unsafe { sys::Esys_TR_SetAuth(self.ctx, tr, &a) }, "TR_SetAuth")
    }

    /// The uncompressed P-256 point of an ECC key (`04 ‖ x ‖ y`).
    fn read_public_p256(&mut self, tr: sys::ESYS_TR) -> Result<[u8; 65]> {
        let mut pubp: *mut sys::TPM2B_PUBLIC = null_mut();
        let mut name: *mut sys::TPM2B_NAME = null_mut();
        let mut qn: *mut sys::TPM2B_NAME = null_mut();
        // SAFETY: valid context and out-params; ReadPublic takes no authorization.
        let r = unsafe {
            sys::Esys_ReadPublic(
                self.ctx,
                tr,
                sys::ESYS_TR_NONE,
                sys::ESYS_TR_NONE,
                sys::ESYS_TR_NONE,
                &mut pubp,
                &mut name,
                &mut qn,
            )
        };
        rc(r, "ReadPublic")?;
        // SAFETY: on success ESAPI returned allocated, initialized structures; copied then freed.
        let out = unsafe {
            let p = &*pubp;
            let res = if p.publicArea.type_ != TPM2_ALG_ECC {
                Err(anyhow!("the key at the ak handle is not an ECC key"))
            } else {
                let e = &p.publicArea.unique.ecc;
                let (x, y) = (pad32(&e.x.buffer[..e.x.size as usize])?, pad32(&e.y.buffer[..e.y.size as usize])?);
                let mut pk = [0u8; 65];
                pk[0] = 0x04;
                pk[1..33].copy_from_slice(&x);
                pk[33..].copy_from_slice(&y);
                Ok(pk)
            };
            sys::Esys_Free(pubp as *mut c_void);
            sys::Esys_Free(name as *mut c_void);
            sys::Esys_Free(qn as *mut c_void);
            res
        }?;
        Ok(out)
    }

    /// The index Name (`alg ‖ digest`, 34 bytes for SHA-256).
    fn nv_name(&mut self, tr: sys::ESYS_TR) -> Result<[u8; NV_NAME_LEN]> {
        let mut nvpub: *mut sys::TPM2B_NV_PUBLIC = null_mut();
        let mut name: *mut sys::TPM2B_NAME = null_mut();
        // SAFETY: valid context and out-params; NV_ReadPublic takes no authorization.
        let r = unsafe {
            sys::Esys_NV_ReadPublic(
                self.ctx,
                tr,
                sys::ESYS_TR_NONE,
                sys::ESYS_TR_NONE,
                sys::ESYS_TR_NONE,
                &mut nvpub,
                &mut name,
            )
        };
        rc(r, "NV_ReadPublic")?;
        // SAFETY: as above.
        let out = unsafe {
            let n = &*name;
            let res = <[u8; NV_NAME_LEN]>::try_from(&n.name[..n.size as usize])
                .map_err(|_| anyhow!("NV index Name is {} bytes, expected {NV_NAME_LEN} (SHA-256 index)", n.size));
            sys::Esys_Free(nvpub as *mut c_void);
            sys::Esys_Free(name as *mut c_void);
            res
        }?;
        Ok(out)
    }

    /// The counter value (8 bytes big-endian), read with the index's own auth.
    fn nv_read_counter(&mut self, tr: sys::ESYS_TR) -> Result<u64> {
        let mut data: *mut sys::TPM2B_MAX_NV_BUFFER = null_mut();
        // SAFETY: valid context; the password session carries the auth set with `set_auth`.
        let r = unsafe {
            sys::Esys_NV_Read(
                self.ctx,
                tr,
                tr,
                sys::ESYS_TR_PASSWORD,
                sys::ESYS_TR_NONE,
                sys::ESYS_TR_NONE,
                8,
                0,
                &mut data,
            )
        };
        rc(r, "NV_Read")?;
        // SAFETY: as above.
        let out = unsafe {
            let d = &*data;
            let res = <[u8; 8]>::try_from(&d.buffer[..d.size as usize])
                .map(u64::from_be_bytes)
                .map_err(|_| anyhow!("NV_Read returned {} bytes, expected 8", d.size));
            sys::Esys_Free(data as *mut c_void);
            res
        }?;
        Ok(out)
    }

    /// `TPM2_NV_Certify(ak, nv)` over `nonce`: the raw `TPMS_ATTEST` and the ECDSA signature as
    /// `r ‖ s`, low-s (the enclave accepts only the low half, `tpm_attest::verify_nv_certify`).
    fn nv_certify(&mut self, ak: sys::ESYS_TR, nv: sys::ESYS_TR, nonce: &[u8; 32]) -> Result<(Vec<u8>, [u8; 64])> {
        // SAFETY: zeroed TPM2Bs are valid (size 0); we then fill size and bytes.
        let mut qd: sys::TPM2B_DATA = unsafe { std::mem::zeroed() };
        qd.size = 32;
        qd.buffer[..32].copy_from_slice(nonce);
        // SAFETY: a zeroed scheme with `TPM2_ALG_NULL` = "the key's own scheme" (the AK is
        // restricted, so its ECDSA/SHA-256 scheme is fixed in the key).
        let mut scheme: sys::TPMT_SIG_SCHEME = unsafe { std::mem::zeroed() };
        scheme.scheme = TPM2_ALG_NULL;
        let mut attest: *mut sys::TPM2B_ATTEST = null_mut();
        let mut sig: *mut sys::TPMT_SIGNATURE = null_mut();
        // SAFETY: valid context, resolved objects, live input structs, out-params. Session 1
        // authorizes the signing key, session 2 the index (its own authValue).
        let r = unsafe {
            sys::Esys_NV_Certify(
                self.ctx,
                ak,
                nv,
                nv,
                sys::ESYS_TR_PASSWORD,
                sys::ESYS_TR_PASSWORD,
                sys::ESYS_TR_NONE,
                &qd,
                &scheme,
                8,
                0,
                &mut attest,
                &mut sig,
            )
        };
        rc(r, "NV_Certify")?;
        // SAFETY: allocated, initialized by ESAPI; copied out then freed. Reading the `ecdsa`
        // union member is guarded by `sigAlg`.
        let out = unsafe {
            let a = &*attest;
            let bytes = a.attestationData[..a.size as usize].to_vec();
            let s = &*sig;
            let res = if s.sigAlg != TPM2_ALG_ECDSA {
                Err(anyhow!("NV_Certify returned signature alg 0x{:04x}, expected ECDSA", s.sigAlg))
            } else if s.signature.ecdsa.hash != TPM2_ALG_SHA256 {
                Err(anyhow!("NV_Certify signed with hash 0x{:04x}, expected SHA-256", s.signature.ecdsa.hash))
            } else {
                let e = &s.signature.ecdsa;
                low_s(
                    &pad32(&e.signatureR.buffer[..e.signatureR.size as usize])?,
                    &pad32(&e.signatureS.buffer[..e.signatureS.size as usize])?,
                )
                .map(|sig64| (bytes, sig64))
            };
            sys::Esys_Free(attest as *mut c_void);
            sys::Esys_Free(sig as *mut c_void);
            res
        }?;
        Ok(out)
    }

    fn nv_increment(&mut self, nv: sys::ESYS_TR) -> Result<()> {
        // SAFETY: valid context; the index authorizes itself through the password session.
        let r = unsafe {
            sys::Esys_NV_Increment(self.ctx, nv, nv, sys::ESYS_TR_PASSWORD, sys::ESYS_TR_NONE, sys::ESYS_TR_NONE)
        };
        rc(r, "NV_Increment")
    }
}

impl Drop for Esys {
    fn drop(&mut self) {
        // SAFETY: both were initialized in `connect` and are finalized exactly once, ESAPI first.
        unsafe {
            sys::Esys_Finalize(&mut self.ctx);
            sys::Tss2_TctiLdr_Finalize(&mut self.tcti);
        }
    }
}

/// TPM2B_ECC_PARAMETER values are curve-sized but may come shorter; left-pad to 32.
fn pad32(b: &[u8]) -> Result<[u8; 32]> {
    let pad = 32usize.checked_sub(b.len()).ok_or_else(|| anyhow!("field element of {} bytes", b.len()))?;
    let mut out = [0u8; 32];
    out[pad..].copy_from_slice(b);
    Ok(out)
}

/// `r ‖ s` with `s` in the low half of the order (a TPM may emit either half).
fn low_s(r: &[u8; 32], s: &[u8; 32]) -> Result<[u8; 64]> {
    let sig = p256::ecdsa::Signature::from_scalars(*r, *s)
        .map_err(|_| anyhow!("TPM signature is not a valid P-256 (r, s)"))?;
    let sig = sig.normalize_s().unwrap_or(sig);
    let mut out = [0u8; 64];
    out.copy_from_slice(&sig.to_bytes());
    Ok(out)
}

/// The runtime transport.
pub struct TssTpm {
    spec: TssSpec,
    esys: Esys,
    ak: sys::ESYS_TR,
    nv: sys::ESYS_TR,
}

impl TssTpm {
    /// Connect, resolve both handles (they must already exist — `tpm-setup`), apply the auth.
    pub fn open(spec: TssSpec) -> Result<Self> {
        let mut esys = Esys::connect(&spec.tcti)?;
        let ak = esys.tr_from_handle(spec.ak)?;
        let nv = esys.tr_from_handle(spec.nv)?;
        if let Some(a) = auth_value() {
            esys.set_auth(ak, &a)?;
            esys.set_auth(nv, &a)?;
        }
        Ok(TssTpm { spec, esys, ak, nv })
    }
}

impl TpmTransport for TssTpm {
    fn describe(&self) -> String {
        self.spec.describe()
    }
    fn info(&mut self) -> Result<TpmInfo> {
        Ok(TpmInfo {
            ak_pk_hex: hex::encode(self.esys.read_public_p256(self.ak)?),
            nv_name_hex: hex::encode(self.esys.nv_name(self.nv)?),
            counter: self.esys.nv_read_counter(self.nv)?,
            transport: self.describe(),
        })
    }
    fn certify(&mut self, nonce: &[u8; 32]) -> Result<TpmProof> {
        let (attest, sig) = self.esys.nv_certify(self.ak, self.nv, nonce)?;
        Ok(TpmProof { attest, sig })
    }
    fn increment(&mut self) -> Result<u64> {
        self.esys.nv_increment(self.nv)?;
        self.esys.nv_read_counter(self.nv)
    }
}

// ---------------------------------------------------------------------------------------------
// setup / teardown (safe tss-esapi API; one-shot commands, never run by the daemon)

mod setup {
    use super::*;
    use tss_esapi::attributes::{NvIndexAttributesBuilder, ObjectAttributesBuilder};
    use tss_esapi::constants::nv_index_type::NvIndexType;
    use tss_esapi::constants::CapabilityType;
    use tss_esapi::handles::{
        KeyHandle, NvIndexHandle, NvIndexTpmHandle, ObjectHandle, PersistentTpmHandle, TpmHandle,
    };
    use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
    use tss_esapi::interface_types::dynamic_handles::Persistent;
    use tss_esapi::interface_types::ecc::EccCurve;
    use tss_esapi::interface_types::resource_handles::{Hierarchy, NvAuth, Provision};
    use tss_esapi::structures::{
        Auth, CapabilityData, EccPoint, EccScheme, HashScheme, KeyDerivationFunctionScheme, NvPublic, NvPublicBuilder,
        Public, PublicBuilder, PublicEccParametersBuilder, SymmetricDefinitionObject,
    };
    use tss_esapi::tcti_ldr::TctiNameConf;
    use tss_esapi::Context;

    fn connect(tcti: &str) -> Result<Context> {
        let conf = TctiNameConf::from_str(tcti).map_err(|e| anyhow!("tcti `{tcti}`: {e}"))?;
        Context::new(conf).map_err(|e| anyhow!("TPM context: {e}"))
    }

    /// Is `handle` listed by `TPM2_GetCapability(HANDLES)` in its range? (The C-R6-2 / C-R9-E
    /// check: an occupied handle is never reused, never evicted.)
    fn listed(ctx: &mut Context, range_first: u32, range_last: u32, handle: u32) -> Result<bool> {
        let mut from = range_first;
        loop {
            let (data, more) =
                ctx.get_capability(CapabilityType::Handles, from, 64).map_err(|e| anyhow!("TPM capability: {e}"))?;
            let CapabilityData::Handles(list) = data else { return Ok(false) };
            let handles: Vec<u32> = list.into_inner().into_iter().map(u32::from).collect();
            if handles.contains(&handle) {
                return Ok(true);
            }
            match (more, handles.last()) {
                (true, Some(last)) if *last < range_last => from = last.saturating_add(1),
                _ => return Ok(false),
            }
        }
    }

    /// The attestation key: a **restricted** P-256 ECDSA/SHA-256 signing primary under the owner
    /// hierarchy. Restricted = the TPM signs only structures it generated itself (`TPM_GENERATED`
    /// magic), so no host can obtain this key's signature over a forged `TPMS_ATTEST`.
    fn ak_template() -> Result<Public> {
        let attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_no_da(true)
            .with_sign_encrypt(true)
            .with_restricted(true)
            .with_decrypt(false)
            .build()
            .map_err(|e| anyhow!("ak attributes: {e}"))?;
        let ecc = PublicEccParametersBuilder::new()
            .with_ecc_scheme(EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)))
            .with_curve(EccCurve::NistP256)
            .with_is_signing_key(true)
            .with_is_decryption_key(false)
            .with_restricted(true)
            .with_symmetric(SymmetricDefinitionObject::Null)
            .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
            .build()
            .map_err(|e| anyhow!("ak ecc parameters: {e}"))?;
        PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(attributes)
            .with_ecc_parameters(ecc)
            .with_ecc_unique_identifier(EccPoint::default())
            .build()
            .map_err(|e| anyhow!("ak template: {e}"))
    }

    /// The uncompressed point `04 ‖ x ‖ y` of an ECC public area (`None` for anything else).
    fn public_point(public: &Public) -> Option<Vec<u8>> {
        let Public::Ecc { unique, .. } = public else { return None };
        let (x, y) = (pad32(unique.x().value()).ok()?, pad32(unique.y().value()).ok()?);
        let mut pk = vec![0x04u8];
        pk.extend_from_slice(&x);
        pk.extend_from_slice(&y);
        Some(pk)
    }

    /// Does a public area match `ak_template` (so the object is one of ours)?
    fn is_our_ak(public: &Public) -> bool {
        match public {
            Public::Ecc { object_attributes: a, parameters, .. } => {
                a.restricted()
                    && a.sign_encrypt()
                    && !a.decrypt()
                    && a.fixed_tpm()
                    && a.fixed_parent()
                    && a.sensitive_data_origin()
                    && a.user_with_auth()
                    && parameters.ecc_curve() == EccCurve::NistP256
                    && parameters.ecc_scheme() == EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256))
            }
            _ => false,
        }
    }

    /// The counter index: 8 bytes, `COUNTER`, readable/writable with its own auth, no dictionary
    /// lockout, optionally hybrid (`ORDERLY`: RAM-resident, written to NV at orderly shutdown and
    /// at boundaries — saves a physical TPM's flash; an unorderly shutdown jumps it *forward*,
    /// which the enclave reports as `STATE_STALE` until the owner re-anchors).
    fn counter_public(nv: u32, orderly: bool) -> Result<NvPublic> {
        let attrs = NvIndexAttributesBuilder::new()
            .with_nv_index_type(NvIndexType::Counter)
            .with_auth_read(true)
            .with_auth_write(true)
            .with_no_da(true)
            .with_orderly(orderly)
            .build()
            .map_err(|e| anyhow!("nv attributes: {e}"))?;
        NvPublicBuilder::new()
            .with_nv_index(NvIndexTpmHandle::new(nv).map_err(|e| anyhow!("nv index: {e}"))?)
            .with_index_name_algorithm(HashingAlgorithm::Sha256)
            .with_index_attributes(attrs)
            .with_data_area_size(8)
            .build()
            .map_err(|e| anyhow!("nv public: {e}"))
    }

    /// Does an index's public area match `counter_public` (either orderly flavour)?
    fn is_our_counter(p: &NvPublic) -> bool {
        let a = p.attributes();
        p.data_size() == 8
            && a.index_type().map(|t| t == NvIndexType::Counter).unwrap_or(false)
            && a.auth_read()
            && a.auth_write()
            && a.no_da()
            && !a.owner_write()
            && !a.policy_write()
            && !a.pp_write()
            && !a.platform_create()
    }

    /// `signerd tpm-setup`: create both objects at the named handles. Refuses either if occupied.
    pub fn setup(spec: &TssSpec, orderly: bool) -> Result<TpmInfo> {
        spec.check_ranges()?;
        let mut ctx = connect(&spec.tcti)?;
        if listed(&mut ctx, PERSISTENT_FIRST, PERSISTENT_LAST, spec.ak)? {
            bail!(
                "REFUSED: persistent handle 0x{:08x} is already in use by another key — never evicted; pick a free one with --ak-handle (`tpm2_getcap handles-persistent`)",
                spec.ak
            );
        }
        if listed(&mut ctx, NV_FIRST, NV_LAST, spec.nv)? {
            bail!(
                "REFUSED: NV index 0x{:08x} is already defined by someone — never undefined; pick a free one with --nv-index (`tpm2_getcap handles-nv-index`)",
                spec.nv
            );
        }
        let auth = match auth_value() {
            Some(a) => Some(Auth::try_from(a.to_vec()).map_err(|e| anyhow!("auth: {e}"))?),
            None => None,
        };
        // the attestation key
        let template = ak_template()?;
        let created = ctx
            .execute_with_nullauth_session(|c| {
                c.create_primary(Hierarchy::Owner, template, auth.clone(), None, None, None)
            })
            .map_err(|e: tss_esapi::Error| anyhow!("CreatePrimary (owner hierarchy): {e}"))?;
        let target = PersistentTpmHandle::new(spec.ak).map_err(|e| anyhow!("ak handle: {e}"))?;
        let key: ObjectHandle = created.key_handle.into();
        ctx.execute_with_nullauth_session(|c| c.evict_control(Provision::Owner, key, Persistent::Persistent(target)))
            .map_err(|e: tss_esapi::Error| anyhow!("EvictControl → 0x{:08x}: {e}", spec.ak))?;
        let _ = ctx.flush_context(key);
        // the counter: define, then the first increment initialises it (an unwritten index can be
        // neither read nor certified)
        let public = counter_public(spec.nv, orderly)?;
        let nv: NvIndexHandle = match ctx
            .execute_with_nullauth_session(|c| c.nv_define_space(Provision::Owner, auth.clone(), public))
        {
            Ok(h) => h,
            Err(e) => {
                // #23: the key is not left behind at its handle — no setup record exists yet for
                // `tpm-teardown` to find it by; evicted again here, best effort, and said either way
                let cleanup = ctx
                    .execute_without_session(|c| c.tr_from_tpm_public(TpmHandle::Persistent(target)))
                    .map_err(|ce| anyhow!("{ce}"))
                    .and_then(|obj| {
                        ctx.execute_with_nullauth_session(|c| {
                            c.evict_control(Provision::Owner, obj, Persistent::Persistent(target))
                        })
                        .map_err(|ce| anyhow!("{ce}"))
                    });
                let note = match cleanup {
                        Ok(_) => format!("the key created at 0x{:08x} was evicted again", spec.ak),
                        Err(ce) => format!(
                            "the key created at 0x{:08x} could NOT be evicted ({ce}) — remove it by hand: tpm2_evictcontrol -C o -c 0x{:08x}",
                            spec.ak, spec.ak
                        ),
                    };
                bail!("NV_DefineSpace 0x{:08x}: {e}; {note}", spec.nv);
            }
        };
        if let Some(a) = auth.as_ref() {
            ctx.tr_set_auth(nv.into(), a.clone()).map_err(|e| anyhow!("nv auth: {e}"))?;
        }
        ctx.execute_with_nullauth_session(|c| c.nv_increment(NvAuth::NvIndex(nv), nv))
            .map_err(|e: tss_esapi::Error| anyhow!("first NV_Increment: {e}"))?;
        drop(ctx);
        // read everything back through the runtime path — the same code the daemon will run
        let mut t = TssTpm::open(spec.clone())?;
        t.info()
    }

    /// `signerd tpm-teardown`: remove exactly the two objects `tpm-setup` recorded in `setup_file`
    /// (its `--out`: the key's public point and the index Name), each only if the object at the named
    /// handle IS that object and matches this module's template. Destroys the anchor of any state
    /// bound to them (the owner re-anchors).
    pub fn teardown(spec: &TssSpec, setup_file: &std::path::Path) -> Result<Vec<String>> {
        spec.check_ranges()?;
        let recorded: TpmInfo = serde_json::from_str(
            &std::fs::read_to_string(setup_file)
                .with_context(|| format!("reading {} (tpm-setup's --out)", setup_file.display()))?,
        )
        .with_context(|| format!("{}: not a tpm-setup/tpm-info record", setup_file.display()))?;
        let want_pk = hex::decode(&recorded.ak_pk_hex).context("setup file: ak_pk_hex")?;
        let want_name = hex::decode(&recorded.nv_name_hex).context("setup file: nv_name_hex")?;
        let mut ctx = connect(&spec.tcti)?;
        let mut done = Vec::new();
        // the index first (it is the one with a state behind it)
        if listed(&mut ctx, NV_FIRST, NV_LAST, spec.nv)? {
            let h = NvIndexTpmHandle::new(spec.nv).map_err(|e| anyhow!("nv index: {e}"))?;
            let obj = ctx
                .execute_without_session(|c| c.tr_from_tpm_public(TpmHandle::NvIndex(h)))
                .map_err(|e| anyhow!("nv 0x{:08x}: {e}", spec.nv))?;
            let nv: NvIndexHandle = obj.into();
            let (public, name) =
                ctx.execute_without_session(|c| c.nv_read_public(nv)).map_err(|e| anyhow!("NV_ReadPublic: {e}"))?;
            if name.value() != want_name.as_slice() {
                bail!(
                    "REFUSED: the index at 0x{:08x} is not the one {} records (its Name differs) — not the object tpm-setup created, not touched",
                    spec.nv,
                    setup_file.display()
                );
            }
            if !is_our_counter(&public) {
                bail!("REFUSED: NV index 0x{:08x} is not a tee-signer counter (attributes/size differ) — someone else's, not touched", spec.nv);
            }
            ctx.execute_with_nullauth_session(|c| c.nv_undefine_space(Provision::Owner, nv))
                .map_err(|e: tss_esapi::Error| anyhow!("NV_UndefineSpace 0x{:08x}: {e}", spec.nv))?;
            done.push(format!("undefined NV index 0x{:08x}", spec.nv));
        } else {
            done.push(format!("NV index 0x{:08x}: not present", spec.nv));
        }
        if listed(&mut ctx, PERSISTENT_FIRST, PERSISTENT_LAST, spec.ak)? {
            let target = PersistentTpmHandle::new(spec.ak).map_err(|e| anyhow!("ak handle: {e}"))?;
            let obj = ctx
                .execute_without_session(|c| c.tr_from_tpm_public(TpmHandle::Persistent(target)))
                .map_err(|e| anyhow!("ak 0x{:08x}: {e}", spec.ak))?;
            let key: KeyHandle = obj.into();
            let (public, _, _) =
                ctx.execute_without_session(|c| c.read_public(key)).map_err(|e| anyhow!("ReadPublic: {e}"))?;
            if public_point(&public).as_deref() != Some(want_pk.as_slice()) {
                bail!(
                    "REFUSED: the key at 0x{:08x} is not the one {} records (public key differs) — not the object tpm-setup created, not touched",
                    spec.ak,
                    setup_file.display()
                );
            }
            if !is_our_ak(&public) {
                bail!("REFUSED: the key at 0x{:08x} is not a tee-signer attestation key (template differs) — someone else's, not touched", spec.ak);
            }
            ctx.execute_with_nullauth_session(|c| {
                c.evict_control(Provision::Owner, obj, Persistent::Persistent(target))
            })
            .map_err(|e: tss_esapi::Error| anyhow!("EvictControl (remove) 0x{:08x}: {e}", spec.ak))?;
            done.push(format!("evicted attestation key 0x{:08x}", spec.ak));
        } else {
            done.push(format!("persistent handle 0x{:08x}: not present", spec.ak));
        }
        Ok(done)
    }
}

pub use setup::{setup, teardown};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_parses_and_refuses() {
        let s = TssSpec::parse("device:/dev/tpmrm0?ak=0x81000200&nv=0x01800200").unwrap();
        assert_eq!(s, TssSpec { tcti: "device:/dev/tpmrm0".into(), ak: 0x8100_0200, nv: 0x0180_0200 });
        assert_eq!(TssSpec::parse("?ak=0x81000200&nv=0x01800200").unwrap().tcti, DEFAULT_TCTI);
        assert!(TssSpec::parse("device:/dev/tpmrm0").is_err(), "handles are mandatory");
        assert!(TssSpec::parse("?ak=0x81000200").is_err(), "nv is mandatory");
        assert!(TssSpec::parse("?nv=0x01800200").is_err(), "ak is mandatory");
        assert!(TssSpec::parse("?ak=0x01800200&nv=0x01800200").is_err(), "ak must be persistent");
        assert!(TssSpec::parse("?ak=0x81000200&nv=0x81000200").is_err(), "nv must be an NV index");
        assert!(TssSpec::parse("?ak=81000200&nv=0x01800200").is_err(), "0x prefix required");
        assert!(TssSpec::parse("?ak=0x81000200&nv=0x01800200&x=1").is_err(), "unknown parameter");
    }

    #[test]
    fn low_s_normalizes() {
        // n - 1 is a high s; the normalized form is 1 (same r)
        let n_minus_1 = hex::decode("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550").unwrap();
        let r = [7u8; 32];
        let out = low_s(&r, &<[u8; 32]>::try_from(n_minus_1.as_slice()).unwrap()).unwrap();
        assert_eq!(&out[..32], &r);
        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(&out[32..], &one);
    }
}
