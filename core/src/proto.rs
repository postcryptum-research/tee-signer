//! The ecall wire protocol: one dispatching ecall, canonical requests and responses.
//!
//! The enclave exposes a single `ecall_call(op, in, out)`; `op` selects the request type below,
//! `in` is the request's canonical bytes, `out` receives a canonical `Response`. Both sides
//! (`rcore` inside, `signerd` outside) use this module, so there is exactly one definition of
//! every byte that crosses the boundary. Everything in a request is untrusted host input; the
//! enclave decodes it with the strict decoder and refuses anything non-canonical.

use alloc::string::String;
use alloc::vec::Vec;

use crate::encoding::{Dec, DecodeError, Enc};

/// Operation codes.
pub mod op {
    /// `InitRequest` → `InitResponse` (keys generated, owner and recovery bound, no mandate yet).
    pub const INIT: u32 = 1;
    /// `SealedWith { sealed: keys-only blob, data: mandate, extra: owner sig }` → `SealedResponse`
    /// (the signed mandate installed; the blob becomes a full one).
    pub const INSTALL: u32 = 9;
    /// sealed → `StatusResponse`.
    pub const STATUS: u32 = 2;
    /// sealed → `PolicyResponse`.
    pub const POLICY: u32 = 3;
    /// `MessageRequest` → `SealedResponse`.
    pub const APPLY_MESSAGE: u32 = 4;
    /// sealed → `SealedResponse`.
    pub const FREEZE: u32 = 5;
    /// `HeadersRequest` → `HeadersResponse`.
    pub const HEADERS: u32 = 6;
    /// `JudgeRequest` → `JudgeResponse`.
    pub const JUDGE: u32 = 7;
    /// `SignRequest` → `SignResponse`.
    pub const SIGN: u32 = 8;
    /// `SealedWith { sealed, data: target_info[512] ‖ nonce[32] }` → `ReportResponse`: a report for
    /// the quoting enclave whose `report_data` binds the identity card and the verifier's nonce
    /// (`quote::DOMAIN`). Read-only; nothing secret leaves. REQ-r5 §3.
    pub const REPORT: u32 = 10;
    /// test builds only: `TestInitRequest` → `InitResponse`.
    pub const TEST_INIT: u32 = 100;
    /// test builds only: reset the volatile session (a new "enclave load") → empty `ok`.
    pub const TEST_RESET_SESSION: u32 = 101;
}

/// Upper bounds on request parts (the fixed enclave heap is sized from these).
pub mod limits {
    /// Sealed blob.
    pub const MAX_SEALED: usize = 512 * 1024;
    /// PSBT.
    pub const MAX_PSBT: usize = 256 * 1024;
    /// Headers per batch.
    pub const MAX_HEADERS: usize = 2048;
    /// A message.
    pub const MAX_MESSAGE: usize = 72 * 1024;
    /// Receipt / card / blob outputs.
    pub const MAX_SMALL: usize = 4096;
}

/// The response envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    /// `true` with a payload, or `false` with reasons (and possibly a payload: a sealed blob the
    /// host must persist even though the operation refused — disarm, chain freeze).
    pub ok: bool,
    /// Refusal identifiers (`reason::Reason::code`), empty when `ok`.
    pub reasons: Vec<String>,
    /// Operation-specific canonical payload.
    pub payload: Vec<u8>,
}

impl Response {
    /// Success.
    pub fn ok(payload: Vec<u8>) -> Self {
        Response { ok: true, reasons: Vec::new(), payload }
    }
    /// Refusal, optionally carrying a payload the host must act on (a sealed blob to persist).
    pub fn refuse(reasons: Vec<String>, payload: Vec<u8>) -> Self {
        Response { ok: false, reasons, payload }
    }
    /// Canonical bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::new();
        e.bool(self.ok)
            .list(&self.reasons, |e, r| {
                e.str(r);
            })
            .bytes(&self.payload);
        e.finish()
    }
    /// Strict decode.
    pub fn decode(b: &[u8]) -> Result<Self, DecodeError> {
        let mut d = Dec::new(b);
        let ok = d.bool()?;
        let reasons = d.list(64, |d| d.str(64))?;
        let payload = d.bytes(limits::MAX_SEALED.saturating_add(limits::MAX_PSBT).saturating_add(limits::MAX_SMALL))?;
        d.finish()?;
        Ok(Response { ok, reasons, payload })
    }
}

/// `INIT`: generate the keys and bind the owner and recovery keys. The mandate follows in
/// `INSTALL`, because it names the wallet fingerprint that only exists after this step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitRequest {
    /// Network byte (`mandate::Network`).
    pub network: u8,
    /// Owner key.
    pub owner_pk: [u8; 65],
    /// Recovery key.
    pub recovery_pk: [u8; 65],
}

impl InitRequest {
    /// Canonical bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::new();
        e.u8(self.network).fixed(&self.owner_pk).fixed(&self.recovery_pk);
        e.finish()
    }
    /// Strict decode.
    pub fn decode(b: &[u8]) -> Result<Self, DecodeError> {
        let mut d = Dec::new(b);
        let r = InitRequest { network: d.u8()?, owner_pk: d.fixed()?, recovery_pk: d.fixed()? };
        d.finish()?;
        Ok(r)
    }
}

/// `SealedResponse`: operations whose only result is the new sealed blob.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedResponse {
    /// The sealed blob to persist.
    pub sealed: Vec<u8>,
}

impl SealedResponse {
    /// Canonical bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::new();
        e.bytes(&self.sealed);
        e.finish()
    }
    /// Strict decode.
    pub fn decode(b: &[u8]) -> Result<Self, DecodeError> {
        let mut d = Dec::new(b);
        let r = SealedResponse { sealed: d.bytes(limits::MAX_SEALED)? };
        d.finish()?;
        Ok(r)
    }
}

/// `TEST_INIT` (test builds only): `InitRequest` plus the secrets and a ready core state, so
/// vectors replay with the known test wallet through the real ecalls.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TestInitRequest {
    /// The ordinary init request.
    pub init: InitRequest,
    /// BIP39 entropy (32 bytes).
    pub seed: [u8; 32],
    /// Identity secret key.
    pub identity_sk: [u8; 32],
    /// Core state bytes (a vector's `state_hex`); the blob is a full one.
    pub state: Vec<u8>,
}

impl TestInitRequest {
    /// Canonical bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::new();
        e.bytes(&self.init.encode()).fixed(&self.seed).fixed(&self.identity_sk).bytes(&self.state);
        e.finish()
    }
    /// Strict decode.
    pub fn decode(b: &[u8]) -> Result<Self, DecodeError> {
        let mut d = Dec::new(b);
        let init = InitRequest::decode(&d.bytes(limits::MAX_MESSAGE)?)?;
        let r = TestInitRequest { init, seed: d.fixed()?, identity_sk: d.fixed()?, state: d.bytes(limits::MAX_SEALED)? };
        d.finish()?;
        Ok(r)
    }
}

/// `INIT` / `TEST_INIT` response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitResponse {
    /// The sealed blob to persist.
    pub sealed: Vec<u8>,
    /// Account xpub, BIP32 serialization (78 bytes).
    pub xpub: [u8; 78],
    /// Master fingerprint.
    pub fingerprint: [u8; 4],
    /// Identity public key, compressed secp256k1.
    pub identity_pk: [u8; 33],
    /// Identity card, canonical bytes (`IdentityCard`).
    pub card: Vec<u8>,
    /// Identity signature over the card's digest.
    pub card_sig: [u8; 64],
    /// Recovery blob (ephemeral pubkey ‖ ciphertext ‖ tag).
    pub recovery_blob: Vec<u8>,
}

impl InitResponse {
    /// Canonical bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::new();
        e.bytes(&self.sealed)
            .fixed(&self.xpub)
            .fixed(&self.fingerprint)
            .fixed(&self.identity_pk)
            .bytes(&self.card)
            .fixed(&self.card_sig)
            .bytes(&self.recovery_blob);
        e.finish()
    }
    /// Strict decode.
    pub fn decode(b: &[u8]) -> Result<Self, DecodeError> {
        let mut d = Dec::new(b);
        let r = InitResponse {
            sealed: d.bytes(limits::MAX_SEALED)?,
            xpub: d.fixed()?,
            fingerprint: d.fixed()?,
            identity_pk: d.fixed()?,
            card: d.bytes(limits::MAX_SMALL)?,
            card_sig: d.fixed()?,
            recovery_blob: d.bytes(limits::MAX_SMALL)?,
        };
        d.finish()?;
        Ok(r)
    }
}

/// The identity card the owner stores at setup (`docs/ENCLAVE.md §5`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityCard {
    /// MRENCLAVE from the enclave's own report (zeros in a non-SGX test build).
    pub mrenclave: [u8; 32],
    /// Network byte.
    pub network: u8,
    /// Account xpub.
    pub xpub: [u8; 78],
    /// Master fingerprint.
    pub fingerprint: [u8; 4],
    /// Identity public key.
    pub identity_pk: [u8; 33],
    /// Tier label, e.g. `T1-debug`.
    pub tier: String,
}

/// Signature domain of the identity card.
pub const IDENTITY_DOMAIN: &str = "tee-signer/identity/v1";

impl IdentityCard {
    /// Canonical bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::new();
        e.fixed(&self.mrenclave).u8(self.network).fixed(&self.xpub).fixed(&self.fingerprint).fixed(&self.identity_pk).str(&self.tier);
        e.finish()
    }
    /// Strict decode.
    pub fn decode(b: &[u8]) -> Result<Self, DecodeError> {
        let mut d = Dec::new(b);
        let c = IdentityCard {
            mrenclave: d.fixed()?,
            network: d.u8()?,
            xpub: d.fixed()?,
            fingerprint: d.fixed()?,
            identity_pk: d.fixed()?,
            tier: d.str(32)?,
        };
        d.finish()?;
        Ok(c)
    }
    /// The digest the identity key signs.
    pub fn digest(&self) -> [u8; 32] {
        crate::domain_digest(IDENTITY_DOMAIN, &self.encode())
    }
}

/// `STATUS` response — every field public. Between `INIT` and `INSTALL` (`installed == false`)
/// only the identity fields are meaningful; the rest are zero.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusResponse {
    /// A mandate is installed (the blob is a full one).
    pub installed: bool,
    /// Tier label.
    pub tier: String,
    /// MRENCLAVE.
    pub mrenclave: [u8; 32],
    /// Per-load random session id.
    pub session_id: [u8; 16],
    /// Network byte.
    pub network: u8,
    /// Account xpub.
    pub xpub: [u8; 78],
    /// Fingerprint.
    pub fingerprint: [u8; 4],
    /// Identity public key.
    pub identity_pk: [u8; 33],
    /// Owner nonce.
    pub nonce: u64,
    /// Receipt sequence.
    pub seq: u64,
    /// Frozen.
    pub frozen: bool,
    /// Armed.
    pub armed: bool,
    /// Chain frozen by a deep reorg.
    pub chain_frozen: bool,
    /// Best height (0 if none).
    pub best_height: u32,
    /// Best hash.
    pub best_hash: [u8; 32],
    /// Window start height.
    pub window_start: u32,
    /// Window outflow so far.
    pub window_outflow: u64,
    /// Window unlisted so far.
    pub window_unlisted: u64,
    /// Window fees so far.
    pub window_fees: u64,
    /// Installed mandate hash.
    pub mandate_hash: [u8; 32],
    /// Pending mandate hash and activation height.
    pub pending: Option<([u8; 32], u32)>,
    /// Pending owner rotation activation height.
    pub pending_owner: Option<u32>,
    /// Weak-clock label for this network (signet/regtest), empty on mainnet.
    pub clock_label: String,
    /// REQ-r7: this enclave load has been approved by the owner (volatile; false after every load).
    pub boot_armed: bool,
    /// REQ-r7: the challenge drawn at this load, which the owner's `Arm` must carry.
    pub boot_challenge: [u8; 32],
    /// REQ-r7: built with the `auto-arm` feature (the pause after a restart compiled OUT; its own MRENCLAVE).
    pub auto_arm: bool,
}

impl StatusResponse {
    /// Canonical bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::new();
        e.bool(self.installed)
            .str(&self.tier)
            .fixed(&self.mrenclave)
            .fixed(&self.session_id)
            .u8(self.network)
            .fixed(&self.xpub)
            .fixed(&self.fingerprint)
            .fixed(&self.identity_pk)
            .u64(self.nonce)
            .u64(self.seq)
            .bool(self.frozen)
            .bool(self.armed)
            .bool(self.chain_frozen)
            .u32(self.best_height)
            .fixed(&self.best_hash)
            .u32(self.window_start)
            .u64(self.window_outflow)
            .u64(self.window_unlisted)
            .u64(self.window_fees)
            .fixed(&self.mandate_hash)
            .option(self.pending.as_ref(), |e, (h, a)| {
                e.fixed(h).u32(*a);
            })
            .option(self.pending_owner.as_ref(), |e, a| {
                e.u32(*a);
            })
            .str(&self.clock_label)
            .bool(self.boot_armed)
            .fixed(&self.boot_challenge)
            .bool(self.auto_arm);
        e.finish()
    }
    /// Strict decode.
    pub fn decode(b: &[u8]) -> Result<Self, DecodeError> {
        let mut d = Dec::new(b);
        let r = StatusResponse {
            installed: d.bool()?,
            tier: d.str(32)?,
            mrenclave: d.fixed()?,
            session_id: d.fixed()?,
            network: d.u8()?,
            xpub: d.fixed()?,
            fingerprint: d.fixed()?,
            identity_pk: d.fixed()?,
            nonce: d.u64()?,
            seq: d.u64()?,
            frozen: d.bool()?,
            armed: d.bool()?,
            chain_frozen: d.bool()?,
            best_height: d.u32()?,
            best_hash: d.fixed()?,
            window_start: d.u32()?,
            window_outflow: d.u64()?,
            window_unlisted: d.u64()?,
            window_fees: d.u64()?,
            mandate_hash: d.fixed()?,
            pending: d.option(|d| Ok((d.fixed()?, d.u32()?)))?,
            pending_owner: d.option(|d| d.u32())?,
            clock_label: d.str(128)?,
            boot_armed: d.bool()?,
            boot_challenge: d.fixed()?,
            auto_arm: d.bool()?,
        };
        d.finish()?;
        Ok(r)
    }
}

/// `POLICY` response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyResponse {
    /// Installed mandate bytes.
    pub mandate: Vec<u8>,
    /// Its owner signature.
    pub sig: [u8; 64],
    /// Owner nonce.
    pub nonce: u64,
    /// Pending: mandate bytes, signature, nonce, activation height.
    pub pending: Option<(Vec<u8>, [u8; 64], u64, u32)>,
}

impl PolicyResponse {
    /// Canonical bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::new();
        e.bytes(&self.mandate).fixed(&self.sig).u64(self.nonce).option(self.pending.as_ref(), |e, (m, s, n, a)| {
            e.bytes(m).fixed(s).u64(*n).u32(*a);
        });
        e.finish()
    }
    /// Strict decode.
    pub fn decode(b: &[u8]) -> Result<Self, DecodeError> {
        let mut d = Dec::new(b);
        let r = PolicyResponse {
            mandate: d.bytes(crate::update::MAX_MANDATE_BYTES)?,
            sig: d.fixed()?,
            nonce: d.u64()?,
            pending: d.option(|d| Ok((d.bytes(crate::update::MAX_MANDATE_BYTES)?, d.fixed()?, d.u64()?, d.u32()?)))?,
        };
        d.finish()?;
        Ok(r)
    }
}


/// The `REPORT` binding (REQ-r5 §3): `report_data = SHA-256(DOMAIN ‖ nonce ‖ card bytes) ‖ 0[32]`.
pub mod quote {
    /// Domain separator in front of the nonce and the card.
    pub const DOMAIN: &[u8] = b"tee-signer/quote/v1";
    /// `sgx_target_info_t` size.
    pub const TARGET_INFO_LEN: usize = 512;
    /// Verifier nonce size.
    pub const NONCE_LEN: usize = 32;
    /// `REPORT` input: target_info ‖ nonce.
    pub const INPUT_LEN: usize = TARGET_INFO_LEN + NONCE_LEN;
    /// `sgx_report_t` size.
    pub const REPORT_LEN: usize = 432;
    /// Offset of `report_data` inside `sgx_report_t` (after the 320-byte body prefix).
    pub const REPORT_DATA_OFFSET: usize = 320;
    /// The bytes the enclave hashes into `report_data[..32]`.
    pub fn preimage(nonce: &[u8; NONCE_LEN], card_bytes: &[u8]) -> alloc::vec::Vec<u8> {
        let mut v = alloc::vec::Vec::with_capacity(DOMAIN.len().saturating_add(NONCE_LEN).saturating_add(card_bytes.len()));
        v.extend_from_slice(DOMAIN);
        v.extend_from_slice(nonce);
        v.extend_from_slice(card_bytes);
        v
    }
}

/// Response to `REPORT`: the raw `sgx_report_t` and the identity card whose hash it binds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportResponse {
    /// `sgx_report_t`, 432 bytes, targeted at the quoting enclave.
    pub report: [u8; quote::REPORT_LEN],
    /// The card (public) recomputed from the envelope for this call.
    pub card: IdentityCard,
}

impl ReportResponse {
    /// Canonical bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::new();
        e.fixed(&self.report).bytes(&self.card.encode());
        e.finish()
    }
    /// Strict decode.
    pub fn decode(b: &[u8]) -> Result<Self, DecodeError> {
        let mut d = Dec::new(b);
        let report = d.fixed()?;
        let card = IdentityCard::decode(&d.bytes(256)?)?;
        d.finish()?;
        Ok(ReportResponse { report, card })
    }
}

/// A request that carries the sealed blob and one more byte string (message, headers, PSBT…).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedWith {
    /// The sealed blob.
    pub sealed: Vec<u8>,
    /// The operation's bytes.
    pub data: Vec<u8>,
    /// A second optional byte string (the witness token for `JUDGE`).
    pub extra: Option<Vec<u8>>,
}

impl SealedWith {
    /// Canonical bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::new();
        e.bytes(&self.sealed).bytes(&self.data).option(self.extra.as_ref(), |e, x| {
            e.bytes(x);
        });
        e.finish()
    }
    /// Strict decode with a bound on `data`.
    pub fn decode(b: &[u8], max_data: usize) -> Result<Self, DecodeError> {
        let mut d = Dec::new(b);
        let r = SealedWith {
            sealed: d.bytes(limits::MAX_SEALED)?,
            data: d.bytes(max_data)?,
            extra: d.option(|d| d.bytes(limits::MAX_MESSAGE))?,
        };
        d.finish()?;
        Ok(r)
    }
}

/// `JUDGE` success payload: the charged sealed blob and the summary fields a receipt will carry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JudgeResponse {
    /// Charged sealed blob — persist before `SIGN`.
    pub sealed: Vec<u8>,
    /// Receipt preview (`receipt::Receipt` canonical bytes, unsigned).
    pub receipt: Vec<u8>,
}

impl JudgeResponse {
    /// Canonical bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::new();
        e.bytes(&self.sealed).bytes(&self.receipt);
        e.finish()
    }
    /// Strict decode.
    pub fn decode(b: &[u8]) -> Result<Self, DecodeError> {
        let mut d = Dec::new(b);
        let r = JudgeResponse { sealed: d.bytes(limits::MAX_SEALED)?, receipt: d.bytes(limits::MAX_SMALL)? };
        d.finish()?;
        Ok(r)
    }
}

/// `SIGN` success payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignResponse {
    /// The PSBT with the enclave's partial signatures.
    pub psbt: Vec<u8>,
    /// Receipt canonical bytes.
    pub receipt: Vec<u8>,
    /// Identity signature over the receipt digest (compact).
    pub receipt_sig: [u8; 64],
    /// Session id of the signing enclave load.
    pub session_id: [u8; 16],
}

impl SignResponse {
    /// Canonical bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::new();
        e.bytes(&self.psbt).bytes(&self.receipt).fixed(&self.receipt_sig).fixed(&self.session_id);
        e.finish()
    }
    /// Strict decode.
    pub fn decode(b: &[u8]) -> Result<Self, DecodeError> {
        let mut d = Dec::new(b);
        let r = SignResponse {
            psbt: d.bytes(limits::MAX_PSBT)?,
            receipt: d.bytes(limits::MAX_SMALL)?,
            receipt_sig: d.fixed()?,
            session_id: d.fixed()?,
        };
        d.finish()?;
        Ok(r)
    }
}

/// `HEADERS` success payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeadersResponse {
    /// Sealed blob (chain view advanced, or frozen).
    pub sealed: Vec<u8>,
    /// Headers newly on the main chain.
    pub accepted: u32,
    /// Best height after.
    pub best_height: u32,
}

impl HeadersResponse {
    /// Canonical bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::new();
        e.bytes(&self.sealed).u32(self.accepted).u32(self.best_height);
        e.finish()
    }
    /// Strict decode.
    pub fn decode(b: &[u8]) -> Result<Self, DecodeError> {
        let mut d = Dec::new(b);
        let r = HeadersResponse { sealed: d.bytes(limits::MAX_SEALED)?, accepted: d.u32()?, best_height: d.u32()? };
        d.finish()?;
        Ok(r)
    }
}
