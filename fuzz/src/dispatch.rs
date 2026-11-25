//! Phase 2, pass (iii): the ecall dispatcher (F10) — `rcore` under `nosgx,test-init`, through the one exported
//! symbol `rcore_call` (what the edger8r bridge calls; `ops`, `envelope` and `session` are private to `rcore`,
//! and nothing here changes `enclave/`).
//!
//! The reading: `rcore` *marshals* — it opens the blob, gates on the volatile session (REQ-r7 boot-arm, the
//! sequence high-water mark) and on the TPM counter proof (REQ-r9, C-R9-C), calls `signer-core`, seals the
//! result. So the oracle for every op is computed from **the very request bytes** by walking `ops.rs`'s order
//! with the decisions taken by `signer-core`'s own functions (`apply_message`, `apply_arm`, `apply_anchor`,
//! `apply_headers`, `classify`, `judge`, `sign_own_inputs`, `verify_nv_certify`) on the state read from the
//! blob, plus the harness's model of the volatile session (armed, HWM, live nonce, deposited proof) and of the
//! host's TPM. No DESIGN §3/§6 state machine is modelled (RESP-r10): the policy decision is the core's.
//!
//! The `nosgx` seal is a tagged, unencrypted container (`sgx.rs`): the harness reads the envelope back
//! (`Env`) — the state the enclave actually decided on, the secrets that must never move, the two-phase
//! `last_judged` record — and predicts the sealed bytes exactly (the container is deterministic). The
//! hardware MAC is R2's smoke test, not this harness's: a mutated blob here is refused `STATE_UNSEALABLE` when
//! the container or the strict envelope decoder refuses it, and otherwise is simply a *different* valid
//! envelope the reading follows (nosgx has no MAC) — never an `Ok` on a garbled plaintext.
//!
//! Oracles (REQ-r10 phase 2 §1 F10, RESP-r10 C-R9-C/C-R7/C-R10-2):
//! - never a panic or an abort in `rcore` or `signer-core`; `rcore_call` returns `OK` for every input;
//!   every `Response` decodes and re-encodes to the same bytes (C-R10-2); `OUT_TOO_SMALL` names the length
//!   the retry needs; null pointers are `BAD_ARGS`;
//! - **the blob changes only through a `Fresh` op** (C-R9-C): `STATUS`/`POLICY`/`REPORT`/`TPM_*` never return
//!   a sealed blob; every new blob a `Fresh` op returns is exactly the core's result on the old one (`seq`,
//!   `nonce`, the window, the chain, the pending records, `tpm.expected + 1`), with the seed, the identity
//!   key, the owner and recovery keys and the network untouched;
//! - **after a TPM-bound state every `Fresh` op is refused without a deposited proof** (`TPM_REQUIRED`), with
//!   a proof for another nonce/index/key (`TPM_NONCE`/`TPM_INDEX`/`TPM_SIG`), for a counter other than the
//!   blob's (`STATE_STALE`); nonce and proof are consumed whatever the verdict; `Anchor` opens stale and pins
//!   the *live* counter (REQ-r9a); `Stale` ops never need a proof;
//! - **`SIGN` signs only the PSBT the preceding `JUDGE` charged for, byte for byte, on the charged blob**
//!   (`last_judged.psbt_hash`, `last_judged.seq == seq`), and `JUDGE` advances `seq` by exactly one; the
//!   signature bytes equal the harness's own RFC 6979 signing of the same inputs; the receipt is the judge's;
//! - REQ-r7: after a reload (`TEST_RESET_SESSION`) `JUDGE`/`SIGN` are `NOT_ARMED` until an `Arm` over this
//!   load's challenge (or a fresh counter proof); an older blob is `SEQ_BEHIND_SESSION` once the load produced
//!   or armed on a higher `seq`; `STATUS` reports the volatile facts (`boot_armed`, the challenge, the
//!   session id, `tpm_last_fresh`) exactly as the model has them;
//! - the direct invariants read off `STATUS`/`POLICY`: at most one pending owner and one pending mandate, a
//!   loosening installed only at its activation height, a freeze taken while unarmed still frozen after the
//!   `Arm` (C-R7-6), `armed == false` after a rollback-suspected refusal until `Rearm` — all as the core's
//!   state says, compared field by field;
//! - `recovery::decrypt` opens the init's recovery blob to the seed with the recovery key only, and to
//!   nothing after any single-byte change of the blob, the fingerprint or the xpub.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, OnceLock};

use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv, Xpub};
use bitcoin::block::Header;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{All, Secp256k1, SecretKey};
use bitcoin::Psbt;

use signer_core::classify::classify;
use signer_core::encoding::{Dec, Enc};
use signer_core::headers::apply_headers;
use signer_core::judge::{judge, Verdict};
use signer_core::mandate::{AccountPath, Freshness, Mandate, Matcher, Network};
use signer_core::proto::{
    limits, op, quote, HeadersResponse, IdentityCard, InitRequest, InitResponse, JudgeResponse, PolicyResponse,
    ReportResponse, Response, SealedResponse, SealedWith, SignResponse, StatusResponse, TestInitRequest, TpmProof,
};
use signer_core::reason::{Reason, Refusal};
use signer_core::receipt::Receipt;
use signer_core::sign::{sign_digest_secp, sign_own_inputs};
use signer_core::state::State;
use signer_core::tpm_attest::{build_nv_attest, certified_counter, verify_nv_certify, TpmAnchor, NV_NAME_LEN};
use signer_core::update::{Message, MAX_MANDATE_BYTES};
use signer_core::wallet::Account;

use crate::fixtures::{self, Keys, P256Key, ENCLAVE_ID};
use crate::{gen, policy, seeds};

/// One enclave = one process: the session mark is process-global, so one input at a time.
static LOCK: Mutex<()> = Mutex::new(());

/// Response buffer: a sealed blob (state ≤ `MAX_SEALED`) or a signed PSBT (≤ `MAX_PSBT`) plus slack.
const OUT_CAP: usize = 1024 * 1024;

const TAG: &[u8] = b"NOSGX-SEAL-V1";
const AAD: &[u8] = b"tee-signer/envelope/v1";
const ENVELOPE_VERSION: u16 = 1;
/// `session::TPM_PROOF` holds 72 words: a deposit longer than this is refused at the deposit (`TPM_NONCE`).
const PROOF_STORE: usize = 72 * 8;

/// The known op codes, for the raw mode's selector and the dictionary.
pub const OPS: [u32; 14] = [
    op::INIT,
    op::STATUS,
    op::POLICY,
    op::APPLY_MESSAGE,
    op::FREEZE,
    op::HEADERS,
    op::JUDGE,
    op::SIGN,
    op::INSTALL,
    op::REPORT,
    op::TPM_NONCE,
    op::TPM_PROOF,
    op::TEST_INIT,
    op::TEST_RESET_SESSION,
];

/// The honest payout script of the `classify`/`judge` seeds (`tests/replay.rs` `spend_spec(2, 0, 0, 0)`): one own
/// input (index 5, 2 000 000 sat), 900 000 sat to an unlisted script, the change to our (1, 0), fee 2 000.
const PAYOUT_SPEC: [u8; 18] = [0, 1, 2, 0, 0, 0, 0, 5, 0xcf, 0x07, 3, 1, 0x83, 0x03, 0, 1, 0x49, 0x04];

// ------------------------------------------------------------------------------------------------------------
// the ecall
// ------------------------------------------------------------------------------------------------------------

/// `rcore_call` as the bridge calls it. The one `unsafe` of the harness: the pointers and lengths are those of
/// live buffers, exactly the contract the edger8r bridge honours (`rcore::lib.rs`).
#[allow(unsafe_code)]
fn raw_call(op_code: u32, input: &[u8], cap: usize) -> (i32, usize, Vec<u8>) {
    let mut out = vec![0u8; cap];
    let mut out_len = 0usize;
    // SAFETY: `input` is a live slice (`in_len` bytes readable at `in_ptr`; the dangling pointer of an empty
    // slice is never dereferenced because `in_len == 0`); `out` has `cap` writable bytes; `out_len` is a live
    // `usize`. `rcore_call` reads at most `in_len`, writes at most `cap`, and checks every pointer first.
    let rc = unsafe { rcore::rcore_call(op_code, input.as_ptr(), input.len(), out.as_mut_ptr(), cap, &mut out_len) };
    if rc == rcore::status::OK {
        out.truncate(out_len.min(cap));
    } else {
        out.clear();
    }
    (rc, out_len, out)
}

/// The ABI's refusals: a null output pointer and a null input pointer with a non-zero length are `BAD_ARGS`,
/// before anything is read.
#[allow(unsafe_code)]
fn abi_bad_args() {
    let mut out_len = 0usize;
    let mut out = [0u8; 8];
    let input = [0u8; 4];
    // SAFETY: every pointer handed over is either a live buffer or null, and `rcore_call` refuses on a null
    // before dereferencing anything.
    let rc1 =
        unsafe { rcore::rcore_call(op::STATUS, input.as_ptr(), input.len(), std::ptr::null_mut(), 8, &mut out_len) };
    let rc2 = unsafe { rcore::rcore_call(op::STATUS, std::ptr::null(), 4, out.as_mut_ptr(), out.len(), &mut out_len) };
    assert_eq!(rc1, rcore::status::BAD_ARGS, "F10: a null output pointer is not BAD_ARGS");
    assert_eq!(rc2, rcore::status::BAD_ARGS, "F10: a null input pointer with a length is not BAD_ARGS");
}

/// One ecall with a large enough buffer; the response must decode and be canonical (C-R10-2).
fn call(op_code: u32, input: &[u8]) -> Response {
    let (rc, len, out) = raw_call(op_code, input, OUT_CAP);
    assert_eq!(rc, rcore::status::OK, "F10: rcore_call status {rc} (out_len {len}) for op {op_code}");
    assert_eq!(out.len(), len, "F10: out_len disagrees with the bytes written");
    let r = Response::decode(&out).expect("F10: the response does not decode (C-R10-2)");
    assert_eq!(r.encode(), out, "F10: the response does not re-encode to the bytes written (C-R10-2)");
    r
}

/// The retry protocol: a buffer too small is `OUT_TOO_SMALL` with the needed length in `out_len`; the retry
/// with exactly that length succeeds with the same bytes a large buffer gets.
fn abi_retry(op_code: u32, input: &[u8]) {
    let (rc, need, _) = raw_call(op_code, input, 4);
    assert_eq!(rc, rcore::status::OUT_TOO_SMALL, "F10: a 4-byte output buffer was not OUT_TOO_SMALL");
    let (rc2, len2, out2) = raw_call(op_code, input, need);
    assert_eq!(rc2, rcore::status::OK, "F10: the retry with the announced length failed");
    assert_eq!(len2, need, "F10: the retry wrote a different length than announced");
    let (rc3, _, out3) = raw_call(op_code, input, OUT_CAP);
    assert_eq!(rc3, rcore::status::OK);
    assert_eq!(out2, out3, "F10: the retry's bytes differ from a large-buffer call's");
}

// ------------------------------------------------------------------------------------------------------------
// the envelope as the nosgx container carries it (mirror of rcore's `envelope.rs` + `sgx.rs` nosgx arms)
// ------------------------------------------------------------------------------------------------------------

/// The two-phase sign record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lj {
    pub psbt_hash: [u8; 32],
    pub txid: [u8; 32],
    pub seq: u64,
    pub receipt: Vec<u8>,
}

/// What a sealed blob contains (`state` is `None` between `INIT` and `INSTALL`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Env {
    pub network: u8,
    pub seed: [u8; 32],
    pub identity_sk: [u8; 32],
    pub owner_pk: [u8; 65],
    pub recovery_pk: [u8; 65],
    pub state: Option<State>,
    pub last_judged: Option<Lj>,
}

fn encode_env(e: &Env) -> Vec<u8> {
    let mut enc = Enc::new();
    enc.u16(ENVELOPE_VERSION)
        .u8(e.network)
        .fixed(&e.seed)
        .fixed(&e.identity_sk)
        .fixed(&e.owner_pk)
        .fixed(&e.recovery_pk)
        .option(e.state.as_ref(), |enc, s| {
            enc.bytes(&s.encode());
        })
        .option(e.last_judged.as_ref(), |enc, l| {
            enc.fixed(&l.psbt_hash).fixed(&l.txid).u64(l.seq).bytes(&l.receipt);
        });
    enc.finish()
}

fn decode_env(b: &[u8]) -> Option<Env> {
    let mut d = Dec::new(b);
    if d.u16().ok()? != ENVELOPE_VERSION {
        return None;
    }
    let network = d.u8().ok()?;
    let seed = d.fixed().ok()?;
    let identity_sk = d.fixed().ok()?;
    let owner_pk = d.fixed().ok()?;
    let recovery_pk = d.fixed().ok()?;
    let state = d.option(|d| State::decode(&d.bytes(limits::MAX_SEALED)?)).ok()?;
    let last_judged = d
        .option(|d| {
            Ok(Lj { psbt_hash: d.fixed()?, txid: d.fixed()?, seq: d.u64()?, receipt: d.bytes(limits::MAX_SMALL)? })
        })
        .ok()?;
    d.finish().ok()?;
    Some(Env { network, seed, identity_sk, owner_pk, recovery_pk, state, last_judged })
}

/// `sgx::unseal`, nosgx arm: `(aad, plain)` or `None`.
fn open_container(sealed: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    if sealed.len() < TAG.len() + 8 || &sealed[..TAG.len()] != TAG {
        return None;
    }
    let mut p = TAG.len();
    let al = u32::from_le_bytes(sealed[p..p + 4].try_into().ok()?) as usize;
    p += 4;
    let aad = sealed.get(p..p.checked_add(al)?)?.to_vec();
    p += al;
    let tl = u32::from_le_bytes(sealed.get(p..p + 4)?.try_into().ok()?) as usize;
    p += 4;
    let txt = sealed.get(p..p.checked_add(tl)?)?.to_vec();
    if p + tl != sealed.len() {
        return None;
    }
    Some((aad, txt))
}

/// `sgx::seal`, nosgx arm.
fn seal_container(plain: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(TAG.len() + 8 + AAD.len() + plain.len());
    out.extend_from_slice(TAG);
    out.extend_from_slice(&(AAD.len() as u32).to_le_bytes());
    out.extend_from_slice(AAD);
    out.extend_from_slice(&(plain.len() as u32).to_le_bytes());
    out.extend_from_slice(plain);
    out
}

/// `Envelope::unseal` as the enclave does it on host bytes: container, AAD, strict decode.
pub fn open_env(sealed: &[u8]) -> Option<Env> {
    let (aad, plain) = open_container(sealed)?;
    if aad != AAD {
        return None;
    }
    let env = decode_env(&plain)?;
    // C-R10-2 on the envelope: whatever the enclave accepts as its own blob re-encodes to the same plaintext
    assert_eq!(encode_env(&env), plain, "F10: an accepted envelope is not canonical (C-R10-2)");
    Some(env)
}

/// `seal_or`: a TPM-bound state leaves with `expected + 1`, then the canonical plaintext in the container.
fn seal_env(env: &Env) -> Vec<u8> {
    let mut e = env.clone();
    if let Some(s) = e.state.as_mut() {
        s.bump_tpm();
    }
    seal_container(&encode_env(&e))
}

// ------------------------------------------------------------------------------------------------------------
// what the enclave derives from the blob (mirror of `ops::derive_keys`), cached — pure functions of (network, seed)
// ------------------------------------------------------------------------------------------------------------

#[derive(Clone)]
struct Derived {
    account_xpriv: Xpriv,
    account: Account,
    xpub: [u8; 78],
    fingerprint: [u8; 4],
}

fn network_from(b: u8) -> Option<Network> {
    match b {
        0 => Some(Network::Mainnet),
        1 => Some(Network::Testnet4),
        2 => Some(Network::Signet),
        3 => Some(Network::Regtest),
        _ => None,
    }
}

type DeriveCache = Mutex<HashMap<(u8, [u8; 32]), Derived>>;

fn derive(secp: &Secp256k1<All>, network: Network, seed: &[u8; 32]) -> Option<Derived> {
    static CACHE: OnceLock<DeriveCache> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let key = (network as u8, *seed);
    if let Some(d) = cache.lock().unwrap().get(&key) {
        return Some(d.clone());
    }
    let m = signer_core::bip39::mnemonic(seed);
    let seed64 = signer_core::bip39::seed(&m);
    let master = Xpriv::new_master(network.to_bitcoin(), &seed64).ok()?;
    let path = DerivationPath::from(vec![
        ChildNumber::from_hardened_idx(84).ok()?,
        ChildNumber::from_hardened_idx(network.coin_type()).ok()?,
        ChildNumber::from_hardened_idx(0).ok()?,
    ]);
    let account_xpriv = master.derive_priv(secp, &path).ok()?;
    let xpub_obj = Xpub::from_priv(secp, &account_xpriv);
    let mut fingerprint = [0u8; 4];
    fingerprint.copy_from_slice(master.fingerprint(secp).as_bytes());
    let d = Derived {
        account_xpriv,
        account: Account {
            fingerprint,
            path: AccountPath { purpose: 84, coin: network.coin_type(), account: 0 },
            xpub: xpub_obj,
        },
        xpub: xpub_obj.encode(),
        fingerprint,
    };
    cache.lock().unwrap().insert(key, d.clone());
    Some(d)
}

/// The regtest fixture (a mined checkpoint, the base mandate on regtest, the state at init), built once.
fn regtest() -> &'static (State, Header) {
    static R: OnceLock<(State, Header)> = OnceLock::new();
    R.get_or_init(|| gen::regtest_state(6))
}

fn identity_pk(secp: &Secp256k1<All>, sk: &[u8; 32]) -> Option<[u8; 33]> {
    Some(SecretKey::from_slice(sk).ok()?.public_key(secp).serialize())
}

fn codes(r: &Refusal) -> Vec<String> {
    r.0.iter().map(|x| x.code().to_string()).collect()
}

fn one(r: Reason) -> Vec<String> {
    vec![r.code().to_string()]
}

/// A refusal with no payload, exactly these codes.
fn refused(r: &Response, want: &[String], what: &str) {
    assert!(!r.ok, "F10 {what}: accepted although the reading refuses {want:?}");
    assert_eq!(r.reasons, want, "F10 {what}: the refusal codes differ from the reading");
    assert!(r.payload.is_empty(), "F10 {what}: a plain refusal carries a payload");
}

fn accepted(r: &Response, payload: &[u8], what: &str) {
    assert!(r.ok, "F10 {what}: refused {:?} although the reading accepts", r.reasons);
    assert!(r.reasons.is_empty(), "F10 {what}: an accepted response carries reasons");
    assert_eq!(r.payload, payload, "F10 {what}: the payload differs from the reading");
}

fn tier() -> String {
    "T0-nosgx".to_string()
}

fn clock_label(n: Network) -> &'static str {
    match n {
        Network::Mainnet => "",
        Network::Testnet4 => "testnet4: min-difficulty blocks allowed; the block clock is weaker than mainnet",
        Network::Signet => {
            "signet: proof-of-work is cheap; the block clock is a correctness device here, not a security one"
        }
        Network::Regtest => "regtest: no proof of work; windows and timelocks are not a defence",
    }
}

// ------------------------------------------------------------------------------------------------------------
// the host's TPM (REQ-r9 software stand-in): an AK, an index Name, a counter that only increments
// ------------------------------------------------------------------------------------------------------------

struct Tpm {
    ak: P256Key,
    other_ak: P256Key,
    name: [u8; NV_NAME_LEN],
    signer_name: Vec<u8>,
    counter: u64,
}

impl Tpm {
    fn new() -> Self {
        let h = seeds::honest();
        Tpm {
            ak: P256Key { sk: h.ak.sk.clone(), pk: h.ak.pk },
            other_ak: fixtures::p256_key(0xe5),
            name: seeds::name(0x5a),
            signer_name: h.signer_name.clone(),
            counter: 1000,
        }
    }
    /// `TPM2_NV_Certify` over `nonce` as the host wants it: honest (`variant` 0) or lying.
    fn certify(&self, nonce: &[u8; 32], variant: u8, junk: u8) -> Vec<u8> {
        let (key, name, counter, n) = match variant {
            1 => (&self.ak, self.name, self.counter.wrapping_add(1), *nonce),
            2 => (&self.ak, self.name, self.counter.wrapping_sub(1), *nonce),
            3 => (&self.other_ak, self.name, self.counter, *nonce),
            4 => (&self.ak, seeds::name(0x5b), self.counter, *nonce),
            5 => (&self.ak, self.name, self.counter, {
                let mut m = *nonce;
                m[0] ^= 0x80;
                m
            }),
            _ => (&self.ak, self.name, self.counter, *nonce),
        };
        let attest = if variant == 6 {
            vec![junk; 1 + usize::from(junk) % 40]
        } else if variant == 7 {
            // MAX_ATTEST_LEN: decodes as a proof, but 4 + 512 + 64 bytes exceed the 576-byte deposit store (§6)
            vec![junk; signer_core::tpm_attest::MAX_ATTEST_LEN]
        } else {
            build_nv_attest(&self.signer_name, &n, &name, counter)
        };
        let sig = seeds::sign_attest(key, &attest);
        TpmProof { attest, sig }.encode()
    }
}

// ------------------------------------------------------------------------------------------------------------
// the model of the volatile session (`rcore::session`) as the harness tracks it
// ------------------------------------------------------------------------------------------------------------

#[derive(Default)]
struct Shell {
    armed: bool,
    hwm: u64,
    /// Learned from `STATUS` after each load; `None` until then.
    challenge: Option<[u8; 32]>,
    session_id: Option<[u8; 16]>,
    /// The live nonce (issued, not yet consumed).
    nonce: Option<[u8; 32]>,
    /// The deposited proof bytes for the live nonce.
    proof: Option<Vec<u8>>,
    last_fresh: bool,
}

// ------------------------------------------------------------------------------------------------------------
// the harness
// ------------------------------------------------------------------------------------------------------------

struct H {
    secp: Secp256k1<All>,
    keys: Keys,
    stranger: P256Key,
    new_owner: P256Key,
    tpm: Tpm,
    shell: Shell,
    /// The blob the host holds now (empty before an init).
    blob: Vec<u8>,
    /// Every blob held so far (replays of an older one are how `SEQ_BEHIND_SESSION` is reached).
    history: Vec<Vec<u8>>,
    /// Every header the harness mined, by hash, so an honest batch extends whatever chain the state adopted.
    headers: BTreeMap<[u8; 32], Header>,
    /// The bytes of the last PSBT a `JUDGE` charged for (the harness's copy; the enclave's is `last_judged`).
    judged_psbt: Option<Vec<u8>>,
    /// Host discipline: increment the counter after persisting a TPM-bound blob (a flag the input may clear).
    increment: bool,
    /// The last init's recovery blob with its wallet binding (when the recovery key is the fixture's).
    recovery: Option<(Vec<u8>, [u8; 4], [u8; 78])>,
}

impl H {
    fn new() -> Self {
        let mut headers = BTreeMap::new();
        let cp = regtest().1;
        headers.insert(gen::hash32(&cp), cp);
        H {
            secp: Secp256k1::new(),
            keys: fixtures::keys(),
            stranger: fixtures::p256_key(0x99),
            new_owner: fixtures::p256_key(0xd4),
            tpm: Tpm::new(),
            shell: Shell::default(),
            blob: Vec::new(),
            history: Vec::new(),
            headers,
            judged_psbt: None,
            increment: true,
            recovery: None,
        }
    }

    /// The host persisted a new blob: it is the current one, and a TPM-bound blob is followed by the counter
    /// increment (unless the input told the host to forget it — then the next `Fresh` op is `STATE_STALE`).
    fn adopt(&mut self, sealed: Vec<u8>) {
        let env = open_env(&sealed).expect("F10: the enclave returned a blob it would not open itself");
        if env.state.as_ref().and_then(|s| s.tpm.as_ref()).is_some() && self.increment {
            self.tpm.counter += 1;
        }
        self.history.push(sealed.clone());
        self.blob = sealed;
    }

    // ---- the session gates, mirrored ---------------------------------------------------------------------

    fn open_stale(&self, sealed: &[u8]) -> Result<(Env, State), Vec<String>> {
        let env = open_env(sealed).ok_or_else(|| one(Reason::StateUnsealable))?;
        if invalid_state(&env) {
            return Err(one(Reason::StateInvalid));
        }
        let s = env.state.clone().ok_or_else(|| one(Reason::StateUnsealable))?;
        Ok((env, s))
    }

    /// `open_full_fresh`: the TPM gate when the state is bound; nonce and proof consumed whatever the verdict;
    /// a verified fresh proof arms the load (RESP-r9 Q4).
    fn open_fresh(&mut self, sealed: &[u8]) -> Result<(Env, State), Vec<String>> {
        let (env, s) = self.open_stale(sealed)?;
        if let Some(anchor) = s.tpm.as_ref() {
            let (n, p) = (self.shell.nonce.take(), self.shell.proof.take());
            let (Some(nonce), Some(bytes)) = (n, p) else {
                self.shell.last_fresh = false;
                return Err(one(Reason::TpmRequired));
            };
            let Ok(proof) = TpmProof::decode(&bytes) else {
                self.shell.last_fresh = false;
                return Err(one(Reason::TpmParse));
            };
            match verify_nv_certify(&proof.attest, &proof.sig, anchor, &nonce) {
                Ok(_) => {
                    self.shell.last_fresh = true;
                    self.shell.armed = true;
                }
                Err(r) => {
                    self.shell.last_fresh = false;
                    return Err(one(r));
                }
            }
        }
        Ok((env, s))
    }

    /// `anchor_live_counter` (REQ-r9a).
    fn anchor_live(&mut self, s: &State, msg: &Message) -> Result<u64, Refusal> {
        let (n, p) = (self.shell.nonce.take(), self.shell.proof.take());
        let (Some(nonce), Some(bytes)) = (n, p) else {
            self.shell.last_fresh = false;
            return Err(Reason::TpmRequired.into());
        };
        let (ak_pk, nv_name) = match s.anchor_identity(msg) {
            Ok(id) => id,
            Err(r) => {
                self.shell.last_fresh = false;
                return Err(r);
            }
        };
        if !(TpmAnchor { ak_pk, nv_name, expected: 0 }).well_formed() {
            self.shell.last_fresh = false;
            return Err(Reason::PolicyInvalid.into());
        }
        let Ok(proof) = TpmProof::decode(&bytes) else {
            self.shell.last_fresh = false;
            return Err(Reason::TpmParse.into());
        };
        match certified_counter(&proof.attest, &proof.sig, &ak_pk, &nv_name, &nonce) {
            Ok(live) => {
                self.shell.last_fresh = true;
                Ok(live)
            }
            Err(r) => {
                self.shell.last_fresh = false;
                Err(r.into())
            }
        }
    }

    fn check_seq(&self, s: &State) -> Result<(), Vec<String>> {
        if s.seq >= self.shell.hwm {
            Ok(())
        } else {
            Err(one(Reason::SeqBehindSession))
        }
    }

    // ---- learning the volatile facts ---------------------------------------------------------------------

    /// A `STATUS` read after a load, to learn this load's challenge and session id (checked like any step).
    fn learn(&mut self) {
        if self.blob.is_empty() {
            return;
        }
        let input = self.blob.clone();
        self.perform(op::STATUS, input);
    }

    fn reset(&mut self) {
        let r = call(op::TEST_RESET_SESSION, &[]);
        accepted(&r, &[], "TEST_RESET_SESSION");
        self.shell = Shell::default();
        self.learn();
    }

    // ---- one op: call, then check the response against the reading --------------------------------------

    fn perform(&mut self, op_code: u32, input: Vec<u8>) {
        let carried = carried_state(op_code, &input);
        if trace() {
            let summary = carried.as_ref().map(|s| {
                let trusted: Vec<String> = s
                    .mandate
                    .destinations
                    .trusted
                    .iter()
                    .map(|t| match &t.matcher {
                        Matcher::Address { .. } => "addr".to_string(),
                        Matcher::Descriptor { branches, gap, .. } => format!("desc{branches:?}/gap={gap}"),
                    })
                    .collect();
                format!("state: seq={} validate={} trusted={:?}", s.seq, s.mandate.validate().is_ok(), trusted)
            });
            eprintln!("F10-trace call op={op_code:<3} in={:<6} {}", input.len(), summary.unwrap_or_default());
        }
        // R11 (C-EXT1-3): a carried state that fails `validate` is no longer skipped — the enclave refuses it
        // STATE_INVALID at `open()`, before any gate and before the counter proof is taken; the reading predicts
        // exactly that (`invalid_state` in every opener)
        let r = call(op_code, &input);
        if trace() {
            eprintln!(
                "F10-trace op={op_code:<3} in={:<6} -> {} {:?} payload={}",
                input.len(),
                if r.ok { "ok    " } else { "refuse" },
                r.reasons,
                r.payload.len()
            );
        }
        match op_code {
            op::INIT => self.check_init(&input, &r),
            op::STATUS => self.check_status(&input, &r),
            op::POLICY => self.check_policy(&input, &r),
            op::REPORT => self.check_report(&input, &r),
            op::FREEZE => self.check_freeze(&input, &r),
            op::HEADERS => self.check_headers(&input, &r),
            op::APPLY_MESSAGE => self.check_apply(&input, &r),
            op::JUDGE => self.check_judge(&input, &r),
            op::SIGN => self.check_sign(&input, &r),
            op::INSTALL => self.check_install(&input, &r),
            op::TPM_NONCE => self.check_tpm_nonce(&r),
            op::TPM_PROOF => self.check_tpm_proof(&input, &r),
            op::TEST_INIT => self.check_test_init(&input, &r),
            op::TEST_RESET_SESSION => {
                accepted(&r, &[], "TEST_RESET_SESSION");
                self.shell = Shell::default();
                self.learn();
            }
            _ => refused(&r, &["UNKNOWN_OP".to_string()], "an unknown op"),
        }
    }

    fn check_status(&mut self, input: &[u8], r: &Response) {
        let Some(env) = open_env(input) else { return refused(r, &one(Reason::StateUnsealable), "STATUS") };
        if invalid_state(&env) {
            return refused(r, &one(Reason::StateInvalid), "STATUS");
        }
        let Some(net) = network_from(env.network) else { return refused(r, &one(Reason::PolicyNetwork), "STATUS") };
        let Some(k) = derive(&self.secp, net, &env.seed) else {
            return refused(r, &["KEY_DERIVATION".to_string()], "STATUS");
        };
        let Some(idpk) = identity_pk(&self.secp, &env.identity_sk) else {
            return refused(r, &["KEY_DERIVATION".to_string()], "STATUS");
        };
        assert!(r.ok, "F10 STATUS: refused {:?} on a blob that opens", r.reasons);
        let got = StatusResponse::decode(&r.payload).expect("F10 STATUS: the payload does not decode");
        if self.shell.challenge.is_none() {
            // the first read after a load learns the random per-load facts
            self.shell.challenge = Some(got.boot_challenge);
            self.shell.session_id = Some(got.session_id);
        }
        let (challenge, session_id) = (self.shell.challenge.unwrap(), self.shell.session_id.unwrap());
        let want = match env.state.as_ref() {
            None => StatusResponse {
                installed: false,
                tier: tier(),
                mrenclave: [0; 32],
                session_id,
                network: env.network,
                xpub: k.xpub,
                fingerprint: k.fingerprint,
                identity_pk: idpk,
                nonce: 0,
                seq: 0,
                frozen: false,
                armed: true,
                chain_frozen: false,
                best_height: 0,
                best_hash: [0; 32],
                window_start: 0,
                window_outflow: 0,
                window_unlisted: 0,
                window_fees: 0,
                mandate_hash: [0; 32],
                pending: None,
                pending_owner: None,
                clock_label: clock_label(net).to_string(),
                boot_armed: self.shell.armed,
                boot_challenge: challenge,
                auto_arm: false,
                tpm_bound: false,
                tpm_expected: 0,
                tpm_last_fresh: self.shell.last_fresh,
            },
            Some(s) => {
                let mut st = s.clone();
                st.activate_pending();
                st.roll_window();
                StatusResponse {
                    installed: true,
                    tier: tier(),
                    mrenclave: [0; 32],
                    session_id,
                    network: env.network,
                    xpub: k.xpub,
                    fingerprint: k.fingerprint,
                    identity_pk: idpk,
                    nonce: st.nonce,
                    seq: st.seq,
                    frozen: st.frozen,
                    armed: st.armed,
                    chain_frozen: st.chain.frozen,
                    best_height: st.chain.best.map(|b| b.height).unwrap_or(0),
                    best_hash: st.chain.best.map(|b| b.hash).unwrap_or([0; 32]),
                    window_start: st.window.start_height,
                    window_outflow: st.window.outflow,
                    window_unlisted: st.window.unlisted,
                    window_fees: st.window.fees,
                    mandate_hash: st.mandate.hash(),
                    pending: st.pending.as_ref().map(|p| (p.mandate.hash(), p.activation_height)),
                    pending_owner: st.pending_owner.as_ref().map(|p| p.activation_height),
                    clock_label: clock_label(net).to_string(),
                    boot_armed: self.shell.armed,
                    boot_challenge: challenge,
                    auto_arm: false,
                    tpm_bound: st.tpm.is_some(),
                    tpm_expected: st.tpm.as_ref().map(|t| t.expected).unwrap_or(0),
                    tpm_last_fresh: self.shell.last_fresh,
                }
            }
        };
        assert_eq!(got, want, "F10 STATUS: the report differs from the state in the blob and the session model");
        assert_eq!(r.payload, want.encode(), "F10 STATUS: payload not canonical");
    }

    fn check_policy(&mut self, input: &[u8], r: &Response) {
        let (_, s) = match self.open_stale(input) {
            Ok(x) => x,
            Err(c) => return refused(r, &c, "POLICY"),
        };
        let want = PolicyResponse {
            mandate: s.mandate.encode(),
            sig: s.mandate_sig,
            nonce: s.nonce,
            pending: s.pending.as_ref().map(|p| (p.mandate.encode(), p.sig, p.nonce, p.activation_height)),
        };
        accepted(r, &want.encode(), "POLICY");
    }

    fn check_report(&mut self, input: &[u8], r: &Response) {
        let enc = || vec!["ENCODING".to_string()];
        let Ok(req) = SealedWith::decode(input, quote::INPUT_LEN) else { return refused(r, &enc(), "REPORT") };
        if req.data.len() != quote::INPUT_LEN || req.extra.is_some() {
            return refused(r, &enc(), "REPORT");
        }
        let Some(env) = open_env(&req.sealed) else { return refused(r, &one(Reason::StateUnsealable), "REPORT") };
        if invalid_state(&env) {
            return refused(r, &one(Reason::StateInvalid), "REPORT");
        }
        let Some(net) = network_from(env.network) else { return refused(r, &one(Reason::PolicyNetwork), "REPORT") };
        let Some(k) = derive(&self.secp, net, &env.seed) else {
            return refused(r, &["KEY_DERIVATION".to_string()], "REPORT");
        };
        let Some(idpk) = identity_pk(&self.secp, &env.identity_sk) else {
            return refused(r, &["KEY_DERIVATION".to_string()], "REPORT");
        };
        let card = IdentityCard {
            mrenclave: [0; 32],
            network: env.network,
            xpub: k.xpub,
            fingerprint: k.fingerprint,
            identity_pk: idpk,
            tier: tier(),
        };
        let mut nonce = [0u8; quote::NONCE_LEN];
        nonce.copy_from_slice(&req.data[quote::TARGET_INFO_LEN..quote::INPUT_LEN]);
        let mut report = [0u8; quote::REPORT_LEN];
        let o = quote::REPORT_DATA_OFFSET;
        report[o..o + 32].copy_from_slice(&signer_core::sha256(&quote::preimage(&nonce, &card.encode())));
        let want = ReportResponse { report, card };
        accepted(r, &want.encode(), "REPORT");
    }

    fn check_freeze(&mut self, input: &[u8], r: &Response) {
        let (mut env, mut s) = match self.open_fresh(input) {
            Ok(x) => x,
            Err(c) => return refused(r, &c, "FREEZE"),
        };
        s.freeze();
        env.state = Some(s);
        let sealed = seal_env(&env);
        accepted(r, &SealedResponse { sealed: sealed.clone() }.encode(), "FREEZE");
        self.adopt(sealed);
    }

    fn check_headers(&mut self, input: &[u8], r: &Response) {
        let hi = || one(Reason::HeaderInvalid);
        let Ok(req) = SealedWith::decode(input, limits::MAX_HEADERS.saturating_mul(80)) else {
            return refused(r, &hi(), "HEADERS");
        };
        if req.data.len() % 80 != 0 {
            return refused(r, &hi(), "HEADERS");
        }
        let (mut env, mut s) = match self.open_fresh(&req.sealed) {
            Ok(x) => x,
            Err(c) => return refused(r, &c, "HEADERS"),
        };
        if let Err(c) = self.check_seq(&s) {
            return refused(r, &c, "HEADERS");
        }
        let hs: Vec<[u8; 80]> = req.data.chunks_exact(80).map(|c| c.try_into().unwrap()).collect();
        let res = apply_headers(&mut s, &hs);
        let best_height = s.chain.best.map(|b| b.height).unwrap_or(0);
        env.state = Some(s);
        let sealed = seal_env(&env);
        match res {
            Ok(accepted_n) => {
                let want = HeadersResponse { sealed: sealed.clone(), accepted: accepted_n, best_height };
                accepted(r, &want.encode(), "HEADERS");
            }
            Err(rf) => {
                // a freeze is a state change the host must persist even though the batch refused
                assert!(!r.ok, "F10 HEADERS: accepted a batch the core refuses {:?}", codes(&rf));
                assert_eq!(r.reasons, codes(&rf), "F10 HEADERS: refusal codes differ from the core's");
                let want = HeadersResponse { sealed: sealed.clone(), accepted: 0, best_height };
                assert_eq!(r.payload, want.encode(), "F10 HEADERS: the refused batch's payload differs");
            }
        }
        self.adopt(sealed);
    }

    fn check_apply(&mut self, input: &[u8], r: &Response) {
        let pi = || one(Reason::PolicyInvalid);
        let Ok(req) = SealedWith::decode(input, limits::MAX_MESSAGE) else { return refused(r, &pi(), "APPLY_MESSAGE") };
        let Ok(msg) = Message::decode(&req.data) else { return refused(r, &pi(), "APPLY_MESSAGE") };
        let opened = match &msg {
            Message::Anchor { .. } => self.open_stale(&req.sealed),
            _ => self.open_fresh(&req.sealed),
        };
        let (mut env, s) = match opened {
            Ok(x) => x,
            Err(c) => return refused(r, &c, "APPLY_MESSAGE"),
        };
        if let Err(c) = self.check_seq(&s) {
            return refused(r, &c, "APPLY_MESSAGE");
        }
        let challenge = self.shell.challenge.unwrap_or([0; 32]);
        let result = match &msg {
            Message::Arm { .. } => s.apply_arm(&msg, &challenge),
            Message::Anchor { .. } => match self.anchor_live(&s, &msg) {
                Ok(live) => {
                    let x = s.apply_anchor(&msg, &challenge, live);
                    if x.is_err() {
                        self.shell.last_fresh = false;
                    }
                    x
                }
                Err(e) => Err(e),
            },
            _ => s.apply_message(&msg),
        };
        match result {
            Ok(ns) => {
                self.shell.hwm = self.shell.hwm.max(ns.seq);
                if matches!(msg, Message::Arm { .. } | Message::Anchor { .. }) {
                    self.shell.armed = true;
                }
                env.state = Some(ns);
                let sealed = seal_env(&env);
                accepted(r, &SealedResponse { sealed: sealed.clone() }.encode(), "APPLY_MESSAGE");
                self.adopt(sealed);
            }
            Err(rf) => refused(r, &codes(&rf), "APPLY_MESSAGE"),
        }
    }

    fn check_judge(&mut self, input: &[u8], r: &Response) {
        let pp = || one(Reason::PsbtParse);
        let Ok(req) = SealedWith::decode(input, limits::MAX_PSBT) else { return refused(r, &pp(), "JUDGE") };
        let (mut env, s) = match self.open_fresh(&req.sealed) {
            Ok(x) => x,
            Err(c) => return refused(r, &c, "JUDGE"),
        };
        if let Err(c) = self.check_seq(&s) {
            return refused(r, &c, "JUDGE");
        }
        if !self.shell.armed {
            return refused(r, &one(Reason::NotArmed), "JUDGE");
        }
        let witness = match &req.extra {
            None => None,
            Some(b) => match Message::decode(b) {
                Ok(m @ Message::WitnessToken { .. }) => Some(m),
                _ => return refused(r, &one(Reason::FreshnessSig), "JUDGE"),
            },
        };
        let Some(net) = network_from(env.network) else { return refused(r, &one(Reason::PolicyNetwork), "JUDGE") };
        let Some(k) = derive(&self.secp, net, &env.seed) else {
            return refused(r, &["KEY_DERIVATION".to_string()], "JUDGE");
        };
        let classified = match classify(&self.secp, &req.data, &k.account, &s.mandate, s.own_index_bound) {
            Ok(c) => c,
            Err(rf) => return refused(r, &codes(&rf), "JUDGE"),
        };
        match judge(&s, &classified, witness.as_ref()) {
            Verdict::Accept { state, summary } => {
                assert_eq!(state.seq, s.seq + 1, "F10: JUDGE did not advance seq by exactly one");
                let receipt = Receipt::from_summary(state.enclave_id, &summary).encode();
                self.shell.hwm = self.shell.hwm.max(state.seq);
                env.last_judged = Some(Lj {
                    psbt_hash: signer_core::sha256(&req.data),
                    txid: summary.txid,
                    seq: state.seq,
                    receipt: receipt.clone(),
                });
                env.state = Some(state);
                let sealed = seal_env(&env);
                accepted(r, &JudgeResponse { sealed: sealed.clone(), receipt }.encode(), "JUDGE");
                self.judged_psbt = Some(req.data.clone());
                self.adopt(sealed);
            }
            Verdict::Refuse { refusal, disarm } => match disarm {
                None => refused(r, &codes(&refusal), "JUDGE"),
                Some(st) => {
                    // C-R10-4 through the dispatcher: the one refusal that changes the blob — the disarmed state
                    // is sealed and returned beside the refusal, nothing else moves (no HWM, no last_judged)
                    assert!(!st.armed && s.armed, "F10: a disarming refusal did not disarm");
                    env.state = Some(st);
                    let sealed = seal_env(&env);
                    assert!(!r.ok, "F10 JUDGE: accepted although the core refuses with a disarm");
                    assert_eq!(r.reasons, codes(&refusal), "F10 JUDGE: disarm refusal codes differ from the core's");
                    assert_eq!(
                        r.payload,
                        SealedResponse { sealed: sealed.clone() }.encode(),
                        "F10 JUDGE: the disarmed blob differs"
                    );
                    self.adopt(sealed);
                }
            },
        }
    }

    fn check_sign(&mut self, input: &[u8], r: &Response) {
        let pp = || one(Reason::PsbtParse);
        let Ok(req) = SealedWith::decode(input, limits::MAX_PSBT) else { return refused(r, &pp(), "SIGN") };
        let (env, s) = match self.open_fresh(&req.sealed) {
            Ok(x) => x,
            Err(c) => return refused(r, &c, "SIGN"),
        };
        if let Err(c) = self.check_seq(&s) {
            return refused(r, &c, "SIGN");
        }
        if !self.shell.armed {
            return refused(r, &one(Reason::NotArmed), "SIGN");
        }
        // the two-phase rule: only the PSBT this very blob was charged for, byte for byte
        let Some(lj) = env.last_judged.as_ref() else { return refused(r, &pp(), "SIGN") };
        if lj.psbt_hash != signer_core::sha256(&req.data) || lj.seq != s.seq {
            return refused(r, &pp(), "SIGN");
        }
        let Some(net) = network_from(env.network) else { return refused(r, &one(Reason::PolicyNetwork), "SIGN") };
        let Some(k) = derive(&self.secp, net, &env.seed) else {
            return refused(r, &["KEY_DERIVATION".to_string()], "SIGN");
        };
        let mut bound = s.own_index_bound;
        bound[0] = bound[0].saturating_add(s.mandate.limits.own_index_gap);
        bound[1] = bound[1].saturating_add(s.mandate.limits.own_index_gap);
        let classified = match classify(&self.secp, &req.data, &k.account, &s.mandate, bound) {
            Ok(c) => c,
            Err(rf) => return refused(r, &codes(&rf), "SIGN"),
        };
        let Ok(mut psbt) = Psbt::deserialize(&req.data) else { return refused(r, &pp(), "SIGN") };
        if let Err(rf) = sign_own_inputs(&self.secp, &mut psbt, &k.account_xpriv, &classified) {
            return refused(r, &codes(&rf), "SIGN");
        }
        let Ok(id_sk) = SecretKey::from_slice(&env.identity_sk) else {
            return refused(r, &["KEY_DERIVATION".to_string()], "SIGN");
        };
        let Ok(receipt) = Receipt::decode(&lj.receipt) else {
            return refused(r, &one(Reason::StateUnsealable), "SIGN");
        };
        let want = SignResponse {
            psbt: psbt.serialize(),
            receipt: lj.receipt.clone(),
            receipt_sig: sign_digest_secp(&self.secp, &id_sk, &receipt.digest()),
            session_id: self.shell.session_id.unwrap_or([0; 16]),
        };
        // RFC 6979 makes both the input signatures and the receipt signature deterministic: exact bytes
        accepted(r, &want.encode(), "SIGN");
        // and what was signed is what was judged: the harness's own copy of the charged bytes
        if let Some(j) = self.judged_psbt.as_ref() {
            assert_eq!(*j, req.data, "F10: SIGN signed bytes other than the ones the harness saw JUDGE charge for");
        }
    }

    fn check_install(&mut self, input: &[u8], r: &Response) {
        let pi = || one(Reason::PolicyInvalid);
        let Ok(req) = SealedWith::decode(input, MAX_MANDATE_BYTES) else { return refused(r, &pi(), "INSTALL") };
        let Some(mut env) = open_env(&req.sealed) else { return refused(r, &one(Reason::StateUnsealable), "INSTALL") };
        if invalid_state(&env) {
            return refused(r, &one(Reason::StateInvalid), "INSTALL");
        }
        if env.state.is_some() {
            return refused(r, &one(Reason::PolicyPending), "INSTALL");
        }
        let Some(sig_bytes) = req.extra.as_deref() else { return refused(r, &one(Reason::PolicySig), "INSTALL") };
        let Ok(sig) = <[u8; 64]>::try_from(sig_bytes) else { return refused(r, &one(Reason::PolicySig), "INSTALL") };
        let Some(net) = network_from(env.network) else { return refused(r, &one(Reason::PolicyNetwork), "INSTALL") };
        let Some(k) = derive(&self.secp, net, &env.seed) else {
            return refused(r, &["KEY_DERIVATION".to_string()], "INSTALL");
        };
        let Some(idpk) = identity_pk(&self.secp, &env.identity_sk) else {
            return refused(r, &["KEY_DERIVATION".to_string()], "INSTALL");
        };
        let enclave_id = signer_core::sha256(&idpk);
        let msg = Message::PolicyUpdate { enclave_id, nonce: 0, mandate: req.data.clone(), sig };
        if !msg.verify(&env.owner_pk) {
            return refused(r, &one(Reason::PolicySig), "INSTALL");
        }
        let Ok(mandate) = Mandate::decode(&req.data) else { return refused(r, &pi(), "INSTALL") };
        if mandate.validate().is_err() {
            return refused(r, &pi(), "INSTALL");
        }
        if mandate.network != net {
            return refused(r, &one(Reason::PolicyNetwork), "INSTALL");
        }
        let want_wallet = signer_core::mandate::WalletSpec {
            fingerprint: k.fingerprint,
            account: AccountPath { purpose: 84, coin: net.coin_type(), account: 0 },
            script_types: vec![signer_core::mandate::ScriptType::P2wpkh],
        };
        if mandate.wallet != want_wallet {
            return refused(r, &one(Reason::PolicyWallet), "INSTALL");
        }
        let Ok(state) = State::new_at_init(enclave_id, env.owner_pk, env.recovery_pk, mandate, sig) else {
            return refused(r, &pi(), "INSTALL");
        };
        env.state = Some(state);
        let sealed = seal_env(&env);
        accepted(r, &SealedResponse { sealed: sealed.clone() }.encode(), "INSTALL");
        self.adopt(sealed);
    }

    fn check_tpm_nonce(&mut self, r: &Response) {
        assert!(r.ok && r.reasons.is_empty(), "F10 TPM_NONCE: refused {:?}", r.reasons);
        assert_eq!(r.payload.len(), 32, "F10 TPM_NONCE: the nonce is not 32 bytes");
        let mut n = [0u8; 32];
        n.copy_from_slice(&r.payload);
        if let Some(prev) = self.shell.nonce {
            assert_ne!(prev, n, "F10 TPM_NONCE: the same nonce issued twice");
        }
        self.shell.nonce = Some(n);
        self.shell.proof = None; // a new nonce forgets any proof deposited for the previous one
    }

    fn check_tpm_proof(&mut self, input: &[u8], r: &Response) {
        if TpmProof::decode(input).is_err() {
            return refused(r, &one(Reason::TpmParse), "TPM_PROOF");
        }
        if self.shell.nonce.is_none() || input.len() > PROOF_STORE {
            return refused(r, &one(Reason::TpmNonce), "TPM_PROOF");
        }
        accepted(r, &[], "TPM_PROOF");
        self.shell.proof = Some(input.to_vec());
    }

    /// The init response's facts, shared by `INIT` and `TEST_INIT`: the blob opens to a keys-only envelope with
    /// the request's keys and network, the card names the derived wallet and verifies under the identity key,
    /// the recovery blob opens with the recovery key to the seed and to nothing else.
    fn check_init_response(
        &mut self,
        r: &Response,
        network: u8,
        owner_pk: [u8; 65],
        recovery_pk: [u8; 65],
        what: &str,
    ) {
        assert!(r.ok && r.reasons.is_empty(), "F10 {what}: refused {:?}", r.reasons);
        let ir =
            InitResponse::decode(&r.payload).unwrap_or_else(|_| panic!("F10 {what}: the response does not decode"));
        assert_eq!(r.payload, ir.encode(), "F10 {what}: payload not canonical");
        let env = open_env(&ir.sealed).unwrap_or_else(|| panic!("F10 {what}: the blob does not open"));
        assert_eq!(
            (env.network, env.owner_pk, env.recovery_pk),
            (network, owner_pk, recovery_pk),
            "F10 {what}: the blob's keys/network"
        );
        assert!(env.last_judged.is_none(), "F10 {what}: a fresh blob carries a sign record");
        let net = network_from(network).expect("checked by the reading");
        let k = derive(&self.secp, net, &env.seed).expect("a 32-byte seed always derives");
        let idpk = identity_pk(&self.secp, &env.identity_sk).expect("the reading refused an invalid identity key");
        assert_eq!(
            (ir.xpub, ir.fingerprint, ir.identity_pk),
            (k.xpub, k.fingerprint, idpk),
            "F10 {what}: the response names another wallet than the blob's seed derives"
        );
        let card = IdentityCard::decode(&ir.card).unwrap_or_else(|_| panic!("F10 {what}: the card does not decode"));
        let want_card = IdentityCard {
            mrenclave: [0; 32],
            network,
            xpub: k.xpub,
            fingerprint: k.fingerprint,
            identity_pk: idpk,
            tier: tier(),
        };
        assert_eq!(card, want_card, "F10 {what}: the identity card");
        let id_sk = SecretKey::from_slice(&env.identity_sk).expect("valid: the reading refused otherwise");
        assert_eq!(ir.card_sig, sign_digest_secp(&self.secp, &id_sk, &card.digest()), "F10 {what}: the card signature");
        // the recovery blob: the recovery key opens it to the seed; nothing else does
        assert_eq!(ir.recovery_blob.len(), 65 + 32 + 16, "F10 {what}: recovery blob length");
        let sk_of = |k: &P256Key| -> [u8; 32] {
            let mut b = [0u8; 32];
            b.copy_from_slice(&k.sk.to_bytes());
            b
        };
        if recovery_pk == self.keys.recovery.pk {
            let rsk = sk_of(&self.keys.recovery);
            let got = rcore::recovery::decrypt(&rsk, &ir.fingerprint, &ir.xpub, &ir.recovery_blob);
            assert_eq!(got, Some(env.seed), "F10 {what}: the recovery blob does not open to the sealed seed");
            assert!(
                rcore::recovery::decrypt(&sk_of(&self.keys.owner), &ir.fingerprint, &ir.xpub, &ir.recovery_blob)
                    .is_none(),
                "F10 {what}: the owner key opens the recovery blob"
            );
            let mut fp = ir.fingerprint;
            fp[0] ^= 1;
            assert!(
                rcore::recovery::decrypt(&rsk, &fp, &ir.xpub, &ir.recovery_blob).is_none(),
                "F10 {what}: the recovery blob opens under another fingerprint"
            );
            let mut xp = ir.xpub;
            xp[77] ^= 1;
            assert!(
                rcore::recovery::decrypt(&rsk, &ir.fingerprint, &xp, &ir.recovery_blob).is_none(),
                "F10 {what}: the recovery blob opens under another xpub"
            );
            self.recovery = Some((ir.recovery_blob.clone(), ir.fingerprint, ir.xpub));
        }
        self.shell.armed = true; // an init is an attended owner operation: the process it runs in is armed
        self.adopt(ir.sealed);
    }

    /// A single-byte change of the recovery blob opens to nothing (AES-GCM + the ephemeral point).
    fn check_recovery_mutation(&self, blob: &[u8], fp: &[u8; 4], xpub: &[u8; 78], pos: u8, val: u8) {
        let mut b = blob.to_vec();
        let i = usize::from(pos) * b.len() / 256;
        b[i] ^= val | 1;
        let mut rsk = [0u8; 32];
        rsk.copy_from_slice(&self.keys.recovery.sk.to_bytes());
        assert!(
            rcore::recovery::decrypt(&rsk, fp, xpub, &b).is_none(),
            "F10: a mutated recovery blob (byte {i}) still opens"
        );
        let mut short = blob.to_vec();
        short.pop();
        assert!(rcore::recovery::decrypt(&rsk, fp, xpub, &short).is_none(), "F10: a truncated recovery blob opens");
    }

    fn check_init(&mut self, input: &[u8], r: &Response) {
        let Ok(req) = InitRequest::decode(input) else { return refused(r, &one(Reason::PolicyInvalid), "INIT") };
        let Some(_) = network_from(req.network) else { return refused(r, &one(Reason::PolicyNetwork), "INIT") };
        if signer_core::update::parse_p256_pubkey(&req.owner_pk).is_none()
            || signer_core::update::parse_p256_pubkey(&req.recovery_pk).is_none()
            || req.owner_pk == req.recovery_pk
        {
            return refused(r, &one(Reason::PolicyInvalid), "INIT");
        }
        self.check_init_response(r, req.network, req.owner_pk, req.recovery_pk, "INIT");
    }

    fn check_test_init(&mut self, input: &[u8], r: &Response) {
        let Ok(req) = TestInitRequest::decode(input) else {
            return refused(r, &one(Reason::PolicyInvalid), "TEST_INIT");
        };
        let Some(net) = network_from(req.init.network) else {
            return refused(r, &one(Reason::PolicyNetwork), "TEST_INIT");
        };
        let state = if req.state.is_empty() {
            None
        } else {
            match State::decode(&req.state) {
                Ok(s) => Some(s),
                Err(_) => return refused(r, &one(Reason::StateUnsealable), "TEST_INIT"),
            }
        };
        // build_init: derive, identity, recovery blob (test-init skips init's public-key checks: a recovery key
        // that is not a point fails at the blob, an owner key that is not a point is stored as given)
        if derive(&self.secp, net, &req.seed).is_none() || identity_pk(&self.secp, &req.identity_sk).is_none() {
            return refused(r, &["KEY_DERIVATION".to_string()], "TEST_INIT");
        }
        if p256::PublicKey::from_sec1_bytes(&req.init.recovery_pk).is_err() {
            return refused(r, &["RECOVERY_BLOB".to_string()], "TEST_INIT");
        }
        self.check_init_response(r, req.init.network, req.init.owner_pk, req.init.recovery_pk, "TEST_INIT");
        // the injected state is sealed as given (bumped if TPM-bound)
        let env = open_env(&self.blob).expect("adopted");
        let want = state.map(|mut s| {
            s.bump_tpm();
            s
        });
        assert_eq!(env.state, want, "F10 TEST_INIT: the sealed state is not the injected one");
        assert_eq!(env.seed, req.seed);
        assert_eq!(env.identity_sk, req.identity_sk);
    }

    // ---- honest material ---------------------------------------------------------------------------------

    fn current_state(&self) -> Option<State> {
        open_env(&self.blob).and_then(|e| e.state)
    }

    fn eid(&self) -> [u8; 32] {
        self.current_state().map(|s| s.enclave_id).unwrap_or(ENCLAVE_ID)
    }

    /// A blob for a request: the current one, an older one, or a mutated copy of the current one.
    fn blob_for(&self, sel: u8, pos: u8, val: u8) -> Vec<u8> {
        if sel == 0 || self.history.len() < 2 {
            if sel >= 8 {
                let mut b = self.blob.clone();
                mutate(&mut b, sel, pos, val);
                return b;
            }
            return self.blob.clone();
        }
        if sel < 8 {
            let back = usize::from(sel).min(self.history.len() - 1);
            return self.history[self.history.len() - 1 - back].clone();
        }
        let mut b = self.blob.clone();
        mutate(&mut b, sel, pos, val);
        b
    }

    fn sealed_with(&self, blob: Vec<u8>, data: Vec<u8>, extra: Option<Vec<u8>>) -> Vec<u8> {
        SealedWith { sealed: blob, data, extra }.encode()
    }

    /// The host's side of a `Fresh` op when the state is TPM-bound: nonce → certify → deposit (variants lie).
    fn deposit(&mut self, variant: u8, junk: u8) {
        if variant == 7 {
            return; // no deposit: TPM_REQUIRED
        }
        self.perform(op::TPM_NONCE, Vec::new());
        let nonce = self.shell.nonce.expect("TPM_NONCE just issued one");
        let proof = self.tpm.certify(&nonce, variant, junk);
        self.perform(op::TPM_PROOF, proof);
    }

    /// Mine `n` headers on the state's best (or a fork `depth` below it); every honest header is remembered.
    fn batch(&mut self, s: &State, n: usize, variant: u8, depth: u8, salt: u8) -> Vec<u8> {
        let best = s.chain.best.map(|b| b.hash).unwrap_or([0; 32]);
        let mut parent = match self.headers.get(&best) {
            Some(h) => *h,
            None => {
                // the state's chain is not one the harness mined (a synthetic fixture chain): any batch is foreign
                regtest().1
            }
        };
        if variant == 1 {
            for _ in 0..depth % 8 {
                let prev = parent.prev_blockhash.to_byte_array();
                match self.headers.get(&prev) {
                    Some(h) => parent = *h,
                    None => break,
                }
            }
        }
        let mut out = Vec::with_capacity(n * 80);
        let mut raws: Vec<[u8; 80]> = Vec::new();
        for i in 0..n {
            let mut h = gen::mine(&parent, parent.time + 10, u32::from(salt) * 64 + i as u32 + 1);
            let honest_header = h;
            let bad_here = usize::from(depth) % n.max(1) == i;
            match variant {
                2 if bad_here => h.bits = bitcoin::pow::CompactTarget::from_consensus(gen::REGTEST_BITS - 1),
                3 if bad_here => h.prev_blockhash = bitcoin::BlockHash::from_byte_array([salt; 32]),
                4 if bad_here => h.time = parent.time, // not above the median of the previous eleven
                _ => {}
            }
            if variant == 2 || variant == 3 || variant == 4 {
                if !bad_here {
                    self.headers.insert(gen::hash32(&honest_header), honest_header);
                }
            } else {
                self.headers.insert(gen::hash32(&honest_header), honest_header);
            }
            raws.push(gen::raw(&h));
            parent = honest_header;
        }
        if variant == 7 && !raws.is_empty() {
            raws.push(raws[0]); // a duplicate
        }
        for r in &raws {
            out.extend_from_slice(r);
        }
        match variant {
            5 => {
                out.pop(); // not a multiple of 80
            }
            6 => out.clear(), // an empty batch: Ok(0)
            _ => {}
        }
        out
    }

    /// An owner message for the current state, honest or with the one named deviation.
    fn message(&self, s: Option<&State>, kind: u8, flags: u8, d: u8) -> Message {
        let eid = if flags & 4 != 0 { [0x5e; 32] } else { self.eid() };
        let (nonce, seq, owner_pk) = match s {
            Some(s) => {
                let mut proj = s.clone();
                proj.activate_pending();
                (proj.nonce + 1 + u64::from(flags & 2 != 0), proj.seq, proj.owner_pk)
            }
            None => (1, 0, self.keys.owner.pk),
        };
        let challenge = if d & 1 != 0 { [0x5c; 32] } else { self.shell.challenge.unwrap_or([0; 32]) };
        let seq_seen = if d & 2 != 0 { seq + 1 } else { seq.saturating_sub(u64::from(d & 16 != 0)) };
        let mut m = match kind % 13 {
            0 => Message::PolicyUpdate {
                enclave_id: eid,
                nonce,
                mandate: s.map(|s| s.mandate.encode()).unwrap_or_default(),
                sig: [0; 64],
            },
            1..=3 | 12 => {
                let mut m = s.map(|s| s.mandate.clone()).unwrap_or_else(|| regtest().0.mandate.clone());
                match kind % 13 {
                    1 => m.destinations.unlisted.max_per_tx = (m.destinations.unlisted.max_per_tx / 2).max(1),
                    2 => {
                        m.destinations.unlisted.max_per_tx =
                            m.destinations.unlisted.max_per_tx.saturating_mul(2).min(m.limits.max_per_tx)
                    }
                    12 => m.limits.max_outputs = 1, // a tightening classify feels: SIGN after a 2-output JUDGE refuses
                    _ => {
                        m.freshness =
                            Freshness { required: true, witness_pk: Some(self.keys.witness.pk), max_tip_lag: 6 }
                    }
                }
                if d & 32 != 0 {
                    m.network = Network::Testnet4;
                }
                if d & 64 != 0 {
                    m.wallet.fingerprint[0] ^= 0xff;
                }
                Message::PolicyUpdate { enclave_id: eid, nonce, mandate: m.encode(), sig: [0; 64] }
            }
            4 => Message::Cancel { enclave_id: eid, nonce, sig: [0; 64] },
            5 => Message::Unfreeze { enclave_id: eid, nonce, sig: [0; 64] },
            6 => Message::Rearm { enclave_id: eid, nonce, seq: seq_seen, sig: [0; 64] },
            7 => Message::Arm { enclave_id: eid, nonce, boot_challenge: challenge, seq_seen, sig: [0; 64] },
            8 => Message::Anchor {
                enclave_id: eid,
                nonce,
                boot_challenge: challenge,
                ak_pk: if d & 8 != 0 { self.tpm.other_ak.pk } else { self.tpm.ak.pk },
                nv_name: {
                    let mut n = self.tpm.name;
                    if d & 128 != 0 {
                        n[1] = 0x04; // a SHA-1 Name: not well-formed
                    }
                    n
                },
                counter: self.tpm.counter.wrapping_add(u64::from(d & 4 != 0)),
                seq_seen,
                sig: [0; 64],
            },
            9 => Message::RotateOwner { enclave_id: eid, nonce, new_owner_pk: self.new_owner.pk, sig: [0; 64] },
            10 => Message::Recover { enclave_id: eid, nonce, new_owner_pk: self.new_owner.pk, sig: [0; 64] },
            _ => Message::WitnessToken {
                enclave_id: eid,
                tip_hash: s.and_then(|s| s.chain.best).map(|b| b.hash).unwrap_or([0; 32]),
                tip_height: s.and_then(|s| s.chain.best).map(|b| b.height).unwrap_or(0),
                last_seen_seq: seq,
                issued: u64::from(d),
                sig: [0; 64],
            },
        };
        // the signer: the owner at the operation (a due rotation activated), the recovery key for Recover,
        // or a stranger / the other role when the input says so
        let owner = self.key_for(&owner_pk);
        let signer: &P256Key = match (kind % 13, flags & 1 != 0) {
            (10, false) => &self.keys.recovery,
            (10, true) => owner.unwrap_or(&self.keys.owner),
            (_, false) => owner.unwrap_or(&self.stranger),
            (_, true) => &self.stranger,
        };
        signer.sign(&mut m);
        m
    }

    fn key_for(&self, pk: &[u8; 65]) -> Option<&P256Key> {
        [&self.keys.owner, &self.keys.recovery, &self.keys.witness, &self.new_owner, &self.stranger]
            .into_iter()
            .find(|k| k.pk == *pk)
    }

    /// A PSBT for the state's wallet from the pass (ii) generator: the honest payout, or a scripted spend with
    /// one lie on demand.
    fn psbt(&self, a: u8, c: u8, d: u8, e: u8, f: u8, g: u8) -> Vec<u8> {
        if a & 4 != 0 {
            return policy::seed_psbt(&PAYOUT_SPEC).expect("the payout spec builds");
        }
        let h = signer_core::sha256(&[a, c, d, e, f, g, 0x4a]);
        let mut spec = vec![h[0] % 2, h[1] % 3, h[2] % 4, h[3] & 3, if a & 1 != 0 { e % 14 } else { 0 }, h[5]];
        let h2 = signer_core::sha256(&h);
        let rec: Vec<u8> = h[6..].iter().chain(h2.iter()).copied().collect();
        for i in 0..8usize {
            let hi = if a & 2 != 0 { rec[4 * i + 3] % 4 } else { rec[4 * i + 3] };
            spec.extend_from_slice(&[rec[4 * i], rec[4 * i + 1], rec[4 * i + 2], hi]);
        }
        policy::seed_psbt(&spec).unwrap_or_else(|| policy::seed_psbt(&PAYOUT_SPEC).expect("the payout spec builds"))
    }

    fn witness_token(&self, s: &State, variant: u8, d: u8) -> Vec<u8> {
        let best = s.chain.best.expect("an installed state has a best header");
        let mut m = match variant {
            3 => Message::Cancel { enclave_id: s.enclave_id, nonce: 1, sig: [0; 64] },
            _ => Message::WitnessToken {
                enclave_id: s.enclave_id,
                tip_hash: if d & 8 != 0 { [0x7a; 32] } else { best.hash },
                tip_height: best.height.saturating_sub(u32::from(d & 16 != 0) * 10),
                last_seen_seq: if variant == 2 { s.seq + 1 } else { s.seq },
                issued: u64::from(d),
                sig: [0; 64],
            },
        };
        if d & 32 != 0 {
            self.stranger.sign(&mut m);
        } else {
            self.keys.witness.sign(&mut m);
        }
        m.encode()
    }

    // ---- the scripted sequence ---------------------------------------------------------------------------

    fn test_init_request(&self, flags: u8) -> Vec<u8> {
        let seed = if flags & 4 != 0 { [0x02; 32] } else { [0x01; 32] };
        let identity_sk = if flags & 8 != 0 { [0; 32] } else { [0x55; 32] };
        let (network, state) = if flags & 64 != 0 {
            (4u8, Vec::new()) // not a network: POLICY_NETWORK, no blob
        } else if flags & 32 != 0 {
            (1u8, Vec::new()) // testnet4, keys-only (the regtest mandate then fails INSTALL's network check)
        } else if flags & 1 != 0 {
            (3u8, Vec::new())
        } else if flags & 2 != 0 {
            (2u8, seeds::honest().state.encode())
        } else {
            (3u8, regtest().0.encode())
        };
        TestInitRequest {
            init: InitRequest { network, owner_pk: self.keys.owner.pk, recovery_pk: self.keys.recovery.pk },
            seed,
            identity_sk,
            state,
        }
        .encode()
    }

    fn step(&mut self, rec: &[u8]) {
        let (kind, a, b, c, d, e, f, g) = (rec[0] % 14, rec[1], rec[2], rec[3], rec[4], rec[5], rec[6], rec[7]);
        let state = self.current_state();
        let bound = state.as_ref().map(|s| s.tpm.is_some()).unwrap_or(false);
        let blob = self.blob_for(b, c, d);
        // the host's TPM discipline for this step
        self.increment = g & 0x40 == 0;
        let mut request: Option<(u32, Vec<u8>)> = None;
        match kind {
            0 => request = Some((op::STATUS, blob)),
            1 => request = Some((op::POLICY, blob)),
            2 => {
                let mut data = vec![c; quote::TARGET_INFO_LEN];
                data.extend_from_slice(&signer_core::sha256(&[d, e]));
                match a % 4 {
                    1 => {
                        data.pop();
                    }
                    2 => request = Some((op::REPORT, self.sealed_with(blob.clone(), data.clone(), Some(vec![1])))),
                    3 => data.push(0),
                    _ => {}
                }
                if request.is_none() {
                    request = Some((op::REPORT, self.sealed_with(blob, data, None)));
                }
            }
            3 => {
                if bound {
                    self.deposit(a % 8, e);
                }
                request = Some((op::FREEZE, blob));
            }
            4 => {
                let s = state.clone().unwrap_or_else(|| regtest().0.clone());
                let data = self.batch(&s, 1 + usize::from(a % 8), c % 8, d, e);
                if bound {
                    self.deposit(f % 8, e);
                }
                request = Some((op::HEADERS, self.sealed_with(blob, data, None)));
            }
            5 => {
                let m = self.message(state.as_ref(), a, c, d);
                let needs_proof = bound || matches!(m, Message::Anchor { .. });
                if needs_proof && e & 0x80 == 0 {
                    self.deposit(e % 8, f);
                }
                request = Some((op::APPLY_MESSAGE, self.sealed_with(blob, m.encode(), None)));
            }
            6 => {
                let data = self.psbt(a, c, d, e, f, g);
                let extra = match (f & 3, state.as_ref()) {
                    (0, _) | (_, None) => None,
                    (v, Some(s)) => Some(self.witness_token(s, v, d)),
                };
                let extra = if f & 4 != 0 { Some(vec![f, g, 0xff]) } else { extra };
                if bound {
                    self.deposit(g % 8, e);
                }
                request = Some((op::JUDGE, self.sealed_with(blob, data, extra)));
            }
            7 => {
                let data = match (a % 4, self.judged_psbt.clone()) {
                    (0, Some(j)) => j,
                    (2, Some(mut j)) => {
                        mutate(&mut j, 8, c, d);
                        j
                    }
                    (3, _) => signer_core::sha256(&[a, c, d]).to_vec(),
                    _ => self.psbt(a | 1, c, d, e, f, g),
                };
                if bound {
                    self.deposit(g % 8, e);
                }
                request = Some((op::SIGN, self.sealed_with(blob, data, None)));
            }
            8 => request = Some((op::TPM_NONCE, Vec::new())),
            9 => {
                let nonce = self.shell.nonce.unwrap_or([c; 32]);
                let mut proof = self.tpm.certify(&nonce, a % 8, d);
                if a & 0x80 != 0 {
                    proof.truncate(proof.len().saturating_sub(1 + usize::from(d % 8)));
                }
                request = Some((op::TPM_PROOF, proof));
            }
            10 => {
                self.reset(); // a reload: unarmed, HWM 0, a new challenge
            }
            11 => {
                let op_code = if a >= 14 { u32::from_le_bytes([c, d, e, f]) } else { OPS[usize::from(a)] };
                let data = match c % 4 {
                    0 => Vec::new(),
                    1 => blob,
                    2 => InitRequest {
                        network: 1 + d % 3,
                        owner_pk: self.keys.owner.pk,
                        recovery_pk: self.keys.recovery.pk,
                    }
                    .encode(),
                    _ => {
                        let mut v = blob;
                        v.extend_from_slice(&signer_core::sha256(&[d, e, f]));
                        v
                    }
                };
                request = Some((op_code, data));
            }
            12 => {
                // INSTALL: the regtest mandate over the identity-derived enclave id, with one deviation on demand
                let mut m = regtest().0.mandate.clone();
                match a % 7 {
                    2 => m.wallet.fingerprint = [9; 4],
                    3 => m.network = Network::Signet,
                    6 => m.timelock_blocks = 0, // decodes, fails validate
                    _ => {}
                }
                let env = open_env(&self.blob);
                let eid = env
                    .as_ref()
                    .and_then(|e| identity_pk(&self.secp, &e.identity_sk))
                    .map(|pk| signer_core::sha256(&pk))
                    .unwrap_or(ENCLAVE_ID);
                let mut msg = Message::PolicyUpdate { enclave_id: eid, nonce: 0, mandate: m.encode(), sig: [0; 64] };
                if a % 7 == 1 {
                    self.keys.recovery.sign(&mut msg);
                } else {
                    self.keys.owner.sign(&mut msg);
                }
                let extra = if a % 7 == 4 { None } else { Some(msg.sig().to_vec()) };
                let data = if a % 7 == 5 { vec![c, d, e] } else { m.encode() };
                request = Some((op::INSTALL, self.sealed_with(blob, data, extra)));
            }
            _ => {
                let req = self.test_init_request(a);
                request = Some((op::TEST_INIT, req));
            }
        }
        if let Some((op_code, mut bytes)) = request {
            if g & 0x80 != 0 {
                mutate(&mut bytes, g, c, e);
            }
            self.perform(op_code, bytes);
            if op_code == op::TEST_INIT || op_code == op::INIT {
                self.learn();
            }
        }
        self.increment = true;
    }
}

/// `TEE_FUZZ_TRACE=1`: print every call's verdict (seed review; never set in CI).
fn trace() -> bool {
    static T: OnceLock<bool> = OnceLock::new();
    *T.get_or_init(|| std::env::var_os("TEE_FUZZ_TRACE").is_some())
}

/// One byte-level change of a request or a blob: flip, truncate, insert or swap, placed by `pos`.
/// The state a request carries, read as the enclave reads it — `None` when the request carries none the enclave would
/// open (a blob the container or the strict envelope decoder refuses, an op without a blob).
///
/// Its one use is the guard in `perform`. The nosgx container has no MAC, so a changed byte inside the plaintext can
/// still decode — as a mandate outside `validate`'s bounds, the bounds `INSTALL`/`APPLY_MESSAGE` establish and the
/// seal alone preserves. A descriptor gap in the millions sends `classify`'s descriptor scan through that many
/// derivations: the two timeouts of the first hour run (gap 20 → 6 881 300 by `blob_for`'s flip; 20 → 2 555 924 by
/// a flip that a refused `HEADERS` re-sealed into the current blob, as the shell does for every batch it opens). On
/// hardware the AES-GCM tag refuses such a blob before a field is read; `TEST_INIT` (test-only) installs a state as
/// given. The harness sends only what the seal would pass — so every call terminates — and sends everything else a
/// change can produce.
/// R11 (C-EXT1-3): the enclave's `open()` refuses a sealed state whose mandate fails `validate` — before any
/// gate reads a bound and before the single-use counter proof is taken (so the deposit survives the refusal).
fn invalid_state(env: &Env) -> bool {
    env.state.as_ref().is_some_and(|s| s.mandate.validate().is_err())
}

/// One raw ecall through `rcore_call`, for the replay gate's own vectors (the R11 guards are break-tested there).
pub fn raw(op_code: u32, input: &[u8]) -> Response {
    let _g = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    call(op_code, input)
}

fn carried_state(op_code: u32, input: &[u8]) -> Option<State> {
    let sealed = match op_code {
        op::STATUS | op::POLICY | op::FREEZE => input.to_vec(),
        op::TEST_INIT => return State::decode(&TestInitRequest::decode(input).ok()?.state).ok(),
        op::INIT | op::TPM_NONCE | op::TPM_PROOF | op::TEST_RESET_SESSION => return None,
        _ => SealedWith::decode(input, limits::MAX_SEALED).ok()?.sealed,
    };
    open_env(&sealed)?.state
}

fn mutate(bytes: &mut Vec<u8>, mode: u8, pos: u8, val: u8) {
    if bytes.is_empty() {
        bytes.push(val);
        return;
    }
    let i = usize::from(pos) * bytes.len() / 256;
    match mode % 4 {
        0 => bytes[i] ^= val | 1,
        1 => {
            let cut = 1 + usize::from(val) % 16;
            let n = bytes.len().saturating_sub(cut);
            bytes.truncate(n);
        }
        2 => bytes.insert(i, val),
        _ => {
            let j = usize::from(val) * bytes.len() / 256;
            bytes.swap(i, j);
        }
    }
}

/// The honest full-flow requests, for the raw mode's seeds and the dictionary: op code and request bytes of
/// every op on a freshly initialised regtest signer (deterministic: the nosgx envelope has no randomness).
pub fn honest_requests() -> Vec<(u32, Vec<u8>)> {
    let _g = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let mut h = H::new();
    h.reset();
    let init = h.test_init_request(0);
    h.perform(op::TEST_INIT, init.clone());
    h.learn();
    let s = h.current_state().expect("installed");
    let blob = h.blob.clone();
    let payout = policy::seed_psbt(&PAYOUT_SPEC).expect("builds");
    let batch = h.batch(&s, 3, 0, 0, 1);
    let arm = h.message(Some(&s), 7, 0, 0).encode();
    let mut data = vec![0u8; quote::TARGET_INFO_LEN];
    data.extend_from_slice(&[7u8; 32]);
    let mut out = vec![
        (op::TEST_INIT, init),
        (op::STATUS, blob.clone()),
        (op::POLICY, blob.clone()),
        (op::REPORT, h.sealed_with(blob.clone(), data, None)),
        (op::FREEZE, blob.clone()),
        (op::HEADERS, h.sealed_with(blob.clone(), batch, None)),
        (op::APPLY_MESSAGE, h.sealed_with(blob.clone(), arm, None)),
        (op::JUDGE, h.sealed_with(blob.clone(), payout.clone(), None)),
        (op::TPM_NONCE, Vec::new()),
        (op::INIT, InitRequest { network: 3, owner_pk: h.keys.owner.pk, recovery_pk: h.keys.recovery.pk }.encode()),
    ];
    // a charged blob for SIGN
    h.perform(op::JUDGE, h.sealed_with(blob.clone(), payout.clone(), None));
    out.push((op::SIGN, h.sealed_with(h.blob.clone(), payout, None)));
    // a keys-only blob for INSTALL
    h.perform(op::TEST_INIT, h.test_init_request(1));
    h.learn();
    let st = &regtest().0;
    let env = open_env(&h.blob).expect("opens");
    let eid = signer_core::sha256(&identity_pk(&h.secp, &env.identity_sk).expect("valid"));
    let mut msg = Message::PolicyUpdate { enclave_id: eid, nonce: 0, mandate: st.mandate.encode(), sig: [0; 64] };
    h.keys.owner.sign(&mut msg);
    out.push((op::INSTALL, h.sealed_with(h.blob.clone(), st.mandate.encode(), Some(msg.sig().to_vec()))));
    out
}

/// The target body: `[mode] ‖ …`.
///
/// - mode 0, raw: `[0, sel] ‖ bytes` — a fresh load with the regtest signer, then `OPS[sel % 14]` (or an arbitrary
///   op code from the next four bytes when `sel ≥ 14`) with `bytes` as the request;
/// - mode 1, scripted: `[1, flags] ‖ 8-byte steps` — a reload, `TEST_INIT` per `flags` (bit 1 keys-only, bit 2 the
///   signet fixture state, bit 4 the cold wallet's seed, bit 8 an invalid identity key, bit 16 the ABI and
///   recovery-blob checks), then up to 16 steps `[kind, a, b, c, d, e, f, g]`: kind % 14 = STATUS, POLICY,
///   REPORT, FREEZE, HEADERS, APPLY_MESSAGE, JUDGE, SIGN, TPM_NONCE, TPM_PROOF, reload, a raw op, INSTALL,
///   TEST_INIT; `a` the variant, `b` the blob (0 current, 1–7 an older one, ≥ 8 a mutated copy placed by `c`/`d`),
///   `g & 0x80` a byte-level change of the final request, `g & 0x40` the host forgetting the counter increment.
pub fn dispatch_target(data: &[u8]) {
    let _g = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let Some((&mode, rest)) = data.split_first() else { return };
    if trace() {
        eprintln!("F10-trace ---- input mode={mode} len={}", data.len());
    }
    let mut h = H::new();
    h.reset();
    match mode {
        0 => {
            let Some((&sel, bytes)) = rest.split_first() else { return };
            let init = h.test_init_request(0);
            h.perform(op::TEST_INIT, init);
            h.learn();
            let (op_code, bytes) = if sel >= 14 {
                if bytes.len() < 4 {
                    return;
                }
                (u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]), &bytes[4..])
            } else {
                (OPS[usize::from(sel)], bytes)
            };
            h.perform(op_code, bytes.to_vec());
        }
        1 => {
            let Some((&flags, steps)) = rest.split_first() else { return };
            let init = h.test_init_request(flags);
            h.perform(op::TEST_INIT, init);
            h.learn();
            if flags & 16 != 0 && !h.blob.is_empty() {
                abi_bad_args();
                abi_retry(op::STATUS, &h.blob.clone());
                if let Some((blob, fp, xpub)) = h.recovery.clone() {
                    h.check_recovery_mutation(
                        &blob,
                        &fp,
                        &xpub,
                        steps.first().copied().unwrap_or(0),
                        steps.get(1).copied().unwrap_or(0),
                    );
                }
            }
            for rec in steps.chunks_exact(8).take(16) {
                h.step(rec);
            }
        }
        _ => {}
    }
}
