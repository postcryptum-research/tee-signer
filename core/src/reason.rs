//! Stable refusal identifiers (`docs/POLICY.md §6`). Every identifier has at least one refusal
//! vector in `vectors/`. The numeric codes are part of the host API and never renumbered.

use alloc::string::String;
use alloc::vec::Vec;

/// Why the enclave refused. Carries a label where the policy names one (trusted destinations).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reason {
    /// The PSBT did not parse (BIP174 structure, transaction, scripts).
    PsbtParse,
    /// A field that affects meaning is unknown.
    UnknownField,
    /// An own input lacks `non_witness_utxo` (I2).
    InputNoPrevTx,
    /// `non_witness_utxo`'s txid does not equal the outpoint's txid (I2).
    InputPrevTxMismatch,
    /// An input claimed as own does not match any in-enclave derivation (I1).
    InputNotOwn,
    /// A foreign input is present and the mandate forbids it.
    InputForeignForbidden,
    /// An input's script type is not in the mandate's `wallet.scriptTypes`.
    InputScriptType,
    /// An own output's script type is not allowed.
    OutputScriptType,
    /// An own output's index is beyond `own_index_bound + ownIndexGap`.
    ChangeIndexBeyondGap,
    /// Sighash other than `ALL`.
    Sighash,
    /// Transaction version other than 1 or 2.
    TxVersion,
    /// RBF signalled while `rules.rbf == false`.
    RbfForbidden,
    /// `OP_RETURN` present under `opReturn = none`, or with non-zero value.
    OpReturnForbidden,
    /// Net outflow exceeds `limits.maxPerTx`.
    CapTx,
    /// Net outflow would exceed `limits.window.maxOutflow` for the window.
    CapWindow,
    /// Unlisted outputs exceed `destinations.unlisted.maxPerTx`.
    CapUnlistedTx,
    /// Unlisted outputs would exceed `destinations.unlisted.maxPerWindow`.
    CapUnlistedWindow,
    /// A trusted destination's `maxPerTx` exceeded (label).
    CapTrustedTx(String),
    /// A trusted destination's `maxPerWindow` would be exceeded (label).
    CapTrustedWindow(String),
    /// Fee exceeds `limits.maxFeeAbs`.
    FeeAbs,
    /// Fee exceeds `limits.maxFeeRate` × upper-bound vsize.
    FeeRate,
    /// Fees would exceed `limits.maxFeePerWindow`.
    FeeWindow,
    /// More inputs than `limits.maxInputs`.
    TooManyInputs,
    /// More outputs than `limits.maxOutputs`.
    TooManyOutputs,
    /// Checked arithmetic overflowed.
    Overflow,
    /// `best_height > validity.notAfterHeight`.
    MandateExpired,
    /// The signer is frozen.
    Frozen,
    /// The chain view is unusable (no verified best header).
    ChainStale,
    /// A reorg deeper than `limits.maxReorg` was seen; re-pin required.
    ChainReorg,
    /// `freshness.required` and no token.
    FreshnessMissing,
    /// Witness token signature invalid.
    FreshnessSig,
    /// Witness token's tip is not in the verified chain within `maxTipLag`.
    FreshnessTip,
    /// Witness token's `last_seen_seq` is ahead of ours: rollback suspected; owner re-arm needed.
    FreshnessSeqBehind,
    /// Owner / recovery signature invalid.
    PolicySig,
    /// Nonce is not `installed + 1`.
    PolicyNonce,
    /// Mandate's network differs from the sealed one.
    PolicyNetwork,
    /// Mandate's wallet differs from the sealed one.
    PolicyWallet,
    /// A loosening update is already pending.
    PolicyPending,
    /// Mandate failed structural validation (bounds, duplicates, shape).
    PolicyInvalid,
    /// The sealed state could not be opened or decoded.
    StateUnsealable,
    /// A header did not verify (link, target, proof of work, median time).
    HeaderInvalid,
    /// The input state's sequence is below what this enclave session already produced
    /// (two judges from one base, or an older blob presented after a newer one).
    SeqBehindSession,
    /// This enclave load has not been approved by the owner (REQ-r7): no signature until `Arm`.
    NotArmed,
    /// `Arm` carries a challenge that is not this load's (a replayed or mis-copied Arm).
    ArmChallenge,
    /// `Arm` says the owner saw a sequence higher than the enclave's: the state was rolled back.
    ArmSeqBehind,
    /// REQ-r9: the state is TPM-bound and no counter proof was presented for this call.
    TpmRequired,
    /// REQ-r9: the counter proof is not a well-formed `TPM_ST_ATTEST_NV` attestation.
    TpmParse,
    /// REQ-r9: the proof's `extraData` is not the nonce this enclave issued for this call (a replay).
    TpmNonce,
    /// REQ-r9: the proof certifies an index other than the pinned one.
    TpmIndex,
    /// REQ-r9: the proof is not signed by the pinned attestation key.
    TpmSig,
    /// REQ-r9: the TPM certifies a counter other than the one this blob expects — the blob is not
    /// the latest state (a rollback, a crash between seal and increment, or a spurious increment).
    StateStale,
    /// REQ-r9a: an `Anchor` on a TPM-bound state names an attestation key or a counter index other
    /// than the sealed ones — the host handed the owner the identity of a TPM it controls. The TPM
    /// identity is bound for the wallet's life; a replaced TPM under a living wallet means a new
    /// wallet (or a re-bind ceremony), never a re-point by Anchor.
    AnchorTpmMismatch,
    /// REQ-r9a: the counter the host's live proof certifies is BELOW the value the owner saw
    /// certified — impossible for an honest, monotone TPM: a lying host or a replaced TPM.
    AnchorCounterBehind,
    /// R11 (C-EXT1-3): the sealed state opened but its policy fails its own bounds — impossible under the
    /// seal (every bound was validated at its write site and the seal preserved it): a corrupted state
    /// file, or a test build without the seal's MAC. Refused at the one door every op passes, before any
    /// gate reads a bound and before a counter proof is consumed.
    StateInvalid,
    /// R11 (C-EXT1-4): the trusted-destination scan would exceed its derivation bound (`wallet::DERIVATION_CAP`,
    /// the validated worst case) — unreachable for a mandate that passed `validate`; the bound makes the
    /// worst case explicit and refuses during the scan, never at its end.
    PolicyTooExpensive,
}

impl Reason {
    /// The stable identifier string of `POLICY.md §6`.
    pub fn code(&self) -> &'static str {
        match self {
            Reason::PsbtParse => "PSBT_PARSE",
            Reason::UnknownField => "UNKNOWN_FIELD",
            Reason::InputNoPrevTx => "INPUT_NO_PREVTX",
            Reason::InputPrevTxMismatch => "INPUT_PREVTX_MISMATCH",
            Reason::InputNotOwn => "INPUT_NOT_OWN",
            Reason::InputForeignForbidden => "INPUT_FOREIGN_FORBIDDEN",
            Reason::InputScriptType => "INPUT_SCRIPT_TYPE",
            Reason::OutputScriptType => "OUTPUT_SCRIPT_TYPE",
            Reason::ChangeIndexBeyondGap => "CHANGE_INDEX_BEYOND_GAP",
            Reason::Sighash => "SIGHASH",
            Reason::TxVersion => "TX_VERSION",
            Reason::RbfForbidden => "RBF_FORBIDDEN",
            Reason::OpReturnForbidden => "OPRETURN_FORBIDDEN",
            Reason::CapTx => "CAP_TX",
            Reason::CapWindow => "CAP_WINDOW",
            Reason::CapUnlistedTx => "CAP_UNLISTED_TX",
            Reason::CapUnlistedWindow => "CAP_UNLISTED_WINDOW",
            Reason::CapTrustedTx(_) => "CAP_TRUSTED_TX",
            Reason::CapTrustedWindow(_) => "CAP_TRUSTED_WINDOW",
            Reason::FeeAbs => "FEE_ABS",
            Reason::FeeRate => "FEE_RATE",
            Reason::FeeWindow => "FEE_WINDOW",
            Reason::TooManyInputs => "TOO_MANY_INPUTS",
            Reason::TooManyOutputs => "TOO_MANY_OUTPUTS",
            Reason::Overflow => "OVERFLOW",
            Reason::MandateExpired => "MANDATE_EXPIRED",
            Reason::Frozen => "FROZEN",
            Reason::ChainStale => "CHAIN_STALE",
            Reason::ChainReorg => "CHAIN_REORG",
            Reason::FreshnessMissing => "FRESHNESS_MISSING",
            Reason::FreshnessSig => "FRESHNESS_SIG",
            Reason::FreshnessTip => "FRESHNESS_TIP",
            Reason::FreshnessSeqBehind => "FRESHNESS_SEQ_BEHIND",
            Reason::PolicySig => "POLICY_SIG",
            Reason::PolicyNonce => "POLICY_NONCE",
            Reason::PolicyNetwork => "POLICY_NETWORK",
            Reason::PolicyWallet => "POLICY_WALLET",
            Reason::PolicyPending => "POLICY_PENDING",
            Reason::PolicyInvalid => "POLICY_INVALID",
            Reason::StateUnsealable => "STATE_UNSEALABLE",
            Reason::HeaderInvalid => "HEADER_INVALID",
            Reason::SeqBehindSession => "SEQ_BEHIND_SESSION",
            Reason::NotArmed => "NOT_ARMED",
            Reason::ArmChallenge => "ARM_CHALLENGE",
            Reason::ArmSeqBehind => "ARM_SEQ_BEHIND",
            Reason::TpmRequired => "TPM_REQUIRED",
            Reason::TpmParse => "TPM_PARSE",
            Reason::TpmNonce => "TPM_NONCE",
            Reason::TpmIndex => "TPM_INDEX",
            Reason::TpmSig => "TPM_SIG",
            Reason::StateStale => "STATE_STALE",
            Reason::AnchorTpmMismatch => "ANCHOR_TPM_MISMATCH",
            Reason::AnchorCounterBehind => "ANCHOR_COUNTER_BEHIND",
            Reason::StateInvalid => "STATE_INVALID",
            Reason::PolicyTooExpensive => "POLICY_TOO_EXPENSIVE",
        }
    }
}

/// A refusal: one or more reasons. Never empty.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal(pub Vec<Reason>);

impl Refusal {
    /// One reason.
    pub fn one(r: Reason) -> Self {
        Refusal(alloc::vec![r])
    }
}

impl From<Reason> for Refusal {
    fn from(r: Reason) -> Self {
        Refusal::one(r)
    }
}

/// Host-side only (REQ-r9a C6): the sanctioned next step for the refusals an operator meets in the
/// daemon's answer, the plugin page or `owner-cli`. The enclave never carries these strings; the
/// host prints them next to the stable code so nobody retries into a wall.
#[cfg(feature = "std")]
pub fn hint_for_code(code: &str) -> Option<&'static str> {
    Some(match code {
        "STATE_INVALID" => {
            "the sealed state opened but its policy fails its own bounds — impossible under the seal; a corrupted \
             state file or a test build: stop the daemon, restore the last written state file (the one the TPM counter \
             expects), nothing signs until then; if the file was not touched, tell the auditor"
        }
        "POLICY_TOO_EXPENSIVE" => {
            "the trusted-destination scan hit its derivation bound — unreachable for a mandate that passed its own \
             validation; the sealed mandate is not what INSTALL accepted: treat as STATE_INVALID and tell the auditor"
        }
        "ANCHOR_TPM_MISMATCH" => {
            "the host presented a TPM identity (attestation key / counter Name) different from the one this wallet is \
             bound to — do not retry; a replaced TPM under a living wallet means a new wallet, or a re-bind ceremony \
             (REQ pending); check tpm-info against the tpm-setup record and tell the auditor"
        }
        "ANCHOR_COUNTER_BEHIND" => {
            "the host's live counter proof is BELOW the value you saw certified — an honest TPM only moves forward; \
             do not retry with this host's files; take tpm-info and tpm-certify again and compare, then tell the auditor"
        }
        "STATE_STALE" => {
            "the TPM counter and the sealed state disagree (a rollback, a crash between seal and increment, or a \
             persist that raced your anchor): the signer pauses; the owner's anchor (tpm-info → your nonce → \
             tpm-certify → owner-cli anchor → submit) is the remedy — from this state it is race-free"
        }
        "TPM_REQUIRED" => {
            "the state is TPM-bound and this call carried no counter proof: the daemon's TPM transport is missing or \
             failing (SIGNERD_TPM, /dev/tpmrm0, the tpm.env secret); fix the transport, nothing to sign until then"
        }
        "NOT_ARMED" => {
            "this enclave load has not been approved: the owner's `arm` (R7), or — when the state is TPM-anchored — \
             the first state-changing call with a fresh counter proof arms it (R9)"
        }
        _ => return None,
    })
}
