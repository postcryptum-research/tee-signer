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
