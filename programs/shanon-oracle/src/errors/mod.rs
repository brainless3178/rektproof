use anchor_lang::prelude::*;

#[error_code]
pub enum ShanonError {
    // ── Authority & Access ──────────────────────────────────────────

    #[msg("Caller is not the oracle authority")]
    UnauthorizedAuthority,

    #[msg("Caller is not a registered active analyst")]
    UnauthorizedAnalyst,

    #[msg("Analyst account is deactivated")]
    AnalystInactive,

    #[msg("Insufficient guardian signatures for this operation")]
    InsufficientGuardianSignatures,

    #[msg("Provided guardian is not in the guardian set")]
    InvalidGuardian,

    #[msg("Duplicate guardian signature detected")]
    DuplicateGuardian,

    // ── Oracle State ────────────────────────────────────────────────

    #[msg("Oracle is currently paused")]
    OraclePaused,

    #[msg("Oracle configuration already initialized")]
    AlreadyInitialized,

    // ── Assessment Validation ───────────────────────────────────────

    #[msg("Risk score must be between 0 and 100")]
    InvalidRiskScore,

    #[msg("Confidence must be between 0 and 100")]
    InvalidConfidence,

    #[msg("Too many flags (maximum 32 per assessment)")]
    TooManyFlags,

    #[msg("Flag description exceeds maximum length")]
    FlagDescriptionTooLong,

    #[msg("Flag ID exceeds maximum length (8 bytes)")]
    FlagIdTooLong,

    #[msg("Assessment already exists; use update instruction")]
    AssessmentAlreadyExists,

    #[msg("No existing assessment found for this program")]
    AssessmentNotFound,

    #[msg("Cannot confirm your own assessment")]
    SelfConfirmation,

    #[msg("Assessment is in a terminal state and cannot be modified")]
    AssessmentFinalized,

    #[msg("Assessment has been superseded by a newer version")]
    AssessmentSuperseded,

    // ── Analyst Management ──────────────────────────────────────────

    #[msg("Analyst name exceeds maximum length (64 bytes)")]
    AnalystNameTooLong,

    #[msg("Analyst already registered")]
    AnalystAlreadyRegistered,

    #[msg("Guardian set is full (maximum 10)")]
    GuardianSetFull,

    #[msg("Cannot reduce guardians below minimum signature threshold")]
    GuardianBelowThreshold,

    #[msg("Minimum signatures must be >= 1 and <= guardian count")]
    InvalidMinSignatures,

    // ── Authority Transfer ────────────────────────────────────────

    #[msg("No pending authority transfer to accept")]
    NoPendingAuthorityTransfer,

    #[msg("Signer does not match the pending authority")]
    InvalidPendingAuthority,

    #[msg("An authority transfer is already pending; cancel it first")]
    PendingAuthorityTransferExists,

    // ── Confirmation ────────────────────────────────────────────────

    #[msg("This analyst has already confirmed this assessment")]
    DuplicateConfirmation,

    // ── Math ────────────────────────────────────────────────────────

    #[msg("Arithmetic overflow in score calculation")]
    MathOverflow,

    #[msg("Target program cannot be the oracle program itself")]
    SelfAssessment,
}
