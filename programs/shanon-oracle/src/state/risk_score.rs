use anchor_lang::prelude::*;

/// Seed prefix for program risk score PDAs.
pub const RISK_SCORE_SEED: &[u8] = b"risk_score";

/// Maximum number of individual security flags stored per assessment.
pub const MAX_FLAGS_PER_ASSESSMENT: usize = 32;

/// Maximum length of a flag description stored on-chain (kept short;
/// full descriptions live off-chain with IPFS hash reference).
pub const MAX_FLAG_DESC_LEN: usize = 64;

/// Severity levels for individual security flags, matching the
/// off-chain Token Security Expert severity model.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq)]
pub enum FlagSeverity {
    /// Score impact: 0-2 points
    Info,
    /// Score impact: 3-4 points
    Low,
    /// Score impact: 5-6 points
    Medium,
    /// Score impact: 7-8 points
    High,
    /// Score impact: 9-10 points
    Critical,
}

impl FlagSeverity {
    /// Returns the risk weight for this severity level.
    pub fn weight(&self) -> u8 {
        match self {
            FlagSeverity::Info => 1,
            FlagSeverity::Low => 3,
            FlagSeverity::Medium => 5,
            FlagSeverity::High => 8,
            FlagSeverity::Critical => 10,
        }
    }
}

/// Category of the security flag, identifying which domain it belongs to.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq)]
pub enum FlagCategory {
    /// Access control and authority issues.
    AccessControl,
    /// Arithmetic overflow, underflow, precision loss.
    Arithmetic,
    /// Reentrancy and CPI ordering issues.
    Reentrancy,
    /// Token extension and SPL Token vulnerabilities.
    TokenSafety,
    /// Economic and game-theory attacks (MEV, sandwich, etc.).
    Economic,
    /// Oracle and price feed manipulation.
    OracleManipulation,
    /// Account validation and PDA safety.
    AccountValidation,
    /// Admin centralization and governance risks.
    Centralization,
    /// Data handling — serialization, deserialization, type confusion.
    DataIntegrity,
    /// Logic bugs — incorrect state transitions, missing checks.
    Logic,
}

/// A single security flag within an assessment. Stored on-chain so other
/// programs can inspect not just the overall score but specific issues.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct SecurityFlag {
    /// The flag identifier from the Shanon knowledge base (e.g., "SOL-018").
    /// Stored as bytes for on-chain efficiency, padded to 8 bytes.
    pub flag_id: [u8; 8],

    /// Severity of this specific finding.
    pub severity: FlagSeverity,

    /// Category classification.
    pub category: FlagCategory,

    /// Short on-chain description (full detail available off-chain).
    pub description: [u8; MAX_FLAG_DESC_LEN],

    /// Number of bytes actually used in description.
    pub description_len: u8,

    /// Whether this flag was confirmed by a second analyst.
    pub confirmed: bool,
}

impl SecurityFlag {
    pub const LEN: usize = 8   // flag_id
        + 1                     // severity (enum, 1 byte)
        + 1                     // category (enum, 1 byte)
        + MAX_FLAG_DESC_LEN     // description
        + 1                     // description_len
        + 1;                    // confirmed
}

/// The security risk assessment for a specific Solana program.
///
/// This is the core data structure of the oracle. Each assessed program
/// gets one of these, derived as a PDA from the target program's pubkey.
///
/// PDA: ["risk_score", target_program.key()]
#[account]
#[derive(Debug)]
pub struct ProgramRiskScore {
    /// The program being assessed.
    pub target_program: Pubkey,

    /// Overall risk score (0-100). 0 = safe, 100 = maximum risk.
    /// Computed as weighted average of individual flag severities.
    pub overall_score: u8,

    /// Confidence level of the assessment (0-100).
    /// Higher when multiple analysts agree, lower for single-analyst reports.
    pub confidence: u8,

    /// Number of critical flags found.
    pub critical_count: u8,

    /// Number of high-severity flags found.
    pub high_count: u8,

    /// Number of medium-severity flags found.
    pub medium_count: u8,

    /// Number of low-severity flags found.
    pub low_count: u8,

    /// Number of informational flags found.
    pub info_count: u8,

    /// Total number of flags in the `flags` vector.
    pub flag_count: u8,

    /// Individual security flags (up to MAX_FLAGS_PER_ASSESSMENT).
    pub flags: Vec<SecurityFlag>,

    /// The analyst who submitted this assessment.
    pub analyst: Pubkey,

    /// Unix timestamp of the initial assessment.
    pub assessed_at: i64,

    /// Unix timestamp of the most recent update.
    pub updated_at: i64,

    /// Number of times this assessment has been updated.
    pub revision: u16,

    /// Number of other analysts who have confirmed this assessment.
    pub confirmations: u8,

    /// IPFS CID (v1, raw bytes) pointing to the full off-chain report.
    /// 36 bytes covers CIDv1 with SHA-256 multihash.
    pub report_ipfs_cid: [u8; 36],

    /// Number of bytes actually used in report_ipfs_cid.
    pub report_cid_len: u8,

    /// Assessment status.
    pub status: AssessmentStatus,

    /// The Anchor program version that was assessed (from the on-chain IDL
    /// or deployment metadata, 0 if unknown).
    pub target_program_version: u32,

    /// Bump seed for this PDA.
    pub bump: u8,

    /// Reserved space for future upgrades.
    pub _reserved: [u8; 64],
}

/// Status of the security assessment.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq)]
pub enum AssessmentStatus {
    /// Initial submission, pending review.
    Pending,
    /// Confirmed by multiple analysts.
    Confirmed,
    /// Under dispute by another analyst.
    Disputed,
    /// Superseded by a newer assessment (target program upgraded).
    Superseded,
    /// Withdrawn by the submitting analyst.
    Withdrawn,
}

impl ProgramRiskScore {
    /// Account size with maximum flag capacity.
    pub const LEN: usize = 8    // discriminator
        + 32                     // target_program
        + 1                      // overall_score
        + 1                      // confidence
        + 1                      // critical_count
        + 1                      // high_count  
        + 1                      // medium_count
        + 1                      // low_count
        + 1                      // info_count
        + 1                      // flag_count
        + 4 + (SecurityFlag::LEN * MAX_FLAGS_PER_ASSESSMENT) // flags vec
        + 32                     // analyst
        + 8                      // assessed_at
        + 8                      // updated_at
        + 2                      // revision
        + 1                      // confirmations
        + 36                     // report_ipfs_cid
        + 1                      // report_cid_len
        + 1                      // status
        + 4                      // target_program_version
        + 1                      // bump
        + 64;                    // reserved

    /// Computes the overall risk score from individual flags.
    /// Uses weighted severity scoring:
    ///   score = min(100, sum(flag.severity.weight() * multiplier) / flag_count)
    pub fn compute_score(&self) -> u8 {
        if self.flags.is_empty() {
            return 0;
        }

        let mut total_weight: u32 = 0;
        for flag in &self.flags {
            total_weight += flag.severity.weight() as u32;
        }

        // Scale: max score per flag is 10, we want result in 0-100 range.
        // With 32 flags at weight 10 each, max raw = 320.
        // We normalize: score = min(100, (total_weight * 100) / (MAX_FLAGS * 10))
        let max_possible = (MAX_FLAGS_PER_ASSESSMENT as u32) * 10;
        let score = (total_weight * 100).checked_div(max_possible).unwrap_or(0);

        std::cmp::min(score, 100) as u8
    }

    /// Computes confidence based on analyst reputation and confirmations.
    pub fn compute_confidence(&self, analyst_reputation: u16) -> u8 {
        // Base confidence from analyst reputation (0-10000 bps -> 0-50%)
        let base = (analyst_reputation as u32 * 50) / 10000;
        // Confirmation bonus (each confirmation adds up to 10%, max 50%)
        let confirmation_bonus = std::cmp::min(self.confirmations as u32 * 10, 50);
        std::cmp::min(base + confirmation_bonus, 100) as u8
    }
}
