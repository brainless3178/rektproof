use anchor_lang::prelude::*;
use crate::state::*;

/// Read-only query of a program's risk score.
///
/// This is the CPI-callable interface that other Solana programs use
/// to check security scores before interacting with a target program.
///
/// Example usage from another program:
/// ```ignore
/// let cpi_ctx = CpiContext::new(
///     shanon_program.to_account_info(),
///     QueryRisk {
///         risk_score: risk_score_pda.to_account_info(),
///     },
/// );
/// let result = shanon_oracle::cpi::query_risk(cpi_ctx, target_program_id)?;
/// ```
#[derive(Accounts)]
#[instruction(target_program: Pubkey)]
pub struct QueryRisk<'info> {
    /// The risk score PDA for the target program.
    #[account(
        seeds = [RISK_SCORE_SEED, target_program.as_ref()],
        bump = risk_score.bump,
    )]
    pub risk_score: Account<'info, ProgramRiskScore>,
}

/// Query result returned via CPI or direct call.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct RiskQueryResult {
    /// The target program queried.
    pub target_program: Pubkey,
    /// Overall risk score (0-100).
    pub overall_score: u8,
    /// Confidence level (0-100).
    pub confidence: u8,
    /// Number of critical flags.
    pub critical_count: u8,
    /// Number of high flags.
    pub high_count: u8,
    /// Whether the assessment has been confirmed by multiple analysts.
    pub is_confirmed: bool,
    /// Unix timestamp of the assessment.
    pub assessed_at: i64,
    /// Unix timestamp of the last update.
    pub updated_at: i64,
    /// Assessment revision number.
    pub revision: u16,
}

pub fn query_risk(
    ctx: Context<QueryRisk>,
    _target_program: Pubkey,
) -> Result<()> {
    let score = &ctx.accounts.risk_score;

    // Log the result for off-chain consumers and CPI callers
    // to read via return data.
    let result = RiskQueryResult {
        target_program: score.target_program,
        overall_score: score.overall_score,
        confidence: score.confidence,
        critical_count: score.critical_count,
        high_count: score.high_count,
        is_confirmed: score.status == AssessmentStatus::Confirmed,
        assessed_at: score.assessed_at,
        updated_at: score.updated_at,
        revision: score.revision,
    };

    // Set return data so CPI callers can read the result
    let serialized = result.try_to_vec()?;
    anchor_lang::solana_program::program::set_return_data(&serialized);

    msg!(
        "Risk query for {}: score={}/100 confidence={}% criticals={} confirmed={}",
        score.target_program,
        score.overall_score,
        score.confidence,
        score.critical_count,
        result.is_confirmed,
    );

    Ok(())
}
