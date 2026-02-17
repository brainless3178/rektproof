use anchor_lang::prelude::*;
use crate::state::*;
use crate::errors::ShanonError;

/// Seed prefix for confirmation receipt PDAs.
pub const CONFIRMATION_RECEIPT_SEED: &[u8] = b"confirmation";

/// A small PDA proving that a specific analyst confirmed a specific assessment.
/// Existence of this account prevents duplicate confirmations.
///
/// PDA: ["confirmation", target_program, confirming_analyst_wallet]
#[account]
pub struct ConfirmationReceipt {
    /// The confirming analyst's wallet.
    pub analyst: Pubkey,
    /// The target program whose assessment was confirmed.
    pub target_program: Pubkey,
    /// When the confirmation was made.
    pub confirmed_at: i64,
    /// Bump seed for this PDA.
    pub bump: u8,
}

impl ConfirmationReceipt {
    pub const LEN: usize = 8  // discriminator
        + 32                   // analyst
        + 32                   // target_program
        + 8                    // confirmed_at
        + 1;                   // bump
}

/// Allows a second analyst to confirm an existing assessment.
///
/// Confirmations increase the assessment's confidence score and
/// boost the original analyst's reputation. An analyst cannot
/// confirm their own assessment, and each analyst can only confirm
/// a given assessment once (enforced by a confirmation receipt PDA).
#[derive(Accounts)]
#[instruction(target_program: Pubkey)]
pub struct ConfirmAssessment<'info> {
    /// The confirming analyst — must be different from the original.
    #[account(mut)]
    pub confirming_analyst_signer: Signer<'info>,

    /// The confirming analyst's registered account.
    #[account(
        mut,
        seeds = [ANALYST_SEED, confirming_analyst_signer.key().as_ref()],
        bump = confirming_analyst_account.bump,
        constraint = confirming_analyst_account.active @ ShanonError::AnalystInactive,
        constraint = confirming_analyst_account.wallet == confirming_analyst_signer.key()
            @ ShanonError::UnauthorizedAnalyst,
    )]
    pub confirming_analyst_account: Account<'info, AnalystAccount>,

    /// The original analyst who submitted the assessment.
    /// Their reputation gets boosted on confirmation.
    #[account(
        mut,
        seeds = [ANALYST_SEED, risk_score.analyst.as_ref()],
        bump = original_analyst_account.bump,
    )]
    pub original_analyst_account: Account<'info, AnalystAccount>,

    /// Oracle config — must not be paused.
    #[account(
        seeds = [CONFIG_SEED],
        bump = config.bump,
        constraint = !config.paused @ ShanonError::OraclePaused,
    )]
    pub config: Account<'info, OracleConfig>,

    /// The risk score being confirmed.
    #[account(
        mut,
        seeds = [RISK_SCORE_SEED, target_program.as_ref()],
        bump = risk_score.bump,
        constraint = risk_score.status == AssessmentStatus::Pending 
            || risk_score.status == AssessmentStatus::Confirmed
            @ ShanonError::AssessmentFinalized,
    )]
    pub risk_score: Account<'info, ProgramRiskScore>,

    /// Confirmation receipt PDA — its `init` constraint ensures the analyst
    /// can only confirm this assessment once. A second call will fail with
    /// "already in use" because the PDA already exists.
    #[account(
        init,
        payer = confirming_analyst_signer,
        space = ConfirmationReceipt::LEN,
        seeds = [
            CONFIRMATION_RECEIPT_SEED,
            target_program.as_ref(),
            confirming_analyst_signer.key().as_ref(),
        ],
        bump,
    )]
    pub confirmation_receipt: Account<'info, ConfirmationReceipt>,

    pub system_program: Program<'info, System>,
}

pub fn confirm_assessment(
    ctx: Context<ConfirmAssessment>,
    target_program: Pubkey,
) -> Result<()> {
    // Prevent self-confirmation
    require!(
        ctx.accounts.confirming_analyst_signer.key() != ctx.accounts.risk_score.analyst,
        ShanonError::SelfConfirmation
    );

    let clock = Clock::get()?;

    // Initialize the confirmation receipt (prevents duplicate confirmations)
    let receipt = &mut ctx.accounts.confirmation_receipt;
    receipt.analyst = ctx.accounts.confirming_analyst_signer.key();
    receipt.target_program = target_program;
    receipt.confirmed_at = clock.unix_timestamp;
    receipt.bump = ctx.bumps.confirmation_receipt;

    let risk_score = &mut ctx.accounts.risk_score;

    // Increment confirmations
    risk_score.confirmations = risk_score.confirmations.saturating_add(1);
    risk_score.updated_at = clock.unix_timestamp;

    // After at least 1 confirmation, mark as Confirmed
    if risk_score.status == AssessmentStatus::Pending {
        risk_score.status = AssessmentStatus::Confirmed;
    }

    // Recompute confidence with updated confirmations
    risk_score.confidence = risk_score.compute_confidence(
        ctx.accounts.original_analyst_account.reputation_bps,
    );

    // Boost original analyst's reputation (capped at 10000)
    let original = &mut ctx.accounts.original_analyst_account;
    // Each confirmation adds 100 basis points (1%)
    original.reputation_bps = std::cmp::min(
        original.reputation_bps.saturating_add(100),
        10000,
    );
    original.assessments_confirmed = original
        .assessments_confirmed
        .checked_add(1)
        .ok_or(ShanonError::MathOverflow)?;

    // Track confirming analyst's activity
    let confirmer = &mut ctx.accounts.confirming_analyst_account;
    confirmer.last_assessment_at = clock.unix_timestamp;

    msg!(
        "Assessment for {} confirmed by {}. Confirmations: {}. Confidence: {}%",
        risk_score.target_program,
        ctx.accounts.confirming_analyst_signer.key(),
        risk_score.confirmations,
        risk_score.confidence,
    );

    Ok(())
}
