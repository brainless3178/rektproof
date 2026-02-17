use anchor_lang::prelude::*;
use crate::state::*;
use crate::errors::ShanonError;
use crate::instructions::submit_assessment::FlagInput;

/// Updates an existing assessment with new flags or revised analysis.
///
/// Only the original submitting analyst can update their own assessment.
/// Updates increment the revision counter and update the timestamp.
#[derive(Accounts)]
#[instruction(target_program: Pubkey)]
pub struct UpdateAssessment<'info> {
    /// The analyst updating the assessment.
    #[account(mut)]
    pub analyst_signer: Signer<'info>,

    /// The analyst's registered account.
    #[account(
        mut,
        seeds = [ANALYST_SEED, analyst_signer.key().as_ref()],
        bump = analyst_account.bump,
        constraint = analyst_account.active @ ShanonError::AnalystInactive,
        constraint = analyst_account.wallet == analyst_signer.key() @ ShanonError::UnauthorizedAnalyst,
    )]
    pub analyst_account: Account<'info, AnalystAccount>,

    /// Oracle config — must not be paused.
    #[account(
        seeds = [CONFIG_SEED],
        bump = config.bump,
        constraint = !config.paused @ ShanonError::OraclePaused,
    )]
    pub config: Account<'info, OracleConfig>,

    /// The existing risk score PDA for the target program.
    #[account(
        mut,
        seeds = [RISK_SCORE_SEED, target_program.as_ref()],
        bump = risk_score.bump,
        constraint = risk_score.analyst == analyst_signer.key() @ ShanonError::UnauthorizedAnalyst,
        constraint = risk_score.status != AssessmentStatus::Superseded @ ShanonError::AssessmentSuperseded,
        constraint = risk_score.status != AssessmentStatus::Withdrawn @ ShanonError::AssessmentFinalized,
    )]
    pub risk_score: Account<'info, ProgramRiskScore>,
}

pub fn update_assessment(
    ctx: Context<UpdateAssessment>,
    _target_program: Pubkey,
    flags: Vec<FlagInput>,
    report_ipfs_cid: Vec<u8>,
    target_program_version: u32,
) -> Result<()> {
    require!(
        flags.len() <= MAX_FLAGS_PER_ASSESSMENT,
        ShanonError::TooManyFlags
    );
    require!(!flags.is_empty(), ShanonError::InvalidRiskScore);

    let clock = Clock::get()?;
    let risk_score = &mut ctx.accounts.risk_score;

    // Rebuild flags
    let mut on_chain_flags: Vec<SecurityFlag> = Vec::with_capacity(flags.len());
    let mut critical_count: u8 = 0;
    let mut high_count: u8 = 0;
    let mut medium_count: u8 = 0;
    let mut low_count: u8 = 0;
    let mut info_count: u8 = 0;

    for input in &flags {
        require!(input.flag_id.len() <= 8, ShanonError::FlagIdTooLong);
        require!(
            input.description.len() <= MAX_FLAG_DESC_LEN,
            ShanonError::FlagDescriptionTooLong
        );

        let mut flag_id_buf = [0u8; 8];
        flag_id_buf[..input.flag_id.len()].copy_from_slice(&input.flag_id);

        let mut desc_buf = [0u8; MAX_FLAG_DESC_LEN];
        desc_buf[..input.description.len()].copy_from_slice(&input.description);

        match input.severity {
            FlagSeverity::Critical => critical_count = critical_count.saturating_add(1),
            FlagSeverity::High => high_count = high_count.saturating_add(1),
            FlagSeverity::Medium => medium_count = medium_count.saturating_add(1),
            FlagSeverity::Low => low_count = low_count.saturating_add(1),
            FlagSeverity::Info => info_count = info_count.saturating_add(1),
        }

        on_chain_flags.push(SecurityFlag {
            flag_id: flag_id_buf,
            severity: input.severity.clone(),
            category: input.category.clone(),
            description: desc_buf,
            description_len: input.description.len() as u8,
            confirmed: false,
        });
    }

    // Update risk score
    risk_score.flags = on_chain_flags;
    risk_score.flag_count = flags.len() as u8;
    risk_score.critical_count = critical_count;
    risk_score.high_count = high_count;
    risk_score.medium_count = medium_count;
    risk_score.low_count = low_count;
    risk_score.info_count = info_count;
    risk_score.updated_at = clock.unix_timestamp;
    risk_score.target_program_version = target_program_version;

    // Increment revision
    risk_score.revision = risk_score
        .revision
        .checked_add(1)
        .ok_or(ShanonError::MathOverflow)?;

    // Reset confirmations since content changed
    risk_score.confirmations = 0;
    risk_score.status = AssessmentStatus::Pending;

    // Update IPFS CID
    let mut cid_buf = [0u8; 36];
    let cid_len = std::cmp::min(report_ipfs_cid.len(), 36);
    cid_buf[..cid_len].copy_from_slice(&report_ipfs_cid[..cid_len]);
    risk_score.report_ipfs_cid = cid_buf;
    risk_score.report_cid_len = cid_len as u8;

    // Recompute score
    risk_score.overall_score = risk_score.compute_score();
    risk_score.confidence = risk_score.compute_confidence(
        ctx.accounts.analyst_account.reputation_bps,
    );

    // Update analyst timestamp
    let analyst = &mut ctx.accounts.analyst_account;
    analyst.last_assessment_at = clock.unix_timestamp;

    msg!(
        "Assessment updated for program {}. Revision: {}. New score: {}/100",
        risk_score.target_program,
        risk_score.revision,
        risk_score.overall_score,
    );

    Ok(())
}
