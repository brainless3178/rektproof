use anchor_lang::prelude::*;
use crate::state::*;
use crate::errors::ShanonError;

/// Input data for a single security flag submitted by an analyst.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct FlagInput {
    /// The flag identifier (e.g., "SOL-018"), max 8 bytes.
    pub flag_id: Vec<u8>,
    /// Severity level.
    pub severity: FlagSeverity,
    /// Category classification.
    pub category: FlagCategory,
    /// Short description, max 64 bytes.
    pub description: Vec<u8>,
}

/// Submits a new security assessment for a target program.
///
/// The analyst must be registered and active. The target program must
/// not have an existing assessment (use `update_assessment` for that).
#[derive(Accounts)]
#[instruction(target_program: Pubkey)]
pub struct SubmitAssessment<'info> {
    /// The analyst submitting the assessment — must be the wallet
    /// associated with the analyst_account PDA.
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
        mut,
        seeds = [CONFIG_SEED],
        bump = config.bump,
        constraint = !config.paused @ ShanonError::OraclePaused,
    )]
    pub config: Account<'info, OracleConfig>,

    /// The risk score PDA for the target program — will be created.
    #[account(
        init,
        payer = analyst_signer,
        space = ProgramRiskScore::LEN,
        seeds = [RISK_SCORE_SEED, target_program.as_ref()],
        bump,
    )]
    pub risk_score: Account<'info, ProgramRiskScore>,

    pub system_program: Program<'info, System>,
}

pub fn submit_assessment(
    ctx: Context<SubmitAssessment>,
    target_program: Pubkey,
    flags: Vec<FlagInput>,
    report_ipfs_cid: Vec<u8>,
    target_program_version: u32,
) -> Result<()> {
    // Prevent self-assessment (oracle assessing itself)
    require!(
        target_program != crate::ID,
        ShanonError::SelfAssessment
    );

    require!(
        flags.len() <= MAX_FLAGS_PER_ASSESSMENT,
        ShanonError::TooManyFlags
    );

    require!(!flags.is_empty(), ShanonError::InvalidRiskScore);

    let clock = Clock::get()?;
    let risk_score = &mut ctx.accounts.risk_score;

    // Convert flag inputs to on-chain flags and compute severity counts
    let mut on_chain_flags: Vec<SecurityFlag> = Vec::with_capacity(flags.len());
    let mut critical_count: u8 = 0;
    let mut high_count: u8 = 0;
    let mut medium_count: u8 = 0;
    let mut low_count: u8 = 0;
    let mut info_count: u8 = 0;

    for input in &flags {
        require!(
            input.flag_id.len() <= 8,
            ShanonError::FlagIdTooLong
        );
        require!(
            input.description.len() <= MAX_FLAG_DESC_LEN,
            ShanonError::FlagDescriptionTooLong
        );

        // Pack flag_id into fixed array
        let mut flag_id_buf = [0u8; 8];
        flag_id_buf[..input.flag_id.len()].copy_from_slice(&input.flag_id);

        // Pack description into fixed array
        let mut desc_buf = [0u8; MAX_FLAG_DESC_LEN];
        desc_buf[..input.description.len()].copy_from_slice(&input.description);

        // Count by severity
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

    // Populate the risk score account
    risk_score.target_program = target_program;
    risk_score.flags = on_chain_flags;
    risk_score.flag_count = flags.len() as u8;
    risk_score.critical_count = critical_count;
    risk_score.high_count = high_count;
    risk_score.medium_count = medium_count;
    risk_score.low_count = low_count;
    risk_score.info_count = info_count;
    risk_score.analyst = ctx.accounts.analyst_signer.key();
    risk_score.assessed_at = clock.unix_timestamp;
    risk_score.updated_at = clock.unix_timestamp;
    risk_score.revision = 1;
    risk_score.confirmations = 0;
    risk_score.status = AssessmentStatus::Pending;
    risk_score.target_program_version = target_program_version;
    risk_score.bump = ctx.bumps.risk_score;
    risk_score._reserved = [0u8; 64];

    // Pack IPFS CID
    let mut cid_buf = [0u8; 36];
    let cid_len = std::cmp::min(report_ipfs_cid.len(), 36);
    cid_buf[..cid_len].copy_from_slice(&report_ipfs_cid[..cid_len]);
    risk_score.report_ipfs_cid = cid_buf;
    risk_score.report_cid_len = cid_len as u8;

    // Compute overall score from flags
    risk_score.overall_score = risk_score.compute_score();

    // Compute confidence from analyst reputation
    risk_score.confidence = risk_score.compute_confidence(
        ctx.accounts.analyst_account.reputation_bps,
    );

    // Update analyst stats
    let analyst = &mut ctx.accounts.analyst_account;
    analyst.assessments_submitted = analyst
        .assessments_submitted
        .checked_add(1)
        .ok_or(ShanonError::MathOverflow)?;
    analyst.last_assessment_at = clock.unix_timestamp;

    // Update global count
    let config = &mut ctx.accounts.config;
    config.scored_program_count = config
        .scored_program_count
        .checked_add(1)
        .ok_or(ShanonError::MathOverflow)?;

    msg!(
        "Assessment submitted for program {}. Score: {}/100, Confidence: {}%, Flags: {} (C:{} H:{} M:{} L:{} I:{})",
        target_program,
        risk_score.overall_score,
        risk_score.confidence,
        risk_score.flag_count,
        critical_count,
        high_count,
        medium_count,
        low_count,
        info_count,
    );

    Ok(())
}
