use anchor_lang::prelude::*;
use crate::state::*;
use crate::errors::ShanonError;

/// Registers a new security analyst. Requires authority signature.
///
/// In production, this would require guardian quorum via a separate
/// approval flow. For the initial version, the authority can directly
/// register analysts.
#[derive(Accounts)]
pub struct RegisterAnalyst<'info> {
    /// The oracle authority — must sign to approve new analysts.
    #[account(
        mut,
        constraint = authority.key() == config.authority @ ShanonError::UnauthorizedAuthority,
    )]
    pub authority: Signer<'info>,

    /// The oracle configuration (must not be paused).
    #[account(
        mut,
        seeds = [CONFIG_SEED],
        bump = config.bump,
        constraint = !config.paused @ ShanonError::OraclePaused,
    )]
    pub config: Account<'info, OracleConfig>,

    /// The wallet address of the new analyst.
    /// CHECK: This is the analyst's wallet — we derive the PDA from it.
    pub analyst_wallet: UncheckedAccount<'info>,

    /// The analyst PDA being created.
    #[account(
        init,
        payer = authority,
        space = AnalystAccount::LEN,
        seeds = [ANALYST_SEED, analyst_wallet.key().as_ref()],
        bump,
    )]
    pub analyst_account: Account<'info, AnalystAccount>,

    pub system_program: Program<'info, System>,
}

pub fn register_analyst(
    ctx: Context<RegisterAnalyst>,
    name: Vec<u8>,
    domain_flags: u8,
) -> Result<()> {
    require!(name.len() <= 64, ShanonError::AnalystNameTooLong);

    let analyst = &mut ctx.accounts.analyst_account;
    let clock = Clock::get()?;

    analyst.wallet = ctx.accounts.analyst_wallet.key();

    // Copy name bytes into fixed array
    let mut name_buf = [0u8; 64];
    name_buf[..name.len()].copy_from_slice(&name);
    analyst.name = name_buf;
    analyst.name_len = name.len() as u8;

    analyst.assessments_submitted = 0;
    analyst.assessments_confirmed = 0;
    analyst.reputation_bps = AnalystAccount::INITIAL_REPUTATION;
    analyst.active = true;
    analyst.registered_at = clock.unix_timestamp;
    analyst.last_assessment_at = 0;
    analyst.domain_flags = domain_flags;
    analyst.bump = ctx.bumps.analyst_account;
    analyst._reserved = [0u8; 64];

    // Update global count
    let config = &mut ctx.accounts.config;
    config.analyst_count = config
        .analyst_count
        .checked_add(1)
        .ok_or(ShanonError::MathOverflow)?;

    msg!(
        "Analyst registered: {}. Total analysts: {}",
        ctx.accounts.analyst_wallet.key(),
        config.analyst_count
    );

    Ok(())
}
