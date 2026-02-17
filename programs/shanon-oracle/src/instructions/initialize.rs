use anchor_lang::prelude::*;
use crate::state::*;
use crate::errors::ShanonError;

/// Initializes the oracle configuration. Can only be called once.
///
/// The caller becomes the initial authority AND the first guardian.
/// This avoids a chicken-and-egg problem where you need guardians
/// to add guardians.
#[derive(Accounts)]
pub struct Initialize<'info> {
    /// The initial authority. Pays for account creation and becomes
    /// both the authority and the first guardian.
    #[account(mut)]
    pub authority: Signer<'info>,

    /// The oracle configuration PDA.
    #[account(
        init,
        payer = authority,
        space = OracleConfig::LEN,
        seeds = [CONFIG_SEED],
        bump,
    )]
    pub config: Account<'info, OracleConfig>,

    pub system_program: Program<'info, System>,
}

pub fn initialize(ctx: Context<Initialize>, min_guardian_signatures: u8) -> Result<()> {
    let config = &mut ctx.accounts.config;

    // The first guardian is the initializer
    let authority_key = ctx.accounts.authority.key();

    require!(
        min_guardian_signatures >= 1,
        ShanonError::InvalidMinSignatures
    );

    config.authority = authority_key;
    config.guardians = vec![authority_key];
    config.min_guardian_signatures = min_guardian_signatures;
    config.analyst_count = 0;
    config.scored_program_count = 0;
    config.paused = false;
    config.version = OracleConfig::CURRENT_VERSION;
    config.bump = ctx.bumps.config;
    config.pending_authority = None;
    config._reserved = [0u8; 95];

    msg!(
        "Shanon Oracle initialized. Authority: {}. Version: {}",
        authority_key,
        OracleConfig::CURRENT_VERSION
    );

    Ok(())
}
