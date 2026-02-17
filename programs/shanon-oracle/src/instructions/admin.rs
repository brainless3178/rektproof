use anchor_lang::prelude::*;
use crate::state::*;
use crate::errors::ShanonError;

// ─── Admin Operations ───────────────────────────────────────────────────────
// All admin operations require the authority signer.
// In production, `authority` should be a multisig or governance PDA.

/// Add a guardian to the guardian committee.
#[derive(Accounts)]
pub struct AddGuardian<'info> {
    #[account(
        constraint = authority.key() == config.authority @ ShanonError::UnauthorizedAuthority,
    )]
    pub authority: Signer<'info>,

    #[account(
        mut,
        seeds = [CONFIG_SEED],
        bump = config.bump,
    )]
    pub config: Account<'info, OracleConfig>,
}

pub fn add_guardian(ctx: Context<AddGuardian>, new_guardian: Pubkey) -> Result<()> {
    let config = &mut ctx.accounts.config;

    require!(
        config.guardians.len() < MAX_GUARDIANS,
        ShanonError::GuardianSetFull
    );

    // Prevent duplicates
    require!(
        !config.guardians.contains(&new_guardian),
        ShanonError::DuplicateGuardian
    );

    config.guardians.push(new_guardian);

    msg!(
        "Guardian added: {}. Total guardians: {}",
        new_guardian,
        config.guardians.len()
    );

    Ok(())
}

/// Remove a guardian from the committee.
#[derive(Accounts)]
pub struct RemoveGuardian<'info> {
    #[account(
        constraint = authority.key() == config.authority @ ShanonError::UnauthorizedAuthority,
    )]
    pub authority: Signer<'info>,

    #[account(
        mut,
        seeds = [CONFIG_SEED],
        bump = config.bump,
    )]
    pub config: Account<'info, OracleConfig>,
}

pub fn remove_guardian(ctx: Context<RemoveGuardian>, guardian: Pubkey) -> Result<()> {
    let config = &mut ctx.accounts.config;

    // Cannot reduce below min_guardian_signatures
    require!(
        config.guardians.len() > config.min_guardian_signatures as usize,
        ShanonError::GuardianBelowThreshold
    );

    let initial_len = config.guardians.len();
    config.guardians.retain(|g| *g != guardian);

    require!(
        config.guardians.len() < initial_len,
        ShanonError::InvalidGuardian
    );

    msg!(
        "Guardian removed: {}. Remaining guardians: {}",
        guardian,
        config.guardians.len()
    );

    Ok(())
}

/// Pause or unpause the oracle (emergency stop).
#[derive(Accounts)]
pub struct SetPaused<'info> {
    #[account(
        constraint = authority.key() == config.authority @ ShanonError::UnauthorizedAuthority,
    )]
    pub authority: Signer<'info>,

    #[account(
        mut,
        seeds = [CONFIG_SEED],
        bump = config.bump,
    )]
    pub config: Account<'info, OracleConfig>,
}

pub fn set_paused(ctx: Context<SetPaused>, paused: bool) -> Result<()> {
    ctx.accounts.config.paused = paused;

    msg!(
        "Oracle {} by authority {}",
        if paused { "PAUSED" } else { "RESUMED" },
        ctx.accounts.authority.key()
    );

    Ok(())
}

// ─── Two-Step Authority Transfer ────────────────────────────────────────────
//
// Step 1: Current authority proposes a new authority.
// Step 2: New authority accepts. Until accepted, the old authority remains.
// This prevents permanent authority loss from a typo.

/// Propose transferring authority to a new address.
/// Does NOT immediately change authority — the new authority must call
/// `accept_authority_transfer` to finalize.
#[derive(Accounts)]
pub struct ProposeAuthorityTransfer<'info> {
    #[account(
        constraint = authority.key() == config.authority @ ShanonError::UnauthorizedAuthority,
    )]
    pub authority: Signer<'info>,

    #[account(
        mut,
        seeds = [CONFIG_SEED],
        bump = config.bump,
    )]
    pub config: Account<'info, OracleConfig>,
}

pub fn propose_authority_transfer(
    ctx: Context<ProposeAuthorityTransfer>,
    new_authority: Pubkey,
) -> Result<()> {
    let config = &mut ctx.accounts.config;

    // Prevent overwriting an existing pending transfer without explicit cancel
    require!(
        config.pending_authority.is_none(),
        ShanonError::PendingAuthorityTransferExists
    );

    config.pending_authority = Some(new_authority);

    msg!(
        "Authority transfer proposed: {} → {}",
        config.authority,
        new_authority
    );

    Ok(())
}

/// Accept a pending authority transfer. Only the proposed new authority
/// can call this instruction.
#[derive(Accounts)]
pub struct AcceptAuthorityTransfer<'info> {
    /// The new authority must sign to prove they control the key.
    pub new_authority: Signer<'info>,

    #[account(
        mut,
        seeds = [CONFIG_SEED],
        bump = config.bump,
    )]
    pub config: Account<'info, OracleConfig>,
}

pub fn accept_authority_transfer(ctx: Context<AcceptAuthorityTransfer>) -> Result<()> {
    let config = &mut ctx.accounts.config;

    let pending = config
        .pending_authority
        .ok_or(ShanonError::NoPendingAuthorityTransfer)?;

    require!(
        ctx.accounts.new_authority.key() == pending,
        ShanonError::InvalidPendingAuthority
    );

    let old_authority = config.authority;
    config.authority = pending;
    config.pending_authority = None;

    msg!(
        "Authority transferred: {} → {}",
        old_authority,
        pending
    );

    Ok(())
}

/// Cancel a pending authority transfer. Only the current authority can cancel.
#[derive(Accounts)]
pub struct CancelAuthorityTransfer<'info> {
    #[account(
        constraint = authority.key() == config.authority @ ShanonError::UnauthorizedAuthority,
    )]
    pub authority: Signer<'info>,

    #[account(
        mut,
        seeds = [CONFIG_SEED],
        bump = config.bump,
    )]
    pub config: Account<'info, OracleConfig>,
}

pub fn cancel_authority_transfer(ctx: Context<CancelAuthorityTransfer>) -> Result<()> {
    let config = &mut ctx.accounts.config;

    require!(
        config.pending_authority.is_some(),
        ShanonError::NoPendingAuthorityTransfer
    );

    let cancelled = config.pending_authority.take();

    msg!(
        "Authority transfer cancelled. Pending authority was: {:?}",
        cancelled
    );

    Ok(())
}

/// Deactivate an analyst (soft-delete, preserves history).
///
/// Takes the analyst's wallet pubkey as an instruction argument so the PDA
/// derivation is enforced — the authority cannot accidentally deactivate
/// the wrong analyst.
#[derive(Accounts)]
#[instruction(analyst_wallet: Pubkey)]
pub struct DeactivateAnalyst<'info> {
    #[account(
        constraint = authority.key() == config.authority @ ShanonError::UnauthorizedAuthority,
    )]
    pub authority: Signer<'info>,

    #[account(
        seeds = [CONFIG_SEED],
        bump = config.bump,
    )]
    pub config: Account<'info, OracleConfig>,

    #[account(
        mut,
        seeds = [ANALYST_SEED, analyst_wallet.as_ref()],
        bump = analyst_account.bump,
    )]
    pub analyst_account: Account<'info, AnalystAccount>,
}

pub fn deactivate_analyst(
    ctx: Context<DeactivateAnalyst>,
    analyst_wallet: Pubkey,
) -> Result<()> {
    ctx.accounts.analyst_account.active = false;

    msg!(
        "Analyst deactivated: {} (wallet: {})",
        ctx.accounts.analyst_account.wallet,
        analyst_wallet
    );

    Ok(())
}
