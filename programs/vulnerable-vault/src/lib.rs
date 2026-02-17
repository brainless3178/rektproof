//! # Vulnerable Vault Program (Intentionally Insecure)
//!
//! ⚠️ DO NOT DEPLOY — This program contains deliberate vulnerabilities for
//! automated security scanner testing. Every handler demonstrates a different
//! class of Solana vulnerability that the Shanon Security Oracle should detect.

use anchor_lang::prelude::*;

declare_id!("Ea1qKkVjEEGa5mLAWdDryPB1nsGHyuxwB7oQFz8obb11");

#[program]
pub mod vulnerable_vault {
    use super::*;

    // ─────────────────────────────────────────────────────────────────
    //  BUG 1: Missing signer check — anyone can initialize
    // ─────────────────────────────────────────────────────────────────
    pub fn initialize(ctx: Context<Initialize>, bump: u8) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.authority = ctx.accounts.authority.key();
        vault.total_deposits = 0;
        vault.total_shares = 0;
        vault.bump = bump;
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────
    //  BUG 2: Unchecked arithmetic overflow on deposit
    // ─────────────────────────────────────────────────────────────────
    pub fn handle_deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        // BUG: unchecked add — attacker can overflow total_deposits
        vault.total_deposits = vault.total_deposits + amount;
        // BUG: unchecked add — share calculation can overflow
        vault.total_shares = vault.total_shares + amount;
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────
    //  BUG 3: Missing authority validation on withdraw
    // ─────────────────────────────────────────────────────────────────
    pub fn handle_withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        // BUG: no check that ctx.accounts.authority == vault.authority
        vault.total_deposits -= amount;
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────
    //  BUG 4: Unsafe price oracle — no validation of oracle data
    // ─────────────────────────────────────────────────────────────────
    pub fn handle_get_secure_price(ctx: Context<GetPrice>) -> Result<()> {
        // BUG: reads price from unvalidated AccountInfo
        let oracle = &ctx.accounts.oracle;
        let data = oracle.try_borrow_data()?;
        let _price = u64::from_le_bytes(data[0..8].try_into().unwrap());
        // No program owner check, no staleness check, no confidence interval
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────
    //  BUG 5: Emergency pause without access control
    // ─────────────────────────────────────────────────────────────────
    pub fn handle_emergency_pause(ctx: Context<Pause>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        // BUG: anyone can pause the vault — no authority check
        vault.paused = true;
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────
    //  BUG 6: Governance manipulation via unchecked voting
    // ─────────────────────────────────────────────────────────────────
    pub fn handle_vote_on_proposal(ctx: Context<Vote>, vote_weight: u64) -> Result<()> {
        let proposal = &mut ctx.accounts.proposal;
        // BUG: no check on voter eligibility, no double-vote prevention
        proposal.yes_votes = proposal.yes_votes + vote_weight;
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────
    //  BUG 7: PDA seed collision — predictable seeds without bump
    // ─────────────────────────────────────────────────────────────────
    pub fn create_user_account(ctx: Context<CreateUserAccount>) -> Result<()> {
        let user_account = &mut ctx.accounts.user_account;
        // BUG: PDA created with only user key as seed — no unique bump
        user_account.owner = ctx.accounts.user.key();
        user_account.balance = 0;
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────
    //  BUG 8: Duplicate mutable accounts (type confusion)
    // ─────────────────────────────────────────────────────────────────
    pub fn handle_swap(ctx: Context<Swap>, amount: u64) -> Result<()> {
        let source = &mut ctx.accounts.source_vault;
        let dest = &mut ctx.accounts.dest_vault;
        // BUG: if source_vault == dest_vault, attacker can double-credit
        source.total_deposits -= amount;
        dest.total_deposits += amount;
        Ok(())
    }
}

// ─── Account Structs ─────────────────────────────────────────────────────────

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = payer, space = 8 + Vault::LEN)]
    pub vault: Account<'info, Vault>,
    /// CHECK: Not validated as signer — BUG
    pub authority: AccountInfo<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub depositor: Signer<'info>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// CHECK: authority not validated — BUG
    pub authority: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct GetPrice<'info> {
    pub vault: Account<'info, Vault>,
    /// CHECK: No owner or program validation — accepts ANY account as oracle
    pub oracle: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct Pause<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// CHECK: Anyone can call this — no signer enforcement
    pub caller: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct Vote<'info> {
    #[account(mut)]
    pub proposal: Account<'info, Proposal>,
    pub voter: Signer<'info>,
}

#[derive(Accounts)]
pub struct CreateUserAccount<'info> {
    #[account(
        init,
        payer = user,
        space = 8 + UserAccount::LEN,
        seeds = [b"user", user.key().as_ref()],
        bump,
    )]
    pub user_account: Account<'info, UserAccount>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Swap<'info> {
    #[account(mut)]
    pub source_vault: Account<'info, Vault>,
    #[account(mut)]
    pub dest_vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

// ─── State ───────────────────────────────────────────────────────────────────

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub total_deposits: u64,
    pub total_shares: u64,
    pub bump: u8,
    pub paused: bool,
}

impl Vault {
    pub const LEN: usize = 32 + 8 + 8 + 1 + 1;
}

#[account]
pub struct Proposal {
    pub id: u64,
    pub yes_votes: u64,
    pub no_votes: u64,
    pub executed: bool,
}

impl Proposal {
    pub const LEN: usize = 8 + 8 + 8 + 1;
}

#[account]
pub struct UserAccount {
    pub owner: Pubkey,
    pub balance: u64,
}

impl UserAccount {
    pub const LEN: usize = 32 + 8;
}
