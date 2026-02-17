//! # Vulnerable Token Program (Intentionally Insecure)
//!
//! ⚠️ DO NOT DEPLOY — This program contains deliberate token-related
//! vulnerabilities for scanner testing. Covers token supply manipulation,
//! unauthorized minting, missing freeze authority checks, and CPI exploits.

use anchor_lang::prelude::*;

declare_id!("Ea1qKkVjEEGa5mLAWdDryPB1nsGHyuxwB7oQFz8obb22");

#[program]
pub mod vulnerable_token {
    use super::*;

    // ─────────────────────────────────────────────────────────────────
    //  BUG 1: Unbounded token minting — no supply cap
    // ─────────────────────────────────────────────────────────────────
    pub fn mint_tokens(ctx: Context<MintTokens>, amount: u64) -> Result<()> {
        let token_state = &mut ctx.accounts.token_state;
        // BUG: no maximum supply check — attacker can mint unlimited tokens
        token_state.total_supply = token_state.total_supply + amount;
        token_state.balances_dirty = true;
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────
    //  BUG 2: Missing mint authority — anyone can mint
    // ─────────────────────────────────────────────────────────────────
    pub fn open_mint(ctx: Context<OpenMint>, amount: u64) -> Result<()> {
        let token_state = &mut ctx.accounts.token_state;
        // BUG: caller is AccountInfo, not Signer, no authority == check
        token_state.total_supply = token_state.total_supply + amount;
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────
    //  BUG 3: Token transfer without balance validation
    // ─────────────────────────────────────────────────────────────────
    pub fn transfer_tokens(
        ctx: Context<TransferTokens>,
        amount: u64,
    ) -> Result<()> {
        let from = &mut ctx.accounts.from_account;
        let to = &mut ctx.accounts.to_account;

        // BUG: no check that from.balance >= amount → underflow
        from.balance = from.balance - amount;
        to.balance = to.balance + amount;
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────
    //  BUG 4: Unvalidated CPI — calls arbitrary program
    // ─────────────────────────────────────────────────────────────────
    pub fn delegate_transfer(ctx: Context<DelegateTransfer>, amount: u64) -> Result<()> {
        let ix = anchor_lang::solana_program::instruction::Instruction {
            program_id: ctx.accounts.target_program.key(),
            accounts: vec![],
            data: amount.to_le_bytes().to_vec(),
        };
        // BUG: invoke() with unvalidated target_program key — arbitrary CPI
        anchor_lang::solana_program::program::invoke(
            &ix,
            &[ctx.accounts.target_program.to_account_info()],
        )?;
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────
    //  BUG 5: Missing freeze authority handling
    // ─────────────────────────────────────────────────────────────────
    pub fn freeze_account(ctx: Context<FreezeAccount>) -> Result<()> {
        let token_state = &mut ctx.accounts.token_state;
        // BUG: no freeze authority check — anyone can freeze
        token_state.frozen = true;
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────
    //  BUG 6: Unsafe integer truncation in fee calculation
    // ─────────────────────────────────────────────────────────────────
    pub fn collect_fee(ctx: Context<CollectFee>, amount: u64, fee_bps: u16) -> Result<()> {
        let token_state = &mut ctx.accounts.token_state;
        // BUG: intermediate multiplication can overflow, then truncation loses data
        let fee = (amount * fee_bps as u64) / 10_000;
        token_state.collected_fees = token_state.collected_fees + fee;
        Ok(())
    }
}

// ─── Account Structs ─────────────────────────────────────────────────────────

#[derive(Accounts)]
pub struct MintTokens<'info> {
    #[account(mut)]
    pub token_state: Account<'info, TokenState>,
    pub minter: Signer<'info>,
}

#[derive(Accounts)]
pub struct OpenMint<'info> {
    #[account(mut)]
    pub token_state: Account<'info, TokenState>,
    /// CHECK: Not validated as signer — BUG
    pub caller: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct TransferTokens<'info> {
    #[account(mut)]
    pub from_account: Account<'info, UserBalance>,
    #[account(mut)]
    pub to_account: Account<'info, UserBalance>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct DelegateTransfer<'info> {
    #[account(mut)]
    pub token_state: Account<'info, TokenState>,
    /// CHECK: Arbitrary program — BUG
    pub target_program: AccountInfo<'info>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct FreezeAccount<'info> {
    #[account(mut)]
    pub token_state: Account<'info, TokenState>,
    /// CHECK: Not validated — BUG
    pub caller: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct CollectFee<'info> {
    #[account(mut)]
    pub token_state: Account<'info, TokenState>,
    pub authority: Signer<'info>,
}

// ─── State ───────────────────────────────────────────────────────────────────

#[account]
pub struct TokenState {
    pub mint_authority: Pubkey,
    pub total_supply: u64,
    pub collected_fees: u64,
    pub frozen: bool,
    pub balances_dirty: bool,
}

impl TokenState {
    pub const LEN: usize = 32 + 8 + 8 + 1 + 1;
}

#[account]
pub struct UserBalance {
    pub owner: Pubkey,
    pub balance: u64,
}

impl UserBalance {
    pub const LEN: usize = 32 + 8;
}
