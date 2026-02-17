//! # Vulnerable Staking Program (Intentionally Insecure)
//!
//! ⚠️ DO NOT DEPLOY — This program contains deliberate staking/DeFi
//! vulnerabilities for scanner testing. Covers reward manipulation,
//! flash loan exploits, reentrancy-style issues, and economic attacks.

use anchor_lang::prelude::*;

declare_id!("Ea1qKkVjEEGa5mLAWdDryPB1nsGHyuxwB7oQFz8obb33");

#[program]
pub mod vulnerable_staking {
    use super::*;

    // ─────────────────────────────────────────────────────────────────
    //  BUG 1: Reward calculation without time normalization
    // ─────────────────────────────────────────────────────────────────
    pub fn stake(ctx: Context<Stake>, amount: u64) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        let user_stake = &mut ctx.accounts.user_stake;

        // BUG: no checked arithmetic
        pool.total_staked = pool.total_staked + amount;
        user_stake.amount = user_stake.amount + amount;
        // BUG: timestamp not recorded → reward gaming possible
        user_stake.last_stake_ts = 0;
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────
    //  BUG 2: Unstake without lockup period
    // ─────────────────────────────────────────────────────────────────
    pub fn unstake(ctx: Context<Unstake>, amount: u64) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        let user_stake = &mut ctx.accounts.user_stake;

        // BUG: no lockup period check → flash stake+unstake
        // BUG: unchecked subtraction → underflow
        pool.total_staked = pool.total_staked - amount;
        user_stake.amount = user_stake.amount - amount;
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────
    //  BUG 3: Reward calculation vulnerable to inflation attack
    // ─────────────────────────────────────────────────────────────────
    pub fn claim_rewards(ctx: Context<ClaimRewards>) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        let user_stake = &mut ctx.accounts.user_stake;

        // BUG: reward_per_token vulnerable to first-depositor inflation attack
        // If total_staked is very small (e.g., 1 lamport), reward_per_token
        // becomes extremely large, allowing disproportionate reward claiming
        let reward_per_token = if pool.total_staked > 0 {
            pool.reward_rate * 1_000_000 / pool.total_staked
        } else {
            0
        };

        // BUG: unchecked multiplication, intermediate overflow possible
        let pending_reward = user_stake.amount * reward_per_token / 1_000_000;

        // BUG: no re-entrancy guard — rewards claimed multiple times
        user_stake.rewards_claimed = user_stake.rewards_claimed + pending_reward;
        pool.total_rewards_distributed = pool.total_rewards_distributed + pending_reward;
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────
    //  BUG 4: Admin update without proper access control
    // ─────────────────────────────────────────────────────────────────
    pub fn update_reward_rate(ctx: Context<UpdatePool>, new_rate: u64) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        // BUG: no authority check — anyone can change reward rate
        pool.reward_rate = new_rate;
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────
    //  BUG 5: Emergency withdraw drains entire pool
    // ─────────────────────────────────────────────────────────────────
    pub fn emergency_withdraw(ctx: Context<EmergencyWithdraw>) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        let user_stake = &mut ctx.accounts.user_stake;

        // BUG: allows withdrawing more than staked amount
        let withdraw_amount = pool.total_staked;
        user_stake.amount = 0;
        pool.total_staked = pool.total_staked - withdraw_amount;
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────
    //  BUG 6: Missing duplicate account check
    // ─────────────────────────────────────────────────────────────────
    pub fn compound_rewards(ctx: Context<CompoundRewards>) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        let user_stake = &mut ctx.accounts.user_stake;

        let rewards = user_stake.rewards_claimed;
        // BUG: re-stake rewards without zeroing rewards_claimed
        // allows infinite compounding
        user_stake.amount = user_stake.amount + rewards;
        pool.total_staked = pool.total_staked + rewards;
        Ok(())
    }
}

// ─── Account Structs ─────────────────────────────────────────────────────────

#[derive(Accounts)]
pub struct Stake<'info> {
    #[account(mut)]
    pub pool: Account<'info, StakingPool>,
    #[account(mut)]
    pub user_stake: Account<'info, UserStake>,
    pub staker: Signer<'info>,
}

#[derive(Accounts)]
pub struct Unstake<'info> {
    #[account(mut)]
    pub pool: Account<'info, StakingPool>,
    #[account(mut)]
    pub user_stake: Account<'info, UserStake>,
    pub staker: Signer<'info>,
}

#[derive(Accounts)]
pub struct ClaimRewards<'info> {
    #[account(mut)]
    pub pool: Account<'info, StakingPool>,
    #[account(mut)]
    pub user_stake: Account<'info, UserStake>,
    pub staker: Signer<'info>,
}

#[derive(Accounts)]
pub struct UpdatePool<'info> {
    #[account(mut)]
    pub pool: Account<'info, StakingPool>,
    /// CHECK: No authority validation — BUG
    pub caller: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct EmergencyWithdraw<'info> {
    #[account(mut)]
    pub pool: Account<'info, StakingPool>,
    #[account(mut)]
    pub user_stake: Account<'info, UserStake>,
    pub staker: Signer<'info>,
}

#[derive(Accounts)]
pub struct CompoundRewards<'info> {
    #[account(mut)]
    pub pool: Account<'info, StakingPool>,
    #[account(mut)]
    pub user_stake: Account<'info, UserStake>,
    pub staker: Signer<'info>,
}

// ─── State ───────────────────────────────────────────────────────────────────

#[account]
pub struct StakingPool {
    pub authority: Pubkey,
    pub total_staked: u64,
    pub reward_rate: u64,
    pub total_rewards_distributed: u64,
    pub last_update_ts: i64,
}

impl StakingPool {
    pub const LEN: usize = 32 + 8 + 8 + 8 + 8;
}

#[account]
pub struct UserStake {
    pub owner: Pubkey,
    pub amount: u64,
    pub rewards_claimed: u64,
    pub last_stake_ts: i64,
}

impl UserStake {
    pub const LEN: usize = 32 + 8 + 8 + 8;
}
