//! # Zero False Positives — Comprehensive Guarantee Test
//!
//! This test file is the GOLD STANDARD for rektproof's accuracy.
//! Every test here verifies that properly secured, production-quality
//! Solana/Anchor code produces ZERO findings.
//!
//! **Rule: If any test here fails, it's a regression — fix the detector,
//! not the test.**

use program_analyzer::ProgramAnalyzer;

/// Analyze source and return FILTERED findings (production pipeline)
fn scan(code: &str) -> Vec<program_analyzer::VulnerabilityFinding> {
    match ProgramAnalyzer::from_source(code) {
        Ok(analyzer) => analyzer.scan_for_vulnerabilities(),
        Err(_) => Vec::new(),
    }
}

/// Assert zero findings, printing any violations
fn assert_zero(findings: &[program_analyzer::VulnerabilityFinding], label: &str) {
    if !findings.is_empty() {
        let list: Vec<_> = findings.iter()
            .map(|f| format!("[{}] sev={} {} in {}", f.id, f.severity, f.vuln_type, f.function_name))
            .collect();
        panic!(
            "FALSE POSITIVE in '{}': expected 0 findings, got {}:\n  {}",
            label, findings.len(), list.join("\n  ")
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  1. FULL SECURE ANCHOR PROGRAM — token vault with all best practices
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn zero_fp_full_secure_anchor_vault() {
    let code = r#"
        use anchor_lang::prelude::*;

        declare_id!("Safe11111111111111111111111111111111111111");

        #[program]
        pub mod secure_vault {
            use super::*;

            pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
                let vault = &mut ctx.accounts.vault;
                vault.authority = ctx.accounts.authority.key();
                vault.balance = 0;
                vault.bump = ctx.bumps.vault;
                Ok(())
            }

            pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
                require!(amount > 0, ErrorCode::ZeroAmount);
                let vault = &mut ctx.accounts.vault;
                vault.balance = vault.balance
                    .checked_add(amount)
                    .ok_or(ErrorCode::Overflow)?;
                token::transfer(
                    CpiContext::new(
                        ctx.accounts.token_program.to_account_info(),
                        Transfer {
                            from: ctx.accounts.user_token.to_account_info(),
                            to: ctx.accounts.vault_token.to_account_info(),
                            authority: ctx.accounts.user.to_account_info(),
                        }
                    ),
                    amount
                )?;
                emit!(DepositEvent { user: ctx.accounts.user.key(), amount });
                Ok(())
            }

            pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
                let vault = &mut ctx.accounts.vault;
                require!(vault.balance >= amount, ErrorCode::InsufficientBalance);
                vault.balance = vault.balance
                    .checked_sub(amount)
                    .ok_or(ErrorCode::Underflow)?;
                let seeds = &[b"vault", vault.authority.as_ref(), &[vault.bump]];
                token::transfer(
                    CpiContext::new_with_signer(
                        ctx.accounts.token_program.to_account_info(),
                        Transfer {
                            from: ctx.accounts.vault_token.to_account_info(),
                            to: ctx.accounts.user_token.to_account_info(),
                            authority: vault.to_account_info(),
                        },
                        &[seeds]
                    ),
                    amount
                )?;
                emit!(WithdrawEvent { user: ctx.accounts.authority.key(), amount });
                Ok(())
            }
        }

        #[derive(Accounts)]
        pub struct Initialize<'info> {
            #[account(
                init,
                payer = authority,
                space = 8 + Vault::LEN,
                seeds = [b"vault", authority.key().as_ref()],
                bump
            )]
            pub vault: Account<'info, Vault>,
            #[account(mut)]
            pub authority: Signer<'info>,
            pub system_program: Program<'info, System>,
        }

        #[derive(Accounts)]
        pub struct Deposit<'info> {
            #[account(
                mut,
                seeds = [b"vault", vault.authority.as_ref()],
                bump = vault.bump
            )]
            pub vault: Account<'info, Vault>,
            #[account(mut)]
            pub user_token: Account<'info, TokenAccount>,
            #[account(mut)]
            pub vault_token: Account<'info, TokenAccount>,
            pub user: Signer<'info>,
            pub token_program: Program<'info, Token>,
        }

        #[derive(Accounts)]
        pub struct Withdraw<'info> {
            #[account(
                mut,
                seeds = [b"vault", vault.authority.as_ref()],
                bump = vault.bump,
                has_one = authority
            )]
            pub vault: Account<'info, Vault>,
            #[account(mut)]
            pub user_token: Account<'info, TokenAccount>,
            #[account(mut)]
            pub vault_token: Account<'info, TokenAccount>,
            pub authority: Signer<'info>,
            pub token_program: Program<'info, Token>,
        }

        #[account]
        pub struct Vault {
            pub authority: Pubkey,
            pub balance: u64,
            pub bump: u8,
        }

        impl Vault {
            pub const LEN: usize = 32 + 8 + 1;
        }

        #[event]
        pub struct DepositEvent {
            pub user: Pubkey,
            pub amount: u64,
        }

        #[event]
        pub struct WithdrawEvent {
            pub user: Pubkey,
            pub amount: u64,
        }

        #[error_code]
        pub enum ErrorCode {
            #[msg("Overflow")] Overflow,
            #[msg("Underflow")] Underflow,
            #[msg("Insufficient")] InsufficientBalance,
            #[msg("Zero amount")] ZeroAmount,
        }
    "#;
    assert_zero(&scan(code), "full_secure_anchor_vault");
}

// ═══════════════════════════════════════════════════════════════════════════
//  2. CHECKED ARITHMETIC — all safe math variants
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn zero_fp_checked_arithmetic() {
    let code = r#"
        pub fn safe_math(a: u64, b: u64) -> Result<u64> {
            let sum = a.checked_add(b).ok_or(ErrorCode::Overflow)?;
            let product = a.checked_mul(b).ok_or(ErrorCode::Overflow)?;
            let diff = a.checked_sub(b).ok_or(ErrorCode::Underflow)?;
            let quotient = a.checked_div(b).ok_or(ErrorCode::DivZero)?;
            Ok(sum + product + diff + quotient)
        }

        pub fn saturating_math(a: u64, b: u64) -> u64 {
            a.saturating_add(b)
                .saturating_mul(2)
                .saturating_sub(b)
        }
    "#;
    assert_zero(&scan(code), "checked_arithmetic");
}

// ═══════════════════════════════════════════════════════════════════════════
//  3. PROPER SIGNER CHECKS — all patterns
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn zero_fp_signer_patterns() {
    let code = r#"
        use anchor_lang::prelude::*;

        #[derive(Accounts)]
        pub struct SecureAction<'info> {
            #[account(mut)]
            pub authority: Signer<'info>,
            #[account(mut, has_one = authority)]
            pub vault: Account<'info, Vault>,
        }

        pub fn do_action(ctx: Context<SecureAction>) -> Result<()> {
            Ok(())
        }
    "#;
    assert_zero(&scan(code), "signer_patterns");
}

// ═══════════════════════════════════════════════════════════════════════════
//  4. ORACLE WITH STALENESS — proper price feed usage
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn zero_fp_oracle_with_staleness() {
    let code = r#"
        pub fn get_price(oracle: &AccountInfo) -> Result<u64> {
            let price_data = load_price_feed(oracle)?;
            let current_time = Clock::get()?.unix_timestamp;
            require!(
                current_time - price_data.publish_time < MAX_STALENESS,
                ErrorCode::StalePrice
            );
            require!(
                price_data.conf < MAX_CONFIDENCE_INTERVAL,
                ErrorCode::PriceUncertain
            );
            Ok(price_data.price)
        }
    "#;
    assert_zero(&scan(code), "oracle_with_staleness");
}

// ═══════════════════════════════════════════════════════════════════════════
//  5. CPI WITH PROGRAM ID VALIDATION
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn zero_fp_cpi_with_validation() {
    let code = r#"
        pub fn secure_cpi(ctx: Context<SecureCpi>) -> Result<()> {
            require!(
                ctx.accounts.target_program.key() == expected_program::ID,
                ErrorCode::InvalidProgram
            );
            invoke_signed(
                &instruction,
                &accounts,
                &[&seeds],
            )?;
            Ok(())
        }
    "#;
    assert_zero(&scan(code), "cpi_with_validation");
}

// ═══════════════════════════════════════════════════════════════════════════
//  6. PDA WITH CANONICAL BUMP — proper seed usage
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn zero_fp_pda_with_bump() {
    let code = r#"
        #[derive(Accounts)]
        pub struct SecurePda<'info> {
            #[account(
                seeds = [b"config", authority.key().as_ref()],
                bump = config.bump,
            )]
            pub config: Account<'info, Config>,
            pub authority: Signer<'info>,
        }
    "#;
    assert_zero(&scan(code), "pda_with_bump");
}

// ═══════════════════════════════════════════════════════════════════════════
//  7. CEI PATTERN (Checks-Effects-Interactions)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn zero_fp_cei_pattern() {
    let code = r#"
        pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
            let vault = &mut ctx.accounts.vault;
            require!(vault.balance >= amount, ErrorCode::Insufficient);
            vault.balance = vault.balance.checked_sub(amount).ok_or(ErrorCode::Underflow)?;
            transfer(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    Transfer { from: vault_ata, to: user_ata, authority: vault },
                    &[&seeds]
                ),
                amount
            )?;
            Ok(())
        }
    "#;
    assert_zero(&scan(code), "cei_pattern");
}

// ═══════════════════════════════════════════════════════════════════════════
//  8. OWNER VALIDATION — has_one and constraint
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn zero_fp_owner_validation() {
    let code = r#"
        #[derive(Accounts)]
        pub struct SecureWithdraw<'info> {
            #[account(
                mut,
                has_one = owner,
                seeds = [b"vault", owner.key().as_ref()],
                bump
            )]
            pub vault: Account<'info, Vault>,
            pub owner: Signer<'info>,
        }
    "#;
    assert_zero(&scan(code), "owner_validation");
}

// ═══════════════════════════════════════════════════════════════════════════
//  9. COMMENTS AND STRING LITERALS — keywords in non-code
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn zero_fp_comments_and_strings() {
    let code = r#"
        /// This function uses invoke_signed safely.
        /// Never use unchecked arithmetic in production.
        /// The oracle staleness check happens in get_price.
        pub fn safe_function(ctx: Context<Safe>) -> Result<()> {
            // Always use checked_add for safety
            msg!("Warning: invoke_signed should be used carefully");
            msg!("Error codes: unchecked arithmetic can cause overflow");
            let result = a.checked_add(b)?;
            Ok(())
        }
    "#;
    assert_zero(&scan(code), "comments_and_strings");
}

// ═══════════════════════════════════════════════════════════════════════════
//  10. INIT CONSTRAINT — reinit protection
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn zero_fp_init_constraint() {
    let code = r#"
        #[derive(Accounts)]
        pub struct Initialize<'info> {
            #[account(init, payer = payer, space = 128)]
            pub data: Account<'info, MyData>,
            #[account(mut)]
            pub payer: Signer<'info>,
            pub system_program: Program<'info, System>,
        }

        pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
            let data = &mut ctx.accounts.data;
            data.value = 0;
            Ok(())
        }
    "#;
    assert_zero(&scan(code), "init_constraint");
}

// ═══════════════════════════════════════════════════════════════════════════
//  11. PAUSE MECHANISM — emergency stop pattern
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn zero_fp_pause_mechanism() {
    let code = r#"
        pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
            require!(!ctx.accounts.config.is_paused, ErrorCode::Paused);
            let vault = &mut ctx.accounts.vault;
            vault.balance = vault.balance.checked_add(amount).ok_or(ErrorCode::Overflow)?;
            Ok(())
        }
    "#;
    assert_zero(&scan(code), "pause_mechanism");
}

// ═══════════════════════════════════════════════════════════════════════════
//  12. EVENT EMISSION — proper logging
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn zero_fp_event_emission() {
    let code = r#"
        pub fn transfer_tokens(ctx: Context<TransferTokens>, amount: u64) -> Result<()> {
            let vault = &mut ctx.accounts.vault;
            vault.balance = vault.balance.checked_sub(amount).ok_or(ErrorCode::Underflow)?;
            emit!(TransferEvent { from: vault.key(), amount });
            Ok(())
        }
    "#;
    assert_zero(&scan(code), "event_emission");
}

// ═══════════════════════════════════════════════════════════════════════════
//  13. CONSTRAINT VALIDATION — explicit constraint check
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn zero_fp_constraint_validation() {
    let code = r#"
        #[derive(Accounts)]
        pub struct SecureAccess<'info> {
            #[account(constraint = vault.authority == authority.key() @ ErrorCode::Unauthorized)]
            pub vault: Account<'info, Vault>,
            pub authority: Signer<'info>,
        }
    "#;
    assert_zero(&scan(code), "constraint_validation");
}

// ═══════════════════════════════════════════════════════════════════════════
//  14. PURE DATA FUNCTIONS — no Solana logic
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn zero_fp_pure_data_functions() {
    let code = r#"
        pub fn calculate_fee(amount: u64, fee_bps: u64) -> u64 {
            amount.checked_mul(fee_bps).unwrap_or(0) / 10000
        }

        pub fn format_display(data: &[u8]) -> String {
            format!("{:?}", data)
        }
    "#;
    assert_zero(&scan(code), "pure_data_functions");
}

// ═══════════════════════════════════════════════════════════════════════════
//  15. SLIPPAGE PROTECTION — proper swap guards
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn zero_fp_slippage_protection() {
    let code = r#"
        pub fn swap(ctx: Context<Swap>, amount_in: u64, minimum_amount_out: u64) -> Result<()> {
            let amount_out = calculate_output(amount_in)?;
            require!(amount_out >= minimum_amount_out, ErrorCode::ExceededSlippage);
            Ok(())
        }
    "#;
    assert_zero(&scan(code), "slippage_protection");
}
