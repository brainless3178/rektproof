//! CVE Regression Tests
//!
//! Tests that verify rektproof catches patterns from real-world Solana exploits.
//! Each test case is modeled after the actual vulnerable code from production incidents.

#[cfg(test)]
mod cve_regression_tests {
    use program_analyzer::ProgramAnalyzer;

    fn scan_raw(src: &str) -> Vec<program_analyzer::VulnerabilityFinding> {
        let analyzer = program_analyzer::ProgramAnalyzer::from_source(src).expect("should parse");
        analyzer.scan_for_vulnerabilities_raw()
    }

    fn has_finding(findings: &[program_analyzer::VulnerabilityFinding], id_prefix: &str) -> bool {
        findings.iter().any(|f| f.id.starts_with(id_prefix))
    }

    fn has_finding_type(findings: &[program_analyzer::VulnerabilityFinding], vuln_type: &str) -> bool {
        findings.iter().any(|f|
            f.vuln_type.to_lowercase().contains(&vuln_type.to_lowercase())
            || f.description.to_lowercase().contains(&vuln_type.to_lowercase())
        )
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  CVE-2022-WORMHOLE: Missing Signer Verification
    //  Lost: $320M (Feb 2022)
    //  Root cause: `verify_signatures` instruction accepted unverified guardian set
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn cve_wormhole_missing_signer() {
        let code = r#"
            use anchor_lang::prelude::*;
            pub fn verify_signatures(
                ctx: Context<VerifySigs>,
                data: Vec<u8>,
            ) -> Result<()> {
                // BUG: No signer verification on guardian_set
                let guardian_set = &ctx.accounts.guardian_set;
                let vaa = deserialize_vaa(&data)?;

                // Missing: require!(guardian_set.is_signer, ...);
                // This allows anyone to pass a fake guardian set
                process_vaa(guardian_set, &vaa)?;
                Ok(())
            }
            #[derive(Accounts)]
            pub struct VerifySigs<'info> {
                pub guardian_set: AccountInfo<'info>,
                pub payer: Signer<'info>,
            }
        "#;
        let findings = scan_raw(code);
        assert!(
            has_finding(&findings, "SOL-001") // missing signer
            || has_finding(&findings, "SOL-062") // unvalidated account
            || has_finding(&findings, "SOL-ALIAS") // account aliasing
            || has_finding(&findings, "SOL-DEEP")
            || has_finding_type(&findings, "signer"),
            "MUST detect Wormhole-style missing signer check. Findings: {:?}",
            findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  CVE-2022-CASHIO: Missing Account Owner Validation
    //  Lost: $52M (Mar 2022)
    //  Root cause: `burn_tokens` accepted any account as collateral
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn cve_cashio_missing_owner_check() {
        let code = r#"
            use anchor_lang::prelude::*;
            pub fn burn_tokens(
                ctx: Context<BurnTokens>,
                amount: u64,
            ) -> Result<()> {
                // BUG: No owner check on collateral account
                let collateral = &ctx.accounts.collateral;
                let data = collateral.try_borrow_data()?;
                // Attacker passes a fake collateral account they control
                let value = u64::from_le_bytes(data[0..8].try_into().unwrap());
                // Missing: require!(collateral.owner == &expected_program_id);
                token::burn(ctx.accounts.into_burn_context(), amount)?;
                Ok(())
            }
            #[derive(Accounts)]
            pub struct BurnTokens<'info> {
                pub collateral: AccountInfo<'info>,
                #[account(mut)]
                pub mint: Account<'info, Mint>,
                pub authority: Signer<'info>,
            }
        "#;
        let findings = scan_raw(code);
        assert!(
            has_finding(&findings, "SOL-002") // missing owner
            || has_finding(&findings, "SOL-DEEP")
            || has_finding_type(&findings, "owner"),
            "MUST detect Cashio-style missing owner check. Findings: {:?}",
            findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  CVE-2022-MANGO: Price Oracle Manipulation
    //  Lost: $114M (Oct 2022)
    //  Root cause: Unchecked oracle price used to compute collateral value
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn cve_mango_oracle_manipulation() {
        let code = r#"
            use anchor_lang::prelude::*;
            pub fn calculate_collateral(
                ctx: Context<CalcCollateral>,
                amount: u64,
            ) -> Result<()> {
                // BUG: Oracle price used without staleness or confidence check
                let oracle = &ctx.accounts.oracle;
                let price_data = oracle.try_borrow_data()?;
                let price = u64::from_le_bytes(price_data[0..8].try_into().unwrap());

                // Missing: price staleness check
                // Missing: confidence interval check
                // Missing: TWAP comparison
                let collateral_value = amount * price;
                // Attacker manipulates price to inflate collateral

                msg!("Collateral value: {}", collateral_value);
                Ok(())
            }
            #[derive(Accounts)]
            pub struct CalcCollateral<'info> {
                pub oracle: AccountInfo<'info>,
                pub authority: Signer<'info>,
            }
        "#;
        let findings = scan_raw(code);
        assert!(
            has_finding(&findings, "SOL-006") // unchecked arithmetic
            || has_finding(&findings, "SOL-ABS") // abstract interp overflow
            || has_finding(&findings, "SOL-Z3")  // Z3 proven overflow
            || has_finding_type(&findings, "overflow")
            || has_finding_type(&findings, "oracle"),
            "MUST detect Mango-style arithmetic vulnerability. Findings: {:?}",
            findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  CVE-2021-SABER: Integer Overflow in Fee Calculation
    //  Root cause: Unchecked multiplication in fee computation
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn cve_saber_integer_overflow() {
        let code = r#"
            pub fn compute_fee(amount: u64, fee_numerator: u64, fee_denominator: u64) -> u64 {
                // BUG: amount * fee_numerator can overflow u64
                let fee = amount * fee_numerator / fee_denominator;
                fee
            }
        "#;
        let findings = scan_raw(code);
        assert!(
            has_finding(&findings, "SOL-006")
            || has_finding(&findings, "SOL-ABS")
            || has_finding(&findings, "SOL-Z3")
            || has_finding_type(&findings, "overflow"),
            "MUST detect integer overflow in fee calculation. Findings: {:?}",
            findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  CVE-2022-CREMA: Missing PDA Seed Validation
    //  Lost: $8.8M
    //  Root cause: PDA derived without proper bump seed validation
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn cve_crema_pda_without_bump() {
        let code = r#"
            use anchor_lang::prelude::*;
            pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> {
                let pool = &ctx.accounts.pool;
                // BUG: PDA derived without canonical bump
                let (expected_pda, _bump) = Pubkey::find_program_address(
                    &[b"pool", pool.key().as_ref()],
                    ctx.program_id,
                );
                // Missing: bump validation against stored canonical bump
                transfer_from_pool(ctx.accounts)?;
                Ok(())
            }
            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                pub pool: AccountInfo<'info>,
                pub authority: Signer<'info>,
            }
        "#;
        let findings = scan_raw(code);
        assert!(
            has_finding(&findings, "SOL-009") // PDA
            || has_finding(&findings, "SOL-DEEP")
            || has_finding_type(&findings, "PDA")
            || has_finding_type(&findings, "bump"),
            "MUST detect PDA without bump validation. Findings: {:?}",
            findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  PATTERN: Reentrancy via CPI
    //  Root cause: State read before CPI, CPI modifies state, stale read used
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn pattern_cpi_reentrancy() {
        let code = r#"
            use anchor_lang::prelude::*;
            pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
                let vault = &ctx.accounts.vault;
                // Read balance BEFORE CPI
                let balance = vault.balance;

                // CPI call — external program could re-enter
                anchor_spl::token::transfer(
                    CpiContext::new(
                        ctx.accounts.token_program.to_account_info(),
                        Transfer {
                            from: vault.to_account_info(),
                            to: ctx.accounts.user.to_account_info(),
                            authority: vault.to_account_info(),
                        },
                    ),
                    amount,
                )?;

                // Update state AFTER CPI — classic reentrancy
                let vault = &mut ctx.accounts.vault;
                vault.balance = balance - amount;
                Ok(())
            }
            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                #[account(mut)]
                pub vault: Account<'info, Vault>,
                pub user: AccountInfo<'info>,
                pub token_program: Program<'info, Token>,
            }
            #[account]
            pub struct Vault { pub balance: u64 }
        "#;
        let findings = scan_raw(code);
        assert!(
            has_finding(&findings, "SOL-012") // reentrancy
            || has_finding(&findings, "SOL-DEEP")
            || has_finding_type(&findings, "reentr"),
            "MUST detect CPI reentrancy pattern. Findings: {:?}",
            findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  PATTERN: Unsafe Account Close (Rent Drain)
    //  Root cause: Account closed without zeroing data/discriminator
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn pattern_unsafe_account_close() {
        let code = r#"
            use anchor_lang::prelude::*;
            pub fn close_account(ctx: Context<CloseAccount>) -> Result<()> {
                let account = &ctx.accounts.target;
                let dest = &ctx.accounts.destination;

                // Transfer lamports
                **dest.to_account_info().try_borrow_mut_lamports()? +=
                    account.to_account_info().lamports();
                **account.to_account_info().try_borrow_mut_lamports()? = 0;

                // BUG: Data not zeroed — can be resurrected
                // Missing: account.data.borrow_mut().fill(0);
                Ok(())
            }
            #[derive(Accounts)]
            pub struct CloseAccount<'info> {
                #[account(mut)]
                pub target: AccountInfo<'info>,
                #[account(mut)]
                pub destination: AccountInfo<'info>,
                pub authority: Signer<'info>,
            }
        "#;
        let findings = scan_raw(code);
        assert!(
            has_finding(&findings, "SOL-013") // unsafe close
            || has_finding(&findings, "SOL-DEEP")
            || has_finding_type(&findings, "close")
            || has_finding_type(&findings, "lamport"),
            "MUST detect unsafe account close. Findings: {:?}",
            findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  PATTERN: Division by Zero
    //  Root cause: User-controlled denominator without zero check
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn pattern_division_by_zero() {
        let code = r#"
            pub fn calculate_share(total: u64, num_holders: u64) -> u64 {
                // BUG: num_holders could be 0
                let share = total / num_holders;
                share
            }
        "#;
        let findings = scan_raw(code);
        assert!(
            has_finding(&findings, "SOL-ABS-03") // abstract interp div-by-zero
            || has_finding(&findings, "SOL-Z3")   // Z3 proven
            || has_finding(&findings, "SOL-006")
            || has_finding_type(&findings, "division"),
            "MUST detect division by zero. Findings: {:?}",
            findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
    }
}
