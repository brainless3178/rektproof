//! Regression tests for vulnerability detection patterns.
//!
//! Each test contains a minimal vulnerable code snippet and asserts the
//! analyzer detects the correct vulnerability class. If any of these
//! tests break, a detection regression has been introduced.

use program_analyzer::ProgramAnalyzer;

/// Helper: analyze inline source and return findings
fn analyze(source: &str) -> Vec<program_analyzer::VulnerabilityFinding> {
    let analyzer = ProgramAnalyzer::from_source(source)
        .expect("Failed to parse test snippet");
    analyzer.scan_for_vulnerabilities()
}

// ─── Missing Signer Check ────────────────────────────────────────────────────

#[test]
fn regression_missing_signer_check() {
    let code = r#"
        use anchor_lang::prelude::*;

        #[derive(Accounts)]
        pub struct Withdraw<'info> {
            #[account(mut)]
            pub vault: Account<'info, Vault>,
            pub authority: AccountInfo<'info>,  // NOT Signer<'info>!
            pub token_program: Program<'info, Token>,
        }

        pub fn handle_withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
            let vault = &mut ctx.accounts.vault;
            vault.balance -= amount;
            Ok(())
        }
    "#;

    let findings = analyze(code);
    let has_signer_finding = findings.iter().any(|f| {
        f.vuln_type.to_lowercase().contains("signer")
            || f.category.to_lowercase().contains("access")
            || f.category.to_lowercase().contains("auth")
            || f.id.starts_with("1.")
            || f.id.starts_with("3.")
    });

    assert!(
        has_signer_finding,
        "REGRESSION: Failed to detect missing signer check. Found {} findings: {:?}",
        findings.len(),
        findings.iter().map(|f| format!("{}: {}", f.id, f.vuln_type)).collect::<Vec<_>>()
    );
}

// ─── Unchecked Arithmetic ────────────────────────────────────────────────────

#[test]
fn regression_unchecked_arithmetic() {
    let code = r#"
        use anchor_lang::prelude::*;

        pub fn handle_deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
            let vault = &mut ctx.accounts.vault;
            // BUG: unchecked add — can overflow
            vault.total_assets = vault.total_assets + amount;
            vault.shares = vault.shares + amount;
            Ok(())
        }
    "#;

    let findings = analyze(code);
    let has_arithmetic_finding = findings.iter().any(|f| {
        f.vuln_type.to_lowercase().contains("overflow")
            || f.vuln_type.to_lowercase().contains("arithmetic")
            || f.vuln_type.to_lowercase().contains("unchecked")
            || f.category.to_lowercase().contains("arithmetic")
            || f.id.starts_with("2.")
    });

    assert!(
        has_arithmetic_finding,
        "REGRESSION: Failed to detect unchecked arithmetic. Found {} findings: {:?}",
        findings.len(),
        findings.iter().map(|f| format!("{}: {}", f.id, f.vuln_type)).collect::<Vec<_>>()
    );
}

// ─── Raw AccountInfo Without CHECK Comment ───────────────────────────────────

#[test]
fn regression_unchecked_account_info() {
    // Include a handler function so the scanner cross-references the struct
    let code = r#"
        use anchor_lang::prelude::*;

        #[derive(Accounts)]
        pub struct Transfer<'info> {
            #[account(mut)]
            pub user: Signer<'info>,
            pub oracle: AccountInfo<'info>,  // Missing /// CHECK: comment
        }

        pub fn handle_transfer(ctx: Context<Transfer>, amount: u64) -> Result<()> {
            // Uses ctx.accounts.oracle without any safety check
            let oracle_data = ctx.accounts.oracle.try_borrow_data()?;
            let _price = u64::from_le_bytes(oracle_data[0..8].try_into().unwrap());
            Ok(())
        }
    "#;

    let findings = analyze(code);
    let has_account_finding = findings.iter().any(|f| {
        f.vuln_type.to_lowercase().contains("account")
            || f.vuln_type.to_lowercase().contains("unchecked")
            || f.vuln_type.to_lowercase().contains("validation")
            || f.vuln_type.to_lowercase().contains("oracle")
            || f.category.to_lowercase().contains("account")
            || f.id.starts_with("3.")
            || f.id.starts_with("4.")
    });

    assert!(
        has_account_finding,
        "REGRESSION: Failed to detect unchecked AccountInfo. Found {} findings: {:?}",
        findings.len(),
        findings.iter().map(|f| format!("{}: {}", f.id, f.vuln_type)).collect::<Vec<_>>()
    );
}

// ─── CPI Without Program ID Validation ───────────────────────────────────────

#[test]
fn regression_cpi_arbitrary_program() {
    let code = r#"
        use anchor_lang::prelude::*;

        pub fn do_transfer(accounts: &[AccountInfo]) -> ProgramResult {
            let ix = spl_token::instruction::transfer(
                &spl_token::id(), &src, &dst, &auth, &[], amount
            )?;
            invoke(&ix, accounts)?;
            Ok(())
        }
    "#;

    let analyzer = cpi_analyzer::CPIAnalyzer::new();
    let findings = analyzer.analyze_source(code, "test.rs")
        .expect("CPI analysis failed");

    assert!(
        !findings.is_empty(),
        "REGRESSION: CPI analyzer failed to detect unvalidated invoke() call"
    );
}

// ─── No False Positive on Safe Code ──────────────────────────────────────────

#[test]
fn no_false_positive_on_safe_signer() {
    let code = r#"
        use anchor_lang::prelude::*;

        #[derive(Accounts)]
        pub struct SafeWithdraw<'info> {
            #[account(mut, has_one = authority)]
            pub vault: Account<'info, Vault>,
            pub authority: Signer<'info>,
            pub token_program: Program<'info, Token>,
        }
    "#;

    let findings = analyze(code);
    let signer_findings: Vec<_> = findings.iter()
        .filter(|f| f.vuln_type.to_lowercase().contains("signer")
            && f.function_name == "SafeWithdraw")
        .collect();

    // Safe code should NOT produce signer findings for this struct
    assert!(
        signer_findings.is_empty(),
        "FALSE POSITIVE: Safe code with Signer<'info> + has_one flagged as vulnerable: {:?}",
        signer_findings.iter().map(|f| &f.vuln_type).collect::<Vec<_>>()
    );
}
