//! Integration Tests for Program Analyzer
//!
//! These tests verify the analyzer correctly detects known vulnerability patterns,
//! extracts account schemas, and processes instruction logic. All tests use inline
//! source code — no external test programs needed. Users bring their own programs.

use program_analyzer::ProgramAnalyzer;

// ═══════════════════════════════════════════════════════════════════════════════
// Vulnerability Detection — prove the scanner catches real bugs
// ═══════════════════════════════════════════════════════════════════════════════

/// Analyzer detects multiple vulnerability classes in realistic DeFi code
#[test]
fn test_detect_known_vulnerability_patterns() {
    let vulnerable_code = r#"
        use anchor_lang::prelude::*;

        pub fn unsafe_transfer(ctx: Context<UnsafeTransfer>, amount: u64) -> Result<()> {
            let vault = &mut ctx.accounts.vault;

            // BUG: Unchecked arithmetic on financial value
            vault.balance = vault.balance + amount;

            // BUG: Direct lamport manipulation
            **ctx.accounts.vault.to_account_info().try_borrow_mut_lamports()? -= amount;
            **ctx.accounts.recipient.try_borrow_mut_lamports()? += amount;

            Ok(())
        }

        #[derive(Accounts)]
        pub struct UnsafeTransfer<'info> {
            pub authority: AccountInfo<'info>,
            #[account(mut)]
            pub vault: Account<'info, Vault>,
            /// CHECK: Unchecked account
            #[account(mut)]
            pub recipient: AccountInfo<'info>,
        }
    "#;

    let analyzer = ProgramAnalyzer::from_source(vulnerable_code)
        .expect("Should parse vulnerable code");

    let findings = analyzer.scan_for_vulnerabilities();

    println!("\n=== Known Pattern Detection ===");
    for f in &findings {
        println!("[{}] {} (severity {})", f.id, f.vuln_type, f.severity);
    }
    println!("Total: {}\n", findings.len());

    assert!(
        findings.len() >= 2,
        "Should detect multiple vulnerabilities in known-bad code, found {}",
        findings.len()
    );
}

/// Analyzer detects missing signer checks on authority accounts
#[test]
fn test_analyze_missing_signer() {
    let code = r#"
        use anchor_lang::prelude::*;

        #[derive(Accounts)]
        pub struct Withdraw<'info> {
            #[account(mut)]
            pub vault: Account<'info, Vault>,
            pub authority: AccountInfo<'info>,
            pub token_program: Program<'info, Token>,
        }

        pub fn handle_withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
            let vault = &mut ctx.accounts.vault;
            vault.balance = vault.balance - amount;
            Ok(())
        }
    "#;

    let analyzer = ProgramAnalyzer::from_source(code)
        .expect("Should parse source");
    let findings = analyzer.scan_for_vulnerabilities();

    let has_signer_or_auth = findings.iter().any(|f| {
        f.vuln_type.to_lowercase().contains("signer")
            || f.category.to_lowercase().contains("auth")
            || f.id == "SOL-001"
    });

    assert!(
        has_signer_or_auth,
        "Should detect missing signer check. Found: {:?}",
        findings.iter().map(|f| format!("{}: {}", f.id, f.vuln_type)).collect::<Vec<_>>()
    );
}

/// Analyzer detects unchecked arithmetic on financial values
#[test]
fn test_analyze_unchecked_arithmetic() {
    let code = r#"
        use anchor_lang::prelude::*;

        pub fn handle_deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
            let vault = &mut ctx.accounts.vault;
            vault.total_assets = vault.total_assets + amount;
            vault.shares = vault.shares + amount;
            Ok(())
        }
    "#;

    let analyzer = ProgramAnalyzer::from_source(code)
        .expect("Should parse source");
    let findings = analyzer.scan_for_vulnerabilities();

    let has_arithmetic = findings.iter().any(|f| {
        f.vuln_type.to_lowercase().contains("overflow")
            || f.vuln_type.to_lowercase().contains("arithmetic")
            || f.id == "SOL-002"
    });

    assert!(
        has_arithmetic,
        "Should detect unchecked arithmetic. Found: {:?}",
        findings.iter().map(|f| format!("{}: {}", f.id, f.vuln_type)).collect::<Vec<_>>()
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Account Schema Extraction — prove the parser reads #[account] structs
// ═══════════════════════════════════════════════════════════════════════════════

/// Account schemas are correctly extracted from Anchor-style structs
#[test]
fn test_extract_account_schemas() {
    let code = r#"
        use anchor_lang::prelude::*;

        #[account]
        pub struct Vault {
            pub admin: Pubkey,
            pub total_shares: u64,
            pub total_assets: u64,
            pub token_mint: Pubkey,
            pub bump: u8,
        }

        #[account]
        pub struct UserPosition {
            pub owner: Pubkey,
            pub shares: u64,
            pub last_deposit_slot: u64,
        }
    "#;

    let analyzer = ProgramAnalyzer::from_source(code)
        .expect("Should parse source");
    let schemas = analyzer.extract_account_schemas();

    println!("\n=== Extracted Account Schemas ===");
    for schema in &schemas {
        println!("Account: {} with {} fields", schema.name, schema.fields.len());
        for (name, ty) in &schema.fields {
            println!("  - {}: {}", name, ty);
        }
    }

    let vault_schema = schemas.iter().find(|s| s.name == "Vault");
    assert!(
        vault_schema.is_some(),
        "Should extract Vault account schema. Found: {:?}",
        schemas.iter().map(|s| &s.name).collect::<Vec<_>>()
    );

    let vault = vault_schema.unwrap();
    assert!(vault.fields.contains_key("admin"), "Vault should have admin field");
    assert!(vault.fields.contains_key("total_shares"), "Vault should have total_shares field");
    assert!(vault.fields.contains_key("bump"), "Vault should have bump field");

    let user_schema = schemas.iter().find(|s| s.name == "UserPosition");
    assert!(
        user_schema.is_some(),
        "Should extract UserPosition account schema"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Instruction Logic Extraction — prove the parser reads fn bodies
// ═══════════════════════════════════════════════════════════════════════════════

/// Instruction logic is correctly extracted from handler functions
#[test]
fn test_extract_instruction_logic() {
    let code = r#"
        use anchor_lang::prelude::*;

        pub fn handle_deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
            let vault = &mut ctx.accounts.vault;
            vault.total_assets = vault.total_assets + amount;
            vault.total_shares = vault.total_shares + amount;
            Ok(())
        }

        pub fn handle_withdraw(ctx: Context<Withdraw>, shares: u64) -> Result<()> {
            let vault = &mut ctx.accounts.vault;
            let payout = shares * vault.total_assets / vault.total_shares;
            vault.total_assets = vault.total_assets - payout;
            vault.total_shares = vault.total_shares - shares;
            Ok(())
        }
    "#;

    let analyzer = ProgramAnalyzer::from_source(code)
        .expect("Should parse source");

    let deposit_logic = analyzer.extract_instruction_logic("handle_deposit");

    println!("\n=== Instruction Logic ===");
    if let Some(logic) = &deposit_logic {
        println!("Function: {}", logic.name);
        println!("Statements: {}", logic.statements.len());
    }

    assert!(
        deposit_logic.is_some(),
        "Should extract handle_deposit instruction logic"
    );

    let withdraw_logic = analyzer.extract_instruction_logic("handle_withdraw");
    assert!(
        withdraw_logic.is_some(),
        "Should extract handle_withdraw instruction logic"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// False-Positive Suppression — prove safe code doesn't trigger
// ═══════════════════════════════════════════════════════════════════════════════

/// Safe Anchor code with Signer<'info> and has_one should NOT produce signer findings
#[test]
fn test_no_false_positive_on_safe_code() {
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

    let analyzer = ProgramAnalyzer::from_source(code)
        .expect("Should parse source");
    let findings = analyzer.scan_for_vulnerabilities();

    let signer_findings: Vec<_> = findings.iter()
        .filter(|f| f.vuln_type.to_lowercase().contains("signer")
            && f.function_name == "SafeWithdraw")
        .collect();

    assert!(
        signer_findings.is_empty(),
        "FALSE POSITIVE: Safe code with Signer<'info> + has_one was flagged: {:?}",
        signer_findings.iter().map(|f| &f.vuln_type).collect::<Vec<_>>()
    );
}
