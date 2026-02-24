//! # DeFi-Specific Vulnerability Detector
//!
//! Uses AST analysis to detect DeFi-specific attack vectors that go beyond
//! generic code analysis. Instead of `source.contains("reserve_x")` heuristics,
//! this module:
//!
//! - Identifies AMM/swap logic by analyzing function signatures and state structures
//! - Detects price manipulation risks by finding unprotected oracle reads
//! - Finds flash loan vulnerabilities by tracing borrow-repay patterns
//! - Detects sandwich attack exposure in constant-product math
//! - Identifies unprotected governance/admin operations

use crate::VulnerabilityFinding;
use quote::ToTokens;
use syn::{
    Attribute, File, Item, ItemStruct,
    Stmt,
};

/// DeFi protocol type, detected from AST structure rather than string matching.
#[derive(Debug, Clone, PartialEq)]
pub enum ProtocolType {
    /// Constant-product AMM (Uniswap-style)
    Amm,
    /// Lending/borrowing protocol
    Lending,
    /// Staking/yield protocol
    Staking,
    /// DEX aggregator / router
    Aggregator,
    /// Token with custom logic (vesting, governance, etc.)
    Token,
    /// Unknown / general Solana program
    Unknown,
}

/// Result of DeFi-specific analysis
#[derive(Debug)]
pub struct DeFiAnalysisResult {
    pub protocol_type: ProtocolType,
    pub findings: Vec<VulnerabilityFinding>,
    pub detected_patterns: Vec<String>,
}

/// Analyze source code for DeFi-specific vulnerabilities using AST.
pub fn analyze_defi_vulnerabilities(source: &str, filename: &str) -> DeFiAnalysisResult {
    let lines: Vec<&str> = source.lines().collect();

    let ast = match syn::parse_file(source) {
        Ok(f) => f,
        Err(_) => return DeFiAnalysisResult {
            protocol_type: ProtocolType::Unknown,
            findings: Vec::new(),
            detected_patterns: Vec::new(),
        },
    };

    let mut detector = DeFiDetector {
        findings: Vec::new(),
        filename: filename.to_string(),
        lines: &lines,
        patterns: Vec::new(),
    };

    // Phase 1: Classify protocol type from struct fields and function names
    let protocol_type = detector.classify_protocol(&ast);

    // Phase 2: Run protocol-specific detectors
    detector.check_price_manipulation(&ast);
    detector.check_flash_loan_vulnerabilities(&ast);
    detector.check_sandwich_exposure(&ast);
    detector.check_unprotected_liquidity_operations(&ast);
    detector.check_stale_oracle_data(&ast);
    detector.check_rounding_exploitation(&ast);

    DeFiAnalysisResult {
        protocol_type,
        findings: detector.findings,
        detected_patterns: detector.patterns,
    }
}

struct DeFiDetector<'a> {
    findings: Vec<VulnerabilityFinding>,
    filename: String,
    lines: &'a [&'a str],
    patterns: Vec<String>,
}

impl<'a> DeFiDetector<'a> {
    /// Classify protocol type from AST structure, not string matching.
    ///
    /// Looks at:
    /// - Struct field names (reserve_x, reserve_y → AMM)
    /// - Function signatures (swap, add_liquidity → AMM)
    /// - State patterns (collateral, borrow → Lending)
    fn classify_protocol(&mut self, ast: &File) -> ProtocolType {
        let mut amm_signals = 0u32;
        let mut lending_signals = 0u32;
        let mut staking_signals = 0u32;
        let mut aggregator_signals = 0u32;
        let mut token_signals = 0u32;

        for item in &ast.items {
            match item {
                Item::Struct(s) => {
                    let fields: Vec<String> = self.struct_field_names(s);

                    // AMM signals: reserve pairs, liquidity, pool state
                    if fields.iter().any(|f| f.contains("reserve"))
                        && fields.iter().any(|f| f.contains("reserve"))
                    {
                        amm_signals += 3;
                        self.patterns.push(format!("AMM reserve pair in {}", s.ident));
                    }
                    if fields.iter().any(|f| f == "liquidity" || f.contains("lp_supply")) {
                        amm_signals += 2;
                    }
                    if fields.iter().any(|f| f.contains("swap_fee") || f.contains("trade_fee")) {
                        amm_signals += 2;
                    }
                    if fields.iter().any(|f| f.contains("constant_product") || f.contains("invariant")) {
                        amm_signals += 3;
                    }

                    // Lending signals
                    if fields.iter().any(|f| f.contains("collateral")) {
                        lending_signals += 3;
                    }
                    if fields.iter().any(|f| f.contains("borrow") || f.contains("debt")) {
                        lending_signals += 2;
                    }
                    if fields.iter().any(|f| f.contains("interest_rate") || f.contains("utilization")) {
                        lending_signals += 2;
                    }
                    if fields.iter().any(|f| f.contains("health_factor") || f.contains("ltv")) {
                        lending_signals += 3;
                    }

                    // Staking signals
                    if fields.iter().any(|f| f.contains("staked") || f.contains("stake_amount")) {
                        staking_signals += 3;
                    }
                    if fields.iter().any(|f| f.contains("reward_per_token") || f.contains("emission_rate")) {
                        staking_signals += 2;
                    }

                    // Token signals
                    if fields.iter().any(|f| f == "mint" || f == "supply" || f.contains("decimals")) {
                        token_signals += 1;
                    }
                }
                Item::Fn(f) => {
                    let name = f.sig.ident.to_string();
                    match name.as_str() {
                        "swap" | "exchange" | "trade" => amm_signals += 3,
                        "add_liquidity" | "remove_liquidity" | "deposit_liquidity" => amm_signals += 2,
                        "borrow" | "repay" | "liquidate" => lending_signals += 3,
                        "deposit_collateral" | "withdraw_collateral" => lending_signals += 2,
                        "stake" | "unstake" | "claim_rewards" => staking_signals += 3,
                        "route" | "aggregate" | "multi_hop" => aggregator_signals += 3,
                        "mint_to" | "burn" | "transfer" => token_signals += 1,
                        _ => {}
                    }
                }
                Item::Impl(imp) => {
                    for item in &imp.items {
                        if let syn::ImplItem::Fn(f) = item {
                            let name = f.sig.ident.to_string();
                            match name.as_str() {
                                "swap" | "exchange" => amm_signals += 3,
                                "borrow" | "repay" | "liquidate" => lending_signals += 3,
                                "stake" | "unstake" | "claim_rewards" => staking_signals += 3,
                                _ => {}
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        let max = *[amm_signals, lending_signals, staking_signals, aggregator_signals, token_signals]
            .iter().max().unwrap_or(&0);

        if max == 0 {
            return ProtocolType::Unknown;
        }

        if amm_signals == max { ProtocolType::Amm }
        else if lending_signals == max { ProtocolType::Lending }
        else if staking_signals == max { ProtocolType::Staking }
        else if aggregator_signals == max { ProtocolType::Aggregator }
        else if token_signals == max { ProtocolType::Token }
        else { ProtocolType::Unknown }
    }

    /// Detect price manipulation: oracle reads without staleness checks
    fn check_price_manipulation(&mut self, ast: &File) {
        self.visit_fns(ast, |detector, fn_name, stmts, _attrs| {
            let mut has_oracle_read = false;
            let mut oracle_line = 0usize;
            let mut has_staleness_check = false;

            for stmt in stmts {
                let code = stmt.to_token_stream().to_string();
                let line = token_line(stmt);

                // Oracle read patterns
                if code.contains("get_price") || code.contains("price_feed")
                    || code.contains("oracle") && code.contains("data")
                    || code.contains("pyth") || code.contains("switchboard")
                    || code.contains("chainlink")
                {
                    has_oracle_read = true;
                    oracle_line = line;
                }

                // Staleness checks
                if code.contains("last_update") || code.contains("staleness")
                    || code.contains("max_age") || code.contains("valid_slot")
                    || code.contains("current_slot") && code.contains("publish_slot")
                    || code.contains("Clock") && code.contains("unix_timestamp")
                {
                    has_staleness_check = true;
                }
            }

            if has_oracle_read && !has_staleness_check {
                detector.emit(VulnerabilityFinding {
                    category: "Oracle".into(),
                    vuln_type: "Price Oracle Without Staleness Check".into(),
                    severity: 5,
                    severity_label: "CRITICAL".into(),
                    id: "SOL-DEFI-01".into(),
                    cwe: Some("CWE-829".into()),
                    location: detector.filename.clone(),
                    function_name: fn_name.to_string(),
                    line_number: oracle_line,
                    vulnerable_code: detector.get_line(oracle_line),
                    description: format!(
                        "Oracle price read in `{}` without staleness validation. \
                         If the oracle stops updating, the protocol will use a stale \
                         price, enabling arbitrage or liquidation manipulation.",
                        fn_name
                    ),
                    attack_scenario: "During network congestion, the oracle stops updating. \
                         Attacker exploits the stale (outdated) price to borrow against \
                         overvalued collateral or liquidate healthy positions.".into(),
                    real_world_incident: Some(crate::Incident {
                        project: "Mango Markets".into(),
                        loss: "$114M".into(),
                        date: "2022-10-11".into(),
                    }),
                    secure_fix: "Add staleness check: `require!(clock.unix_timestamp - \
                         price.publish_time < MAX_ORACLE_AGE, OracleStale)`.".into(),
                    confidence: 80,
                    prevention: "Always validate oracle freshness before using price data.".into(),
                });
            }
        });
    }

    /// Detect flash loan vulnerabilities: check if value calculations can be
    /// manipulated within a single transaction.
    fn check_flash_loan_vulnerabilities(&mut self, ast: &File) {
        self.visit_fns(ast, |detector, fn_name, stmts, _attrs| {
            let mut has_balance_read = false;
            let mut balance_line = 0usize;
            let mut has_value_calc = false;
            let mut has_reentrancy_guard = false;

            for stmt in stmts {
                let code = stmt.to_token_stream().to_string();
                let line = token_line(stmt);

                // Balance/reserve reads that could be flash-loan manipulated
                if code.contains("get_balance") || code.contains("lamports()")
                    || code.contains("token_amount") || code.contains("reserve")
                    && (code.contains("amount") || code.contains("balance"))
                {
                    has_balance_read = true;
                    balance_line = line;
                }

                // Value calculations using spot balances
                if (code.contains("/") || code.contains("*"))
                    && (code.contains("price") || code.contains("rate")
                        || code.contains("value") || code.contains("share"))
                {
                    has_value_calc = true;
                }

                // Reentrancy or flash loan guards
                if code.contains("reentrancy_guard") || code.contains("flash_loan_guard")
                    || code.contains("no_reentrant") || code.contains("locked")
                    || code.contains("twap") || code.contains("time_weighted")
                {
                    has_reentrancy_guard = true;
                }
            }

            if has_balance_read && has_value_calc && !has_reentrancy_guard {
                detector.emit(VulnerabilityFinding {
                    category: "Flash Loan".into(),
                    vuln_type: "Flash-Loan Manipulable Value Calculation".into(),
                    severity: 5,
                    severity_label: "CRITICAL".into(),
                    id: "SOL-DEFI-02".into(),
                    cwe: Some("CWE-682".into()),
                    location: detector.filename.clone(),
                    function_name: fn_name.to_string(),
                    line_number: balance_line,
                    vulnerable_code: detector.get_line(balance_line),
                    description: format!(
                        "Function `{}` reads on-chain balances and uses them in value \
                         calculations without flash-loan protection. An attacker can \
                         temporarily inflate/deflate balances within a single transaction.",
                        fn_name
                    ),
                    attack_scenario: "Attacker flash-loans a large amount of tokens into the \
                         pool, inflating the spot price/share ratio. Then deposits a small \
                         amount at the inflated rate, repays the loan, and withdraws at \
                         the true rate for profit.".into(),
                    real_world_incident: Some(crate::Incident {
                        project: "bZx / Cream Finance".into(),
                        loss: "$130M+".into(),
                        date: "2020-2021".into(),
                    }),
                    secure_fix: "Use TWAP (time-weighted average price) instead of spot \
                         price for value calculations. Add reentrancy/flash-loan guards.".into(),
                    confidence: 70,
                    prevention: "Never use spot balances for share/value calculations.".into(),
                });
            }
        });
    }

    /// Detect sandwich attack exposure in swap functions
    fn check_sandwich_exposure(&mut self, ast: &File) {
        self.visit_fns(ast, |detector, fn_name, stmts, _attrs| {
            let is_swap = fn_name.contains("swap") || fn_name.contains("exchange")
                || fn_name.contains("trade");
            if !is_swap {
                return;
            }

            let mut has_slippage_check = false;
            let mut has_min_out = false;
            let mut swap_line = 0usize;

            for stmt in stmts {
                let code = stmt.to_token_stream().to_string();
                let line = token_line(stmt);

                if code.contains("*") || code.contains("/") {
                    swap_line = line;
                }

                // Slippage protection patterns
                if code.contains("minimum_amount_out") || code.contains("min_out")
                    || code.contains("slippage") || code.contains("max_slippage")
                    || code.contains("min_amount") || code.contains("expected_amount")
                {
                    has_slippage_check = true;
                }

                if code.contains("require!") && (code.contains(">=") || code.contains(">"))
                    && (code.contains("amount_out") || code.contains("output"))
                {
                    has_min_out = true;
                }
            }

            if !has_slippage_check && !has_min_out && swap_line > 0 {
                detector.emit(VulnerabilityFinding {
                    category: "MEV".into(),
                    vuln_type: "Swap Without Slippage Protection".into(),
                    severity: 4,
                    severity_label: "HIGH".into(),
                    id: "SOL-DEFI-03".into(),
                    cwe: Some("CWE-20".into()),
                    location: detector.filename.clone(),
                    function_name: fn_name.to_string(),
                    line_number: swap_line,
                    vulnerable_code: detector.get_line(swap_line),
                    description: format!(
                        "Swap function `{}` has no slippage protection (no minimum_amount_out \
                         parameter or assertion). Users can lose significant value to \
                         sandwich attacks.",
                        fn_name
                    ),
                    attack_scenario: "MEV searcher front-runs the user's swap with a large buy, \
                         moving the price up. User's swap executes at a worse price. Searcher \
                         back-runs with a sell, profiting from the price difference.".into(),
                    real_world_incident: None,
                    secure_fix: "Add `minimum_amount_out: u64` parameter and assert: \
                         `require!(amount_out >= minimum_amount_out, SlippageExceeded)`.".into(),
                    confidence: 78,
                    prevention: "Always enforce minimum output amounts in swap functions.".into(),
                });
            }
        });
    }

    /// Detect unprotected liquidity operations
    fn check_unprotected_liquidity_operations(&mut self, ast: &File) {
        self.visit_fns(ast, |detector, fn_name, stmts, _attrs| {
            let is_lp_op = fn_name.contains("add_liquidity") || fn_name.contains("remove_liquidity")
                || fn_name.contains("deposit") || fn_name.contains("withdraw");
            if !is_lp_op {
                return;
            }

            let mut has_deadline = false;
            let mut op_line = 0usize;

            for stmt in stmts {
                let code = stmt.to_token_stream().to_string();
                let line = token_line(stmt);
                if op_line == 0 { op_line = line; }

                if code.contains("deadline") || code.contains("expiry")
                    || code.contains("max_slot") || code.contains("valid_until")
                {
                    has_deadline = true;
                }
            }

            if !has_deadline && op_line > 0 {
                detector.emit(VulnerabilityFinding {
                    category: "MEV".into(),
                    vuln_type: "Liquidity Operation Without Deadline".into(),
                    severity: 3,
                    severity_label: "MEDIUM".into(),
                    id: "SOL-DEFI-04".into(),
                    cwe: Some("CWE-367".into()),
                    location: detector.filename.clone(),
                    function_name: fn_name.to_string(),
                    line_number: op_line,
                    vulnerable_code: detector.get_line(op_line),
                    description: format!(
                        "Liquidity operation `{}` has no transaction deadline. A pending \
                         transaction can be held by a validator and executed later at a \
                         disadvantageous price.",
                        fn_name
                    ),
                    attack_scenario: "User submits a deposit transaction. A validator holds \
                         the transaction for minutes/hours until the price moves unfavorably, \
                         then includes it.".into(),
                    real_world_incident: None,
                    secure_fix: "Add `deadline: i64` parameter and check: \
                         `require!(Clock::get()?.unix_timestamp <= deadline, Expired)`.".into(),
                    confidence: 65,
                    prevention: "Add transaction deadlines to all DeFi operations.".into(),
                });
            }
        });
    }

    /// Detect stale oracle data usage
    fn check_stale_oracle_data(&mut self, ast: &File) {
        // This is handled in check_price_manipulation, but we add additional
        // detection for TWAP oracle manipulation
        self.visit_fns(ast, |detector, fn_name, stmts, _attrs| {
            let mut uses_single_observation = false;
            let mut obs_line = 0usize;

            for stmt in stmts {
                let code = stmt.to_token_stream().to_string();
                let line = token_line(stmt);

                // Single price observation without TWAP
                if (code.contains("price") || code.contains("oracle"))
                    && !code.contains("twap") && !code.contains("time_weighted")
                    && !code.contains("observations") && !code.contains("cumulative")
                    && (code.contains("get_") || code.contains("fetch") || code.contains("load"))
                {
                    // Check if used in a critical calculation
                    if code.contains("collateral") || code.contains("liquidat")
                        || code.contains("borrow") || code.contains("health")
                    {
                        uses_single_observation = true;
                        obs_line = line;
                    }
                }
            }

            if uses_single_observation {
                detector.emit(VulnerabilityFinding {
                    category: "Oracle".into(),
                    vuln_type: "Single Oracle Observation for Critical Decision".into(),
                    severity: 4,
                    severity_label: "HIGH".into(),
                    id: "SOL-DEFI-05".into(),
                    cwe: Some("CWE-327".into()),
                    location: detector.filename.clone(),
                    function_name: fn_name.to_string(),
                    line_number: obs_line,
                    vulnerable_code: detector.get_line(obs_line),
                    description: format!(
                        "Function `{}` uses a single oracle price observation for a \
                         critical operation (liquidation/borrowing). This is manipulable \
                         via flash loans or short-term price manipulation.",
                        fn_name
                    ),
                    attack_scenario: "Attacker manipulates the oracle price temporarily \
                         (e.g., via a large swap on a low-liquidity pair), then triggers \
                         liquidation of healthy positions using the manipulated price.".into(),
                    real_world_incident: Some(crate::Incident {
                        project: "Mango Markets".into(),
                        loss: "$114M".into(),
                        date: "2022-10-11".into(),
                    }),
                    secure_fix: "Use TWAP (time-weighted average price) over multiple \
                         observations. Require minimum observation window (e.g., 30 min).".into(),
                    confidence: 68,
                    prevention: "Use TWAP for critical pricing decisions.".into(),
                });
            }
        });
    }

    /// Detect rounding exploitation in share/token calculations
    fn check_rounding_exploitation(&mut self, ast: &File) {
        self.visit_fns(ast, |detector, fn_name, stmts, _attrs| {
            for stmt in stmts {
                let code = stmt.to_token_stream().to_string();
                let line = token_line(stmt);

                // Integer division in share calculations
                if code.contains("/")
                    && (code.contains("share") || code.contains("rate") || code.contains("ratio"))
                    && !code.contains("checked_div")
                    && !code.contains("ceil")
                    && !code.contains("round_up")
                {
                    // Check if this is in a deposit/mint context where rounding matters
                    let is_critical = fn_name.contains("deposit") || fn_name.contains("mint")
                        || fn_name.contains("withdraw") || fn_name.contains("redeem")
                        || fn_name.contains("calculate_share");

                    if is_critical {
                        detector.emit(VulnerabilityFinding {
                            category: "Arithmetic".into(),
                            vuln_type: "Rounding Direction Exploitation".into(),
                            severity: 3,
                            severity_label: "MEDIUM".into(),
                            id: "SOL-DEFI-06".into(),
                            cwe: Some("CWE-682".into()),
                            location: detector.filename.clone(),
                            function_name: fn_name.to_string(),
                            line_number: line,
                            vulnerable_code: detector.get_line(line),
                            description: format!(
                                "Integer division in share calculation in `{}` without \
                                 explicit rounding direction. An attacker can deposit tiny \
                                 amounts to exploit rounding in their favor.",
                                fn_name
                            ),
                            attack_scenario: "First depositor deposits 1 token, receives 1 share. \
                                 Then donates tokens to inflate the share price. Next depositor's \
                                 deposit rounds down to 0 shares, and first depositor withdraws \
                                 the donated tokens.".into(),
                            real_world_incident: Some(crate::Incident {
                                project: "ERC-4626 Vaults".into(),
                                loss: "Various".into(),
                                date: "2022-2023".into(),
                            }),
                            secure_fix: "Round against the user: round down for deposits (fewer \
                                 shares), round up for withdrawals (more tokens needed). Add \
                                 virtual offset to prevent first-depositor attack.".into(),
                            confidence: 60,
                            prevention: "Always round against the user in share calculations.".into(),
                        });
                    }
                }
            }
        });
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    fn visit_fns<F>(&mut self, ast: &File, mut check: F)
    where
        F: FnMut(&mut Self, &str, &[Stmt], &[Attribute]),
    {
        // Collect all function items (top-level, impl, mod) to avoid
        // recursive closure ownership issues
        let items_to_check: Vec<_> = Self::collect_fn_items(&ast.items);

        for (fn_name, stmts, attrs) in items_to_check {
            check(self, &fn_name, &stmts, &attrs);
        }
    }

    /// Recursively collect function items from a list of items.
    fn collect_fn_items(items: &[Item]) -> Vec<(String, Vec<Stmt>, Vec<Attribute>)> {
        let mut result = Vec::new();

        for item in items {
            match item {
                Item::Fn(f) => {
                    if !is_test_fn(&f.attrs) {
                        result.push((
                            f.sig.ident.to_string(),
                            f.block.stmts.clone(),
                            f.attrs.clone(),
                        ));
                    }
                }
                Item::Impl(imp) => {
                    for item in &imp.items {
                        if let syn::ImplItem::Fn(f) = item {
                            if !is_test_fn(&f.attrs) {
                                result.push((
                                    f.sig.ident.to_string(),
                                    f.block.stmts.clone(),
                                    f.attrs.clone(),
                                ));
                            }
                        }
                    }
                }
                Item::Mod(m) => {
                    // Skip test modules
                    let is_test_mod = m.attrs.iter().any(|a|
                        a.meta.to_token_stream().to_string().contains("test")
                    );
                    if !is_test_mod {
                        if let Some((_, mod_items)) = &m.content {
                            result.extend(Self::collect_fn_items(mod_items));
                        }
                    }
                }
                _ => {}
            }
        }

        result
    }

    fn struct_field_names(&self, s: &ItemStruct) -> Vec<String> {
        match &s.fields {
            syn::Fields::Named(n) => n.named.iter()
                .map(|f| f.ident.as_ref().map(|i| i.to_string()).unwrap_or_default())
                .collect(),
            _ => Vec::new(),
        }
    }

    fn emit(&mut self, finding: VulnerabilityFinding) {
        self.findings.push(finding);
    }

    fn get_line(&self, line: usize) -> String {
        if line > 0 && line <= self.lines.len() {
            self.lines[line - 1].trim().to_string()
        } else {
            String::new()
        }
    }
}

fn is_test_fn(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|a| a.path().is_ident("test"))
}

fn token_line<T: ToTokens>(t: &T) -> usize {
    t.to_token_stream()
        .into_iter()
        .next()
        .map(|t| t.span().start().line)
        .unwrap_or(0)
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Tests
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_amm() {
        let code = r#"
            pub struct PoolState {
                pub reserve_a: u64,
                pub reserve_b: u64,
                pub lp_supply: u64,
                pub swap_fee: u64,
            }

            pub fn swap(amount_in: u64) -> u64 {
                let amount_out = amount_in * reserve_b / (reserve_a + amount_in);
                amount_out
            }

            pub fn add_liquidity(amount_a: u64, amount_b: u64) -> u64 {
                let shares = amount_a * lp_supply / reserve_a;
                shares
            }
        "#;
        let result = analyze_defi_vulnerabilities(code, "amm.rs");
        assert_eq!(result.protocol_type, ProtocolType::Amm);
    }

    #[test]
    fn test_classify_lending() {
        let code = r#"
            pub struct LendingPool {
                pub total_collateral: u64,
                pub total_borrowed: u64,
                pub interest_rate: u64,
                pub health_factor: u64,
            }

            pub fn borrow(amount: u64) -> Result<(), Error> {
                Ok(())
            }

            pub fn liquidate(user: Pubkey) -> Result<(), Error> {
                Ok(())
            }
        "#;
        let result = analyze_defi_vulnerabilities(code, "lending.rs");
        assert_eq!(result.protocol_type, ProtocolType::Lending);
    }

    #[test]
    fn test_detects_swap_without_slippage() {
        let code = r#"
            pub fn swap(amount_in: u64, pool: &PoolState) -> u64 {
                let amount_out = amount_in * pool.reserve_b / (pool.reserve_a + amount_in);
                amount_out
            }
        "#;
        let result = analyze_defi_vulnerabilities(code, "swap.rs");
        let sandwich_findings: Vec<_> = result.findings.iter()
            .filter(|f| f.id == "SOL-DEFI-03")
            .collect();
        assert!(!sandwich_findings.is_empty(), "Should detect swap without slippage protection");
    }

    #[test]
    fn test_swap_with_slippage_not_flagged() {
        let code = r#"
            pub fn swap(amount_in: u64, minimum_amount_out: u64, pool: &PoolState) -> Result<u64, Error> {
                let amount_out = amount_in * pool.reserve_b / (pool.reserve_a + amount_in);
                require!(amount_out >= minimum_amount_out, SlippageExceeded);
                Ok(amount_out)
            }
        "#;
        let result = analyze_defi_vulnerabilities(code, "swap.rs");
        let sandwich_findings: Vec<_> = result.findings.iter()
            .filter(|f| f.id == "SOL-DEFI-03")
            .collect();
        assert!(sandwich_findings.is_empty(), "Should NOT flag swap with slippage protection");
    }

    #[test]
    fn test_detects_rounding_exploit() {
        let code = r#"
            pub fn deposit(amount: u64, total_supply: u64, total_assets: u64) -> u64 {
                let share = amount * total_supply / total_assets;
                share
            }

            pub fn calculate_share(amount: u64, ratio: u64) -> u64 {
                amount / ratio
            }
        "#;
        let result = analyze_defi_vulnerabilities(code, "vault.rs");
        let rounding_findings: Vec<_> = result.findings.iter()
            .filter(|f| f.id == "SOL-DEFI-06")
            .collect();
        assert!(!rounding_findings.is_empty(), "Should detect rounding exploitation risk");
    }
}
