//! Validation accuracy test — scan deliberately vulnerable programs and
//! verify the enterprise pipeline catches real bugs while eliminating
//! false positives on audited code.

use program_analyzer::ProgramAnalyzer;
use std::path::{Path, PathBuf};

fn scan_program(dir: &str) -> Vec<program_analyzer::VulnerabilityFinding> {
    let path = PathBuf::from(dir);
    if !path.exists() {
        eprintln!("  ⚠ Program not found: {}", dir);
        return vec![];
    }
    let analyzer = ProgramAnalyzer::new(Path::new(dir))
        .expect("Should parse program directory");
    analyzer.scan_for_vulnerabilities()
}

fn scan_raw(dir: &str) -> Vec<program_analyzer::VulnerabilityFinding> {
    let path = PathBuf::from(dir);
    if !path.exists() {
        return vec![];
    }
    let analyzer = ProgramAnalyzer::new(Path::new(dir))
        .expect("Should parse program directory");
    analyzer.scan_for_vulnerabilities_raw()
}


fn main() {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║     ENTERPRISE VALIDATION ACCURACY TEST                    ║");
    println!("║     Proving: catches real vulns, ignores audited code      ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    // ── 1. Raydium CP-Swap (audited, should have ZERO findings) ─────────
    println!("━━━ TEST 1: Raydium CP-Swap (audited by OtterSec) ━━━");
    let raydium_dir = "/tmp/raydium-cp-swap/programs/cp-swap";
    let raydium_raw = scan_raw(raydium_dir);
    let raydium_validated = scan_program(raydium_dir);
    println!("  Raw findings:       {}", raydium_raw.len());
    println!("  Validated findings: {}", raydium_validated.len());
    println!("  FP reduction:       {}%", if raydium_raw.len() > 0 {
        100 - (raydium_validated.len() * 100 / raydium_raw.len())
    } else { 0 });
    let raydium_pass = raydium_validated.is_empty();
    println!("  Result: {}", if raydium_pass { "✅ PASS — zero false positives" } else { "❌ FAIL — still has false positives" });
    for f in &raydium_validated {
        println!("    ⚠ [{} {}] {} @ {}::{}", f.severity_label, f.id, f.vuln_type, f.location, f.function_name);
    }

    // ── 2. Vulnerable Vault (deliberately broken, should catch vulns) ───
    println!("\n━━━ TEST 2: Vulnerable Vault (deliberately broken) ━━━");
    let vault_findings = scan_program("programs/vulnerable-vault");
    println!("  Validated findings: {}", vault_findings.len());
    for f in &vault_findings {
        println!("    🔴 [{} {}] {} (conf: {}%) @ {}", f.severity_label, f.id, f.vuln_type, f.confidence, f.function_name);
    }
    let vault_pass = vault_findings.len() >= 2;
    println!("  Result: {}", if vault_pass { "✅ PASS — caught real vulnerabilities" } else { "❌ FAIL — missed vulnerabilities" });

    // ── 3. Vulnerable Token (deliberately broken, should catch vulns) ───
    println!("\n━━━ TEST 3: Vulnerable Token (deliberately broken) ━━━");
    let token_findings = scan_program("programs/vulnerable-token");
    println!("  Validated findings: {}", token_findings.len());
    for f in &token_findings {
        println!("    🔴 [{} {}] {} (conf: {}%) @ {}", f.severity_label, f.id, f.vuln_type, f.confidence, f.function_name);
    }
    let token_pass = token_findings.len() >= 2;
    println!("  Result: {}", if token_pass { "✅ PASS — caught real vulnerabilities" } else { "❌ FAIL — missed vulnerabilities" });

    // ── 4. Vulnerable Staking (deliberately broken, should catch vulns) ─
    println!("\n━━━ TEST 4: Vulnerable Staking (deliberately broken) ━━━");
    let staking_findings = scan_program("programs/vulnerable-staking");
    println!("  Validated findings: {}", staking_findings.len());
    for f in &staking_findings {
        println!("    🔴 [{} {}] {} (conf: {}%) @ {}", f.severity_label, f.id, f.vuln_type, f.confidence, f.function_name);
    }
    let staking_pass = staking_findings.len() >= 2;
    println!("  Result: {}", if staking_pass { "✅ PASS — caught real vulnerabilities" } else { "❌ FAIL — missed vulnerabilities" });

    // ── Summary ────────────────────────────────────────────────────────
    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║                     ACCURACY SUMMARY                       ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    let all_pass = raydium_pass && vault_pass && token_pass && staking_pass;
    println!("║  Raydium (audited):      {} Zero false positives           ║",
        if raydium_pass { "✅" } else { "❌" });
    println!("║  Vulnerable Vault:       {} Real vulns detected            ║",
        if vault_pass { "✅" } else { "❌" });
    println!("║  Vulnerable Token:       {} Real vulns detected            ║",
        if token_pass { "✅" } else { "❌" });
    println!("║  Vulnerable Staking:     {} Real vulns detected            ║",
        if staking_pass { "✅" } else { "❌" });
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║  Overall:                {} Enterprise-grade accuracy      ║",
        if all_pass { "✅" } else { "❌" });
    println!("╚══════════════════════════════════════════════════════════════╝");
}
