//! Shared helper functions used across CLI commands.

use std::path::Path;
use crate::tui;

/// Count findings by severity level.
pub fn severity_counts(f: &[program_analyzer::VulnerabilityFinding]) -> (usize, usize, usize, usize) {
    let c = f.iter().filter(|x| x.severity >= 5).count();
    let h = f.iter().filter(|x| x.severity == 4).count();
    let m = f.iter().filter(|x| x.severity == 3).count();
    let l = f.iter().filter(|x| x.severity <= 2).count();
    (c, h, m, l)
}

/// Compute a letter grade from a numeric score.
pub fn compute_grade(score: u8) -> &'static str {
    match score {
        95..=100 => "A+", 90..=94 => "A", 85..=89 => "A-", 80..=84 => "B+",
        75..=79 => "B", 70..=74 => "B-", 65..=69 => "C+", 60..=64 => "C",
        50..=59 => "D", _ => "F",
    }
}

/// Build engine result summaries for the TUI dashboard.
pub fn build_engine_results(findings: &[program_analyzer::VulnerabilityFinding]) -> Vec<tui::EngineResult> {
    let count = |pred: &dyn Fn(&str) -> bool| findings.iter().filter(|f| pred(&f.id)).count();
    vec![
        tui::EngineResult { name: "Pattern Scanner", desc: "72 heuristic rules", color: (239,68,68),
            findings: count(&|id: &str| !id.starts_with("SOL-TAINT") && !id.starts_with("SOL-CFG") && !id.starts_with("SOL-ABS") && !id.starts_with("SOL-ALIAS") && !id.starts_with("SOL-DEEP")) },
        tui::EngineResult { name: "Deep AST Scanner", desc: "syn::Visit", color: (168,85,247),
            findings: count(&|id: &str| id.starts_with("SOL-DEEP")) },
        tui::EngineResult { name: "Taint Lattice", desc: "information flow", color: (234,179,8),
            findings: count(&|id: &str| id.starts_with("SOL-TAINT")) },
        tui::EngineResult { name: "CFG Dominators", desc: "graph proofs", color: (6,182,212),
            findings: count(&|id: &str| id.starts_with("SOL-CFG")) },
        tui::EngineResult { name: "Abstract Interp", desc: "interval ℤ", color: (34,197,94),
            findings: count(&|id: &str| id.starts_with("SOL-ABS")) },
        tui::EngineResult { name: "Account Aliasing", desc: "must-not-alias", color: (59,130,246),
            findings: count(&|id: &str| id.starts_with("SOL-ALIAS")) },
    ]
}

/// Recursively collect all `.rs` source files from a directory into a buffer.
pub fn collect_rs(dir: &Path, buf: &mut String) {
    let entries = match std::fs::read_dir(dir) { Ok(e) => e, Err(_) => return };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            let n = p.file_name().unwrap_or_default().to_str().unwrap_or("");
            if n != "target" && n != ".git" { collect_rs(&p, buf); }
        } else if p.extension().map_or(false, |e| e == "rs") {
            if let Ok(c) = std::fs::read_to_string(&p) { buf.push_str(&c); buf.push('\n'); }
        }
    }
}
