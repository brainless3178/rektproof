//! Report Formatting
//!
//! Pretty-prints guard scan results for CLI output with colored severity indicators.

use colored::Colorize;
use crate::{GuardReport, GuardSeverity, FindingCategory};

impl GuardReport {
    /// Print a colored summary to stdout.
    pub fn print_colored(&self) {
        println!();
        println!("{}", "╔══════════════════════════════════════════════════════════════╗".cyan());
        println!("{}", "║           🛡️  SHANON GUARD — Dependency Firewall            ║".cyan());
        println!("{}", "╚══════════════════════════════════════════════════════════════╝".cyan());
        println!();

        if self.is_clean() {
            println!(
                "  {} All dependencies are clean — no known threats detected.",
                "✅".green()
            );
            println!();
            self.print_stats();
            return;
        }

        // Group findings by severity
        let critical: Vec<_> = self
            .all_findings()
            .filter(|f| f.severity == GuardSeverity::Critical)
            .collect();
        let high: Vec<_> = self
            .all_findings()
            .filter(|f| f.severity == GuardSeverity::High)
            .collect();
        let medium: Vec<_> = self
            .all_findings()
            .filter(|f| f.severity == GuardSeverity::Medium)
            .collect();
        let low: Vec<_> = self
            .all_findings()
            .filter(|f| f.severity == GuardSeverity::Low)
            .collect();

        if !critical.is_empty() {
            println!(
                "  {} {} CRITICAL {}",
                "🚨".red(),
                critical.len(),
                "— IMMEDIATE ACTION REQUIRED".red().bold()
            );
            for f in &critical {
                println!();
                println!(
                    "    {} {} {}",
                    "CRITICAL".on_red().white().bold(),
                    &f.package_name.red().bold(),
                    format!("({})", f.version).dimmed()
                );
                println!("    {}", f.title.red());
                println!("    {}", f.description.dimmed());
                println!("    {} {}", "Fix:".yellow().bold(), f.remediation);
                if let Some(ref r) = f.reference {
                    println!("    {} {}", "Ref:".dimmed(), r);
                }
            }
            println!();
        }

        if !high.is_empty() {
            println!("  {} {} HIGH", "⚠️ ".yellow(), high.len());
            for f in &high {
                println!();
                println!(
                    "    {} {} {}",
                    "HIGH".on_yellow().black().bold(),
                    &f.package_name.yellow().bold(),
                    format!("({})", f.version).dimmed()
                );
                println!("    {}", f.title);
                println!("    {}", f.description.dimmed());
                println!("    {} {}", "Fix:".yellow().bold(), f.remediation);
            }
            println!();
        }

        if !medium.is_empty() {
            println!("  {} {} MEDIUM", "ℹ️ ".blue(), medium.len());
            for f in &medium {
                println!(
                    "    {} {} — {}",
                    "MEDIUM".blue(),
                    f.package_name,
                    f.title
                );
            }
            println!();
        }

        if !low.is_empty() {
            println!("  {} {} LOW", "📝", low.len());
            for f in &low {
                println!(
                    "    {} {} — {}",
                    "LOW".dimmed(),
                    f.package_name,
                    f.title
                );
            }
            println!();
        }

        self.print_stats();

        // Exit code hint
        if !critical.is_empty() {
            println!();
            println!(
                "  {} {}",
                "EXIT CODE: 1".red().bold(),
                "— Critical vulnerabilities detected, failing CI gate."
                    .red()
            );
        }
    }

    fn print_stats(&self) {
        println!("{}", "─".repeat(60).dimmed());
        println!(
            "  Scanned: {} Cargo deps, {} npm deps, {} behavioral checks",
            self.cargo_findings.len()
                + self
                    .npm_findings
                    .len()
                    .saturating_sub(self.behavioral_findings.len()),
            self.npm_findings.len(),
            self.behavioral_findings.len()
        );
        println!("  Risk Score: {}/100", self.risk_score);
        println!("{}", "─".repeat(60).dimmed());
    }

    /// Serialize to JSON for CI/API consumption.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".into())
    }
}

impl std::fmt::Display for GuardSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Critical => write!(f, "critical"),
            Self::High => write!(f, "high"),
            Self::Medium => write!(f, "medium"),
            Self::Low => write!(f, "low"),
        }
    }
}

impl std::fmt::Display for FindingCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KnownMalicious => write!(f, "Known Malicious"),
            Self::Typosquat => write!(f, "Typosquat"),
            Self::SuspiciousBehavior => write!(f, "Suspicious Behavior"),
            Self::SuspiciousSource => write!(f, "Suspicious Source"),
            Self::KnownVulnerability => write!(f, "Known Vulnerability"),
            Self::Deprecated => write!(f, "Deprecated"),
        }
    }
}
