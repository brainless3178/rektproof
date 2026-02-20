//! # Phase Timing Infrastructure
//!
//! Records execution time and finding counts for each scanning phase.
//! Enables performance analysis, bottleneck detection, and per-phase
//! value assessment (findings-per-second metric).
//!
//! # Usage
//!
//! ```ignore
//! let mut timer = PhaseTimer::new();
//! timer.start("Pattern scanner");
//! // ... run phase ...
//! timer.stop("Pattern scanner", finding_count);
//! println!("{}", timer.report());
//! ```

use std::collections::BTreeMap;
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};

/// Tracks per-phase execution timing and finding counts.
#[derive(Debug, Clone)]
pub struct PhaseTimer {
    phases: BTreeMap<String, PhaseRecord>,
    active: Option<(String, Instant)>,
    overall_start: Instant,
}

/// Record for a single scanning phase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseRecord {
    /// Human-readable phase name
    pub name: String,
    /// Execution time
    pub duration_ms: u64,
    /// Number of raw findings produced
    pub findings_produced: usize,
    /// Number of errors encountered
    pub errors: Vec<String>,
    /// Whether the phase completed successfully
    pub completed: bool,
}

/// Summary of all phase timings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingReport {
    pub phases: Vec<PhaseRecord>,
    pub total_duration_ms: u64,
    pub total_findings: usize,
    pub slowest_phase: String,
    pub most_productive_phase: String,
}

impl PhaseTimer {
    /// Create a new phase timer.
    pub fn new() -> Self {
        Self {
            phases: BTreeMap::new(),
            active: None,
            overall_start: Instant::now(),
        }
    }

    /// Start timing a phase.
    pub fn start(&mut self, name: &str) {
        self.active = Some((name.to_string(), Instant::now()));
    }

    /// Stop timing the current phase and record results.
    pub fn stop(&mut self, name: &str, findings: usize) {
        if let Some((active_name, start)) = self.active.take() {
            let phase_name = if active_name == name { active_name } else { name.to_string() };
            let duration = start.elapsed();
            self.phases.insert(phase_name.clone(), PhaseRecord {
                name: phase_name,
                duration_ms: duration.as_millis() as u64,
                findings_produced: findings,
                errors: Vec::new(),
                completed: true,
            });
        }
    }

    /// Record a phase that completed with timing already measured.
    pub fn record(&mut self, name: &str, duration: Duration, findings: usize) {
        self.phases.insert(name.to_string(), PhaseRecord {
            name: name.to_string(),
            duration_ms: duration.as_millis() as u64,
            findings_produced: findings,
            errors: Vec::new(),
            completed: true,
        });
    }

    /// Record a phase error.
    pub fn record_error(&mut self, name: &str, error: String) {
        let entry = self.phases.entry(name.to_string()).or_insert_with(|| PhaseRecord {
            name: name.to_string(),
            duration_ms: 0,
            findings_produced: 0,
            errors: Vec::new(),
            completed: false,
        });
        entry.errors.push(error);
    }

    /// Generate a summary report.
    pub fn report(&self) -> TimingReport {
        let phases: Vec<PhaseRecord> = self.phases.values().cloned().collect();
        let total_duration = self.overall_start.elapsed().as_millis() as u64;
        let total_findings: usize = phases.iter().map(|p| p.findings_produced).sum();

        let slowest = phases.iter()
            .max_by_key(|p| p.duration_ms)
            .map(|p| p.name.clone())
            .unwrap_or_default();

        let most_productive = phases.iter()
            .max_by_key(|p| p.findings_produced)
            .map(|p| p.name.clone())
            .unwrap_or_default();

        TimingReport {
            phases,
            total_duration_ms: total_duration,
            total_findings,
            slowest_phase: slowest,
            most_productive_phase: most_productive,
        }
    }

    /// Format a human-readable timing table.
    pub fn format_table(&self) -> String {
        let report = self.report();
        let mut output = String::new();
        output.push_str("┌──────────────────────────────────────────┬──────────┬──────────┬────────┐\n");
        output.push_str("│ Phase                                    │ Time(ms) │ Findings │ Status │\n");
        output.push_str("├──────────────────────────────────────────┼──────────┼──────────┼────────┤\n");

        for phase in &report.phases {
            let status = if phase.errors.is_empty() { "  ✓ " } else { " ⚠️ " };
            output.push_str(&format!(
                "│ {:<40} │ {:>8} │ {:>8} │{status}│\n",
                truncate_str(&phase.name, 40),
                phase.duration_ms,
                phase.findings_produced,
            ));
        }

        output.push_str("├──────────────────────────────────────────┼──────────┼──────────┼────────┤\n");
        output.push_str(&format!(
            "│ {:<40} │ {:>8} │ {:>8} │      │\n",
            "TOTAL", report.total_duration_ms, report.total_findings
        ));
        output.push_str("└──────────────────────────────────────────┴──────────┴──────────┴────────┘\n");

        if !report.slowest_phase.is_empty() {
            output.push_str(&format!("  Slowest: {}\n", report.slowest_phase));
        }
        if !report.most_productive_phase.is_empty() {
            output.push_str(&format!("  Most productive: {}\n", report.most_productive_phase));
        }

        // Show errors
        for phase in &report.phases {
            for err in &phase.errors {
                output.push_str(&format!("  ⚠️  {}: {}\n", phase.name, err));
            }
        }

        output
    }
}

impl Default for PhaseTimer {
    fn default() -> Self {
        Self::new()
    }
}

fn truncate_str(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max - 1])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_phase_timer_basic() {
        let mut timer = PhaseTimer::new();
        timer.start("Phase 1");
        std::thread::sleep(Duration::from_millis(10));
        timer.stop("Phase 1", 5);

        let report = timer.report();
        assert_eq!(report.phases.len(), 1);
        assert_eq!(report.total_findings, 5);
        assert!(report.phases[0].duration_ms >= 5);
    }

    #[test]
    fn test_phase_timer_errors() {
        let mut timer = PhaseTimer::new();
        timer.record_error("Broken Phase", "Z3 timeout".to_string());

        let report = timer.report();
        assert_eq!(report.phases.len(), 1);
        assert!(!report.phases[0].completed);
        assert_eq!(report.phases[0].errors.len(), 1);
    }

    #[test]
    fn test_format_table() {
        let mut timer = PhaseTimer::new();
        timer.record("Pattern Scanner", Duration::from_millis(50), 10);
        timer.record("Taint Analysis", Duration::from_millis(120), 3);
        timer.record_error("FV Layer 1", "Kani not installed".to_string());

        let table = timer.format_table();
        assert!(table.contains("Pattern Scanner"));
        assert!(table.contains("Taint Analysis"));
        assert!(table.contains("TOTAL"));
    }

    #[test]
    fn test_report_serialization() {
        let mut timer = PhaseTimer::new();
        timer.record("Test", Duration::from_millis(100), 5);
        let report = timer.report();
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("Test"));
        let deser: TimingReport = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.total_findings, 5);
    }
}
