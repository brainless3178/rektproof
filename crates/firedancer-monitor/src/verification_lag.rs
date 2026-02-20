//! Verification Lag Detector
//!
//! Detects delays between transaction inclusion and verification.
//! Firedancer aims to minimize this lag for faster finality.

use crate::report::{FiredancerFinding, FiredancerIssue, FiredancerSeverity};
use sha2::{Digest, Sha256};
use solana_client::rpc_client::RpcClient;

pub struct VerificationLagDetector {
    threshold_ms: u64,
}

impl VerificationLagDetector {
    pub fn new(threshold_ms: u64) -> Self {
        Self { threshold_ms }
    }

    pub async fn detect_lag(
        &self,
        rpc_client: &RpcClient,
    ) -> Result<Vec<FiredancerFinding>, anyhow::Error> {
        let mut findings = Vec::new();

        // Get current slot
        let slot = rpc_client.get_slot()?;

        // Measure verification lag from consecutive block timestamps
        let measured_lag_ms = self.measure_verification_lag(rpc_client, slot)?;

        if measured_lag_ms > self.threshold_ms {
            let severity = if measured_lag_ms > self.threshold_ms * 3 {
                FiredancerSeverity::Critical
            } else if measured_lag_ms > self.threshold_ms * 2 {
                FiredancerSeverity::High
            } else {
                FiredancerSeverity::Medium
            };

            findings.push(FiredancerFinding {
                id: format!("FD-VLAG-{}", self.fingerprint(slot)),
                issue: FiredancerIssue::VerificationLag,
                severity,
                slot,
                timestamp: chrono::Utc::now().to_rfc3339(),
                description: format!(
                    "Verification lag detected: {}ms (threshold: {}ms)",
                    measured_lag_ms, self.threshold_ms
                ),
                measured_value: measured_lag_ms as f64,
                threshold_value: self.threshold_ms as f64,
                risk_explanation:
                    "High verification lag delays transaction finality and can cause \
                    consensus issues. Firedancer is designed to minimize this lag."
                        .to_string(),
                mitigation: "Monitor validator performance, check network connectivity, \
                    consider upgrading to Firedancer if using legacy validator."
                    .to_string(),
                validator_identity: None,
            });
        }

        Ok(findings)
    }

    fn measure_verification_lag(
        &self,
        rpc_client: &RpcClient,
        slot: u64,
    ) -> Result<u64, anyhow::Error> {
        // Measure real verification lag by comparing block timestamps
        // between consecutive confirmed slots.
        //
        // Solana targets ~400ms per slot. Lag is the delta between the
        // actual inter-block time and the expected slot time.

        // Fetch block times for the current and previous slot
        let current_time = rpc_client.get_block_time(slot);
        let prev_slot = slot.saturating_sub(1);
        let prev_time = rpc_client.get_block_time(prev_slot);

        match (current_time, prev_time) {
            (Ok(curr), Ok(prev)) => {
                // Block times are in Unix seconds; convert delta to milliseconds
                let delta_ms = ((curr - prev).unsigned_abs()) * 1000;

                // Expected slot time is 400ms; lag is the excess
                let expected_slot_ms = 400u64;
                let lag = delta_ms.saturating_sub(expected_slot_ms);
                Ok(lag.min(5000)) // Cap at 5s to avoid outlier skew
            }
            _ => {
                // Fallback: use performance samples if block times unavailable
                let recent_perf = rpc_client.get_recent_performance_samples(Some(1))?;
                if let Some(sample) = recent_perf.first() {
                    // Compute average slot time from sample period
                    if sample.num_slots > 0 {
                        let avg_slot_ms =
                            (sample.sample_period_secs as u64 * 1000) / sample.num_slots;
                        let lag = avg_slot_ms.saturating_sub(400);
                        Ok(lag.min(5000))
                    } else {
                        Ok(0)
                    }
                } else {
                    Ok(0)
                }
            }
        }
    }

    fn fingerprint(&self, slot: u64) -> String {
        let mut h = Sha256::new();
        h.update(b"verification_lag");
        h.update(slot.to_string().as_bytes());
        hex::encode(&h.finalize()[..8])
    }
}
