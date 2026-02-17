//! Upgrade Authority Watcher
//!
//! Polls Solana program accounts at a configurable interval and detects
//! authority changes. When a change is detected, it records the event
//! in the indexer and sends alerts via configured webhooks.

use solana_client::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;
use std::time::Duration;
use tracing::{info, warn, error};

use crate::alerts::{Alert, AlertSender, AlertSeverity};
use crate::indexer::{AuthorityEventType, AuthorityEvent, AuthorityIndexer};

/// Configuration for the authority watcher
#[derive(Debug, Clone)]
pub struct WatcherConfig {
    /// RPC endpoint URL
    pub rpc_url: String,
    /// Programs to watch (base58 IDs)
    pub program_ids: Vec<String>,
    /// Polling interval in seconds
    pub poll_interval_secs: u64,
    /// Maximum number of poll cycles (0 = infinite)
    pub max_polls: u64,
}

impl Default for WatcherConfig {
    fn default() -> Self {
        Self {
            rpc_url: "https://api.mainnet-beta.solana.com".into(),
            program_ids: Vec::new(),
            poll_interval_secs: 30,
            max_polls: 0,
        }
    }
}

/// Authority watcher that polls programs and sends alerts
pub struct AuthorityWatcher {
    config: WatcherConfig,
    rpc_client: RpcClient,
    indexer: AuthorityIndexer,
    alert_sender: AlertSender,
}

/// Result of a single poll cycle
#[derive(Debug)]
pub struct PollResult {
    pub programs_checked: usize,
    pub changes_detected: usize,
    pub errors: Vec<String>,
}

impl AuthorityWatcher {
    pub fn new(config: WatcherConfig, alert_sender: AlertSender) -> Self {
        let rpc_client = RpcClient::new_with_timeout(
            config.rpc_url.clone(),
            Duration::from_secs(30),
        );

        Self {
            config,
            rpc_client,
            indexer: AuthorityIndexer::new(),
            alert_sender,
        }
    }

    /// Run the watcher loop for a specified number of cycles
    pub async fn run(&mut self) -> Result<(), String> {
        info!(
            "Starting authority watcher for {} programs, polling every {}s",
            self.config.program_ids.len(),
            self.config.poll_interval_secs
        );

        let max = if self.config.max_polls == 0 {
            u64::MAX
        } else {
            self.config.max_polls
        };

        for cycle in 0..max {
            info!("Poll cycle {}", cycle + 1);

            let result = self.poll_once().await;

            if result.changes_detected > 0 {
                info!(
                    "Detected {} authority changes in cycle {}",
                    result.changes_detected,
                    cycle + 1
                );
            }

            for err in &result.errors {
                warn!("Poll error: {}", err);
            }

            if cycle + 1 < max {
                tokio::time::sleep(Duration::from_secs(self.config.poll_interval_secs)).await;
            }
        }

        Ok(())
    }

    /// Execute a single poll cycle checking all watched programs
    pub async fn poll_once(&mut self) -> PollResult {
        let mut result = PollResult {
            programs_checked: 0,
            changes_detected: 0,
            errors: Vec::new(),
        };

        let program_ids = self.config.program_ids.clone();

        for pid in &program_ids {
            result.programs_checked += 1;

            let pubkey = match Pubkey::from_str(pid) {
                Ok(pk) => pk,
                Err(e) => {
                    result.errors.push(format!("Invalid pubkey {}: {}", pid, e));
                    continue;
                }
            };

            match self.check_program_authority(&pubkey, pid).await {
                Ok(changed) => {
                    if changed {
                        result.changes_detected += 1;
                    }
                }
                Err(e) => {
                    result.errors.push(format!("Error checking {}: {}", pid, e));
                }
            }
        }

        result
    }

    /// Check a single program's authority status
    async fn check_program_authority(
        &mut self,
        pubkey: &Pubkey,
        program_id: &str,
    ) -> Result<bool, String> {
        let account = self
            .rpc_client
            .get_account(pubkey)
            .map_err(|e| format!("RPC error: {}", e))?;

        let bpf_loader = Pubkey::from_str("BPFLoaderUpgradeab1e11111111111111111111111")
            .unwrap();

        let new_authority = if account.owner == bpf_loader && account.data.len() >= 36 {
            let authority_bytes = &account.data[4..36];
            let authority_key = Pubkey::new_from_array({
                let mut arr = [0u8; 32];
                arr.copy_from_slice(authority_bytes);
                arr
            });
            if authority_key == Pubkey::default() {
                None
            } else {
                Some(authority_key.to_string())
            }
        } else {
            None
        };

        // Check if state changed
        let change_type = self
            .indexer
            .check_state_change(program_id, new_authority.as_deref());

        if let Some(event_type) = change_type {
            let previous = self
                .indexer
                .get_current_authority(program_id)
                .and_then(|a| a.cloned());

            let now = chrono::Utc::now().to_rfc3339();

            // Record the event
            self.indexer.record_event(AuthorityEvent {
                program_id: program_id.to_string(),
                event_type: event_type.clone(),
                previous_authority: previous.clone(),
                new_authority: new_authority.clone(),
                detected_at: now.clone(),
                slot: None,
            });

            // Send alert (except for first-seen which is just registration)
            let (severity, title, message) = match &event_type {
                AuthorityEventType::AuthorityTransferred => (
                    AlertSeverity::Critical,
                    "🔄 Authority Transferred".to_string(),
                    format!(
                        "Upgrade authority for `{}` changed from `{}` to `{}`",
                        &program_id[..8.min(program_id.len())],
                        previous.as_deref().unwrap_or("unknown"),
                        new_authority.as_deref().unwrap_or("unknown")
                    ),
                ),
                AuthorityEventType::AuthorityRevoked => (
                    AlertSeverity::High,
                    "🔒 Authority Revoked".to_string(),
                    format!(
                        "Upgrade authority for `{}` has been revoked — program is now immutable.",
                        &program_id[..8.min(program_id.len())]
                    ),
                ),
                AuthorityEventType::ProgramUpgraded => (
                    AlertSeverity::Critical,
                    "⬆️ Program Upgraded".to_string(),
                    format!(
                        "Program `{}` was upgraded (new code deployed).",
                        &program_id[..8.min(program_id.len())]
                    ),
                ),
                AuthorityEventType::FirstSeen => (
                    AlertSeverity::Info,
                    "👁️ Program Registered".to_string(),
                    format!(
                        "Now monitoring program `{}`. Current authority: `{}`",
                        &program_id[..8.min(program_id.len())],
                        new_authority.as_deref().unwrap_or("none (immutable)")
                    ),
                ),
            };

            let alert = Alert {
                severity,
                title,
                message,
                program_id: program_id.to_string(),
                timestamp: now,
                details: serde_json::json!({
                    "event_type": format!("{:?}", event_type),
                    "previous_authority": previous,
                    "new_authority": new_authority,
                }),
            };

            // Only send webhook alerts for real changes (not first-seen)
            if event_type != AuthorityEventType::FirstSeen {
                let results = self.alert_sender.send(&alert).await;
                for (i, res) in results.iter().enumerate() {
                    if let Err(e) = res {
                        error!("Webhook {} failed: {}", i, e);
                    }
                }
            }

            return Ok(true);
        }

        Ok(false)
    }

    /// Get the indexer for inspecting state
    pub fn indexer(&self) -> &AuthorityIndexer {
        &self.indexer
    }

    /// Get history for a program
    pub fn get_history(&self, program_id: &str) -> Vec<&AuthorityEvent> {
        self.indexer.get_history(program_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_watcher_config_default() {
        let config = WatcherConfig::default();
        assert_eq!(config.poll_interval_secs, 30);
        assert_eq!(config.max_polls, 0);
        assert!(config.program_ids.is_empty());
    }

    #[test]
    fn test_watcher_creation() {
        let config = WatcherConfig {
            program_ids: vec!["TestProg111".into()],
            max_polls: 1,
            ..Default::default()
        };
        let sender = AlertSender::new(vec![]);
        let watcher = AuthorityWatcher::new(config, sender);
        assert_eq!(watcher.indexer().tracked_count(), 0);
    }
}
