//! Authority Change Indexer
//!
//! Tracks historical authority changes for Solana programs,
//! building a timeline of upgrade authority events.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A recorded authority change event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorityEvent {
    /// Program ID this event is for
    pub program_id: String,
    /// Type of event
    pub event_type: AuthorityEventType,
    /// Previous authority (if known)
    pub previous_authority: Option<String>,
    /// New authority (None = revoked)
    pub new_authority: Option<String>,
    /// When the event was detected (ISO 8601)
    pub detected_at: String,
    /// Optional slot number
    pub slot: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthorityEventType {
    /// Authority was transferred to a new address
    AuthorityTransferred,
    /// Authority was revoked (set to None) — program is now immutable
    AuthorityRevoked,
    /// Program was first seen (initial registration)
    FirstSeen,
    /// Program was upgraded (new code deployed)
    ProgramUpgraded,
}

/// In-memory index of authority history
pub struct AuthorityIndexer {
    /// events indexed by program_id
    events: HashMap<String, Vec<AuthorityEvent>>,
    /// current known state: program_id -> current authority
    current_state: HashMap<String, Option<String>>,
}

impl AuthorityIndexer {
    pub fn new() -> Self {
        Self {
            events: HashMap::new(),
            current_state: HashMap::new(),
        }
    }

    /// Record an authority change event
    pub fn record_event(&mut self, event: AuthorityEvent) {
        // Update current state
        self.current_state
            .insert(event.program_id.clone(), event.new_authority.clone());

        // Append to history
        self.events
            .entry(event.program_id.clone())
            .or_insert_with(Vec::new)
            .push(event);
    }

    /// Get the full history for a program
    pub fn get_history(&self, program_id: &str) -> Vec<&AuthorityEvent> {
        self.events
            .get(program_id)
            .map(|events| events.iter().collect())
            .unwrap_or_default()
    }

    /// Get the current known authority for a program
    pub fn get_current_authority(&self, program_id: &str) -> Option<Option<&String>> {
        self.current_state.get(program_id).map(|a| a.as_ref())
    }

    /// Check if a state change occurred (returns the change event if so)
    pub fn check_state_change(
        &self,
        program_id: &str,
        new_authority: Option<&str>,
    ) -> Option<AuthorityEventType> {
        match self.current_state.get(program_id) {
            Some(current) => {
                let current_str = current.as_deref();
                if current_str != new_authority {
                    if new_authority.is_none() {
                        Some(AuthorityEventType::AuthorityRevoked)
                    } else {
                        Some(AuthorityEventType::AuthorityTransferred)
                    }
                } else {
                    None
                }
            }
            None => Some(AuthorityEventType::FirstSeen),
        }
    }

    /// Get number of tracked programs
    pub fn tracked_count(&self) -> usize {
        self.current_state.len()
    }

    /// Get all programs with active (non-revoked) authorities
    pub fn programs_with_active_authority(&self) -> Vec<(&String, &String)> {
        self.current_state
            .iter()
            .filter_map(|(pid, auth)| {
                auth.as_ref().map(|a| (pid, a))
            })
            .collect()
    }

    /// Export full index as JSON
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(&self.events).unwrap_or_default()
    }
}

impl Default for AuthorityIndexer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_indexer_creation() {
        let indexer = AuthorityIndexer::new();
        assert_eq!(indexer.tracked_count(), 0);
    }

    #[test]
    fn test_record_and_retrieve() {
        let mut indexer = AuthorityIndexer::new();

        indexer.record_event(AuthorityEvent {
            program_id: "Prog111".into(),
            event_type: AuthorityEventType::FirstSeen,
            previous_authority: None,
            new_authority: Some("Auth111".into()),
            detected_at: "2025-01-01T00:00:00Z".into(),
            slot: Some(100),
        });

        assert_eq!(indexer.tracked_count(), 1);
        assert_eq!(indexer.get_history("Prog111").len(), 1);
        assert_eq!(
            indexer.get_current_authority("Prog111"),
            Some(Some(&"Auth111".to_string()))
        );
    }

    #[test]
    fn test_detect_authority_transfer() {
        let mut indexer = AuthorityIndexer::new();

        indexer.record_event(AuthorityEvent {
            program_id: "Prog111".into(),
            event_type: AuthorityEventType::FirstSeen,
            previous_authority: None,
            new_authority: Some("Auth111".into()),
            detected_at: "2025-01-01T00:00:00Z".into(),
            slot: None,
        });

        // Same authority — no change
        assert!(indexer.check_state_change("Prog111", Some("Auth111")).is_none());

        // Different authority — transfer
        assert_eq!(
            indexer.check_state_change("Prog111", Some("Auth222")),
            Some(AuthorityEventType::AuthorityTransferred)
        );

        // None — revocation
        assert_eq!(
            indexer.check_state_change("Prog111", None),
            Some(AuthorityEventType::AuthorityRevoked)
        );
    }

    #[test]
    fn test_first_seen_detection() {
        let indexer = AuthorityIndexer::new();
        assert_eq!(
            indexer.check_state_change("Unknown111", Some("Auth111")),
            Some(AuthorityEventType::FirstSeen)
        );
    }

    #[test]
    fn test_active_authority_listing() {
        let mut indexer = AuthorityIndexer::new();

        indexer.record_event(AuthorityEvent {
            program_id: "Active111".into(),
            event_type: AuthorityEventType::FirstSeen,
            previous_authority: None,
            new_authority: Some("Auth111".into()),
            detected_at: "2025-01-01".into(),
            slot: None,
        });

        indexer.record_event(AuthorityEvent {
            program_id: "Revoked222".into(),
            event_type: AuthorityEventType::AuthorityRevoked,
            previous_authority: Some("Auth222".into()),
            new_authority: None,
            detected_at: "2025-01-01".into(),
            slot: None,
        });

        let active = indexer.programs_with_active_authority();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].0, "Active111");
    }
}
