//! Consensus Engine for Multi-LLM Verification
//!
//! Uses multiple LLMs to verify vulnerability findings through voting.
//! Reduces false positives by requiring agreement between models.

use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Verdict from a single LLM on a finding
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Verdict {
    Confirmed,
    Rejected,
    Uncertain,
}

/// A vote from a specific LLM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmVote {
    pub model: String,
    pub verdict: Verdict,
    pub confidence: f32,
    pub reasoning: String,
}

/// Consensus result after all LLMs have voted
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusResult {
    pub finding_id: String,
    pub final_verdict: Verdict,
    pub votes: Vec<LlmVote>,
    pub agreement_ratio: f32,
    pub confidence_score: f32,
    pub should_report: bool,
}

/// Configuration for a participating LLM
#[derive(Debug, Clone)]
pub struct LlmConfig {
    pub name: String,
    pub provider: LlmProvider,
    pub api_key: String,
    pub model_id: String,
    pub weight: f32,
}

#[derive(Debug, Clone)]
pub enum LlmProvider {
    OpenRouter,
    OpenAI,
    Anthropic,
    Nvidia,
}

/// Main consensus engine
pub struct ConsensusEngine {
    client: Client,
    models: Vec<LlmConfig>,
    threshold: f32,
    pub require_majority: bool,
}

impl ConsensusEngine {
    /// Create a new consensus engine with given LLM configurations
    pub fn new(models: Vec<LlmConfig>) -> Self {
        Self {
            client: Client::new(),
            models,
            threshold: 0.6,
            require_majority: true,
        }
    }

    /// Create with default OpenRouter models
    pub fn with_openrouter(api_key: &str) -> Self {
        let models = vec![
            LlmConfig {
                name: "Claude Sonnet".to_string(),
                provider: LlmProvider::OpenRouter,
                api_key: api_key.to_string(),
                model_id: "anthropic/claude-sonnet-4".to_string(),
                weight: 1.0,
            },
            LlmConfig {
                name: "GPT-4".to_string(),
                provider: LlmProvider::OpenRouter,
                api_key: api_key.to_string(),
                model_id: "openai/gpt-4o".to_string(),
                weight: 1.0,
            },
            LlmConfig {
                name: "Gemini Pro".to_string(),
                provider: LlmProvider::OpenRouter,
                api_key: api_key.to_string(),
                model_id: "google/gemini-2.0-flash-001".to_string(),
                weight: 0.8,
            },
        ];
        Self::new(models)
    }

    /// Set the agreement threshold (0.0 - 1.0)
    pub fn with_threshold(mut self, threshold: f32) -> Self {
        self.threshold = threshold.clamp(0.0, 1.0);
        self
    }

    /// Build the verification prompt for a finding
    fn build_prompt(&self, finding: &FindingForConsensus) -> String {
        format!(
            r#"You are a Solana security expert. Analyze this vulnerability finding and determine if it is a TRUE POSITIVE or FALSE POSITIVE.

## Vulnerability Report

**Type:** {}
**Severity:** {}
**Location:** {} in function `{}`
**Line:** {}

**Description:** {}

**Attack Scenario:** {}

**Vulnerable Code:**
```rust
{}
```

**Suggested Fix:** {}

## Your Task

Analyze this finding and respond with EXACTLY one of these verdicts:

1. **CONFIRMED** - This is a real vulnerability that needs to be fixed
2. **REJECTED** - This is a false positive (explain why the code is actually safe)
3. **UNCERTAIN** - Cannot determine without more context

Respond in this exact JSON format:
```json
{{
  "verdict": "CONFIRMED" | "REJECTED" | "UNCERTAIN",
  "confidence": 0.0-1.0,
  "reasoning": "Brief explanation of your decision"
}}
```"#,
            finding.vuln_type,
            finding.severity,
            finding.location,
            finding.function_name,
            finding.line_number,
            finding.description,
            finding.attack_scenario,
            finding.vulnerable_code,
            finding.secure_fix
        )
    }

    /// Query a single LLM for its verdict
    async fn query_llm(&self, config: &LlmConfig, prompt: &str) -> Result<LlmVote, ConsensusError> {
        let url = match config.provider {
            LlmProvider::OpenRouter => "https://openrouter.ai/api/v1/chat/completions",
            LlmProvider::OpenAI => "https://api.openai.com/v1/chat/completions",
            LlmProvider::Anthropic => "https://api.anthropic.com/v1/messages",
            LlmProvider::Nvidia => "https://integrate.api.nvidia.com/v1/chat/completions",
        };

        let request_body = serde_json::json!({
            "model": config.model_id,
            "messages": [
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.1,
            "max_tokens": 500
        });

        let response = self
            .client
            .post(url)
            .header("Authorization", format!("Bearer {}", config.api_key))
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await
            .map_err(|e| ConsensusError::NetworkError(e.to_string()))?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(ConsensusError::ApiError(error_text));
        }

        let response_json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| ConsensusError::ParseError(e.to_string()))?;

        let content = response_json["choices"][0]["message"]["content"]
            .as_str()
            .ok_or_else(|| ConsensusError::ParseError("Missing content".to_string()))?;

        // Parse the JSON from the response
        let vote = self.parse_vote(content, &config.name)?;
        Ok(vote)
    }

    /// Parse the LLM's vote from its response
    fn parse_vote(&self, content: &str, model_name: &str) -> Result<LlmVote, ConsensusError> {
        // Try to extract JSON from the response
        let json_start = content.find('{');
        let json_end = content.rfind('}');

        let json_str = match (json_start, json_end) {
            (Some(start), Some(end)) if end >= start => &content[start..=end],
            _ => {
                return Err(ConsensusError::ParseError(
                    "No JSON found in response".to_string(),
                ))
            }
        };

        let parsed: serde_json::Value = serde_json::from_str(json_str)
            .map_err(|e| ConsensusError::ParseError(e.to_string()))?;

        let verdict_str = parsed["verdict"].as_str().unwrap_or("UNCERTAIN");
        let verdict = match verdict_str.to_uppercase().as_str() {
            "CONFIRMED" => Verdict::Confirmed,
            "REJECTED" => Verdict::Rejected,
            _ => Verdict::Uncertain,
        };

        let confidence = parsed["confidence"].as_f64().unwrap_or(0.5) as f32;
        let reasoning = parsed["reasoning"]
            .as_str()
            .unwrap_or("No reasoning provided")
            .to_string();

        Ok(LlmVote {
            model: model_name.to_string(),
            verdict,
            confidence,
            reasoning,
        })
    }

    /// Run consensus voting on a finding
    pub async fn verify_finding(
        &self,
        finding: &FindingForConsensus,
    ) -> Result<ConsensusResult, ConsensusError> {
        let prompt = self.build_prompt(finding);
        let mut votes = Vec::new();

        for config in &self.models {
            match self.query_llm(config, &prompt).await {
                Ok(vote) => votes.push(vote),
                Err(e) => {
                    eprintln!("Warning: {} failed to respond: {}", config.name, e);
                    // Continue with other models
                }
            }
        }

        if votes.is_empty() {
            return Err(ConsensusError::NoVotes);
        }

        self.compute_consensus(&finding.id, votes)
    }

    /// Compute the final consensus from all votes
    fn compute_consensus(
        &self,
        finding_id: &str,
        votes: Vec<LlmVote>,
    ) -> Result<ConsensusResult, ConsensusError> {
        let mut verdict_counts: HashMap<Verdict, f32> = HashMap::new();
        let mut total_weight = 0.0;
        let mut weighted_confidence = 0.0;

        for vote in &votes {
            let weight = self
                .models
                .iter()
                .find(|m| m.name == vote.model)
                .map(|m| m.weight)
                .unwrap_or(1.0);

            *verdict_counts.entry(vote.verdict.clone()).or_insert(0.0) += weight;
            total_weight += weight;
            weighted_confidence += vote.confidence * weight;
        }

        let confirmed = verdict_counts
            .get(&Verdict::Confirmed)
            .copied()
            .unwrap_or(0.0);
        let rejected = verdict_counts
            .get(&Verdict::Rejected)
            .copied()
            .unwrap_or(0.0);

        let agreement_ratio = if total_weight > 0.0 {
            confirmed.max(rejected) / total_weight
        } else {
            0.0
        };

        let confidence_score = if total_weight > 0.0 {
            weighted_confidence / total_weight
        } else {
            0.0
        };

        let final_verdict = if confirmed > rejected && agreement_ratio >= self.threshold {
            Verdict::Confirmed
        } else if rejected > confirmed && agreement_ratio >= self.threshold {
            Verdict::Rejected
        } else {
            Verdict::Uncertain
        };

        let should_report = final_verdict == Verdict::Confirmed && confidence_score >= 0.5;

        Ok(ConsensusResult {
            finding_id: finding_id.to_string(),
            final_verdict,
            votes,
            agreement_ratio,
            confidence_score,
            should_report,
        })
    }

    /// Verify multiple findings in batch
    pub async fn verify_findings_batch(
        &self,
        findings: &[FindingForConsensus],
    ) -> Vec<ConsensusResult> {
        let mut results = Vec::new();

        for finding in findings {
            match self.verify_finding(finding).await {
                Ok(result) => results.push(result),
                Err(e) => {
                    eprintln!("Failed to verify finding {}: {}", finding.id, e);
                }
            }
        }

        results
    }

    /// Filter findings to only include confirmed ones
    pub fn filter_confirmed<'a>(&self, results: &'a [ConsensusResult]) -> Vec<&'a ConsensusResult> {
        results.iter().filter(|r| r.should_report).collect()
    }

    /// Offline rule-based fallback when no API key is available.
    /// Uses heuristic rules instead of LLM queries.
    pub fn verify_finding_offline(&self, finding: &FindingForConsensus) -> ConsensusResult {
        let mut confidence: f32 = 0.5;
        let mut reasons = Vec::new();

        // Rule 1: High/Critical severity gets a boost
        let severity_upper = finding.severity.to_uppercase();
        if severity_upper == "CRITICAL" {
            confidence += 0.25;
            reasons.push("Critical severity".to_string());
        } else if severity_upper == "HIGH" {
            confidence += 0.15;
            reasons.push("High severity".to_string());
        }

        // Rule 2: Known dangerous vuln types
        let known_dangerous = [
            "missing signer", "missing owner", "integer overflow",
            "unchecked arithmetic", "arbitrary cpi", "reentrancy",
        ];
        let vt = finding.vuln_type.to_lowercase();
        if known_dangerous.iter().any(|kd| vt.contains(kd)) {
            confidence += 0.15;
            reasons.push(format!("Known dangerous pattern: {}", finding.vuln_type));
        }

        // Rule 3: Has concrete attack scenario
        if !finding.attack_scenario.is_empty() && finding.attack_scenario.len() > 20 {
            confidence += 0.05;
            reasons.push("Detailed attack scenario provided".to_string());
        }

        // Rule 4: Has vulnerable code snippet
        if !finding.vulnerable_code.is_empty() {
            confidence += 0.05;
            reasons.push("Vulnerable code identified".to_string());
        }

        confidence = confidence.clamp(0.0, 1.0);
        let verdict = if confidence >= 0.7 {
            Verdict::Confirmed
        } else if confidence <= 0.3 {
            Verdict::Rejected
        } else {
            Verdict::Uncertain
        };

        let should_report = verdict == Verdict::Confirmed && confidence >= 0.5;

        ConsensusResult {
            finding_id: finding.id.clone(),
            final_verdict: verdict.clone(),
            votes: vec![LlmVote {
                model: "offline-heuristic-v1".to_string(),
                verdict,
                confidence,
                reasoning: reasons.join("; "),
            }],
            agreement_ratio: 1.0,
            confidence_score: confidence,
            should_report,
        }
    }
}

/// Finding data structure for consensus verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingForConsensus {
    pub id: String,
    pub vuln_type: String,
    pub severity: String,
    pub location: String,
    pub function_name: String,
    pub line_number: usize,
    pub description: String,
    pub attack_scenario: String,
    pub vulnerable_code: String,
    pub secure_fix: String,
}

/// Errors during consensus process
#[derive(Debug, thiserror::Error)]
pub enum ConsensusError {
    #[error("Network error: {0}")]
    NetworkError(String),
    #[error("API error: {0}")]
    ApiError(String),
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("No votes received from any LLM")]
    NoVotes,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verdict_equality() {
        assert_eq!(Verdict::Confirmed, Verdict::Confirmed);
        assert_ne!(Verdict::Confirmed, Verdict::Rejected);
    }

    #[test]
    fn test_consensus_creation() {
        let engine = ConsensusEngine::new(vec![]);
        assert!(engine.models.is_empty());
    }

    #[test]
    fn test_threshold_clamping() {
        let engine = ConsensusEngine::new(vec![]).with_threshold(1.5);
        assert_eq!(engine.threshold, 1.0);

        let engine = ConsensusEngine::new(vec![]).with_threshold(-0.5);
        assert_eq!(engine.threshold, 0.0);
    }

    fn make_finding(severity: &str, vuln_type: &str) -> FindingForConsensus {
        FindingForConsensus {
            id: "SOL-001".to_string(),
            vuln_type: vuln_type.to_string(),
            severity: severity.to_string(),
            location: "lib.rs".to_string(),
            function_name: "transfer".to_string(),
            line_number: 42,
            description: "Missing signer check allows unauthorized transfers".to_string(),
            attack_scenario: "An attacker can call transfer without being the authority, draining funds from the vault.".to_string(),
            vulnerable_code: "pub fn transfer(ctx: Context<Transfer>, amount: u64) { ... }".to_string(),
            secure_fix: "Add signer check".to_string(),
        }
    }

    #[test]
    fn test_offline_fallback_confirms_critical_known_vuln() {
        let engine = ConsensusEngine::new(vec![]);
        let finding = make_finding("CRITICAL", "Missing Signer Check");
        let result = engine.verify_finding_offline(&finding);
        assert_eq!(result.final_verdict, Verdict::Confirmed);
        assert!(result.should_report, "critical + known vuln should be reported");
        assert!(result.confidence_score >= 0.7);
    }

    #[test]
    fn test_offline_fallback_uncertain_for_low_unknown() {
        let engine = ConsensusEngine::new(vec![]);
        let finding = make_finding("LOW", "Style Issue");
        let result = engine.verify_finding_offline(&finding);
        // Low severity + unknown type = uncertain
        assert_ne!(result.final_verdict, Verdict::Confirmed);
    }

    #[test]
    fn test_parse_vote_extracts_json() {
        let engine = ConsensusEngine::new(vec![]);
        let response = r#"Based on my analysis:
{"verdict": "CONFIRMED", "confidence": 0.9, "reasoning": "Real vulnerability"}
End of analysis."#;
        let vote = engine.parse_vote(response, "test-model").unwrap();
        assert_eq!(vote.verdict, Verdict::Confirmed);
        assert!((vote.confidence - 0.9).abs() < 0.01);
        assert_eq!(vote.model, "test-model");
    }

    #[test]
    fn test_build_prompt_includes_finding_details() {
        let engine = ConsensusEngine::new(vec![]);
        let finding = make_finding("HIGH", "Integer Overflow");
        let prompt = engine.build_prompt(&finding);
        assert!(prompt.contains("Integer Overflow"), "prompt should contain vuln type");
        assert!(prompt.contains("transfer"), "prompt should contain function name");
        assert!(prompt.contains("42"), "prompt should contain line number");
        assert!(prompt.contains("CONFIRMED"), "prompt should list verdict options");
    }

    #[test]
    fn test_compute_consensus_majority_confirmed() {
        let engine = ConsensusEngine::new(vec![
            LlmConfig {
                name: "a".to_string(),
                provider: LlmProvider::OpenRouter,
                api_key: String::new(),
                model_id: String::new(),
                weight: 1.0,
            },
            LlmConfig {
                name: "b".to_string(),
                provider: LlmProvider::OpenRouter,
                api_key: String::new(),
                model_id: String::new(),
                weight: 1.0,
            },
        ]);
        let votes = vec![
            LlmVote { model: "a".to_string(), verdict: Verdict::Confirmed, confidence: 0.9, reasoning: "yes".to_string() },
            LlmVote { model: "b".to_string(), verdict: Verdict::Confirmed, confidence: 0.8, reasoning: "yes".to_string() },
        ];
        let result = engine.compute_consensus("SOL-001", votes).unwrap();
        assert_eq!(result.final_verdict, Verdict::Confirmed);
        assert!(result.should_report);
        assert!(result.agreement_ratio >= 0.99);
    }

    #[test]
    fn test_filter_confirmed_only_reports() {
        let engine = ConsensusEngine::new(vec![]);
        let results = vec![
            ConsensusResult {
                finding_id: "a".to_string(),
                final_verdict: Verdict::Confirmed,
                votes: vec![],
                agreement_ratio: 1.0,
                confidence_score: 0.9,
                should_report: true,
            },
            ConsensusResult {
                finding_id: "b".to_string(),
                final_verdict: Verdict::Rejected,
                votes: vec![],
                agreement_ratio: 1.0,
                confidence_score: 0.9,
                should_report: false,
            },
        ];
        let confirmed = engine.filter_confirmed(&results);
        assert_eq!(confirmed.len(), 1);
        assert_eq!(confirmed[0].finding_id, "a");
    }
}
