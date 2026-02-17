use futures_util::stream::{self, StreamExt};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{info, warn};

// ═══════════════════════════════════════════════════════════════════════════
//  NVIDIA NIM / Kimi K2.5 — Chat Completion API types
//  Docs: https://docs.api.nvidia.com/nim/reference/moonshotai-kimi-k2-5
// ═══════════════════════════════════════════════════════════════════════════

/// Chat completion request (NVIDIA NIM / OpenAI / OpenRouter compatible)
#[derive(Debug, Serialize)]
struct ChatCompletionRequest {
    model: String,
    messages: Vec<ChatMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    top_p: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_completion_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reasoning_budget: Option<u32>,
    /// Kimi K2.5 thinking mode: {"thinking": true}
    #[serde(skip_serializing_if = "Option::is_none")]
    chat_template_kwargs: Option<serde_json::Value>,
    /// Do NOT stream — we parse full JSON responses
    #[serde(skip_serializing_if = "Option::is_none")]
    stream: Option<bool>,
}

#[derive(Debug, Serialize)]
struct ChatMessage {
    role: String,
    content: String,
}

/// Chat completion response
#[derive(Debug, Deserialize)]
struct ChatCompletionResponse {
    choices: Option<Vec<Choice>>,
    error: Option<ApiError>,
    /// Token usage from Kimi K2.5
    usage: Option<Usage>,
}

#[derive(Debug, Deserialize)]
struct Choice {
    message: ResponseMessage,
}

#[derive(Debug, Deserialize)]
struct ResponseMessage {
    content: String,
    /// Kimi K2.5 Thinking Mode: reasoning trace (chain-of-thought)
    #[serde(default)]
    reasoning_content: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ApiError {
    message: String,
    code: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Usage {
    prompt_tokens: Option<u32>,
    completion_tokens: Option<u32>,
    total_tokens: Option<u32>,
}

// ═══════════════════════════════════════════════════════════════════════════
//  Public types: Enhanced vulnerability analysis output
// ═══════════════════════════════════════════════════════════════════════════

/// AI-generated vulnerability analysis — deep research from Kimi K2.5
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EnhancedExplanation {
    pub technical_explanation: String,
    pub attack_scenario: String,
    pub proof_of_concept: String,
    pub recommended_fix: String,
    pub economic_impact: String,
    pub severity_justification: String,
    /// Kimi K2.5 reasoning trace (thinking chain). Only present in Thinking mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_trace: Option<String>,
}

/// Vulnerability metadata passed to the AI for analysis
#[derive(Debug, Clone, Serialize)]
pub struct VulnerabilityInput {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: u8,
    pub code_snippet: String,
    pub file_path: String,
    pub line_number: usize,
}

// ═══════════════════════════════════════════════════════════════════════════
//  Configuration
// ═══════════════════════════════════════════════════════════════════════════

/// Tuning knobs for AI requests
#[derive(Debug, Clone)]
pub struct AIEnhancerConfig {
    pub model: String,
    pub max_retries: u32,
    pub retry_delay_ms: u64,
    pub concurrency_limit: usize,
    /// Kimi K2.5 Thinking Mode: temperature=1.0, Instant Mode: temperature=0.6
    pub temperature: f32,
    /// Kimi K2.5 recommended top_p=0.95
    pub top_p: f32,
    pub max_tokens: u32,
    /// Enable Kimi K2.5 Thinking Mode (includes reasoning traces)
    pub thinking_mode: bool,
}

impl Default for AIEnhancerConfig {
    fn default() -> Self {
        Self {
            model: "moonshotai/kimi-k2.5".to_string(),
            max_retries: 3,
            retry_delay_ms: 1000,
            concurrency_limit: 1,
            // NVIDIA NIM docs: Thinking Mode → 1.0, Instant Mode → 0.6
            temperature: 1.0,
            // NVIDIA NIM docs: recommended top_p = 0.95
            top_p: 0.95,
            max_tokens: 16384,
            thinking_mode: true,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  AIEnhancer — calls NVIDIA NIM / Kimi K2.5 for deep vuln analysis
// ═══════════════════════════════════════════════════════════════════════════

/// Calls Kimi K2.5 via NVIDIA NIM API to generate expert-level
/// Solana vulnerability analysis with reasoning traces.
pub struct AIEnhancer {
    api_key: String,
    config: AIEnhancerConfig,
    client: reqwest::Client,
}

impl AIEnhancer {
    pub fn new(api_key: String, model: String) -> Self {
        let config = AIEnhancerConfig {
            model,
            ..Default::default()
        };
        Self::with_config(api_key, config)
    }

    pub fn with_config(api_key: String, config: AIEnhancerConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(180)) // Kimi thinking mode can be slow
            .build()
            .expect("Failed to create HTTP client");

        Self {
            api_key,
            config,
            client,
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    //  Prompt Engineering — Web3 Security Researcher persona
    // ─────────────────────────────────────────────────────────────────────

    /// System prompt that frames Kimi K2.5 as a senior Web3 security researcher.
    fn system_prompt() -> String {
        r#"You are a senior Web3 security researcher and Solana exploit developer with 5+ years of experience auditing DeFi protocols on Solana. You have personally discovered and reported critical vulnerabilities in major protocols. You think like both a builder and an attacker.

Your expertise spans:
• Solana runtime internals: Sealevel parallel execution, BPF/SBF bytecode, account model, cross-program invocation (CPI), Program Derived Addresses (PDAs)
• Anchor framework: account validation macros, #[derive(Accounts)], #[account(...)], discriminators, SPL token integration  
• DeFi attack vectors: flash loans, oracle manipulation, reentrancy via CPI, first-depositor inflation, price manipulation, sandwich attacks, authority hijacking
• Real exploit analysis: Wormhole ($320M), Cashio ($52M), Mango Markets ($114M), Crema Finance ($8.8M), Slope Wallet, Solend oracle manipulation

When analyzing vulnerabilities, you:
1. Think deeply about the Solana runtime's guarantees (or lack thereof)
2. Consider what an attacker with unlimited SOL and compute would do  
3. Trace the exact data flow from instruction deserialization through validation (or missing validation) to state mutation
4. Reference concrete Solana types: AccountInfo, Signer<'info>, Account<'info, T>, ProgramAccount, UncheckedAccount
5. Write real, compilable exploit code — not pseudocode"#.to_string()
    }

    /// Build the analysis prompt. Deeply references Solana runtime internals
    /// so Kimi K2.5's reasoning produces actionable, expert-level analysis.
    fn generate_prompt(&self, vuln: &VulnerabilityInput) -> String {
        format!(
            r#"Analyze this Solana smart contract vulnerability with the depth of a professional security audit report.

## SOLANA RUNTIME CONTEXT
- Solana's Sealevel runtime processes transactions in parallel across accounts. Each instruction receives `AccountInfo` references with `is_signer`, `is_writable`, `owner`, `key`, and `data` fields. The runtime does NOT enforce type safety on account data — programs must validate everything.
- Anchor's `#[derive(Accounts)]` macro generates account validation via 8-byte discriminators and constraint checks. `Account<'info, T>` auto-deserializes and validates owner + discriminator. Raw `AccountInfo<'info>` does neither.
- `#[account(mut)]` marks writable. `#[account(signer)]` or `Signer<'info>` enforces signer. `#[account(has_one = authority)]` cross-references stored pubkeys. Missing any of these is exploitable.
- CPIs via `invoke()` / `invoke_signed()` pass the caller's privileges. If the target program isn't validated, an attacker substitutes a malicious program that mirrors the expected interface but steals funds.
- PDAs derived via `Pubkey::find_program_address(&[seeds], program_id)` return a canonical (address, bump). If you don't store/validate the bump, an attacker can derive a non-canonical PDA at a different address.
- Solana's BPF runtime uses u64 natively. All arithmetic on u64/u128/i64 wraps silently in release builds unless you use `checked_*`, `saturating_*`, or enable `overflow-checks = true` in Cargo.toml.
- Account closing requires: (1) transfer ALL lamports to recipient, (2) zero the data buffer, (3) set discriminator to `CLOSED_ACCOUNT_DISCRIMINATOR`. Missing step 2 or 3 allows same-transaction resurrection.

## VULNERABILITY UNDER ANALYSIS
- **Finding ID**: {id}
- **Vulnerability Type**: {title}
- **Scanner Description**: {description}
- **Severity**: {severity}/5 (5=Critical, 4=High, 3=Medium, 2=Low, 1=Info)
- **Source File**: `{file_path}` line {line_number}

## VULNERABLE CODE
```rust
{code}
```

## REQUIRED OUTPUT
Respond with a JSON object. Every field must contain expert-level Solana-specific analysis — NOT generic security advice. Write as if you're submitting this to an Immunefi bug bounty report:

{{
  "technical_explanation": "Root cause analysis referencing what Solana runtime guarantees are MISSING. Name specific Anchor types (Account<T>, Signer, UncheckedAccount), constraint attributes (#[account(has_one, seeds, constraint)]), and BPF runtime behaviors. Explain what the attacker controls and why the program's validation is insufficient. 2-3 detailed paragraphs.",

  "attack_scenario": "Step-by-step exploitation as a red team operator would execute it. Include: (1) which accounts to create/construct and their exact layout, (2) the instruction data bytes to send, (3) what happens inside the program on each step showing the missing check, (4) final state — where funds flow. Reference Solana concepts: transaction layout, compute budget, PDA derivation, CPI forwarding. Each step should be numbered and concrete.",

  "proof_of_concept": "A working Solana exploit: 20-40 lines of real Rust using anchor_client or solana_sdk, OR TypeScript using @coral-xyz/anchor. Show AccountMeta setup with is_signer/is_writable flags. Include malicious account creation. This should be copy-pasteable into an exploit test.",

  "recommended_fix": "The COMPLETE corrected Rust code — the full fixed struct and/or function. Use proper Anchor constraints: #[account(mut, has_one = authority)], Signer<'info>, seeds + bump, constraint = .... If arithmetic, show checked_* or require!() guards. Each added security line gets a // SECURITY: comment explaining why.",

  "economic_impact": "Estimated dollar impact based on what this program handles. Cross-reference real Solana exploits with identical patterns: Wormhole ($320M, missing signer verification on guardian set), Cashio ($52M, missing collateral mint validation), Mango Markets ($114M, oracle price manipulation), Crema Finance ($8.8M, unchecked CPI return). Format: 'Estimated $X-$Y at risk. Pattern matches [incident] because [specific shared root cause].'",

  "severity_justification": "Justify severity using three axes: (1) Exploitability — single transaction? requires setup? (2) Impact — total fund loss vs partial vs DoS? (3) Likelihood — is this pattern actively exploited on Solana mainnet? Include CWE ID and estimated CVSS v3.1 base score."
}}

CRITICAL: Output ONLY the raw JSON object. No markdown fencing. No preamble. No text outside the JSON."#,
            id = vuln.id,
            title = vuln.title,
            description = vuln.description,
            severity = vuln.severity,
            file_path = vuln.file_path,
            line_number = vuln.line_number,
            code = vuln.code_snippet
        )
    }

    // ─────────────────────────────────────────────────────────────────────
    //  API Call — NVIDIA NIM with Kimi K2.5 Thinking Mode
    // ─────────────────────────────────────────────────────────────────────

    /// Retry wrapper with rate-limit backoff (NVIDIA NIM has 3 RPM free tier)
    async fn call_api_with_retry(&self, prompt: &str) -> Result<(String, Option<String>), String> {
        let mut last_error = String::new();
        let max_attempts = self.config.max_retries + 2; // extra headroom for rate limits

        for attempt in 1..=max_attempts {
            match self.call_api(prompt).await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    last_error = e.clone();
                    if attempt < max_attempts {
                        let is_rate_limit = e.contains("429")
                            || e.contains("rate_limit")
                            || e.contains("quota")
                            || e.contains("Too Many Requests");

                        let delay = if is_rate_limit {
                            warn!("NVIDIA NIM rate limit. Backing off 35s (3 RPM window)...");
                            35_000 // clear the 3 RPM sliding window
                        } else {
                            self.config.retry_delay_ms * (attempt as u64)
                        };

                        warn!(
                            "API call failed (attempt {}/{}): {}. Retrying in {}ms...",
                            attempt, max_attempts, e, delay
                        );
                        tokio::time::sleep(Duration::from_millis(delay)).await;
                    }
                }
            }
        }

        Err(format!(
            "Kimi K2.5 API failed after {} attempts: {}",
            max_attempts, last_error
        ))
    }

    /// Single API call to NVIDIA NIM / Kimi K2.5 using **streaming SSE**.
    /// Streaming avoids NVIDIA NIM's 504 gateway timeout on thinking mode.
    /// Returns (content, reasoning_content).
    async fn call_api(&self, prompt: &str) -> Result<(String, Option<String>), String> {
        let is_nvidia = self.api_key.starts_with("nvapi-");
        let is_openai = !is_nvidia
            && (self.api_key.starts_with("sk-proj-")
                || (self.api_key.starts_with("sk-") && !self.api_key.starts_with("sk-or-")));
        let is_kimi = self.config.model.contains("kimi") || self.config.model.contains("moonshot");

        // ── Build request body per NVIDIA NIM docs ──────────────────────
        let chat_template_kwargs = if is_kimi && self.config.thinking_mode {
            Some(serde_json::json!({"thinking": true}))
        } else if is_kimi && !self.config.thinking_mode {
            Some(serde_json::json!({"thinking": false}))
        } else if is_nvidia && self.config.model.contains("nemotron") {
            Some(serde_json::json!({"enable_thinking": true}))
        } else {
            None
        };

        let mut messages = Vec::new();

        // System prompt — Web3 security researcher persona
        if is_kimi || is_nvidia {
            messages.push(ChatMessage {
                role: "system".to_string(),
                content: Self::system_prompt(),
            });
        }

        messages.push(ChatMessage {
            role: "user".to_string(),
            content: prompt.to_string(),
        });

        // Use streaming for NVIDIA NIM to avoid 504 gateway timeout
        let use_streaming = is_nvidia || is_kimi;

        let request = ChatCompletionRequest {
            model: self.config.model.clone(),
            messages,
            temperature: if is_openai { None } else { Some(self.config.temperature) },
            top_p: if is_openai { None } else { Some(self.config.top_p) },
            max_tokens: if is_openai { None } else { Some(self.config.max_tokens) },
            max_completion_tokens: if is_openai {
                Some(self.config.max_tokens)
            } else {
                None
            },
            reasoning_budget: None,
            chat_template_kwargs,
            stream: Some(use_streaming),
        };

        // ── Select API endpoint ────────────────────────────────────────
        let api_url = if let Ok(custom_url) = std::env::var("LLM_BASE_URL") {
            custom_url
        } else if is_nvidia || is_kimi {
            "https://integrate.api.nvidia.com/v1/chat/completions".to_string()
        } else if is_openai {
            "https://api.openai.com/v1/chat/completions".to_string()
        } else {
            "https://openrouter.ai/api/v1/chat/completions".to_string()
        };

        // ── Build HTTP request ─────────────────────────────────────────
        let accept_header = if use_streaming { "text/event-stream" } else { "application/json" };
        let mut req_builder = self
            .client
            .post(&api_url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .header("Accept", accept_header);

        if !is_openai && !is_nvidia {
            req_builder = req_builder
                .header("HTTP-Referer", "https://shanon.security")
                .header("X-Title", "Shanon Security Auditor");
        }

        info!(
            "Calling {} via {} (thinking={}, streaming={})",
            self.config.model, api_url, self.config.thinking_mode, use_streaming
        );

        let response = req_builder
            .json(&request)
            .send()
            .await
            .map_err(|e| format!("HTTP request to NVIDIA NIM failed: {}", e))?;

        let status = response.status();

        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(format!("NVIDIA NIM returned {}: {}", status, body));
        }

        // ── STREAMING: accumulate SSE chunks ───────────────────────────
        if use_streaming {
            return self.consume_sse_stream(response).await;
        }

        // ── NON-STREAMING: parse full JSON response ────────────────────
        let body = response
            .text()
            .await
            .map_err(|e| format!("Failed to read response: {}", e))?;

        let parsed: ChatCompletionResponse = serde_json::from_str(&body)
            .map_err(|e| format!("JSON parse error: {} — body: {}", e, &body[..body.len().min(500)]))?;

        if let Some(error) = parsed.error {
            return Err(format!("API error: {}", error.message));
        }

        let choice = parsed
            .choices
            .and_then(|c| c.into_iter().next())
            .ok_or_else(|| "Empty response from Kimi K2.5".to_string())?;

        Ok((choice.message.content, choice.message.reasoning_content))
    }

    /// Consume SSE stream from NVIDIA NIM / Kimi K2.5.
    /// Accumulates `content` and `reasoning_content` from delta chunks.
    async fn consume_sse_stream(
        &self,
        response: reqwest::Response,
    ) -> Result<(String, Option<String>), String> {
        let mut content = String::new();
        let mut reasoning_content = String::new();

        let mut stream = response.bytes_stream();

        // SSE buffer — events can span multiple TCP frames
        let mut buffer = String::new();

        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result
                .map_err(|e| format!("Stream read error: {}", e))?;
            let chunk_str = String::from_utf8_lossy(&chunk);
            buffer.push_str(&chunk_str);

            // Process complete SSE lines from buffer
            while let Some(newline_pos) = buffer.find('\n') {
                let line = buffer[..newline_pos].trim().to_string();
                buffer = buffer[newline_pos + 1..].to_string();

                if line.is_empty() || line.starts_with(':') {
                    continue; // SSE comment or empty keepalive
                }

                if let Some(data) = line.strip_prefix("data: ") {
                    let data = data.trim();
                    if data == "[DONE]" {
                        info!("Kimi K2.5 stream complete");
                        let reasoning = if reasoning_content.is_empty() {
                            None
                        } else {
                            Some(reasoning_content)
                        };
                        return Ok((content, reasoning));
                    }

                    // Parse the streaming delta chunk
                    if let Ok(chunk_json) = serde_json::from_str::<serde_json::Value>(data) {
                        if let Some(choices) = chunk_json.get("choices").and_then(|c| c.as_array()) {
                            for choice in choices {
                                if let Some(delta) = choice.get("delta") {
                                    // Accumulate content tokens
                                    if let Some(c) = delta.get("content").and_then(|c| c.as_str()) {
                                        content.push_str(c);
                                    }
                                    // Accumulate reasoning_content tokens (Kimi thinking mode)
                                    if let Some(r) = delta.get("reasoning_content").and_then(|r| r.as_str()) {
                                        reasoning_content.push_str(r);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Stream ended without [DONE] — return what we have
        if content.is_empty() {
            return Err("Kimi K2.5 stream ended with no content".to_string());
        }

        let reasoning = if reasoning_content.is_empty() {
            None
        } else {
            Some(reasoning_content)
        };
        Ok((content, reasoning))
    }

    // ─────────────────────────────────────────────────────────────────────
    //  Response Parsing — extract JSON from Kimi K2.5 output
    // ─────────────────────────────────────────────────────────────────────

    /// Extract the structured analysis JSON from Kimi K2.5's response.
    /// Handles raw JSON, markdown-fenced JSON, and mixed text + JSON.
    fn parse_response(
        &self,
        response: &str,
        reasoning: Option<String>,
    ) -> Result<EnhancedExplanation, String> {
        // Try raw parse first
        if let Ok(mut parsed) = serde_json::from_str::<EnhancedExplanation>(response.trim()) {
            parsed.reasoning_trace = reasoning;
            return Ok(parsed);
        }

        // Strip markdown code fences: ```json ... ``` or ``` ... ```
        let json_str = if response.contains("```json") {
            response
                .split("```json")
                .nth(1)
                .and_then(|s| s.split("```").next())
                .unwrap_or(response)
        } else if response.contains("```") {
            response.split("```").nth(1).unwrap_or(response)
        } else {
            response
        };

        // Try to find JSON object boundaries { ... }
        let json_candidate = if let Some(start) = json_str.find('{') {
            if let Some(end) = json_str.rfind('}') {
                &json_str[start..=end]
            } else {
                json_str
            }
        } else {
            json_str
        };

        let mut parsed: EnhancedExplanation =
            serde_json::from_str(json_candidate.trim()).map_err(|e| {
                format!(
                    "Kimi K2.5 JSON parse error: {} — response preview: {}",
                    e,
                    &response[..response.len().min(500)]
                )
            })?;

        parsed.reasoning_trace = reasoning;
        Ok(parsed)
    }

    // ─────────────────────────────────────────────────────────────────────
    //  Public API
    // ─────────────────────────────────────────────────────────────────────

    /// Enhance one vulnerability with Kimi K2.5 deep analysis.
    /// In Thinking Mode, includes the model's chain-of-thought reasoning trace.
    pub async fn enhance_vulnerability(
        &self,
        vuln: &VulnerabilityInput,
    ) -> Result<EnhancedExplanation, String> {
        info!(
            "🧠 Enhancing {} — {} (sev {}/5)",
            vuln.id, vuln.title, vuln.severity
        );

        let prompt = self.generate_prompt(vuln);
        let (response, reasoning) = self.call_api_with_retry(&prompt).await?;

        let enhanced = self.parse_response(&response, reasoning)?;

        info!("✓ Enhanced {} — {}", vuln.id, vuln.title);
        Ok(enhanced)
    }

    /// Enhance a batch with controlled concurrency.
    /// NVIDIA NIM free tier is 3 RPM, so we serialize by default.
    pub async fn enhance_vulnerabilities_batch(
        &self,
        vulns: Vec<VulnerabilityInput>,
    ) -> Vec<(String, Result<EnhancedExplanation, String>)> {
        info!(
            "Starting batch enhancement of {} vulnerabilities via Kimi K2.5",
            vulns.len()
        );

        let results: Vec<_> = stream::iter(vulns)
            .map(|vuln| async move {
                let id = vuln.id.clone();
                let result = self.enhance_vulnerability(&vuln).await;
                (id, result)
            })
            .buffer_unordered(self.config.concurrency_limit)
            .collect()
            .await;

        let success_count = results.iter().filter(|(_, r)| r.is_ok()).count();
        info!(
            "Batch enhancement complete: {}/{} successful",
            success_count,
            results.len()
        );

        results
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_parsing_clean() {
        let json = r#"{
            "technical_explanation": "The code lacks signer verification on the authority account. In Solana's Sealevel runtime, AccountInfo is a raw reference — the runtime does NOT check is_signer unless the program explicitly validates it.",
            "attack_scenario": "1. Attacker constructs a transaction with their own pubkey as authority\n2. Since AccountInfo has no Signer constraint, the BPF runtime accepts it\n3. Attacker calls withdraw() draining all vault lamports",
            "proof_of_concept": "let ix = Instruction { program_id, accounts: vec![AccountMeta::new(vault, false), AccountMeta::new_readonly(attacker, false)], data: WithdrawData { amount: vault_balance }.try_to_vec().unwrap() };",
            "recommended_fix": "pub authority: Signer<'info>, // SECURITY: enforce signer check",
            "economic_impact": "Estimated $1M-$50M at risk. Pattern matches Wormhole ($320M) — both involve missing signer verification on a privileged authority account.",
            "severity_justification": "CVSS 9.8 Critical. CWE-287: Improper Authentication. Single-transaction exploitable, total fund loss, actively exploited pattern on Solana mainnet."
        }"#;

        let enhancer = AIEnhancer::new("test".to_string(), "test".to_string());
        let result = enhancer.parse_response(json, None);
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert!(parsed.technical_explanation.contains("Sealevel"));
        assert!(parsed.reasoning_trace.is_none());
    }

    #[test]
    fn test_json_parsing_with_markdown() {
        let response = r#"Here's my analysis:

```json
{
    "technical_explanation": "Missing signer check on authority.",
    "attack_scenario": "Direct call bypasses auth.",
    "proof_of_concept": "// exploit code",
    "recommended_fix": "Use Signer<'info>.",
    "economic_impact": "$50k-$1M",
    "severity_justification": "Critical. CWE-287."
}
```

This is a critical finding."#;

        let enhancer = AIEnhancer::new("test".to_string(), "test".to_string());
        let result = enhancer.parse_response(response, Some("I need to think about this...".to_string()));
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.reasoning_trace.as_deref(), Some("I need to think about this..."));
    }

    #[test]
    fn test_json_parsing_with_brace_extraction() {
        let response = r#"Sure, here is my analysis:
{
    "technical_explanation": "The withdraw function uses raw AccountInfo.",
    "attack_scenario": "Attacker sends fake authority.",
    "proof_of_concept": "code here",
    "recommended_fix": "Add Signer constraint.",
    "economic_impact": "$100k",
    "severity_justification": "High severity."
}
That concludes my findings."#;

        let enhancer = AIEnhancer::new("test".to_string(), "test".to_string());
        let result = enhancer.parse_response(response, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_prompt_generation() {
        let vuln = VulnerabilityInput {
            id: "SOL-001".to_string(),
            title: "Missing Signer Check".to_string(),
            description: "Authority not verified".to_string(),
            severity: 5,
            code_snippet: "pub authority: AccountInfo<'info>".to_string(),
            file_path: "src/lib.rs".to_string(),
            line_number: 42,
        };

        let enhancer = AIEnhancer::new(
            "nvapi-test".to_string(),
            "moonshotai/kimi-k2.5".to_string(),
        );
        let prompt = enhancer.generate_prompt(&vuln);

        assert!(prompt.contains("Missing Signer Check"));
        assert!(prompt.contains("`src/lib.rs` line 42"));
        assert!(prompt.contains("JSON object"));
        assert!(prompt.contains("Immunefi"));
    }

    #[test]
    fn test_system_prompt_quality() {
        let prompt = AIEnhancer::system_prompt();
        assert!(prompt.contains("Web3 security researcher"));
        assert!(prompt.contains("Wormhole"));
        assert!(prompt.contains("Sealevel"));
        assert!(prompt.contains("CPI"));
    }

    #[test]
    fn test_config_defaults() {
        let config = AIEnhancerConfig::default();
        assert_eq!(config.model, "moonshotai/kimi-k2.5");
        assert_eq!(config.temperature, 1.0); // Thinking mode
        assert_eq!(config.top_p, 0.95);
        assert!(config.thinking_mode);
    }
}
