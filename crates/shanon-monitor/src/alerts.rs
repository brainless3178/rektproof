//! Webhook Alert Delivery
//!
//! Sends formatted alerts to Discord, Slack, and Telegram webhooks
//! when authority changes are detected.

use serde::{Deserialize, Serialize};

/// Supported webhook platforms
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WebhookPlatform {
    Discord,
    Slack,
    Telegram,
    Generic,
}

/// Webhook configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub platform: WebhookPlatform,
    pub url: String,
    /// Optional: Telegram chat_id (required for Telegram)
    pub chat_id: Option<String>,
}

/// An alert to be delivered
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub severity: AlertSeverity,
    pub title: String,
    pub message: String,
    pub program_id: String,
    pub timestamp: String,
    pub details: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertSeverity {
    Critical,
    High,
    Medium,
    Info,
}

impl AlertSeverity {
    pub fn emoji(&self) -> &str {
        match self {
            AlertSeverity::Critical => "🚨",
            AlertSeverity::High => "⚠️",
            AlertSeverity::Medium => "📋",
            AlertSeverity::Info => "ℹ️",
        }
    }

    pub fn color(&self) -> u32 {
        match self {
            AlertSeverity::Critical => 0xFF0000,
            AlertSeverity::High => 0xFF8C00,
            AlertSeverity::Medium => 0xFFD700,
            AlertSeverity::Info => 0x4169E1,
        }
    }
}

/// Alert delivery client
pub struct AlertSender {
    webhooks: Vec<WebhookConfig>,
    client: reqwest::Client,
}

impl AlertSender {
    pub fn new(webhooks: Vec<WebhookConfig>) -> Self {
        Self {
            webhooks,
            client: reqwest::Client::new(),
        }
    }

    /// Send an alert to all configured webhooks
    pub async fn send(&self, alert: &Alert) -> Vec<Result<(), String>> {
        let mut results = Vec::new();

        for webhook in &self.webhooks {
            let result = match webhook.platform {
                WebhookPlatform::Discord => self.send_discord(webhook, alert).await,
                WebhookPlatform::Slack => self.send_slack(webhook, alert).await,
                WebhookPlatform::Telegram => self.send_telegram(webhook, alert).await,
                WebhookPlatform::Generic => self.send_generic(webhook, alert).await,
            };
            results.push(result);
        }

        results
    }

    async fn send_discord(&self, webhook: &WebhookConfig, alert: &Alert) -> Result<(), String> {
        let payload = serde_json::json!({
            "embeds": [{
                "title": format!("{} {}", alert.severity.emoji(), alert.title),
                "description": alert.message,
                "color": alert.severity.color(),
                "fields": [
                    { "name": "Program", "value": &alert.program_id, "inline": true },
                    { "name": "Time", "value": &alert.timestamp, "inline": true },
                ],
                "footer": { "text": "Shanon Security Monitor" }
            }]
        });

        self.client
            .post(&webhook.url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("Discord webhook failed: {}", e))?;

        Ok(())
    }

    async fn send_slack(&self, webhook: &WebhookConfig, alert: &Alert) -> Result<(), String> {
        let payload = serde_json::json!({
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": format!("{} {}", alert.severity.emoji(), alert.title)
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": format!("*Program:* `{}`\n{}\n_{}_ ", alert.program_id, alert.message, alert.timestamp)
                    }
                }
            ]
        });

        self.client
            .post(&webhook.url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("Slack webhook failed: {}", e))?;

        Ok(())
    }

    async fn send_telegram(&self, webhook: &WebhookConfig, alert: &Alert) -> Result<(), String> {
        let chat_id = webhook
            .chat_id
            .as_ref()
            .ok_or_else(|| "Telegram requires chat_id".to_string())?;

        let text = format!(
            "{} *{}*\n\n{}\n\n`Program: {}`\n_{}_",
            alert.severity.emoji(),
            alert.title,
            alert.message,
            alert.program_id,
            alert.timestamp
        );

        let payload = serde_json::json!({
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "Markdown"
        });

        let url = format!("{}/sendMessage", webhook.url);

        self.client
            .post(&url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("Telegram send failed: {}", e))?;

        Ok(())
    }

    async fn send_generic(&self, webhook: &WebhookConfig, alert: &Alert) -> Result<(), String> {
        self.client
            .post(&webhook.url)
            .json(alert)
            .send()
            .await
            .map_err(|e| format!("Generic webhook failed: {}", e))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alert_severity() {
        assert_eq!(AlertSeverity::Critical.emoji(), "🚨");
        assert_eq!(AlertSeverity::High.color(), 0xFF8C00);
    }

    #[test]
    fn test_alert_sender_creation() {
        let sender = AlertSender::new(vec![WebhookConfig {
            platform: WebhookPlatform::Discord,
            url: "https://discord.com/api/webhooks/test/test".into(),
            chat_id: None,
        }]);
        assert_eq!(sender.webhooks.len(), 1);
    }

    #[test]
    fn test_alert_construction() {
        let alert = Alert {
            severity: AlertSeverity::Critical,
            title: "Authority Change Detected".into(),
            message: "Upgrade authority transferred".into(),
            program_id: "TestProgram111".into(),
            timestamp: "2025-01-01T00:00:00Z".into(),
            details: serde_json::json!({}),
        };
        assert_eq!(alert.severity, AlertSeverity::Critical);
    }
}
