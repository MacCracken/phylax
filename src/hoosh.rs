//! Hoosh LLM triage client.
//!
//! Sends threat findings to hoosh's OpenAI-compatible `/v1/chat/completions`
//! endpoint for automated classification and triage.

use crate::core::ThreatFinding;
use serde::{Deserialize, Serialize};
use tracing::{debug, instrument, warn};

/// Default hoosh endpoint.
pub const HOOSH_DEFAULT_URL: &str = "http://127.0.0.1:8088";

/// Default model to use for triage.
pub const HOOSH_DEFAULT_MODEL: &str = "llama3";

/// Hoosh client for LLM-assisted threat triage.
#[derive(Debug, Clone)]
pub struct HooshClient {
    base_url: String,
    model: String,
    client: reqwest::Client,
}

/// Triage result from hoosh.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageResult {
    /// The finding ID that was triaged.
    pub finding_id: String,
    /// LLM classification (e.g. "true_positive", "false_positive", "needs_review").
    pub classification: String,
    /// Confidence score from 0.0 to 1.0.
    pub confidence: f64,
    /// LLM explanation.
    pub explanation: String,
    /// Model that produced the result.
    pub model: String,
}

// ---------------------------------------------------------------------------
// OpenAI-compatible request/response types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<ChatMessage>,
    max_tokens: u32,
    temperature: f64,
}

#[derive(Debug, Serialize, Deserialize)]
struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct ChatResponse {
    choices: Vec<ChatChoice>,
}

#[derive(Debug, Deserialize)]
struct ChatChoice {
    message: ChatMessage,
}

impl HooshClient {
    /// Create a new client with default settings (30s request timeout).
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            model: HOOSH_DEFAULT_MODEL.to_string(),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
        }
    }

    /// Create a client using the default localhost URL.
    pub fn default_local() -> Self {
        Self::new(HOOSH_DEFAULT_URL)
    }

    /// Set the model to use for triage.
    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = model.into();
        self
    }

    /// Return the base URL.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Return the configured model.
    pub fn model(&self) -> &str {
        &self.model
    }

    /// Triage a single threat finding via hoosh.
    ///
    /// Sends the finding details to the LLM and parses the classification response.
    #[instrument(skip(self, finding), fields(finding_id = %finding.id, rule = %finding.rule_name))]
    pub async fn triage_finding(&self, finding: &ThreatFinding) -> anyhow::Result<TriageResult> {
        let prompt = build_triage_prompt(finding);

        let request = ChatRequest {
            model: self.model.clone(),
            messages: vec![
                ChatMessage {
                    role: "system".into(),
                    content: TRIAGE_SYSTEM_PROMPT.to_string(),
                },
                ChatMessage {
                    role: "user".into(),
                    content: prompt,
                },
            ],
            max_tokens: 512,
            temperature: 0.3,
        };

        let url = format!("{}/v1/chat/completions", self.base_url);
        debug!(url = %url, model = %self.model, "sending triage request");

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await?
            .error_for_status()?
            .json::<ChatResponse>()
            .await?;

        let content = response
            .choices
            .first()
            .map(|c| c.message.content.clone())
            .unwrap_or_default();

        let result = parse_triage_response(&content, &finding.id.to_string(), &self.model);
        debug!(
            classification = %result.classification,
            confidence = result.confidence,
            "triage complete"
        );

        Ok(result)
    }

    /// Triage multiple findings, returning results in order.
    pub async fn triage_findings(
        &self,
        findings: &[ThreatFinding],
    ) -> Vec<anyhow::Result<TriageResult>> {
        let mut results = Vec::with_capacity(findings.len());
        for finding in findings {
            results.push(self.triage_finding(finding).await);
        }
        results
    }
}

const TRIAGE_SYSTEM_PROMPT: &str = "\
You are a security analyst triaging threat detection findings. \
For each finding, respond with a JSON object containing: \
{\"classification\": \"true_positive|false_positive|needs_review\", \
\"confidence\": 0.0-1.0, \"explanation\": \"brief reason\"}. \
Respond with ONLY the JSON object, no other text.";

fn build_triage_prompt(finding: &ThreatFinding) -> String {
    let mut prompt = format!(
        "Triage this finding:\n\
         Rule: {}\n\
         Severity: {}\n\
         Category: {}\n\
         Description: {}\n\
         Target: {}",
        finding.rule_name, finding.severity, finding.category, finding.description, finding.target,
    );

    if !finding.metadata.is_empty() {
        prompt.push_str("\nMetadata:");
        for (k, v) in &finding.metadata {
            prompt.push_str(&format!("\n  {k}: {v}"));
        }
    }

    prompt
}

/// Parse the LLM response into a TriageResult.
///
/// Attempts JSON parsing first, falls back to heuristic extraction.
fn parse_triage_response(content: &str, finding_id: &str, model: &str) -> TriageResult {
    // Try to parse as JSON
    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(content) {
        return TriageResult {
            finding_id: finding_id.to_string(),
            classification: parsed
                .get("classification")
                .and_then(|v| v.as_str())
                .unwrap_or("needs_review")
                .to_string(),
            confidence: parsed
                .get("confidence")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.5),
            explanation: parsed
                .get("explanation")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            model: model.to_string(),
        };
    }

    // Fallback: extract from raw text
    warn!("failed to parse triage response as JSON, using fallback");
    let classification = if content.contains("false_positive") {
        "false_positive"
    } else if content.contains("true_positive") {
        "true_positive"
    } else {
        "needs_review"
    };

    TriageResult {
        finding_id: finding_id.to_string(),
        classification: classification.to_string(),
        confidence: 0.5,
        explanation: content.chars().take(256).collect(),
        model: model.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{FindingCategory, FindingSeverity, ScanTarget};

    #[test]
    fn client_defaults() {
        let client = HooshClient::default_local();
        assert_eq!(client.base_url(), HOOSH_DEFAULT_URL);
        assert_eq!(client.model(), HOOSH_DEFAULT_MODEL);
    }

    #[test]
    fn client_custom() {
        let client = HooshClient::new("http://10.0.0.1:9090").with_model("mistral");
        assert_eq!(client.base_url(), "http://10.0.0.1:9090");
        assert_eq!(client.model(), "mistral");
    }

    #[test]
    fn build_prompt_basic() {
        let finding = ThreatFinding::new(
            ScanTarget::File("/tmp/test.bin".into()),
            FindingCategory::Suspicious,
            FindingSeverity::High,
            "high_entropy",
            "High entropy detected: 7.89 bits/byte",
        );
        let prompt = build_triage_prompt(&finding);
        assert!(prompt.contains("high_entropy"));
        assert!(prompt.contains("HIGH"));
        assert!(prompt.contains("7.89"));
        assert!(prompt.contains("/tmp/test.bin"));
    }

    #[test]
    fn build_prompt_with_metadata() {
        let mut finding = ThreatFinding::new(
            ScanTarget::Memory,
            FindingCategory::Malware,
            FindingSeverity::Critical,
            "packed_binary",
            "UPX packed",
        );
        finding.metadata.insert("sha256".into(), "abc123".into());
        let prompt = build_triage_prompt(&finding);
        assert!(prompt.contains("sha256: abc123"));
    }

    #[test]
    fn parse_response_valid_json() {
        let content = r#"{"classification": "true_positive", "confidence": 0.92, "explanation": "known malware signature"}"#;
        let result = parse_triage_response(content, "f-1", "llama3");
        assert_eq!(result.classification, "true_positive");
        assert!((result.confidence - 0.92).abs() < f64::EPSILON);
        assert_eq!(result.explanation, "known malware signature");
        assert_eq!(result.model, "llama3");
    }

    #[test]
    fn parse_response_false_positive() {
        let content = r#"{"classification": "false_positive", "confidence": 0.85, "explanation": "benign packed installer"}"#;
        let result = parse_triage_response(content, "f-2", "mistral");
        assert_eq!(result.classification, "false_positive");
    }

    #[test]
    fn parse_response_fallback_true_positive() {
        let content = "This appears to be a true_positive detection based on the entropy pattern.";
        let result = parse_triage_response(content, "f-3", "llama3");
        assert_eq!(result.classification, "true_positive");
        assert_eq!(result.confidence, 0.5);
    }

    #[test]
    fn parse_response_fallback_false_positive() {
        let content = "Likely a false_positive — common compression artifact.";
        let result = parse_triage_response(content, "f-4", "llama3");
        assert_eq!(result.classification, "false_positive");
    }

    #[test]
    fn parse_response_fallback_unknown() {
        let content = "I cannot determine the classification with certainty.";
        let result = parse_triage_response(content, "f-5", "llama3");
        assert_eq!(result.classification, "needs_review");
    }

    #[test]
    fn parse_response_malformed_json() {
        let content = r#"{"classification": "true_positive", broken json"#;
        let result = parse_triage_response(content, "f-6", "llama3");
        // Falls back to text heuristic
        assert_eq!(result.classification, "true_positive");
    }

    #[test]
    fn parse_response_missing_fields() {
        let content = r#"{"classification": "false_positive"}"#;
        let result = parse_triage_response(content, "f-7", "llama3");
        assert_eq!(result.classification, "false_positive");
        assert_eq!(result.confidence, 0.5); // default when missing
    }

    #[test]
    fn parse_response_empty_content() {
        let result = parse_triage_response("", "f-8", "llama3");
        assert_eq!(result.classification, "needs_review");
        assert_eq!(result.confidence, 0.5);
    }

    #[test]
    fn parse_response_json_with_extra_fields() {
        let content = r#"{"classification": "true_positive", "confidence": 0.88, "explanation": "match", "extra": "ignored"}"#;
        let result = parse_triage_response(content, "f-9", "llama3");
        assert_eq!(result.classification, "true_positive");
        assert!((result.confidence - 0.88).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn triage_findings_empty_batch() {
        let client = HooshClient::default_local();
        let results = client.triage_findings(&[]).await;
        assert!(results.is_empty());
    }

    #[test]
    fn client_timeout_configured() {
        // Just verify construction doesn't panic
        let client = HooshClient::new("http://localhost:9999");
        assert_eq!(client.base_url(), "http://localhost:9999");
    }

    #[test]
    fn triage_result_serialization_roundtrip() {
        let result = TriageResult {
            finding_id: "f-1".into(),
            classification: "true_positive".into(),
            confidence: 0.95,
            explanation: "confirmed malware".into(),
            model: "llama3".into(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: TriageResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.finding_id, "f-1");
        assert_eq!(parsed.classification, "true_positive");
    }
}
