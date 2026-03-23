//! AI integration — daimon agent registration and hoosh LLM triage.

use serde::{Deserialize, Serialize};

/// Agent capabilities advertised to daimon.
pub const AGENT_NAME: &str = "phylax";
pub const AGENT_CAPABILITIES: &[&str] = &[
    "threat_scan",
    "yara",
    "entropy",
    "magic_bytes",
    "ml_classify",
];

/// Registration request sent to daimon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRegistration {
    pub name: String,
    pub capabilities: Vec<String>,
    pub version: String,
}

impl Default for AgentRegistration {
    fn default() -> Self {
        Self {
            name: AGENT_NAME.to_string(),
            capabilities: AGENT_CAPABILITIES
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

/// LLM triage request sent to hoosh for classification assistance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageRequest {
    pub finding_id: String,
    pub description: String,
    pub context: String,
}

/// LLM triage response from hoosh.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageResponse {
    pub finding_id: String,
    pub classification: String,
    pub confidence: f64,
    pub explanation: String,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_registration_defaults() {
        let reg = AgentRegistration::default();
        assert_eq!(reg.name, "phylax");
        assert!(reg.capabilities.contains(&"threat_scan".to_string()));
        assert!(reg.capabilities.contains(&"yara".to_string()));
        assert!(reg.capabilities.contains(&"entropy".to_string()));
        assert!(reg.capabilities.contains(&"magic_bytes".to_string()));
        assert!(reg.capabilities.contains(&"ml_classify".to_string()));
        assert_eq!(reg.capabilities.len(), 5);
    }

    #[test]
    fn agent_registration_serialization_roundtrip() {
        let reg = AgentRegistration::default();
        let json = serde_json::to_string(&reg).unwrap();
        let parsed: AgentRegistration = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, reg.name);
        assert_eq!(parsed.capabilities, reg.capabilities);
    }

    #[test]
    fn triage_response_serialization_roundtrip() {
        let resp = TriageResponse {
            finding_id: "f-1".into(),
            classification: "false_positive".into(),
            confidence: 0.95,
            explanation: "benign packed binary".into(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: TriageResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.finding_id, "f-1");
        assert_eq!(parsed.classification, "false_positive");
        assert!((parsed.confidence - 0.95).abs() < f64::EPSILON);
    }

    #[test]
    fn triage_request_serialization() {
        let req = TriageRequest {
            finding_id: "abc-123".into(),
            description: "suspicious entropy".into(),
            context: "file: /tmp/test.bin".into(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: TriageRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.finding_id, "abc-123");
    }
}
