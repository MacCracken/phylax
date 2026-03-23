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

// LLM triage is handled by the `hoosh` module (see `hoosh::HooshClient`).

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
}
