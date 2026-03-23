//! daimon — Client for registering with the AGNOS agent orchestrator.

use crate::AgentRegistration;
use serde::{Deserialize, Serialize};

/// Default daimon endpoint.
pub const DAIMON_DEFAULT_URL: &str = "http://127.0.0.1:8090";

/// Daimon client for agent lifecycle operations.
#[derive(Debug, Clone)]
pub struct DaimonClient {
    base_url: String,
    client: reqwest::Client,
}

/// Registration response from daimon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub agent_id: String,
    pub status: String,
}

impl DaimonClient {
    /// Create a new client pointing at the given daimon URL.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            client: reqwest::Client::new(),
        }
    }

    /// Create a client using the default localhost URL.
    pub fn default_local() -> Self {
        Self::new(DAIMON_DEFAULT_URL)
    }

    /// Register the phylax agent with daimon.
    pub async fn register(&self) -> anyhow::Result<RegisterResponse> {
        let reg = AgentRegistration::default();
        let url = format!("{}/v1/agents/register", self.base_url);
        let resp = self
            .client
            .post(&url)
            .json(&reg)
            .send()
            .await?
            .error_for_status()?
            .json::<RegisterResponse>()
            .await?;
        Ok(resp)
    }

    /// Send a heartbeat to daimon.
    pub async fn heartbeat(&self, agent_id: &str) -> anyhow::Result<()> {
        let url = format!("{}/v1/agents/{}/heartbeat", self.base_url, agent_id);
        self.client.post(&url).send().await?.error_for_status()?;
        Ok(())
    }

    /// Return the base URL.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daimon_client_default_url() {
        let client = DaimonClient::default_local();
        assert_eq!(client.base_url(), DAIMON_DEFAULT_URL);
    }

    #[test]
    fn daimon_client_custom_url() {
        let client = DaimonClient::new("http://10.0.0.1:9090");
        assert_eq!(client.base_url(), "http://10.0.0.1:9090");
    }
}
