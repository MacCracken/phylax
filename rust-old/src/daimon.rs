//! Daimon client — registration, heartbeat, and deregistration with the AGNOS
//! agent orchestrator.

use crate::ai::AgentRegistration;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

/// Default daimon endpoint.
pub const DAIMON_DEFAULT_URL: &str = "http://127.0.0.1:8090";

/// Default heartbeat interval.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);

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

/// Handle for a running daimon lifecycle (heartbeat loop).
/// Drop to stop heartbeats and deregister.
pub struct DaimonHandle {
    shutdown_tx: watch::Sender<bool>,
    join: tokio::task::JoinHandle<()>,
    agent_id: String,
    client: Arc<DaimonClient>,
}

impl DaimonHandle {
    /// The agent ID assigned by daimon.
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    /// Gracefully stop heartbeats and deregister from daimon.
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        let _ = self.join.await;
        if let Err(e) = self.client.deregister(&self.agent_id).await {
            warn!(error = %e, "failed to deregister from daimon");
        } else {
            info!(agent_id = %self.agent_id, "deregistered from daimon");
        }
    }
}

impl DaimonClient {
    /// Create a new client pointing at the given daimon URL (10s timeout).
    ///
    /// # Errors
    /// Returns an error if the HTTP client cannot be constructed.
    pub fn new(base_url: impl Into<String>) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self {
            base_url: base_url.into(),
            client,
        })
    }

    /// Create a client using the default localhost URL.
    ///
    /// # Errors
    /// Returns an error if the HTTP client cannot be constructed.
    pub fn default_local() -> anyhow::Result<Self> {
        Self::new(DAIMON_DEFAULT_URL)
    }

    /// Register the phylax agent with daimon.
    ///
    /// # Errors
    /// Returns an error if the HTTP request fails or daimon returns a non-2xx status.
    pub async fn register(&self) -> anyhow::Result<RegisterResponse> {
        let reg = AgentRegistration::default();
        let url = format!("{}/v1/agents/register", self.base_url);
        info!(url = %url, "registering with daimon");
        let resp = self
            .client
            .post(&url)
            .json(&reg)
            .send()
            .await?
            .error_for_status()?
            .json::<RegisterResponse>()
            .await?;
        info!(agent_id = %resp.agent_id, "registered with daimon");
        Ok(resp)
    }

    /// Send a heartbeat to daimon.
    ///
    /// # Errors
    /// Returns an error if `agent_id` contains path separators, the HTTP request
    /// fails, or daimon returns a non-2xx status.
    pub async fn heartbeat(&self, agent_id: &str) -> anyhow::Result<()> {
        anyhow::ensure!(
            !agent_id.is_empty() && !agent_id.contains('/') && !agent_id.contains('\\'),
            "invalid agent_id: must be non-empty and contain no path separators"
        );
        let url = format!("{}/v1/agents/{}/heartbeat", self.base_url, agent_id);
        self.client.post(&url).send().await?.error_for_status()?;
        debug!(agent_id = %agent_id, "heartbeat sent");
        Ok(())
    }

    /// Deregister the agent from daimon.
    ///
    /// # Errors
    /// Returns an error if `agent_id` is invalid, the HTTP request fails,
    /// or daimon returns a non-2xx status.
    pub async fn deregister(&self, agent_id: &str) -> anyhow::Result<()> {
        anyhow::ensure!(
            !agent_id.is_empty() && !agent_id.contains('/') && !agent_id.contains('\\'),
            "invalid agent_id: must be non-empty and contain no path separators"
        );
        let url = format!("{}/v1/agents/{}", self.base_url, agent_id);
        self.client.delete(&url).send().await?.error_for_status()?;
        info!(agent_id = %agent_id, "deregistered from daimon");
        Ok(())
    }

    /// Return the base URL.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Register with daimon and start a background heartbeat loop.
    ///
    /// Returns a `DaimonHandle` — drop or call `shutdown()` to stop
    /// heartbeats and deregister.
    ///
    /// # Errors
    /// Returns an error if the initial registration request fails.
    pub async fn start_lifecycle(self, interval: Duration) -> anyhow::Result<DaimonHandle> {
        let resp = self.register().await?;
        let agent_id = resp.agent_id.clone();
        let client = Arc::new(self);

        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let heartbeat_client = client.clone();
        let heartbeat_id = agent_id.clone();

        let join = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await; // skip first immediate tick

            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        if let Err(e) = heartbeat_client.heartbeat(&heartbeat_id).await {
                            error!(error = %e, "heartbeat failed");
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        debug!("heartbeat loop shutting down");
                        break;
                    }
                }
            }
        });

        Ok(DaimonHandle {
            shutdown_tx,
            join,
            agent_id,
            client,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daimon_client_default_url() {
        let client = DaimonClient::default_local().unwrap();
        assert_eq!(client.base_url(), DAIMON_DEFAULT_URL);
    }

    #[test]
    fn daimon_client_custom_url() {
        let client = DaimonClient::new("http://10.0.0.1:9090").unwrap();
        assert_eq!(client.base_url(), "http://10.0.0.1:9090");
    }

    #[tokio::test]
    async fn heartbeat_rejects_empty_agent_id() {
        let client = DaimonClient::default_local().unwrap();
        assert!(client.heartbeat("").await.is_err());
    }

    #[tokio::test]
    async fn heartbeat_rejects_path_traversal() {
        let client = DaimonClient::default_local().unwrap();
        assert!(client.heartbeat("../etc/passwd").await.is_err());
        assert!(client.heartbeat("foo/bar").await.is_err());
        assert!(client.heartbeat("foo\\bar").await.is_err());
    }

    #[tokio::test]
    async fn deregister_rejects_empty_id() {
        let client = DaimonClient::default_local().unwrap();
        assert!(client.deregister("").await.is_err());
    }

    #[tokio::test]
    async fn deregister_rejects_path_traversal() {
        let client = DaimonClient::default_local().unwrap();
        assert!(client.deregister("../etc").await.is_err());
        assert!(client.deregister("a/b").await.is_err());
    }

    #[test]
    fn client_new_returns_result() {
        assert!(DaimonClient::new("http://localhost:8090").is_ok());
        assert!(DaimonClient::default_local().is_ok());
    }

    #[test]
    fn heartbeat_interval_constant() {
        assert_eq!(HEARTBEAT_INTERVAL, Duration::from_secs(15));
    }
}
