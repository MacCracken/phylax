//! Error types for the Phylax engine.

/// Errors produced by the phylax engine.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PhylaxError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("file too large: {size} bytes (max {max})")]
    FileTooLarge { size: u64, max: u64 },

    #[error("scan timed out after {0}s")]
    Timeout(u64),

    #[error("rule parse error: {0}")]
    RuleParse(String),

    #[error("invalid severity: {0}")]
    InvalidSeverity(String),

    #[error("invalid category: {0}")]
    InvalidCategory(String),

    #[error("scan error: {0}")]
    Scan(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("agent error: {0}")]
    Agent(String),
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, PhylaxError>;
