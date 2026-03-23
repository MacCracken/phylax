//! Error types for the Phylax engine.
//!
//! # Error Strategy
//!
//! Phylax uses three error approaches depending on context:
//!
//! | Module | Error Type | Rationale |
//! |--------|-----------|-----------|
//! | `yara` | `YaraError` (custom enum) | Domain-specific parse/validation errors |
//! | `quarantine` | `std::io::Result` | Pure filesystem operations |
//! | `hoosh`, `daimon` | `anyhow::Result` | HTTP clients with diverse error sources |
//! | `watch` | `anyhow::Result` | Wraps `notify` crate errors |
//! | `pe`, `elf` | `Option` (returns `None`) | Parsing untrusted data — absence, not error |
//!
//! `PhylaxError` below is the top-level error enum for core engine operations.

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_error_display() {
        let e = PhylaxError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "gone"));
        assert!(e.to_string().contains("gone"));
    }

    #[test]
    fn file_too_large_display() {
        let e = PhylaxError::FileTooLarge { size: 100, max: 50 };
        let msg = e.to_string();
        assert!(msg.contains("100"));
        assert!(msg.contains("50"));
    }

    #[test]
    fn timeout_display() {
        let e = PhylaxError::Timeout(30);
        assert!(e.to_string().contains("30"));
    }

    #[test]
    fn rule_parse_display() {
        let e = PhylaxError::RuleParse("bad rule".into());
        assert!(e.to_string().contains("bad rule"));
    }

    #[test]
    fn scan_error_display() {
        let e = PhylaxError::Scan("scan failed".into());
        assert!(e.to_string().contains("scan failed"));
    }

    #[test]
    fn config_error_display() {
        let e = PhylaxError::Config("missing field".into());
        assert!(e.to_string().contains("missing field"));
    }

    #[test]
    fn serialization_error_display() {
        let e = PhylaxError::Serialization("invalid json".into());
        assert!(e.to_string().contains("invalid json"));
    }

    #[test]
    fn agent_error_display() {
        let e = PhylaxError::Agent("connection refused".into());
        assert!(e.to_string().contains("connection refused"));
    }

    #[test]
    fn io_error_from_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let phylax_err: PhylaxError = io_err.into();
        assert!(matches!(phylax_err, PhylaxError::Io(_)));
    }
}
