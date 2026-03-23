//! phylax-core — Core types for the Phylax threat detection engine.
//!
//! Provides scan targets, finding severity/category, threat findings,
//! scan results, configuration, and error types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// ScanTarget
// ---------------------------------------------------------------------------

/// What is being scanned.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ScanTarget {
    /// A file on disk.
    File(PathBuf),
    /// A running agent by name.
    Agent(String),
    /// A package by name.
    Package(String),
    /// In-memory data (e.g. a buffer passed directly).
    Memory,
}

impl fmt::Display for ScanTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File(p) => write!(f, "file:{}", p.display()),
            Self::Agent(name) => write!(f, "agent:{name}"),
            Self::Package(name) => write!(f, "package:{name}"),
            Self::Memory => write!(f, "memory"),
        }
    }
}

// ---------------------------------------------------------------------------
// FindingSeverity
// ---------------------------------------------------------------------------

/// Severity of a threat finding. Ordered so that Critical > High > Medium > Low > Info.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FindingSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl FindingSeverity {
    fn rank(self) -> u8 {
        match self {
            Self::Critical => 4,
            Self::High => 3,
            Self::Medium => 2,
            Self::Low => 1,
            Self::Info => 0,
        }
    }
}

impl PartialOrd for FindingSeverity {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FindingSeverity {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl fmt::Display for FindingSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Critical => write!(f, "CRITICAL"),
            Self::High => write!(f, "HIGH"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::Low => write!(f, "LOW"),
            Self::Info => write!(f, "INFO"),
        }
    }
}

impl std::str::FromStr for FindingSeverity {
    type Err = PhylaxError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "critical" => Ok(Self::Critical),
            "high" => Ok(Self::High),
            "medium" => Ok(Self::Medium),
            "low" => Ok(Self::Low),
            "info" => Ok(Self::Info),
            _ => Err(PhylaxError::InvalidSeverity(s.to_string())),
        }
    }
}

// ---------------------------------------------------------------------------
// FindingCategory
// ---------------------------------------------------------------------------

/// Category of threat finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FindingCategory {
    Malware,
    Ransomware,
    Suspicious,
    EmbeddedPayload,
    VulnerableDependency,
    BehaviorAnomaly,
    CustomRule,
}

impl fmt::Display for FindingCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malware => write!(f, "Malware"),
            Self::Ransomware => write!(f, "Ransomware"),
            Self::Suspicious => write!(f, "Suspicious"),
            Self::EmbeddedPayload => write!(f, "Embedded Payload"),
            Self::VulnerableDependency => write!(f, "Vulnerable Dependency"),
            Self::BehaviorAnomaly => write!(f, "Behavior Anomaly"),
            Self::CustomRule => write!(f, "Custom Rule"),
        }
    }
}

impl std::str::FromStr for FindingCategory {
    type Err = PhylaxError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().replace(' ', "_").as_str() {
            "malware" => Ok(Self::Malware),
            "ransomware" => Ok(Self::Ransomware),
            "suspicious" => Ok(Self::Suspicious),
            "embedded_payload" => Ok(Self::EmbeddedPayload),
            "vulnerable_dependency" => Ok(Self::VulnerableDependency),
            "behavior_anomaly" => Ok(Self::BehaviorAnomaly),
            "custom_rule" => Ok(Self::CustomRule),
            _ => Err(PhylaxError::InvalidCategory(s.to_string())),
        }
    }
}

// ---------------------------------------------------------------------------
// ThreatFinding
// ---------------------------------------------------------------------------

/// A single threat finding produced by a scanner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFinding {
    pub id: Uuid,
    pub target: ScanTarget,
    pub category: FindingCategory,
    pub severity: FindingSeverity,
    pub rule_name: String,
    pub description: String,
    pub metadata: HashMap<String, String>,
    pub timestamp: DateTime<Utc>,
}

impl ThreatFinding {
    /// Create a new finding with the given fields. Generates a UUID and timestamp.
    pub fn new(
        target: ScanTarget,
        category: FindingCategory,
        severity: FindingSeverity,
        rule_name: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            target,
            category,
            severity,
            rule_name: rule_name.into(),
            description: description.into(),
            metadata: HashMap::new(),
            timestamp: Utc::now(),
        }
    }

    /// Whether this finding is critical severity.
    pub fn is_critical(&self) -> bool {
        self.severity == FindingSeverity::Critical
    }
}

// ---------------------------------------------------------------------------
// ScanResult
// ---------------------------------------------------------------------------

/// Result of scanning a target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub target: ScanTarget,
    pub findings: Vec<ThreatFinding>,
    pub scan_duration: std::time::Duration,
    pub scanner_version: String,
}

impl ScanResult {
    /// Return the highest severity among all findings, or None if empty.
    pub fn highest_severity(&self) -> Option<FindingSeverity> {
        self.findings.iter().map(|f| f.severity).max()
    }

    /// Whether any threats were found.
    pub fn has_threats(&self) -> bool {
        !self.findings.is_empty()
    }

    /// Number of findings.
    pub fn finding_count(&self) -> usize {
        self.findings.len()
    }
}

// ---------------------------------------------------------------------------
// ScanConfig
// ---------------------------------------------------------------------------

/// Configuration for a scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    /// Maximum file size in bytes (default 50 MB).
    pub max_file_size: u64,
    /// Timeout for a single scan in seconds (default 60).
    pub timeout_secs: u64,
    /// Enable YARA rule scanning.
    pub enable_yara: bool,
    /// Enable entropy analysis.
    pub enable_entropy: bool,
    /// Enable magic bytes / file type detection.
    pub enable_magic_bytes: bool,
    /// Enable ML classification.
    pub enable_ml: bool,
    /// Custom rule paths.
    pub rule_paths: Vec<PathBuf>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            max_file_size: 50 * 1024 * 1024, // 50 MB
            timeout_secs: 60,
            enable_yara: true,
            enable_entropy: true,
            enable_magic_bytes: true,
            enable_ml: true,
            rule_paths: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// PhylaxError
// ---------------------------------------------------------------------------

/// Errors produced by the phylax engine.
#[derive(Debug, thiserror::Error)]
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

/// Engine version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_target_display_file() {
        let t = ScanTarget::File(PathBuf::from("/tmp/malware.bin"));
        assert_eq!(t.to_string(), "file:/tmp/malware.bin");
    }

    #[test]
    fn scan_target_display_agent() {
        let t = ScanTarget::Agent("my-agent".into());
        assert_eq!(t.to_string(), "agent:my-agent");
    }

    #[test]
    fn scan_target_display_package() {
        let t = ScanTarget::Package("foo".into());
        assert_eq!(t.to_string(), "package:foo");
    }

    #[test]
    fn scan_target_display_memory() {
        assert_eq!(ScanTarget::Memory.to_string(), "memory");
    }

    #[test]
    fn severity_ordering() {
        assert!(FindingSeverity::Critical > FindingSeverity::High);
        assert!(FindingSeverity::High > FindingSeverity::Medium);
        assert!(FindingSeverity::Medium > FindingSeverity::Low);
        assert!(FindingSeverity::Low > FindingSeverity::Info);
    }

    #[test]
    fn severity_display() {
        assert_eq!(FindingSeverity::Critical.to_string(), "CRITICAL");
        assert_eq!(FindingSeverity::Info.to_string(), "INFO");
    }

    #[test]
    fn severity_from_str() {
        assert_eq!(
            "critical".parse::<FindingSeverity>().unwrap(),
            FindingSeverity::Critical
        );
        assert_eq!(
            "HIGH".parse::<FindingSeverity>().unwrap(),
            FindingSeverity::High
        );
        assert!("bogus".parse::<FindingSeverity>().is_err());
    }

    #[test]
    fn category_display() {
        assert_eq!(FindingCategory::Malware.to_string(), "Malware");
        assert_eq!(
            FindingCategory::EmbeddedPayload.to_string(),
            "Embedded Payload"
        );
    }

    #[test]
    fn category_from_str() {
        assert_eq!(
            "malware".parse::<FindingCategory>().unwrap(),
            FindingCategory::Malware
        );
        assert_eq!(
            "embedded_payload".parse::<FindingCategory>().unwrap(),
            FindingCategory::EmbeddedPayload
        );
        assert!("nope".parse::<FindingCategory>().is_err());
    }

    #[test]
    fn threat_finding_new() {
        let f = ThreatFinding::new(
            ScanTarget::Memory,
            FindingCategory::Suspicious,
            FindingSeverity::Medium,
            "test-rule",
            "test desc",
        );
        assert_eq!(f.rule_name, "test-rule");
        assert!(!f.is_critical());
    }

    #[test]
    fn threat_finding_is_critical() {
        let f = ThreatFinding::new(
            ScanTarget::Memory,
            FindingCategory::Malware,
            FindingSeverity::Critical,
            "crit-rule",
            "critical finding",
        );
        assert!(f.is_critical());
    }

    #[test]
    fn scan_result_empty() {
        let r = ScanResult {
            target: ScanTarget::Memory,
            findings: vec![],
            scan_duration: std::time::Duration::from_millis(10),
            scanner_version: "0.1.0".into(),
        };
        assert!(!r.has_threats());
        assert_eq!(r.finding_count(), 0);
        assert!(r.highest_severity().is_none());
    }

    #[test]
    fn scan_result_highest_severity() {
        let r = ScanResult {
            target: ScanTarget::Memory,
            findings: vec![
                ThreatFinding::new(
                    ScanTarget::Memory,
                    FindingCategory::Suspicious,
                    FindingSeverity::Low,
                    "r1",
                    "d1",
                ),
                ThreatFinding::new(
                    ScanTarget::Memory,
                    FindingCategory::Malware,
                    FindingSeverity::High,
                    "r2",
                    "d2",
                ),
                ThreatFinding::new(
                    ScanTarget::Memory,
                    FindingCategory::Suspicious,
                    FindingSeverity::Medium,
                    "r3",
                    "d3",
                ),
            ],
            scan_duration: std::time::Duration::from_millis(50),
            scanner_version: "0.1.0".into(),
        };
        assert!(r.has_threats());
        assert_eq!(r.finding_count(), 3);
        assert_eq!(r.highest_severity(), Some(FindingSeverity::High));
    }

    #[test]
    fn scan_config_defaults() {
        let cfg = ScanConfig::default();
        assert_eq!(cfg.max_file_size, 50 * 1024 * 1024);
        assert_eq!(cfg.timeout_secs, 60);
        assert!(cfg.enable_yara);
        assert!(cfg.enable_entropy);
        assert!(cfg.enable_magic_bytes);
        assert!(cfg.enable_ml);
        assert!(cfg.rule_paths.is_empty());
    }

    #[test]
    fn error_display() {
        let e = PhylaxError::FileTooLarge { size: 100, max: 50 };
        assert!(e.to_string().contains("100"));
        assert!(e.to_string().contains("50"));
    }

    #[test]
    fn scan_target_equality() {
        assert_eq!(ScanTarget::Memory, ScanTarget::Memory);
        assert_ne!(ScanTarget::Memory, ScanTarget::Agent("x".into()));
    }

    #[test]
    fn finding_metadata() {
        let mut f = ThreatFinding::new(
            ScanTarget::File("/bin/test".into()),
            FindingCategory::CustomRule,
            FindingSeverity::Info,
            "meta-rule",
            "desc",
        );
        f.metadata.insert("key".into(), "value".into());
        assert_eq!(f.metadata.get("key").unwrap(), "value");
    }

    #[test]
    fn severity_sort() {
        let mut sevs = vec![
            FindingSeverity::Low,
            FindingSeverity::Critical,
            FindingSeverity::Info,
            FindingSeverity::High,
            FindingSeverity::Medium,
        ];
        sevs.sort();
        assert_eq!(
            sevs,
            vec![
                FindingSeverity::Info,
                FindingSeverity::Low,
                FindingSeverity::Medium,
                FindingSeverity::High,
                FindingSeverity::Critical,
            ]
        );
    }
}
