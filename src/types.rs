//! Core types for the Phylax threat detection engine.
//!
//! Provides scan targets, finding severity/category, threat findings,
//! scan results, and configuration.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use uuid::Uuid;

use crate::error::PhylaxError;

/// Engine version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// ---------------------------------------------------------------------------
// ScanTarget
// ---------------------------------------------------------------------------

/// What is being scanned.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
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
#[non_exhaustive]
pub enum FindingSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl FindingSeverity {
    #[inline]
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
#[non_exhaustive]
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
    #[must_use]
    pub fn is_critical(&self) -> bool {
        self.severity == FindingSeverity::Critical
    }

    /// Compute a stable fingerprint for deduplication across scans.
    ///
    /// The fingerprint is a hex-encoded SHA-256 of `rule_name || target || severity`.
    /// Findings with the same fingerprint across different scans represent the same
    /// issue and can be suppressed via baseline files.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};
        use std::fmt::Write;
        let mut hasher = Sha256::new();
        hasher.update(self.rule_name.as_bytes());
        hasher.update(b"|");
        hasher.update(self.target.to_string().as_bytes());
        hasher.update(b"|");
        hasher.update(self.severity.to_string().as_bytes());
        let result = hasher.finalize();
        let mut s = String::with_capacity(64);
        for &b in result.as_slice() {
            let _ = write!(s, "{b:02x}");
        }
        s
    }
}

// ---------------------------------------------------------------------------
// ScanResult
// ---------------------------------------------------------------------------

/// Result of scanning a target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Scan session ID (shared across all targets in one invocation).
    pub session_id: Uuid,
    pub target: ScanTarget,
    pub findings: Vec<ThreatFinding>,
    pub scan_duration: std::time::Duration,
    pub scanner_version: String,
}

impl ScanResult {
    /// Return the highest severity among all findings, or None if empty.
    #[must_use]
    pub fn highest_severity(&self) -> Option<FindingSeverity> {
        self.findings.iter().map(|f| f.severity).max()
    }

    /// Whether any threats were found.
    #[must_use]
    pub fn has_threats(&self) -> bool {
        !self.findings.is_empty()
    }

    /// Number of findings.
    #[must_use]
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
// Baseline suppression
// ---------------------------------------------------------------------------

/// A set of known finding fingerprints for suppression.
///
/// Load from a previous scan result (JSON) or a `.phylax-ignore` file
/// (one fingerprint or rule name per line).
#[derive(Debug, Default)]
pub struct Baseline {
    fingerprints: std::collections::HashSet<String>,
    rule_names: std::collections::HashSet<String>,
}

impl Baseline {
    /// Load a baseline from a `.phylax-ignore` file.
    ///
    /// Each line is either a 64-char hex fingerprint or a rule name.
    /// Empty lines and lines starting with `#` are skipped.
    pub fn from_ignore_file(content: &str) -> Self {
        let mut b = Self::default();
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
                b.fingerprints.insert(trimmed.to_string());
            } else {
                b.rule_names.insert(trimmed.to_string());
            }
        }
        b
    }

    /// Load a baseline from a previous scan result JSON file.
    ///
    /// Extracts fingerprints from all findings in the scan results.
    pub fn from_scan_json(json: &str) -> Self {
        let mut b = Self::default();
        if let Ok(results) = serde_json::from_str::<Vec<ScanResult>>(json) {
            for result in &results {
                for finding in &result.findings {
                    b.fingerprints.insert(finding.fingerprint());
                }
            }
        }
        // Also try as a ThreatReport
        if b.fingerprints.is_empty() {
            if let Ok(report) = serde_json::from_str::<crate::report::ThreatReport>(json) {
                for result in &report.results {
                    for finding in &result.findings {
                        b.fingerprints.insert(finding.fingerprint());
                    }
                }
            }
        }
        b
    }

    /// Check if a finding should be suppressed.
    #[must_use]
    pub fn is_suppressed(&self, finding: &ThreatFinding) -> bool {
        self.fingerprints.contains(&finding.fingerprint())
            || self.rule_names.contains(&finding.rule_name)
    }

    /// Number of entries in the baseline.
    #[must_use]
    pub fn len(&self) -> usize {
        self.fingerprints.len() + self.rule_names.len()
    }

    /// Whether the baseline is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fingerprints.is_empty() && self.rule_names.is_empty()
    }

    /// Filter a list of findings, removing suppressed ones.
    #[must_use]
    pub fn filter(&self, findings: Vec<ThreatFinding>) -> Vec<ThreatFinding> {
        findings
            .into_iter()
            .filter(|f| !self.is_suppressed(f))
            .collect()
    }
}

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
            session_id: Uuid::new_v4(),
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
            session_id: Uuid::new_v4(),
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
    fn threat_finding_serialization_roundtrip() {
        let f = ThreatFinding::new(
            ScanTarget::File("/tmp/test".into()),
            FindingCategory::Malware,
            FindingSeverity::High,
            "test-rule",
            "test desc",
        );
        let json = serde_json::to_string(&f).unwrap();
        let parsed: ThreatFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.rule_name, "test-rule");
        assert_eq!(parsed.severity, FindingSeverity::High);
        assert_eq!(parsed.category, FindingCategory::Malware);
    }

    #[test]
    fn scan_config_serialization_roundtrip() {
        let cfg = ScanConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let parsed: ScanConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.max_file_size, cfg.max_file_size);
        assert_eq!(parsed.enable_yara, cfg.enable_yara);
    }

    #[test]
    fn category_from_str_all_variants() {
        assert_eq!(
            "ransomware".parse::<FindingCategory>().unwrap(),
            FindingCategory::Ransomware
        );
        assert_eq!(
            "suspicious".parse::<FindingCategory>().unwrap(),
            FindingCategory::Suspicious
        );
        assert_eq!(
            "vulnerable_dependency".parse::<FindingCategory>().unwrap(),
            FindingCategory::VulnerableDependency
        );
        assert_eq!(
            "behavior_anomaly".parse::<FindingCategory>().unwrap(),
            FindingCategory::BehaviorAnomaly
        );
        assert_eq!(
            "custom_rule".parse::<FindingCategory>().unwrap(),
            FindingCategory::CustomRule
        );
    }

    #[test]
    fn severity_from_str_all_variants() {
        assert_eq!(
            "medium".parse::<FindingSeverity>().unwrap(),
            FindingSeverity::Medium
        );
        assert_eq!(
            "low".parse::<FindingSeverity>().unwrap(),
            FindingSeverity::Low
        );
        assert_eq!(
            "info".parse::<FindingSeverity>().unwrap(),
            FindingSeverity::Info
        );
    }

    #[test]
    fn scan_target_serialization_roundtrip() {
        let targets = vec![
            ScanTarget::File("/tmp/test".into()),
            ScanTarget::Agent("agent-1".into()),
            ScanTarget::Package("pkg".into()),
            ScanTarget::Memory,
        ];
        for target in targets {
            let json = serde_json::to_string(&target).unwrap();
            let parsed: ScanTarget = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, target);
        }
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

    // ── Fingerprint + baseline tests ───────────────────────────────────

    #[test]
    fn fingerprint_deterministic() {
        let f = ThreatFinding::new(
            ScanTarget::File("/tmp/test".into()),
            FindingCategory::Malware,
            FindingSeverity::High,
            "test_rule",
            "desc",
        );
        assert_eq!(f.fingerprint().len(), 64);
        assert_eq!(f.fingerprint(), f.fingerprint());
    }

    #[test]
    fn fingerprint_changes_with_rule() {
        let f1 = ThreatFinding::new(
            ScanTarget::Memory,
            FindingCategory::Malware,
            FindingSeverity::High,
            "rule_a",
            "desc",
        );
        let f2 = ThreatFinding::new(
            ScanTarget::Memory,
            FindingCategory::Malware,
            FindingSeverity::High,
            "rule_b",
            "desc",
        );
        assert_ne!(f1.fingerprint(), f2.fingerprint());
    }

    #[test]
    fn baseline_from_ignore_file() {
        let content = "# comment\nhigh_entropy\n\nabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\n";
        let baseline = Baseline::from_ignore_file(content);
        assert_eq!(baseline.rule_names.len(), 1);
        assert_eq!(baseline.fingerprints.len(), 1);
        assert!(baseline.rule_names.contains("high_entropy"));
    }

    #[test]
    fn baseline_suppresses_by_rule_name() {
        let baseline = Baseline::from_ignore_file("test_rule\n");
        let f = ThreatFinding::new(
            ScanTarget::Memory,
            FindingCategory::Suspicious,
            FindingSeverity::Low,
            "test_rule",
            "desc",
        );
        assert!(baseline.is_suppressed(&f));
    }

    #[test]
    fn baseline_suppresses_by_fingerprint() {
        let f = ThreatFinding::new(
            ScanTarget::Memory,
            FindingCategory::Suspicious,
            FindingSeverity::Low,
            "test_rule",
            "desc",
        );
        let fp = f.fingerprint();
        let baseline = Baseline::from_ignore_file(&fp);
        assert!(baseline.is_suppressed(&f));
    }

    #[test]
    fn baseline_filter() {
        let baseline = Baseline::from_ignore_file("suppress_me\n");
        let findings = vec![
            ThreatFinding::new(
                ScanTarget::Memory,
                FindingCategory::Suspicious,
                FindingSeverity::Low,
                "suppress_me",
                "will be filtered",
            ),
            ThreatFinding::new(
                ScanTarget::Memory,
                FindingCategory::Suspicious,
                FindingSeverity::High,
                "keep_me",
                "will remain",
            ),
        ];
        let filtered = baseline.filter(findings);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].rule_name, "keep_me");
    }

    #[test]
    fn baseline_empty() {
        let baseline = Baseline::default();
        assert!(baseline.is_empty());
        assert_eq!(baseline.len(), 0);
    }
}
