//! YARA-compatible rule engine for Phylax.
//!
//! Provides pattern types, rule definitions, conditions, and a scanning engine
//! that performs real byte-level pattern matching.

use crate::core::{FindingCategory, FindingSeverity, ScanTarget, ThreatFinding};
use regex::bytes::Regex;
use serde::Deserialize;
use tracing::{debug, instrument, trace, warn};

// ---------------------------------------------------------------------------
// YaraPattern
// ---------------------------------------------------------------------------

/// A pattern to match within binary data.
///
/// Regex patterns are compiled once at construction time and cached.
#[derive(Debug, Clone)]
pub enum YaraPattern {
    /// Exact byte sequence.
    Literal(Vec<u8>),
    /// Hex-encoded byte sequence (stored as raw bytes).
    Hex(Vec<u8>),
    /// Compiled regular expression (applied to raw bytes).
    Regex(Regex),
}

impl YaraPattern {
    /// Create a regex pattern, compiling it upfront.
    pub fn regex(pattern: &str) -> std::result::Result<Self, regex::Error> {
        Regex::new(pattern).map(Self::Regex)
    }

    /// Check whether this pattern matches anywhere in `data`.
    pub fn matches(&self, data: &[u8]) -> bool {
        match self {
            Self::Literal(needle) | Self::Hex(needle) => {
                if needle.is_empty() {
                    return false;
                }
                data.windows(needle.len()).any(|w| w == needle.as_slice())
            }
            Self::Regex(re) => re.is_match(data),
        }
    }
}

// ---------------------------------------------------------------------------
// RuleCondition
// ---------------------------------------------------------------------------

/// How many patterns must match for the rule to fire.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum RuleCondition {
    /// All patterns must match.
    All,
    /// At least one pattern must match.
    Any,
    /// At least N patterns must match.
    AtLeast(usize),
}

// ---------------------------------------------------------------------------
// YaraRule
// ---------------------------------------------------------------------------

/// A single YARA-style rule.
#[derive(Debug, Clone)]
pub struct YaraRule {
    pub name: String,
    pub description: String,
    pub severity: FindingSeverity,
    pub tags: Vec<String>,
    /// Named patterns: (identifier, pattern).
    pub patterns: Vec<(String, YaraPattern)>,
    pub condition: RuleCondition,
}

// ---------------------------------------------------------------------------
// YaraError
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum YaraError {
    #[error("rule parse error: {0}")]
    Parse(String),

    #[error("invalid hex string: {0}")]
    InvalidHex(String),

    #[error("invalid regex: {0}")]
    InvalidRegex(String),

    #[error("TOML parse error: {0}")]
    Toml(String),
}

pub type Result<T> = std::result::Result<T, YaraError>;

// ---------------------------------------------------------------------------
// TOML schema for rule loading
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct RulesFile {
    #[serde(default)]
    rule: Vec<TomlRule>,
}

#[derive(Debug, Deserialize)]
struct TomlRule {
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default = "default_severity")]
    severity: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default = "default_condition")]
    condition: String,
    #[serde(default)]
    patterns: Vec<TomlPattern>,
}

#[derive(Debug, Deserialize)]
struct TomlPattern {
    id: String,
    #[serde(default = "default_pattern_type")]
    r#type: String,
    value: String,
}

fn default_severity() -> String {
    "medium".into()
}
fn default_condition() -> String {
    "any".into()
}
fn default_pattern_type() -> String {
    "literal".into()
}

/// Parse a hex string like "4d5a90" into bytes.
fn parse_hex(s: &str) -> Result<Vec<u8>> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.len() % 2 != 0 {
        return Err(YaraError::InvalidHex(s.to_string()));
    }
    (0..clean.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&clean[i..i + 2], 16)
                .map_err(|_| YaraError::InvalidHex(s.to_string()))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// YaraEngine
// ---------------------------------------------------------------------------

/// The YARA scanning engine. Holds a set of rules and matches them against data.
#[derive(Debug, Default)]
pub struct YaraEngine {
    rules: Vec<YaraRule>,
}

impl YaraEngine {
    /// Create an empty engine.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a single rule.
    pub fn add_rule(&mut self, rule: YaraRule) {
        self.rules.push(rule);
    }

    /// Load rules from a TOML string.
    #[instrument(skip(self, toml_str), fields(toml_len = toml_str.len()))]
    pub fn load_rules_toml(&mut self, toml_str: &str) -> Result<usize> {
        let file: RulesFile = toml::from_str(toml_str).map_err(|e| {
            warn!(error = %e, "failed to parse TOML rules");
            YaraError::Toml(e.to_string())
        })?;

        let mut count = 0;
        for tr in file.rule {
            let severity: FindingSeverity = tr
                .severity
                .parse()
                .map_err(|_| YaraError::Parse(format!("invalid severity: {}", tr.severity)))?;

            let condition = match tr.condition.to_lowercase().as_str() {
                "all" => RuleCondition::All,
                "any" => RuleCondition::Any,
                s if s.starts_with("at_least_") => {
                    let n: usize = s
                        .strip_prefix("at_least_")
                        .unwrap()
                        .parse()
                        .map_err(|_| YaraError::Parse(format!("invalid condition: {s}")))?;
                    RuleCondition::AtLeast(n)
                }
                _ => {
                    return Err(YaraError::Parse(format!(
                        "unknown condition: {}",
                        tr.condition
                    )));
                }
            };

            let mut patterns = Vec::new();
            for p in tr.patterns {
                let pat = match p.r#type.as_str() {
                    "literal" => YaraPattern::Literal(p.value.as_bytes().to_vec()),
                    "hex" => YaraPattern::Hex(parse_hex(&p.value)?),
                    "regex" => YaraPattern::regex(&p.value)
                        .map_err(|e| YaraError::InvalidRegex(e.to_string()))?,
                    _ => {
                        return Err(YaraError::Parse(format!(
                            "unknown pattern type: {}",
                            p.r#type
                        )));
                    }
                };
                patterns.push((p.id, pat));
            }

            let rule_name = tr.name.clone();
            self.rules.push(YaraRule {
                name: tr.name,
                description: tr.description.unwrap_or_default(),
                severity,
                tags: tr.tags,
                patterns,
                condition,
            });
            debug!(rule = %rule_name, "loaded YARA rule");
            count += 1;
        }

        debug!(count, "finished loading TOML rules");
        Ok(count)
    }

    /// Scan data against all loaded rules.
    #[instrument(skip(self, data), fields(data_len = data.len(), rule_count = self.rules.len()))]
    pub fn scan(&self, data: &[u8]) -> Vec<ThreatFinding> {
        let mut findings = Vec::new();

        for rule in &self.rules {
            let match_count = rule
                .patterns
                .iter()
                .filter(|(_, p)| p.matches(data))
                .count();
            let total = rule.patterns.len();

            let matched = match &rule.condition {
                RuleCondition::All => match_count == total && total > 0,
                RuleCondition::Any => match_count > 0,
                RuleCondition::AtLeast(n) => match_count >= *n,
            };

            if matched {
                trace!(rule = %rule.name, match_count, total, "rule matched");
                let mut finding = ThreatFinding::new(
                    ScanTarget::Memory,
                    FindingCategory::CustomRule,
                    rule.severity,
                    &rule.name,
                    &rule.description,
                );
                finding
                    .metadata
                    .insert("matched_patterns".into(), match_count.to_string());
                finding
                    .metadata
                    .insert("total_patterns".into(), total.to_string());
                for tag in &rule.tags {
                    finding.metadata.insert(format!("tag:{tag}"), "true".into());
                }
                findings.push(finding);
            }
        }

        findings
    }

    /// Number of loaded rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Get all loaded rules (read-only).
    pub fn rules(&self) -> &[YaraRule] {
        &self.rules
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_pattern_match() {
        let p = YaraPattern::Literal(b"MZ".to_vec());
        assert!(p.matches(b"MZ\x90\x00"));
        assert!(!p.matches(b"ELF"));
    }

    #[test]
    fn hex_pattern_match() {
        let p = YaraPattern::Hex(vec![0x7f, 0x45, 0x4c, 0x46]);
        assert!(p.matches(b"\x7fELF\x02\x01"));
        assert!(!p.matches(b"MZ\x90\x00"));
    }

    #[test]
    fn regex_pattern_match() {
        let p = YaraPattern::regex(r"(?-u)\x7fELF").unwrap();
        assert!(p.matches(b"\x7fELF\x02"));
        assert!(!p.matches(b"not elf"));
    }

    #[test]
    fn empty_literal_no_match() {
        let p = YaraPattern::Literal(vec![]);
        assert!(!p.matches(b"anything"));
    }

    #[test]
    fn invalid_regex_rejected() {
        assert!(YaraPattern::regex("[invalid").is_err());
    }

    #[test]
    fn engine_add_rule() {
        let mut engine = YaraEngine::new();
        assert_eq!(engine.rule_count(), 0);
        engine.add_rule(YaraRule {
            name: "test".into(),
            description: "desc".into(),
            severity: FindingSeverity::Low,
            tags: vec![],
            patterns: vec![("$a".into(), YaraPattern::Literal(b"test".to_vec()))],
            condition: RuleCondition::Any,
        });
        assert_eq!(engine.rule_count(), 1);
    }

    #[test]
    fn engine_scan_match() {
        let mut engine = YaraEngine::new();
        engine.add_rule(YaraRule {
            name: "detect_mz".into(),
            description: "PE executable".into(),
            severity: FindingSeverity::Medium,
            tags: vec!["pe".into()],
            patterns: vec![("$mz".into(), YaraPattern::Literal(b"MZ".to_vec()))],
            condition: RuleCondition::Any,
        });

        let findings = engine.scan(b"MZ\x90\x00\x03\x00");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_name, "detect_mz");
        assert_eq!(findings[0].severity, FindingSeverity::Medium);
    }

    #[test]
    fn engine_scan_no_match() {
        let mut engine = YaraEngine::new();
        engine.add_rule(YaraRule {
            name: "detect_mz".into(),
            description: "PE".into(),
            severity: FindingSeverity::Medium,
            tags: vec![],
            patterns: vec![("$mz".into(), YaraPattern::Literal(b"MZ".to_vec()))],
            condition: RuleCondition::Any,
        });
        let findings = engine.scan(b"\x7fELF");
        assert!(findings.is_empty());
    }

    #[test]
    fn engine_condition_all() {
        let mut engine = YaraEngine::new();
        engine.add_rule(YaraRule {
            name: "multi".into(),
            description: "needs both".into(),
            severity: FindingSeverity::High,
            tags: vec![],
            patterns: vec![
                ("$a".into(), YaraPattern::Literal(b"AA".to_vec())),
                ("$b".into(), YaraPattern::Literal(b"BB".to_vec())),
            ],
            condition: RuleCondition::All,
        });

        assert!(engine.scan(b"only AA here").is_empty());
        assert_eq!(engine.scan(b"AA and BB together").len(), 1);
    }

    #[test]
    fn engine_condition_at_least() {
        let mut engine = YaraEngine::new();
        engine.add_rule(YaraRule {
            name: "atleast2".into(),
            description: "need 2 of 3".into(),
            severity: FindingSeverity::Low,
            tags: vec![],
            patterns: vec![
                ("$a".into(), YaraPattern::Literal(b"AA".to_vec())),
                ("$b".into(), YaraPattern::Literal(b"BB".to_vec())),
                ("$c".into(), YaraPattern::Literal(b"CC".to_vec())),
            ],
            condition: RuleCondition::AtLeast(2),
        });

        assert!(engine.scan(b"only AA").is_empty());
        assert_eq!(engine.scan(b"AA and BB").len(), 1);
        assert_eq!(engine.scan(b"AA BB CC").len(), 1);
    }

    #[test]
    fn load_rules_toml_basic() {
        let mut engine = YaraEngine::new();
        let toml = r#"
[[rule]]
name = "elf_detect"
description = "Detects ELF binaries"
severity = "medium"
tags = ["elf", "linux"]
condition = "any"

[[rule.patterns]]
id = "$magic"
type = "hex"
value = "7f454c46"
"#;
        let count = engine.load_rules_toml(toml).unwrap();
        assert_eq!(count, 1);
        assert_eq!(engine.rule_count(), 1);

        let findings = engine.scan(b"\x7fELF\x02\x01\x01");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_name, "elf_detect");
    }

    #[test]
    fn load_rules_toml_multiple() {
        let mut engine = YaraEngine::new();
        let toml = r#"
[[rule]]
name = "rule_a"
severity = "low"
condition = "any"
[[rule.patterns]]
id = "$a"
type = "literal"
value = "AAAA"

[[rule]]
name = "rule_b"
severity = "high"
condition = "any"
[[rule.patterns]]
id = "$b"
type = "literal"
value = "BBBB"
"#;
        let count = engine.load_rules_toml(toml).unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn load_rules_toml_regex_pattern() {
        let mut engine = YaraEngine::new();
        let toml = r#"
[[rule]]
name = "script_detect"
severity = "info"
condition = "any"
[[rule.patterns]]
id = "$shebang"
type = "regex"
value = "^#!"
"#;
        engine.load_rules_toml(toml).unwrap();
        assert_eq!(engine.scan(b"#!/bin/bash\necho hi").len(), 1);
        assert!(engine.scan(b"no shebang").is_empty());
    }

    #[test]
    fn load_rules_toml_invalid_severity() {
        let mut engine = YaraEngine::new();
        let toml = r#"
[[rule]]
name = "bad"
severity = "ultra"
condition = "any"
"#;
        assert!(engine.load_rules_toml(toml).is_err());
    }

    #[test]
    fn parse_hex_valid() {
        assert_eq!(parse_hex("4d5a").unwrap(), vec![0x4d, 0x5a]);
        assert_eq!(
            parse_hex("7f 45 4c 46").unwrap(),
            vec![0x7f, 0x45, 0x4c, 0x46]
        );
    }

    #[test]
    fn parse_hex_invalid() {
        assert!(parse_hex("4d5").is_err()); // odd length
        assert!(parse_hex("ZZZZ").is_err()); // not hex
    }

    #[test]
    fn engine_rules_accessor() {
        let mut engine = YaraEngine::new();
        engine.add_rule(YaraRule {
            name: "r1".into(),
            description: String::new(),
            severity: FindingSeverity::Info,
            tags: vec![],
            patterns: vec![],
            condition: RuleCondition::Any,
        });
        assert_eq!(engine.rules().len(), 1);
        assert_eq!(engine.rules()[0].name, "r1");
    }

    #[test]
    fn regex_pattern_compiled_once() {
        // Regex should work without recompilation on each call
        let p = YaraPattern::regex(r"(?-u)\x7fELF").unwrap();
        // Multiple calls should all work (cached regex)
        assert!(p.matches(b"\x7fELF"));
        assert!(p.matches(b"\x7fELF"));
        assert!(!p.matches(b"nope"));
    }

    #[test]
    fn load_rules_toml_invalid_regex() {
        let mut engine = YaraEngine::new();
        let toml = r#"
[[rule]]
name = "bad_regex"
severity = "low"
condition = "any"
[[rule.patterns]]
id = "$bad"
type = "regex"
value = "[invalid"
"#;
        let err = engine.load_rules_toml(toml);
        assert!(err.is_err());
    }

    #[test]
    fn load_rules_toml_unknown_pattern_type() {
        let mut engine = YaraEngine::new();
        let toml = r#"
[[rule]]
name = "bad_type"
severity = "low"
condition = "any"
[[rule.patterns]]
id = "$x"
type = "binary"
value = "data"
"#;
        let err = engine.load_rules_toml(toml);
        assert!(err.is_err());
    }

    #[test]
    fn load_rules_toml_unknown_condition() {
        let mut engine = YaraEngine::new();
        let toml = r#"
[[rule]]
name = "bad_cond"
severity = "low"
condition = "maybe"
"#;
        let err = engine.load_rules_toml(toml);
        assert!(err.is_err());
    }

    #[test]
    fn load_rules_toml_at_least_condition() {
        let mut engine = YaraEngine::new();
        let toml = r#"
[[rule]]
name = "at_least"
severity = "low"
condition = "at_least_2"
[[rule.patterns]]
id = "$a"
type = "literal"
value = "AA"
[[rule.patterns]]
id = "$b"
type = "literal"
value = "BB"
[[rule.patterns]]
id = "$c"
type = "literal"
value = "CC"
"#;
        engine.load_rules_toml(toml).unwrap();
        assert!(engine.scan(b"only AA").is_empty());
        assert_eq!(engine.scan(b"AA and BB").len(), 1);
    }

    #[test]
    fn empty_rules_file() {
        let mut engine = YaraEngine::new();
        let count = engine.load_rules_toml("").unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn scan_empty_data() {
        let mut engine = YaraEngine::new();
        engine.add_rule(YaraRule {
            name: "test".into(),
            description: String::new(),
            severity: FindingSeverity::Low,
            tags: vec![],
            patterns: vec![("$a".into(), YaraPattern::Literal(b"X".to_vec()))],
            condition: RuleCondition::Any,
        });
        assert!(engine.scan(b"").is_empty());
    }

    #[test]
    fn load_rules_toml_defaults() {
        // severity defaults to "medium", condition defaults to "any", type defaults to "literal"
        let mut engine = YaraEngine::new();
        let toml = r#"
[[rule]]
name = "defaults_test"
[[rule.patterns]]
id = "$a"
value = "TEST"
"#;
        engine.load_rules_toml(toml).unwrap();
        let rules = engine.rules();
        assert_eq!(rules[0].severity, FindingSeverity::Medium);
        assert!(matches!(rules[0].condition, RuleCondition::Any));
        assert_eq!(engine.scan(b"has TEST in it").len(), 1);
    }

    #[test]
    fn parse_hex_uppercase() {
        assert_eq!(parse_hex("4D5A").unwrap(), vec![0x4d, 0x5a]);
        assert_eq!(parse_hex("7F454C46").unwrap(), vec![0x7f, 0x45, 0x4c, 0x46]);
    }

    #[test]
    fn parse_hex_mixed_case() {
        assert_eq!(parse_hex("4d5A").unwrap(), vec![0x4d, 0x5a]);
    }

    #[test]
    fn parse_hex_empty() {
        assert_eq!(parse_hex("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn multiple_rules_multiple_matches() {
        let mut engine = YaraEngine::new();
        let toml = r#"
[[rule]]
name = "rule_a"
severity = "low"
condition = "any"
[[rule.patterns]]
id = "$a"
type = "literal"
value = "COMMON"

[[rule]]
name = "rule_b"
severity = "high"
condition = "any"
[[rule.patterns]]
id = "$b"
type = "literal"
value = "COMMON"
"#;
        engine.load_rules_toml(toml).unwrap();
        let findings = engine.scan(b"data with COMMON string");
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn scan_tags_in_metadata() {
        let mut engine = YaraEngine::new();
        engine.add_rule(YaraRule {
            name: "tagged".into(),
            description: String::new(),
            severity: FindingSeverity::Info,
            tags: vec!["malware".into(), "pe".into()],
            patterns: vec![("$a".into(), YaraPattern::Literal(b"X".to_vec()))],
            condition: RuleCondition::Any,
        });
        let findings = engine.scan(b"X");
        assert_eq!(findings[0].metadata.get("tag:malware").unwrap(), "true");
        assert_eq!(findings[0].metadata.get("tag:pe").unwrap(), "true");
    }
}
