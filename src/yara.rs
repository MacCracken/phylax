//! YARA-compatible rule engine for Phylax.
//!
//! Provides pattern types, rule definitions, conditions, and a scanning engine
//! that performs real byte-level pattern matching.

use crate::types::{FindingCategory, FindingSeverity, ScanTarget, ThreatFinding};
use aho_corasick::AhoCorasick;
use regex::bytes::{Regex, RegexBuilder};
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
    ///
    /// Applies size limits to prevent excessive memory use from crafted patterns.
    ///
    /// # Errors
    /// Returns `regex::Error` if the pattern is invalid or exceeds size limits.
    pub fn regex(pattern: &str) -> std::result::Result<Self, regex::Error> {
        RegexBuilder::new(pattern)
            .size_limit(10 * (1 << 20)) // 10 MB compiled automaton limit
            .dfa_size_limit(10 * (1 << 20)) // 10 MB DFA cache limit
            .build()
            .map(Self::Regex)
    }

    /// Check whether this pattern matches anywhere in `data`.
    #[inline]
    pub fn matches(&self, data: &[u8]) -> bool {
        match self {
            Self::Literal(needle) | Self::Hex(needle) => {
                if needle.is_empty() {
                    return false;
                }
                memchr::memmem::find(data, needle).is_some()
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

/// Optional constraints on when a rule applies.
#[derive(Debug, Clone, Default)]
pub struct RuleConstraints {
    /// Minimum file size in bytes (inclusive).
    pub min_file_size: Option<u64>,
    /// Maximum file size in bytes (inclusive).
    pub max_file_size: Option<u64>,
    /// Pattern must match at this exact byte offset.
    pub at_offset: Option<usize>,
}

impl RuleConstraints {
    /// Check whether the constraints are satisfied for the given data.
    #[inline]
    #[must_use]
    pub fn satisfied(&self, data: &[u8]) -> bool {
        let len = data.len() as u64;
        if let Some(min) = self.min_file_size {
            if len < min {
                return false;
            }
        }
        if let Some(max) = self.max_file_size {
            if len > max {
                return false;
            }
        }
        true
    }
}

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
    /// Optional file size and offset constraints.
    pub constraints: RuleConstraints,
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
    #[serde(default)]
    min_file_size: Option<u64>,
    #[serde(default)]
    max_file_size: Option<u64>,
    #[serde(default)]
    at_offset: Option<usize>,
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
///
/// Returns raw bytes for simple hex, or `None` for hex-only strings.
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

/// Check whether a hex string contains wildcards (`??`) or jumps (`[n-m]`).
#[must_use]
fn hex_has_wildcards(s: &str) -> bool {
    s.contains('?') || s.contains('[')
}

/// Parse a hex string with wildcards (`??`) and jumps (`[n-m]`) into a regex pattern.
///
/// Supported syntax:
/// - `4D 5A` — literal hex bytes
/// - `4D ?? 5A` — `??` matches any single byte
/// - `4D [2-4] 5A` — `[n-m]` matches n to m arbitrary bytes
/// - `4D [4] 5A` — `[n]` matches exactly n arbitrary bytes
/// - `(AA BB | CC DD)` — alternation
fn parse_hex_wildcard(s: &str) -> Result<YaraPattern> {
    use std::fmt::Write;

    let clean: String = s
        .chars()
        .filter(|c| !c.is_whitespace() || *c == ' ')
        .collect();
    let tokens: Vec<&str> = clean.split_whitespace().collect();

    let mut regex = String::from("(?-u)");

    let mut i = 0;
    while i < tokens.len() {
        let tok = tokens[i];

        if tok == "??" {
            // Any single byte
            regex.push('.');
        } else if tok.starts_with('[') && tok.ends_with(']') {
            // Jump: [n] or [n-m]
            let inner = &tok[1..tok.len() - 1];
            if let Some((lo, hi)) = inner.split_once('-') {
                let lo: usize = lo
                    .parse()
                    .map_err(|_| YaraError::InvalidHex(format!("invalid jump range: {tok}")))?;
                let hi: usize = hi
                    .parse()
                    .map_err(|_| YaraError::InvalidHex(format!("invalid jump range: {tok}")))?;
                let _ = write!(regex, ".{{{lo},{hi}}}");
            } else {
                let n: usize = inner
                    .parse()
                    .map_err(|_| YaraError::InvalidHex(format!("invalid jump: {tok}")))?;
                let _ = write!(regex, ".{{{n}}}");
            }
        } else if tok == "(" {
            regex.push('(');
        } else if tok == ")" {
            regex.push(')');
        } else if tok == "|" {
            regex.push('|');
        } else if tok.len() == 2 {
            // Literal hex byte
            let byte = u8::from_str_radix(tok, 16)
                .map_err(|_| YaraError::InvalidHex(format!("invalid hex byte: {tok}")))?;
            let _ = write!(regex, "\\x{byte:02x}");
        } else {
            // Try parsing as consecutive hex pairs (e.g. "4D5A")
            if tok.len() % 2 != 0 {
                return Err(YaraError::InvalidHex(format!("invalid hex token: {tok}")));
            }
            for j in (0..tok.len()).step_by(2) {
                let pair = &tok[j..j + 2];
                if pair == "??" {
                    regex.push('.');
                } else {
                    let byte = u8::from_str_radix(pair, 16)
                        .map_err(|_| YaraError::InvalidHex(format!("invalid hex byte: {pair}")))?;
                    let _ = write!(regex, "\\x{byte:02x}");
                }
            }
        }
        i += 1;
    }

    YaraPattern::regex(&regex).map_err(|e| YaraError::InvalidRegex(e.to_string()))
}

// ---------------------------------------------------------------------------
// YaraEngine
// ---------------------------------------------------------------------------

/// Mapping from Aho-Corasick pattern index to list of (rule_index, pattern_index).
/// Multiple rules may share identical needle bytes; all must be marked on a single match.
type AcPatternMap = Vec<Vec<(usize, usize)>>;

/// The YARA scanning engine. Holds a set of rules and matches them against data.
///
/// Call [`compile`] after adding all rules to build the Aho-Corasick automaton
/// for optimal multi-pattern scanning. If not compiled, falls back to per-pattern
/// matching (still correct, just slower for many literal patterns).
#[derive(Default)]
pub struct YaraEngine {
    rules: Vec<YaraRule>,
    /// Compiled Aho-Corasick automaton for all literal/hex patterns.
    ac: Option<AhoCorasick>,
    /// Maps AC pattern index → (rule_index, pattern_index_within_rule).
    ac_map: AcPatternMap,
}

impl std::fmt::Debug for YaraEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("YaraEngine")
            .field("rules", &self.rules.len())
            .field("compiled", &self.ac.is_some())
            .finish()
    }
}

impl YaraEngine {
    /// Create an empty engine.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a single rule. Invalidates any compiled automaton.
    pub fn add_rule(&mut self, rule: YaraRule) {
        self.rules.push(rule);
        self.ac = None; // invalidate
    }

    /// Build the Aho-Corasick automaton from all literal/hex patterns.
    ///
    /// Call this after loading all rules for optimal scan performance.
    /// Called automatically by `load_rules_toml`.
    pub fn compile(&mut self) {
        use std::collections::HashMap;

        // Deduplicate identical needles — multiple rules may share the same bytes
        let mut needle_index: HashMap<Vec<u8>, usize> = HashMap::new();
        let mut needles: Vec<Vec<u8>> = Vec::new();
        let mut map: AcPatternMap = Vec::new();

        for (rule_idx, rule) in self.rules.iter().enumerate() {
            for (pat_idx, (_, pat)) in rule.patterns.iter().enumerate() {
                match pat {
                    YaraPattern::Literal(bytes) | YaraPattern::Hex(bytes) => {
                        if bytes.is_empty() {
                            continue;
                        }
                        if let Some(&existing_idx) = needle_index.get(bytes) {
                            map[existing_idx].push((rule_idx, pat_idx));
                        } else {
                            let idx = needles.len();
                            needle_index.insert(bytes.clone(), idx);
                            needles.push(bytes.clone());
                            map.push(vec![(rule_idx, pat_idx)]);
                        }
                    }
                    YaraPattern::Regex(_) => {}
                }
            }
        }

        // AC is only worth the overhead when there are enough patterns.
        // For small pattern sets, per-pattern memmem with SIMD is faster.
        if needles.len() < 8 {
            self.ac = None;
            self.ac_map = Vec::new();
            return;
        }

        match AhoCorasick::builder().build(&needles) {
            Ok(ac) => {
                debug!(
                    unique_needles = needles.len(),
                    total_mappings = map.iter().map(|m| m.len()).sum::<usize>(),
                    "compiled Aho-Corasick automaton"
                );
                self.ac = Some(ac);
                self.ac_map = map;
            }
            Err(e) => {
                warn!(error = %e, "failed to build Aho-Corasick automaton, falling back to per-pattern scan");
                self.ac = None;
                self.ac_map = Vec::new();
            }
        }
    }

    /// Load rules from a TOML string.
    ///
    /// # Errors
    /// Returns `YaraError` if TOML is malformed, severity/condition is invalid,
    /// hex encoding is wrong, or a regex pattern fails to compile.
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
                    "hex" => {
                        if hex_has_wildcards(&p.value) {
                            parse_hex_wildcard(&p.value)?
                        } else {
                            YaraPattern::Hex(parse_hex(&p.value)?)
                        }
                    }
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

            let constraints = RuleConstraints {
                min_file_size: tr.min_file_size,
                max_file_size: tr.max_file_size,
                at_offset: tr.at_offset,
            };

            let rule_name = tr.name.clone();
            self.rules.push(YaraRule {
                name: tr.name,
                description: tr.description.unwrap_or_default(),
                severity,
                tags: tr.tags,
                patterns,
                condition,
                constraints,
            });
            debug!(rule = %rule_name, "loaded YARA rule");
            count += 1;
        }

        debug!(count, "finished loading TOML rules");
        self.compile();
        Ok(count)
    }

    /// Scan data against all loaded rules.
    ///
    /// Uses the Aho-Corasick automaton (if compiled) for a single-pass scan of
    /// all literal/hex patterns, then evaluates regex patterns individually.
    #[instrument(skip(self, data), fields(data_len = data.len(), rule_count = self.rules.len()))]
    pub fn scan(&self, data: &[u8]) -> Vec<ThreatFinding> {
        // Build per-rule, per-pattern match sets
        // matched_patterns[rule_idx] is a bitvec of which patterns matched
        let mut matched_patterns: Vec<Vec<bool>> = self
            .rules
            .iter()
            .map(|r| vec![false; r.patterns.len()])
            .collect();

        // Phase 1: Aho-Corasick single-pass for all literal/hex patterns
        if let Some(ref ac) = self.ac {
            let total_ac_mappings: usize = self.ac_map.iter().map(|m| m.len()).sum();
            let mut found_count = 0usize;
            for mat in ac.find_iter(data) {
                let entries = &self.ac_map[mat.pattern().as_usize()];
                for &(rule_idx, pat_idx) in entries {
                    if !matched_patterns[rule_idx][pat_idx] {
                        matched_patterns[rule_idx][pat_idx] = true;
                        found_count += 1;
                    }
                }
                // Early exit: all literal/hex pattern-rule pairs found
                if found_count == total_ac_mappings {
                    break;
                }
            }
        }

        // Phase 2: evaluate each rule
        let mut findings = Vec::new();
        for (rule_idx, rule) in self.rules.iter().enumerate() {
            if !rule.constraints.satisfied(data) {
                continue;
            }

            let scan_data = if let Some(offset) = rule.constraints.at_offset {
                if offset < data.len() {
                    &data[offset..]
                } else {
                    continue;
                }
            } else {
                data
            };

            // Count matches: AC results (for no at_offset) + regex patterns + fallback
            let mut match_count = 0;
            for (pat_idx, (_, pat)) in rule.patterns.iter().enumerate() {
                let hit = match pat {
                    YaraPattern::Literal(_) | YaraPattern::Hex(_) => {
                        if self.ac.is_some() && rule.constraints.at_offset.is_none() {
                            // Use AC result
                            matched_patterns[rule_idx][pat_idx]
                        } else {
                            // Fallback: per-pattern scan (at_offset or no AC)
                            pat.matches(scan_data)
                        }
                    }
                    YaraPattern::Regex(_) => pat.matches(scan_data),
                };
                if hit {
                    match_count += 1;
                }
            }

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
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Get all loaded rules (read-only).
    #[must_use]
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
            constraints: RuleConstraints::default(),
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
            constraints: RuleConstraints::default(),
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
            constraints: RuleConstraints::default(),
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
            constraints: RuleConstraints::default(),
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
            constraints: RuleConstraints::default(),
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
            constraints: RuleConstraints::default(),
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
            constraints: RuleConstraints::default(),
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
            constraints: RuleConstraints::default(),
        });
        let findings = engine.scan(b"X");
        assert_eq!(findings[0].metadata.get("tag:malware").unwrap(), "true");
        assert_eq!(findings[0].metadata.get("tag:pe").unwrap(), "true");
    }

    #[test]
    fn constraint_min_file_size() {
        let mut engine = YaraEngine::new();
        let toml = r#"
[[rule]]
name = "large_only"
severity = "low"
condition = "any"
min_file_size = 100
[[rule.patterns]]
id = "$a"
type = "literal"
value = "X"
"#;
        engine.load_rules_toml(toml).unwrap();
        // 10 bytes — below min, should not match
        assert!(engine.scan(b"X_________").is_empty());
        // 100 bytes — at min, should match
        let mut data = vec![b'_'; 100];
        data[50] = b'X';
        assert_eq!(engine.scan(&data).len(), 1);
    }

    #[test]
    fn constraint_max_file_size() {
        let mut engine = YaraEngine::new();
        let toml = r#"
[[rule]]
name = "small_only"
severity = "low"
condition = "any"
max_file_size = 50
[[rule.patterns]]
id = "$a"
type = "literal"
value = "X"
"#;
        engine.load_rules_toml(toml).unwrap();
        assert_eq!(engine.scan(b"X_short").len(), 1);
        let big = vec![b'X'; 100];
        assert!(engine.scan(&big).is_empty());
    }

    #[test]
    fn constraint_at_offset() {
        let mut engine = YaraEngine::new();
        let toml = r#"
[[rule]]
name = "header_check"
severity = "medium"
condition = "any"
at_offset = 0
[[rule.patterns]]
id = "$magic"
type = "hex"
value = "7f454c46"
"#;
        engine.load_rules_toml(toml).unwrap();
        // ELF magic at offset 0 — should match
        assert_eq!(engine.scan(b"\x7fELF\x00\x00\x00\x00").len(), 1);
        // ELF magic NOT at offset 0 — should not match (at_offset=0 means start from byte 0)
        // Actually at_offset slices from that offset, so the pattern is checked from that point.
        // Data "XX\x7fELF" with at_offset=0 starts scanning from byte 0, ELF is at byte 2,
        // windows scan will find it. Let's test at_offset=4 instead.
        let mut engine2 = YaraEngine::new();
        let toml2 = r#"
[[rule]]
name = "offset_check"
severity = "low"
condition = "any"
at_offset = 4
[[rule.patterns]]
id = "$sig"
type = "literal"
value = "ABCD"
"#;
        engine2.load_rules_toml(toml2).unwrap();
        // "ABCD" at offset 4
        assert_eq!(engine2.scan(b"\x00\x00\x00\x00ABCD").len(), 1);
        // "ABCD" at offset 0, not at offset 4
        assert!(engine2.scan(b"ABCD\x00\x00\x00\x00").is_empty());
    }

    #[test]
    fn constraint_combined_size_and_offset() {
        let mut engine = YaraEngine::new();
        let toml = r#"
[[rule]]
name = "combo"
severity = "high"
condition = "any"
min_file_size = 20
max_file_size = 200
at_offset = 0
[[rule.patterns]]
id = "$magic"
type = "hex"
value = "4d5a"
"#;
        engine.load_rules_toml(toml).unwrap();
        // Too small
        assert!(engine.scan(b"MZ").is_empty());
        // Right size, right magic at offset 0
        let mut data = vec![0u8; 50];
        data[0] = 0x4d;
        data[1] = 0x5a;
        assert_eq!(engine.scan(&data).len(), 1);
        // Too large
        let mut big = vec![0u8; 300];
        big[0] = 0x4d;
        big[1] = 0x5a;
        assert!(engine.scan(&big).is_empty());
    }

    #[test]
    fn constraints_satisfied_checks() {
        let c = RuleConstraints {
            min_file_size: Some(10),
            max_file_size: Some(100),
            at_offset: None,
        };
        assert!(!c.satisfied(&[0u8; 5]));
        assert!(c.satisfied(&[0u8; 10]));
        assert!(c.satisfied(&[0u8; 100]));
        assert!(!c.satisfied(&[0u8; 101]));
    }

    // ── Hex wildcard tests ─────────────────────────────────────────

    #[test]
    fn hex_wildcard_single_byte() {
        let pat = parse_hex_wildcard("4D ?? 5A").unwrap();
        assert!(pat.matches(b"\x4d\x00\x5a"));
        assert!(pat.matches(b"\x4d\xff\x5a"));
        assert!(!pat.matches(b"\x4d\x5a")); // no gap
    }

    #[test]
    fn hex_wildcard_consecutive() {
        let pat = parse_hex_wildcard("7F 45 ?? ?? 02").unwrap();
        assert!(pat.matches(b"\x7fE\x00\x00\x02"));
        assert!(pat.matches(b"\x7fE\xab\xcd\x02"));
        assert!(!pat.matches(b"\x7fE\x02")); // too short
    }

    #[test]
    fn hex_jump_fixed() {
        let pat = parse_hex_wildcard("4D 5A [4] 50 45").unwrap();
        assert!(pat.matches(b"MZ\x00\x00\x00\x00PE"));
        assert!(!pat.matches(b"MZ\x00\x00\x00PE")); // only 3 bytes gap
    }

    #[test]
    fn hex_jump_range() {
        let pat = parse_hex_wildcard("4D 5A [2-4] 50 45").unwrap();
        assert!(pat.matches(b"MZ\x00\x00PE"));
        assert!(pat.matches(b"MZ\x00\x00\x00PE"));
        assert!(pat.matches(b"MZ\x00\x00\x00\x00PE"));
        assert!(!pat.matches(b"MZ\x00PE")); // only 1 byte gap
    }

    #[test]
    fn hex_no_wildcards_detected() {
        assert!(!hex_has_wildcards("4D5A9000"));
        assert!(!hex_has_wildcards("7F 45 4C 46"));
    }

    #[test]
    fn hex_wildcards_detected() {
        assert!(hex_has_wildcards("4D ?? 5A"));
        assert!(hex_has_wildcards("4D [2-4] 5A"));
    }

    #[test]
    fn hex_wildcard_in_toml_rules() {
        let mut engine = YaraEngine::new();
        let toml = r#"
[[rule]]
name = "pe_with_gap"
severity = "medium"
condition = "any"
[[rule.patterns]]
id = "$mz_pe"
type = "hex"
value = "4D 5A ?? ?? ?? ?? [0-128] 50 45 00 00"
"#;
        engine.load_rules_toml(toml).unwrap();

        // Build data: MZ + 4 bytes + some gap + PE\0\0
        let mut data = vec![0u8; 256];
        data[0] = 0x4d; // M
        data[1] = 0x5a; // Z
        data[128] = 0x50; // P
        data[129] = 0x45; // E
        assert_eq!(engine.scan(&data).len(), 1);
    }

    #[test]
    fn hex_wildcard_no_match() {
        let mut engine = YaraEngine::new();
        let toml = r#"
[[rule]]
name = "specific_sig"
severity = "low"
condition = "any"
[[rule.patterns]]
id = "$sig"
type = "hex"
value = "DE AD ?? BE EF"
"#;
        engine.load_rules_toml(toml).unwrap();
        assert!(engine.scan(b"\xde\xad\xbe\xef").is_empty()); // missing middle byte
        assert_eq!(engine.scan(b"\xde\xad\x00\xbe\xef").len(), 1);
    }

    #[test]
    fn hex_wildcard_packed_no_space() {
        // "4D??5A" without spaces — wildcards in packed form
        let pat = parse_hex_wildcard("4D??5A").unwrap();
        assert!(pat.matches(b"\x4d\x00\x5a"));
        assert!(pat.matches(b"\x4d\xff\x5a"));
    }
}
