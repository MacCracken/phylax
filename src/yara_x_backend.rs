//! Optional YARA-X backend for 100% YARA compatibility.
//!
//! This module wraps VirusTotal's [`yara-x`](https://github.com/VirusTotal/yara-x)
//! crate to provide full YARA rule support including all modules, conditions,
//! and features that the native phylax parser may not yet cover.
//!
//! Enable with `--features yara-x`.

use crate::types::{FindingCategory, FindingSeverity, ScanTarget, ThreatFinding};
use tracing::{debug, instrument, warn};

/// YARA-X backed scanning engine.
///
/// Uses VirusTotal's yara-x for rule compilation and scanning, mapping
/// results to phylax's `ThreatFinding` type.
pub struct YaraXEngine {
    rules: yara_x::Rules,
}

impl std::fmt::Debug for YaraXEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("YaraXEngine")
            .field("rules", &self.rules.iter().count())
            .finish()
    }
}

impl YaraXEngine {
    /// Compile rules from a native YARA `.yar` string.
    ///
    /// # Errors
    /// Returns an error if rule compilation fails.
    #[instrument(skip(yar_str), fields(yar_len = yar_str.len()))]
    pub fn from_source(yar_str: &str) -> Result<Self, YaraXError> {
        let mut compiler = yara_x::Compiler::new();
        compiler
            .add_source(yar_str.as_bytes())
            .map_err(|e| YaraXError::Compile(e.to_string()))?;
        let rules = compiler.build();
        let count = rules.iter().count();
        debug!(count, "compiled YARA-X rules");
        Ok(Self { rules })
    }

    /// Compile rules from multiple source strings.
    ///
    /// # Errors
    /// Returns an error if any rule compilation fails.
    pub fn from_sources(sources: &[&str]) -> Result<Self, YaraXError> {
        let mut compiler = yara_x::Compiler::new();
        for src in sources {
            compiler
                .add_source(src.as_bytes())
                .map_err(|e| YaraXError::Compile(e.to_string()))?;
        }
        let rules = compiler.build();
        let count = rules.iter().count();
        debug!(
            count,
            "compiled YARA-X rules from {} sources",
            sources.len()
        );
        Ok(Self { rules })
    }

    /// Scan data against all compiled rules.
    ///
    /// Returns phylax `ThreatFinding`s for each matching rule.
    #[instrument(skip(self, data), fields(data_len = data.len()))]
    pub fn scan(&self, data: &[u8]) -> Vec<ThreatFinding> {
        let mut scanner = yara_x::Scanner::new(&self.rules);
        let results = match scanner.scan(data) {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "YARA-X scan failed");
                return Vec::new();
            }
        };

        results
            .matching_rules()
            .map(|rule| {
                let severity = rule
                    .metadata()
                    .into_iter()
                    .find(|(key, _)| *key == "severity")
                    .and_then(|(_, val)| match val {
                        yara_x::MetaValue::String(s) => s.parse::<FindingSeverity>().ok(),
                        _ => None,
                    })
                    .unwrap_or(FindingSeverity::Medium);

                let description = rule
                    .metadata()
                    .into_iter()
                    .find(|(key, _)| *key == "description")
                    .and_then(|(_, val)| match val {
                        yara_x::MetaValue::String(s) => Some(s.to_string()),
                        _ => None,
                    })
                    .unwrap_or_default();

                let mut finding = ThreatFinding::new(
                    ScanTarget::Memory,
                    FindingCategory::CustomRule,
                    severity,
                    rule.identifier(),
                    description,
                );
                finding.metadata.insert("engine".into(), "yara-x".into());
                finding
                    .metadata
                    .insert("namespace".into(), rule.namespace().to_string());

                // Add tags
                for tag in rule.tags() {
                    finding
                        .metadata
                        .insert(format!("tag:{}", tag.identifier()), "true".into());
                }

                // Add matched pattern info
                let match_count: usize = rule.patterns().map(|p| p.matches().count()).sum();
                finding
                    .metadata
                    .insert("matched_patterns".into(), match_count.to_string());

                finding
            })
            .collect()
    }

    /// Number of compiled rules.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules.iter().count()
    }
}

/// Errors from the YARA-X backend.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum YaraXError {
    #[error("YARA-X compilation error: {0}")]
    Compile(String),
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compile_simple_rule() {
        let engine = YaraXEngine::from_source(
            r#"
            rule TestRule {
                strings:
                    $a = "test"
                condition:
                    $a
            }
            "#,
        )
        .unwrap();
        assert_eq!(engine.rule_count(), 1);
    }

    #[test]
    fn scan_match() {
        let engine = YaraXEngine::from_source(
            r#"
            rule FindMarker {
                meta:
                    severity = "high"
                    description = "Finds MARKER"
                strings:
                    $m = "MARKER"
                condition:
                    $m
            }
            "#,
        )
        .unwrap();

        let findings = engine.scan(b"data with MARKER inside");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_name, "FindMarker");
        assert_eq!(findings[0].severity, FindingSeverity::High);
        assert_eq!(findings[0].metadata.get("engine").unwrap(), "yara-x");
    }

    #[test]
    fn scan_no_match() {
        let engine = YaraXEngine::from_source(
            r#"
            rule NoMatch {
                strings:
                    $a = "NONEXISTENT"
                condition:
                    $a
            }
            "#,
        )
        .unwrap();
        assert!(engine.scan(b"nothing here").is_empty());
    }

    #[test]
    fn compile_error() {
        let result = YaraXEngine::from_source("rule Bad {{{");
        assert!(result.is_err());
    }

    #[test]
    fn multiple_sources() {
        let engine = YaraXEngine::from_sources(&[
            r#"rule A { strings: $a = "AA" condition: $a }"#,
            r#"rule B { strings: $b = "BB" condition: $b }"#,
        ])
        .unwrap();
        assert_eq!(engine.rule_count(), 2);
        assert_eq!(engine.scan(b"AA and BB").len(), 2);
    }

    #[test]
    fn severity_default_medium() {
        let engine = YaraXEngine::from_source(
            r#"
            rule NoMeta {
                strings:
                    $a = "X"
                condition:
                    $a
            }
            "#,
        )
        .unwrap();
        let findings = engine.scan(b"X");
        assert_eq!(findings[0].severity, FindingSeverity::Medium);
    }
}
