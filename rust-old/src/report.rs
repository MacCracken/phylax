//! Threat report generation.
//!
//! Produces structured reports from scan results in JSON and Markdown formats.

use crate::types::{ScanResult, VERSION};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Report output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReportFormat {
    Json,
    Markdown,
    Sarif,
}

/// A structured threat report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatReport {
    /// Scan session ID.
    pub session_id: Uuid,
    /// Report generation timestamp.
    pub generated_at: DateTime<Utc>,
    /// Engine version.
    pub engine_version: String,
    /// Scan results included in this report.
    pub results: Vec<ScanResult>,
    /// Total number of findings across all results.
    pub total_findings: usize,
    /// Summary statistics.
    pub summary: ReportSummary,
}

/// Summary statistics for a report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    pub targets_scanned: usize,
    pub targets_clean: usize,
    pub targets_with_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
}

impl ThreatReport {
    /// Build a report from a list of scan results.
    #[must_use]
    pub fn from_results(session_id: Uuid, results: Vec<ScanResult>) -> Self {
        let total_findings: usize = results.iter().map(|r| r.findings.len()).sum();
        let targets_scanned = results.len();
        let targets_with_findings = results
            .iter()
            .filter(|r: &&ScanResult| r.has_threats())
            .count();
        let targets_clean = targets_scanned - targets_with_findings;

        let mut critical_count = 0;
        let mut high_count = 0;
        let mut medium_count = 0;
        let mut low_count = 0;
        let mut info_count = 0;

        for finding in results.iter().flat_map(|r| &r.findings) {
            match finding.severity {
                crate::types::FindingSeverity::Critical => critical_count += 1,
                crate::types::FindingSeverity::High => high_count += 1,
                crate::types::FindingSeverity::Medium => medium_count += 1,
                crate::types::FindingSeverity::Low => low_count += 1,
                crate::types::FindingSeverity::Info => info_count += 1,
            }
        }

        let summary = ReportSummary {
            targets_scanned,
            targets_clean,
            targets_with_findings,
            critical_count,
            high_count,
            medium_count,
            low_count,
            info_count,
        };

        Self {
            session_id,
            generated_at: Utc::now(),
            engine_version: VERSION.to_string(),
            results,
            total_findings,
            summary,
        }
    }

    /// Render the report in the given format.
    #[must_use]
    pub fn render(&self, format: ReportFormat) -> String {
        match format {
            ReportFormat::Json => self.render_json(),
            ReportFormat::Markdown => self.render_markdown(),
            ReportFormat::Sarif => self.render_sarif(),
        }
    }

    fn render_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|e| {
            tracing::error!(error = %e, "failed to serialize report to JSON");
            "{}".to_string()
        })
    }

    fn render_sarif(&self) -> String {
        use crate::types::FindingSeverity;

        let sarif_level = |sev: FindingSeverity| -> &'static str {
            match sev {
                FindingSeverity::Critical | FindingSeverity::High => "error",
                FindingSeverity::Medium => "warning",
                FindingSeverity::Low | FindingSeverity::Info => "note",
            }
        };

        // Collect unique rules
        let mut rule_ids: Vec<String> = Vec::new();
        let mut rules_json: Vec<serde_json::Value> = Vec::new();
        for result in &self.results {
            for f in &result.findings {
                if !rule_ids.contains(&f.rule_name) {
                    rule_ids.push(f.rule_name.clone());
                    rules_json.push(serde_json::json!({
                        "id": f.rule_name,
                        "shortDescription": { "text": f.rule_name },
                        "defaultConfiguration": {
                            "level": sarif_level(f.severity)
                        }
                    }));
                }
            }
        }

        // Build results
        let mut results_json: Vec<serde_json::Value> = Vec::new();
        for result in &self.results {
            let location = match &result.target {
                crate::types::ScanTarget::File(p) => p.display().to_string(),
                other => other.to_string(),
            };

            for f in &result.findings {
                results_json.push(serde_json::json!({
                    "ruleId": f.rule_name,
                    "level": sarif_level(f.severity),
                    "message": { "text": f.description },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": location
                            }
                        }
                    }],
                    "partialFingerprints": {
                        "phylax/v1": format!("{}:{}:{}", f.rule_name, location, f.severity)
                    },
                    "properties": {
                        "severity": f.severity.to_string(),
                        "category": f.category.to_string(),
                        "session_id": self.session_id.to_string(),
                    }
                }));
            }
        }

        let sarif = serde_json::json!({
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "phylax",
                        "version": self.engine_version,
                        "informationUri": "https://github.com/MacCracken/phylax",
                        "rules": rules_json
                    }
                },
                "results": results_json
            }]
        });

        serde_json::to_string_pretty(&sarif).unwrap_or_else(|e| {
            tracing::error!(error = %e, "failed to serialize SARIF report");
            "{}".to_string()
        })
    }

    fn render_markdown(&self) -> String {
        use std::fmt::Write;
        let mut md = String::new();

        writeln!(md, "# Phylax Threat Report").unwrap();
        writeln!(md).unwrap();
        writeln!(
            md,
            "**Generated**: {}",
            self.generated_at.format("%Y-%m-%d %H:%M:%S UTC")
        )
        .unwrap();
        writeln!(md, "**Engine**: v{}", self.engine_version).unwrap();
        writeln!(md).unwrap();

        writeln!(md, "## Summary").unwrap();
        writeln!(md).unwrap();
        writeln!(md, "| Metric | Count |").unwrap();
        writeln!(md, "|--------|-------|").unwrap();
        writeln!(md, "| Targets scanned | {} |", self.summary.targets_scanned).unwrap();
        writeln!(md, "| Clean | {} |", self.summary.targets_clean).unwrap();
        writeln!(
            md,
            "| With findings | {} |",
            self.summary.targets_with_findings
        )
        .unwrap();
        writeln!(md, "| Critical | {} |", self.summary.critical_count).unwrap();
        writeln!(md, "| High | {} |", self.summary.high_count).unwrap();
        writeln!(md, "| Medium | {} |", self.summary.medium_count).unwrap();
        writeln!(md, "| Low | {} |", self.summary.low_count).unwrap();
        writeln!(md, "| Info | {} |", self.summary.info_count).unwrap();
        writeln!(md).unwrap();

        if self.total_findings > 0 {
            writeln!(md, "## Findings").unwrap();
            writeln!(md).unwrap();

            for result in &self.results {
                if result.findings.is_empty() {
                    continue;
                }
                writeln!(md, "### {}", result.target).unwrap();
                writeln!(md).unwrap();
                writeln!(md, "| Severity | Rule | Description |").unwrap();
                writeln!(md, "|----------|------|-------------|").unwrap();
                for f in &result.findings {
                    let rule = f.rule_name.replace('|', "\\|");
                    let desc = f.description.replace('|', "\\|");
                    writeln!(md, "| {} | {} | {} |", f.severity, rule, desc).unwrap();
                }
                writeln!(md).unwrap();
            }
        }

        md
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{FindingCategory, FindingSeverity, ScanTarget, ThreatFinding};

    fn sample_results() -> Vec<ScanResult> {
        vec![
            ScanResult {
                session_id: Uuid::new_v4(),
                target: ScanTarget::File("/tmp/clean.bin".into()),
                findings: vec![],
                scan_duration: std::time::Duration::from_millis(10),
                scanner_version: "0.1.0".into(),
            },
            ScanResult {
                session_id: Uuid::new_v4(),
                target: ScanTarget::File("/tmp/suspicious.bin".into()),
                findings: vec![
                    ThreatFinding::new(
                        ScanTarget::File("/tmp/suspicious.bin".into()),
                        FindingCategory::Suspicious,
                        FindingSeverity::High,
                        "high_entropy",
                        "High entropy detected",
                    ),
                    ThreatFinding::new(
                        ScanTarget::File("/tmp/suspicious.bin".into()),
                        FindingCategory::CustomRule,
                        FindingSeverity::Medium,
                        "packed_binary",
                        "UPX packed",
                    ),
                ],
                scan_duration: std::time::Duration::from_millis(50),
                scanner_version: "0.1.0".into(),
            },
        ]
    }

    #[test]
    fn report_from_results() {
        let report = ThreatReport::from_results(Uuid::new_v4(), sample_results());
        assert_eq!(report.summary.targets_scanned, 2);
        assert_eq!(report.summary.targets_clean, 1);
        assert_eq!(report.summary.targets_with_findings, 1);
        assert_eq!(report.summary.high_count, 1);
        assert_eq!(report.summary.medium_count, 1);
        assert_eq!(report.total_findings, 2);
    }

    #[test]
    fn report_empty() {
        let report = ThreatReport::from_results(Uuid::new_v4(), vec![]);
        assert_eq!(report.summary.targets_scanned, 0);
        assert_eq!(report.total_findings, 0);
    }

    #[test]
    fn render_json() {
        let report = ThreatReport::from_results(Uuid::new_v4(), sample_results());
        let json = report.render(ReportFormat::Json);
        assert!(json.contains("high_entropy"));
        assert!(json.contains("packed_binary"));
        // Should be valid JSON
        let _: serde_json::Value = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn render_markdown() {
        let report = ThreatReport::from_results(Uuid::new_v4(), sample_results());
        let md = report.render(ReportFormat::Markdown);
        assert!(md.contains("# Phylax Threat Report"));
        assert!(md.contains("| Targets scanned | 2 |"));
        assert!(md.contains("| HIGH | high_entropy |"));
        assert!(md.contains("| MEDIUM | packed_binary |"));
    }

    #[test]
    fn render_markdown_no_findings() {
        let report = ThreatReport::from_results(
            Uuid::new_v4(),
            vec![ScanResult {
                session_id: Uuid::new_v4(),
                target: ScanTarget::Memory,
                findings: vec![],
                scan_duration: std::time::Duration::from_millis(5),
                scanner_version: "0.1.0".into(),
            }],
        );
        let md = report.render(ReportFormat::Markdown);
        assert!(md.contains("| Clean | 1 |"));
        assert!(!md.contains("## Findings"));
    }

    #[test]
    fn report_serialization_roundtrip() {
        let report = ThreatReport::from_results(Uuid::new_v4(), sample_results());
        let json = serde_json::to_string(&report).unwrap();
        let parsed: ThreatReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.total_findings, report.total_findings);
        assert_eq!(
            parsed.summary.targets_scanned,
            report.summary.targets_scanned
        );
    }

    #[test]
    fn report_multiple_results() {
        let results = vec![
            ScanResult {
                session_id: Uuid::new_v4(),
                target: ScanTarget::File("/a".into()),
                findings: vec![ThreatFinding::new(
                    ScanTarget::File("/a".into()),
                    FindingCategory::Malware,
                    FindingSeverity::Critical,
                    "r1",
                    "d1",
                )],
                scan_duration: std::time::Duration::from_millis(10),
                scanner_version: "0.1.0".into(),
            },
            ScanResult {
                session_id: Uuid::new_v4(),
                target: ScanTarget::File("/b".into()),
                findings: vec![],
                scan_duration: std::time::Duration::from_millis(5),
                scanner_version: "0.1.0".into(),
            },
            ScanResult {
                session_id: Uuid::new_v4(),
                target: ScanTarget::File("/c".into()),
                findings: vec![ThreatFinding::new(
                    ScanTarget::File("/c".into()),
                    FindingCategory::Suspicious,
                    FindingSeverity::Low,
                    "r2",
                    "d2",
                )],
                scan_duration: std::time::Duration::from_millis(15),
                scanner_version: "0.1.0".into(),
            },
        ];
        let report = ThreatReport::from_results(Uuid::new_v4(), results);
        assert_eq!(report.summary.targets_scanned, 3);
        assert_eq!(report.summary.targets_clean, 1);
        assert_eq!(report.summary.targets_with_findings, 2);
        assert_eq!(report.summary.critical_count, 1);
        assert_eq!(report.summary.low_count, 1);
        assert_eq!(report.total_findings, 2);

        // Markdown should show both findings sections
        let md = report.render(ReportFormat::Markdown);
        assert!(md.contains("file:/a"));
        assert!(md.contains("file:/c"));
        assert!(!md.contains("file:/b")); // clean target not in findings
    }

    #[test]
    fn render_markdown_escapes_pipe() {
        let results = vec![ScanResult {
            session_id: Uuid::new_v4(),
            target: ScanTarget::Memory,
            findings: vec![ThreatFinding::new(
                ScanTarget::Memory,
                FindingCategory::Suspicious,
                FindingSeverity::Medium,
                "rule_with|pipe",
                "desc with | pipe",
            )],
            scan_duration: std::time::Duration::from_millis(5),
            scanner_version: "0.1.0".into(),
        }];
        let report = ThreatReport::from_results(Uuid::new_v4(), results);
        let md = report.render(ReportFormat::Markdown);
        // Pipes should be escaped to avoid breaking markdown tables
        assert!(md.contains(r"rule_with\|pipe"));
        assert!(md.contains(r"desc with \| pipe"));
    }

    #[test]
    fn summary_all_severities() {
        let findings = vec![
            ThreatFinding::new(
                ScanTarget::Memory,
                FindingCategory::Malware,
                FindingSeverity::Critical,
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
            ThreatFinding::new(
                ScanTarget::Memory,
                FindingCategory::CustomRule,
                FindingSeverity::Low,
                "r4",
                "d4",
            ),
            ThreatFinding::new(
                ScanTarget::Memory,
                FindingCategory::CustomRule,
                FindingSeverity::Info,
                "r5",
                "d5",
            ),
        ];
        let results = vec![ScanResult {
            session_id: Uuid::new_v4(),
            target: ScanTarget::Memory,
            findings,
            scan_duration: std::time::Duration::from_millis(10),
            scanner_version: "0.1.0".into(),
        }];
        let report = ThreatReport::from_results(Uuid::new_v4(), results);
        assert_eq!(report.summary.critical_count, 1);
        assert_eq!(report.summary.high_count, 1);
        assert_eq!(report.summary.medium_count, 1);
        assert_eq!(report.summary.low_count, 1);
        assert_eq!(report.summary.info_count, 1);
    }

    #[test]
    fn render_sarif_valid_json() {
        let report = ThreatReport::from_results(Uuid::new_v4(), sample_results());
        let sarif = report.render(ReportFormat::Sarif);
        let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();

        assert_eq!(parsed["version"], "2.1.0");
        assert_eq!(parsed["runs"][0]["tool"]["driver"]["name"], "phylax");

        let results = parsed["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2); // 2 findings from sample_results
        assert_eq!(results[0]["ruleId"], "high_entropy");
        assert_eq!(results[0]["level"], "error"); // High severity
        assert_eq!(results[1]["ruleId"], "packed_binary");
        assert_eq!(results[1]["level"], "warning"); // Medium severity
    }

    #[test]
    fn render_sarif_empty() {
        let report = ThreatReport::from_results(Uuid::new_v4(), vec![]);
        let sarif = report.render(ReportFormat::Sarif);
        let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        let results = parsed["runs"][0]["results"].as_array().unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn render_sarif_has_session_id() {
        let sid = Uuid::new_v4();
        let report = ThreatReport::from_results(sid, sample_results());
        let sarif = report.render(ReportFormat::Sarif);
        let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        let result_props = &parsed["runs"][0]["results"][0]["properties"];
        assert_eq!(result_props["session_id"], sid.to_string());
    }
}
