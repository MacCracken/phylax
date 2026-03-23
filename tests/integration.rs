//! Integration tests for the Phylax scan pipeline.

use phylax::analyze::{
    FileType, analyze, analyze_findings, detect_file_type, detect_polyglot, entropy_profile,
    escalate_severity, file_sha256, findings_from_analysis, is_suspicious_entropy, shannon_entropy,
};
use phylax::core::{FindingCategory, FindingSeverity, ScanTarget, ThreatFinding};
use phylax::report::{ReportFormat, ThreatReport};
use phylax::yara::YaraEngine;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Full scan pipeline
// ---------------------------------------------------------------------------

#[test]
fn scan_elf_binary_end_to_end() {
    let mut data = vec![0u8; 1024];
    data[0] = 0x7f;
    data[1] = 0x45;
    data[2] = 0x4c;
    data[3] = 0x46;

    let ft = detect_file_type(&data);
    assert_eq!(ft, FileType::Elf);

    let entropy = shannon_entropy(&data);
    assert!((0.0..=8.0).contains(&entropy));

    let hash = file_sha256(&data);
    assert_eq!(hash.len(), 64);

    let analysis = analyze(&data);
    assert_eq!(analysis.file_type, FileType::Elf);
    assert_eq!(analysis.size, 1024);

    let findings = analyze_findings(&data, ScanTarget::File("/test/elf".into()));
    for f in &findings {
        assert!(!f.rule_name.is_empty());
    }
}

#[test]
fn scan_with_yara_rules() {
    let rules_toml = r#"
    [[rule]]
    name = "test_rule"
    description = "Detects test marker"
    severity = "high"
    tags = ["test"]
    condition = "any"

    [[rule.patterns]]
    id = "$marker"
    type = "literal"
    value = "MALWARE_MARKER"
    "#;

    let mut engine = YaraEngine::new();
    let count = engine.load_rules_toml(rules_toml).unwrap();
    assert_eq!(count, 1);

    let data = b"some content MALWARE_MARKER more content";
    let findings = engine.scan(data);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_name, "test_rule");
    assert_eq!(findings[0].severity, FindingSeverity::High);

    let clean = b"perfectly normal content here";
    let findings = engine.scan(clean);
    assert!(findings.is_empty());
}

#[test]
fn entropy_profile_consistency() {
    let data = vec![0xAA; 8192];

    let entropy = shannon_entropy(&data);
    let profile = entropy_profile(&data, 4096);

    assert!(entropy < 0.01);
    assert!(!is_suspicious_entropy(entropy));

    for block_entropy in &profile {
        assert!(*block_entropy < 0.01);
    }
}

#[test]
fn polyglot_detection() {
    let mut data = vec![0u8; 512];
    data[0] = 0x50;
    data[1] = 0x4b;
    data[2] = 0x03;
    data[3] = 0x04;
    data[256] = 0x25;
    data[257] = 0x50;
    data[258] = 0x44;
    data[259] = 0x46;

    let types = detect_polyglot(&data);
    assert!(
        types.len() >= 2,
        "expected polyglot detection, got {types:?}"
    );
}

// ---------------------------------------------------------------------------
// Multi-file scan pipeline
// ---------------------------------------------------------------------------

#[test]
fn scan_multiple_file_types() {
    // ELF binary
    let mut elf_data = vec![0u8; 256];
    elf_data[0] = 0x7f;
    elf_data[1] = 0x45;
    elf_data[2] = 0x4c;
    elf_data[3] = 0x46;

    // PE binary
    let mut pe_data = vec![0u8; 256];
    pe_data[0] = 0x4d;
    pe_data[1] = 0x5a;

    // Script
    let script_data = b"#!/bin/bash\necho hello";

    assert_eq!(detect_file_type(&elf_data), FileType::Elf);
    assert_eq!(detect_file_type(&pe_data), FileType::Pe);
    assert_eq!(detect_file_type(script_data), FileType::Script);

    // All should produce valid analysis
    for data in [
        elf_data.as_slice(),
        pe_data.as_slice(),
        script_data.as_slice(),
    ] {
        let analysis = analyze(data);
        assert!(!analysis.sha256.is_empty());
        assert_eq!(analysis.size, data.len());
    }
}

// ---------------------------------------------------------------------------
// Full pipeline: scan + escalate + report
// ---------------------------------------------------------------------------

#[test]
fn full_pipeline_scan_escalate_report() {
    // Build high-entropy ELF-like data (triggers entropy + executable escalation)
    let mut data = Vec::with_capacity(256 * 4);
    for _ in 0..4 {
        for b in 0..=255u8 {
            data.push(b);
        }
    }
    // Set ELF magic at start
    data[0] = 0x7f;
    data[1] = 0x45;
    data[2] = 0x4c;
    data[3] = 0x46;

    let analysis = analyze(&data);
    assert_eq!(analysis.file_type, FileType::Elf);
    assert!(is_suspicious_entropy(analysis.entropy));

    // Get findings and escalate
    let mut findings = findings_from_analysis(&data, &analysis, ScanTarget::Memory);
    assert!(!findings.is_empty(), "high entropy should produce findings");
    escalate_severity(&mut findings, &analysis);

    // Executable + high entropy should escalate Medium -> High
    let entropy_finding = findings.iter().find(|f| f.rule_name == "high_entropy");
    assert!(entropy_finding.is_some());
    assert!(
        entropy_finding.unwrap().severity >= FindingSeverity::High,
        "executable file should escalate entropy finding"
    );

    // Generate report from results
    let result = phylax::core::ScanResult {
        target: ScanTarget::Memory,
        findings,
        scan_duration: Duration::from_millis(42),
        scanner_version: "test".into(),
    };
    let report = ThreatReport::from_results(vec![result]);
    assert!(report.total_findings > 0);
    assert!(report.summary.targets_with_findings == 1);

    // JSON round-trip
    let json = report.render(ReportFormat::Json);
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(parsed.get("total_findings").is_some());

    // Markdown contains findings
    let md = report.render(ReportFormat::Markdown);
    assert!(md.contains("high_entropy"));
}

// ---------------------------------------------------------------------------
// YARA with constraints
// ---------------------------------------------------------------------------

#[test]
fn yara_constraints_in_pipeline() {
    let rules = r##"
[[rule]]
name = "large_elf"
description = "ELF binary over 100 bytes"
severity = "medium"
condition = "any"
min_file_size = 100

[[rule.patterns]]
id = "$elf"
type = "hex"
value = "7f454c46"

[[rule]]
name = "small_script"
description = "Small script"
severity = "low"
condition = "any"
max_file_size = 50

[[rule.patterns]]
id = "$sh"
type = "literal"
value = "#!/"
"##;

    let mut engine = YaraEngine::new();
    engine.load_rules_toml(rules).unwrap();

    // Large ELF (200 bytes) — should match large_elf, not small_script
    let mut elf = vec![0u8; 200];
    elf[0] = 0x7f;
    elf[1] = 0x45;
    elf[2] = 0x4c;
    elf[3] = 0x46;
    let findings = engine.scan(&elf);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_name, "large_elf");

    // Small script (20 bytes) — should match small_script, not large_elf
    let script = b"#!/bin/sh\necho hi\n\n";
    let findings = engine.scan(script);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_name, "small_script");
}

// ---------------------------------------------------------------------------
// PE + ELF parsing integration
// ---------------------------------------------------------------------------

#[test]
fn pe_elf_string_extraction_pipeline() {
    // Build minimal PE
    let mut pe = vec![0u8; 512];
    pe[0] = 0x4d; // MZ
    pe[1] = 0x5a;
    pe[0x3C] = 0x80; // e_lfanew
    pe[0x80] = 0x50; // PE signature
    pe[0x81] = 0x45;
    pe[0x98] = 0x0b; // PE32 magic
    pe[0x99] = 0x01;

    let pe_info = phylax::pe::parse_pe(&pe);
    assert!(pe_info.is_some());

    // Build minimal ELF
    let mut elf = vec![0u8; 128];
    elf[0..4].copy_from_slice(&[0x7f, 0x45, 0x4c, 0x46]);
    elf[4] = 2; // 64-bit
    elf[5] = 1; // little-endian
    elf[6] = 1;
    elf[16] = 2; // executable
    elf[18] = 62; // x86_64

    let elf_info = phylax::elf::parse_elf(&elf);
    assert!(elf_info.is_some());

    // String extraction
    let data_with_strings = b"\x00\x00KERNEL32.DLL\x00\x00LoadLibraryA\x00\x00";
    let strings = phylax::strings::extract_ascii(data_with_strings, 4);
    assert!(strings.iter().any(|s| s.value == "KERNEL32.DLL"));
    assert!(strings.iter().any(|s| s.value == "LoadLibraryA"));
}

// ---------------------------------------------------------------------------
// Watch config
// ---------------------------------------------------------------------------

#[test]
fn watch_config_integration() {
    use phylax::watch::WatchConfig;

    let config = WatchConfig {
        paths: vec![std::path::PathBuf::from("/tmp")],
        recursive: true,
        extensions: vec!["bin".into(), "exe".into()],
        ..Default::default()
    };

    assert!(config.recursive);
    assert_eq!(config.extensions.len(), 2);
    assert_eq!(config.max_file_size, 50 * 1024 * 1024);
}

// ---------------------------------------------------------------------------
// Queue + Report integration
// ---------------------------------------------------------------------------

#[test]
fn queue_feeds_report() {
    use phylax::queue::{ScanPriority, ScanQueue};

    let q = ScanQueue::new(100);
    q.enqueue(ScanTarget::File("/a".into()), ScanPriority::Critical);
    q.enqueue(ScanTarget::File("/b".into()), ScanPriority::Low);
    q.enqueue(ScanTarget::File("/c".into()), ScanPriority::High);

    // Dequeue in priority order
    let first = q.dequeue().unwrap();
    assert_eq!(first.priority, ScanPriority::Critical);

    // Simulate scan results from queue
    let results: Vec<phylax::core::ScanResult> = vec![phylax::core::ScanResult {
        target: first.target,
        findings: vec![ThreatFinding::new(
            ScanTarget::File("/a".into()),
            FindingCategory::Malware,
            FindingSeverity::Critical,
            "malware_detected",
            "Known malware signature",
        )],
        scan_duration: Duration::from_millis(100),
        scanner_version: "test".into(),
    }];

    let report = ThreatReport::from_results(results);
    assert_eq!(report.summary.critical_count, 1);
    assert_eq!(report.total_findings, 1);
}
