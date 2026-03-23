//! Integration tests for the Phylax scan pipeline.

use phylax_analyze::{
    FileType, analyze, analyze_findings, detect_file_type, detect_polyglot, entropy_profile,
    file_sha256, is_suspicious_entropy, shannon_entropy,
};
use phylax_core::{FindingSeverity, ScanTarget};
use phylax_mcp::list_tools;
use phylax_yara::YaraEngine;

// ---------------------------------------------------------------------------
// Full scan pipeline
// ---------------------------------------------------------------------------

#[test]
fn scan_elf_binary_end_to_end() {
    // Construct a minimal ELF-like payload
    let mut data = vec![0u8; 1024];
    data[0] = 0x7f;
    data[1] = 0x45;
    data[2] = 0x4c;
    data[3] = 0x46;

    // File type detection
    let ft = detect_file_type(&data);
    assert_eq!(ft, FileType::Elf);

    // Entropy
    let entropy = shannon_entropy(&data);
    assert!((0.0..=8.0).contains(&entropy));

    // SHA-256
    let hash = file_sha256(&data);
    assert_eq!(hash.len(), 64);

    // Full analysis
    let analysis = analyze(&data);
    assert_eq!(analysis.file_type, FileType::Elf);
    assert_eq!(analysis.size, 1024);

    // Findings
    let findings = analyze_findings(&data, ScanTarget::File("/test/elf".into()));
    // ELF detection should not produce findings on its own (it's a known type, not suspicious)
    // but entropy or polyglot might
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

    // Data with the marker
    let data = b"some content MALWARE_MARKER more content";
    let findings = engine.scan(data);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_name, "test_rule");
    assert_eq!(findings[0].severity, FindingSeverity::High);

    // Data without the marker
    let clean = b"perfectly normal content here";
    let findings = engine.scan(clean);
    assert!(findings.is_empty());
}

#[test]
fn entropy_profile_consistency() {
    let data = vec![0xAA; 8192];

    let entropy = shannon_entropy(&data);
    let profile = entropy_profile(&data, 4096);

    // Uniform data should have zero entropy
    assert!(entropy < 0.01);
    assert!(!is_suspicious_entropy(entropy));

    for block_entropy in &profile {
        assert!(*block_entropy < 0.01);
    }
}

#[test]
fn polyglot_detection() {
    // ZIP magic followed by PDF magic later in the file
    let mut data = vec![0u8; 512];
    // ZIP header
    data[0] = 0x50;
    data[1] = 0x4b;
    data[2] = 0x03;
    data[3] = 0x04;
    // PDF header at offset 256
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

#[test]
fn mcp_tools_complete() {
    let tools = list_tools();
    assert_eq!(tools.len(), 5);

    let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
    assert!(names.contains(&"phylax_scan"));
    assert!(names.contains(&"phylax_rules"));
    assert!(names.contains(&"phylax_status"));
    assert!(names.contains(&"phylax_quarantine"));
    assert!(names.contains(&"phylax_report"));
}
