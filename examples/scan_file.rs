//! Example: scan a file using the Phylax analysis pipeline.
//!
//! Usage:
//!   cargo run --example scan_file -- <path-to-file>

use phylax::analyze::{
    analyze, analyze_findings, entropy_profile, is_suspicious_entropy, shannon_entropy,
};
use phylax::core::ScanTarget;
use phylax::yara::YaraEngine;
use std::env;

fn main() {
    let path = env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: scan_file <path>");
        std::process::exit(1);
    });

    let data = std::fs::read(&path).expect("failed to read file");
    let start = std::time::Instant::now();

    let analysis = analyze(&data);
    println!("File:     {path}");
    println!("Type:     {}", analysis.file_type);
    println!("Size:     {} bytes", analysis.size);
    println!("SHA-256:  {}", analysis.sha256);

    let entropy = shannon_entropy(&data);
    println!(
        "Entropy:  {entropy:.4} bits/byte {}",
        if is_suspicious_entropy(entropy) {
            "(SUSPICIOUS)"
        } else {
            "(normal)"
        }
    );

    let profile = entropy_profile(&data, 4096);
    if let Some((idx, &max)) = profile
        .iter()
        .enumerate()
        .max_by(|a, b| a.1.partial_cmp(b.1).unwrap())
    {
        println!(
            "Profile:  {} blocks, max {max:.4} at block {idx}",
            profile.len()
        );
    }

    let engine = YaraEngine::new();
    let yara_findings = engine.scan(&data);
    let analyze_findings = analyze_findings(&data, ScanTarget::File(path.into()));
    let total = yara_findings.len() + analyze_findings.len();

    println!("\nFindings: {total} ({:.2?})", start.elapsed());
    for f in yara_findings.iter().chain(analyze_findings.iter()) {
        println!(
            "  [{severity}] {rule}: {desc}",
            severity = f.severity,
            rule = f.rule_name,
            desc = f.description,
        );
    }
}
