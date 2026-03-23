//! phylax-analyze — Entropy analysis, magic bytes detection, and binary classification.

use phylax_core::{FindingCategory, FindingSeverity, ScanTarget, ThreatFinding};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

// ---------------------------------------------------------------------------
// Entropy analysis
// ---------------------------------------------------------------------------

/// Compute Shannon entropy of a byte slice (bits per byte, 0.0..=8.0).
///
/// Returns 0.0 for empty data.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Compute entropy for successive blocks of `block_size` bytes.
///
/// The last block may be smaller than `block_size`.
pub fn entropy_profile(data: &[u8], block_size: usize) -> Vec<f64> {
    if data.is_empty() || block_size == 0 {
        return vec![];
    }

    data.chunks(block_size)
        .map(|chunk| shannon_entropy(chunk))
        .collect()
}

/// Heuristic: entropy above 7.5 bits/byte is suspicious (likely encrypted or compressed).
pub fn is_suspicious_entropy(entropy: f64) -> bool {
    entropy > 7.5
}

// ---------------------------------------------------------------------------
// File type detection via magic bytes
// ---------------------------------------------------------------------------

/// Known file types identified by magic bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FileType {
    Elf,
    Pe,
    MachO,
    Pdf,
    Zip,
    Gzip,
    Png,
    Jpeg,
    Script,
    Unknown,
}

impl fmt::Display for FileType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Elf => write!(f, "ELF"),
            Self::Pe => write!(f, "PE"),
            Self::MachO => write!(f, "Mach-O"),
            Self::Pdf => write!(f, "PDF"),
            Self::Zip => write!(f, "ZIP"),
            Self::Gzip => write!(f, "GZIP"),
            Self::Png => write!(f, "PNG"),
            Self::Jpeg => write!(f, "JPEG"),
            Self::Script => write!(f, "Script"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Detect file type from magic bytes at the start of data.
pub fn detect_file_type(data: &[u8]) -> FileType {
    if data.len() < 2 {
        return FileType::Unknown;
    }

    // ELF: 7f 45 4c 46
    if data.len() >= 4 && data[..4] == [0x7f, 0x45, 0x4c, 0x46] {
        return FileType::Elf;
    }

    // PE (DOS MZ header): 4d 5a
    if data[..2] == [0x4d, 0x5a] {
        return FileType::Pe;
    }

    // Mach-O: feedface (32-bit) or feedfacf (64-bit), both endiannesses
    if data.len() >= 4 {
        let magic4 = &data[..4];
        if magic4 == [0xfe, 0xed, 0xfa, 0xce]
            || magic4 == [0xfe, 0xed, 0xfa, 0xcf]
            || magic4 == [0xce, 0xfa, 0xed, 0xfe]
            || magic4 == [0xcf, 0xfa, 0xed, 0xfe]
        {
            return FileType::MachO;
        }
    }

    // PDF: 25 50 44 46 (%PDF)
    if data.len() >= 4 && data[..4] == [0x25, 0x50, 0x44, 0x46] {
        return FileType::Pdf;
    }

    // PNG: 89 50 4e 47
    if data.len() >= 4 && data[..4] == [0x89, 0x50, 0x4e, 0x47] {
        return FileType::Png;
    }

    // JPEG: ff d8 ff
    if data.len() >= 3 && data[..3] == [0xff, 0xd8, 0xff] {
        return FileType::Jpeg;
    }

    // ZIP: 50 4b 03 04
    if data.len() >= 4 && data[..4] == [0x50, 0x4b, 0x03, 0x04] {
        return FileType::Zip;
    }

    // GZIP: 1f 8b
    if data[..2] == [0x1f, 0x8b] {
        return FileType::Gzip;
    }

    // Script: #!
    if data[..2] == [0x23, 0x21] {
        return FileType::Script;
    }

    FileType::Unknown
}

/// Detect if data could be a polyglot (multiple valid file types).
///
/// Checks header and also scans for embedded signatures.
pub fn detect_polyglot(data: &[u8]) -> Vec<FileType> {
    let mut types = Vec::new();

    let primary = detect_file_type(data);
    if primary != FileType::Unknown {
        types.push(primary);
    }

    // Check for embedded signatures beyond the header
    let signatures: &[(&[u8], FileType)] = &[
        (b"\x7fELF", FileType::Elf),
        (b"MZ", FileType::Pe),
        (b"%PDF", FileType::Pdf),
        (b"PK\x03\x04", FileType::Zip),
    ];

    for &(sig, ft) in signatures {
        if ft == primary {
            continue;
        }
        // Search after the first few bytes (skip header)
        if data.len() > sig.len() + 4 {
            let search_area = &data[4..];
            if search_area
                .windows(sig.len())
                .any(|w| w == sig)
            {
                types.push(ft);
            }
        }
    }

    types
}

// ---------------------------------------------------------------------------
// SHA-256
// ---------------------------------------------------------------------------

/// Compute the SHA-256 hash of data, returned as a lowercase hex string.
pub fn file_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex_encode(&result)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ---------------------------------------------------------------------------
// BinaryAnalysis
// ---------------------------------------------------------------------------

/// Summary of binary analysis results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryAnalysis {
    pub file_type: FileType,
    pub entropy: f64,
    pub size: usize,
    pub sha256: String,
}

/// Perform a full binary analysis on raw data.
pub fn analyze(data: &[u8]) -> BinaryAnalysis {
    BinaryAnalysis {
        file_type: detect_file_type(data),
        entropy: shannon_entropy(data),
        size: data.len(),
        sha256: file_sha256(data),
    }
}

/// Produce threat findings from binary analysis.
pub fn analyze_findings(data: &[u8], target: ScanTarget) -> Vec<ThreatFinding> {
    let analysis = analyze(data);
    let mut findings = Vec::new();

    if is_suspicious_entropy(analysis.entropy) {
        let mut f = ThreatFinding::new(
            target.clone(),
            FindingCategory::Suspicious,
            FindingSeverity::Medium,
            "high_entropy",
            format!(
                "High entropy detected: {:.2} bits/byte (threshold: 7.5)",
                analysis.entropy
            ),
        );
        f.metadata
            .insert("entropy".into(), format!("{:.4}", analysis.entropy));
        f.metadata
            .insert("sha256".into(), analysis.sha256.clone());
        findings.push(f);
    }

    // Check for polyglot files
    let poly = detect_polyglot(data);
    if poly.len() > 1 {
        let types_str: Vec<String> = poly.iter().map(|t| t.to_string()).collect();
        let mut f = ThreatFinding::new(
            target,
            FindingCategory::EmbeddedPayload,
            FindingSeverity::High,
            "polyglot_file",
            format!("Polyglot file detected: {}", types_str.join(", ")),
        );
        f.metadata
            .insert("file_types".into(), types_str.join(","));
        findings.push(f);
    }

    findings
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_of_zeros() {
        let data = vec![0u8; 1024];
        let e = shannon_entropy(&data);
        assert!((e - 0.0).abs() < 0.001, "entropy of zeros should be 0, got {e}");
    }

    #[test]
    fn entropy_of_two_values() {
        // 50/50 split of two values => entropy = 1.0
        let mut data = vec![0u8; 512];
        data.extend(vec![1u8; 512]);
        let e = shannon_entropy(&data);
        assert!((e - 1.0).abs() < 0.01, "entropy of two equal values should be ~1.0, got {e}");
    }

    #[test]
    fn entropy_of_uniform_random_high() {
        // All 256 byte values equally represented => entropy = 8.0
        let mut data = Vec::with_capacity(256 * 100);
        for _ in 0..100 {
            for b in 0..=255u8 {
                data.push(b);
            }
        }
        let e = shannon_entropy(&data);
        assert!(e > 7.9 && e <= 8.0, "uniform distribution entropy should be ~8.0, got {e}");
    }

    #[test]
    fn entropy_empty() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn entropy_profile_basic() {
        let data = vec![0u8; 200];
        let profile = entropy_profile(&data, 100);
        assert_eq!(profile.len(), 2);
        assert!(profile[0] < 0.01);
    }

    #[test]
    fn entropy_profile_empty() {
        assert!(entropy_profile(&[], 100).is_empty());
        assert!(entropy_profile(&[1, 2, 3], 0).is_empty());
    }

    #[test]
    fn suspicious_entropy_threshold() {
        assert!(!is_suspicious_entropy(5.0));
        assert!(!is_suspicious_entropy(7.5));
        assert!(is_suspicious_entropy(7.51));
        assert!(is_suspicious_entropy(8.0));
    }

    #[test]
    fn detect_elf() {
        assert_eq!(detect_file_type(b"\x7fELF\x02\x01\x01"), FileType::Elf);
    }

    #[test]
    fn detect_pe() {
        assert_eq!(detect_file_type(b"MZ\x90\x00\x03"), FileType::Pe);
    }

    #[test]
    fn detect_pdf() {
        assert_eq!(detect_file_type(b"%PDF-1.7"), FileType::Pdf);
    }

    #[test]
    fn detect_zip() {
        assert_eq!(detect_file_type(b"PK\x03\x04extra"), FileType::Zip);
    }

    #[test]
    fn detect_gzip() {
        assert_eq!(detect_file_type(b"\x1f\x8b\x08\x00"), FileType::Gzip);
    }

    #[test]
    fn detect_png() {
        assert_eq!(detect_file_type(b"\x89PNG\r\n\x1a\n"), FileType::Png);
    }

    #[test]
    fn detect_jpeg() {
        assert_eq!(detect_file_type(b"\xff\xd8\xff\xe0"), FileType::Jpeg);
    }

    #[test]
    fn detect_macho_32() {
        assert_eq!(detect_file_type(b"\xfe\xed\xfa\xce"), FileType::MachO);
    }

    #[test]
    fn detect_macho_64() {
        assert_eq!(detect_file_type(b"\xfe\xed\xfa\xcf"), FileType::MachO);
    }

    #[test]
    fn detect_macho_reversed() {
        assert_eq!(detect_file_type(b"\xcf\xfa\xed\xfe"), FileType::MachO);
    }

    #[test]
    fn detect_script() {
        assert_eq!(detect_file_type(b"#!/bin/bash\n"), FileType::Script);
    }

    #[test]
    fn detect_unknown() {
        assert_eq!(detect_file_type(b"\x00\x00\x00\x00"), FileType::Unknown);
    }

    #[test]
    fn detect_too_short() {
        assert_eq!(detect_file_type(b"X"), FileType::Unknown);
    }

    #[test]
    fn sha256_known_value() {
        // SHA-256 of empty input
        let hash = file_sha256(b"");
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_hello() {
        let hash = file_sha256(b"hello");
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn analyze_basic() {
        let data = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let a = analyze(data);
        assert_eq!(a.file_type, FileType::Elf);
        assert_eq!(a.size, data.len());
        assert!(!a.sha256.is_empty());
        assert!(a.entropy >= 0.0);
    }

    #[test]
    fn polyglot_detection() {
        // Build data: starts as PDF but has embedded ZIP signature
        let mut data = b"%PDF-1.7 some content ".to_vec();
        data.extend_from_slice(b"PK\x03\x04 more data");
        let types = detect_polyglot(&data);
        assert!(types.contains(&FileType::Pdf));
        assert!(types.contains(&FileType::Zip));
    }

    #[test]
    fn analyze_findings_clean() {
        let data = vec![0u8; 100];
        let findings = analyze_findings(&data, ScanTarget::Memory);
        // Low entropy, single type => no findings
        assert!(findings.is_empty());
    }

    #[test]
    fn file_type_display() {
        assert_eq!(FileType::Elf.to_string(), "ELF");
        assert_eq!(FileType::Pe.to_string(), "PE");
        assert_eq!(FileType::Unknown.to_string(), "Unknown");
    }
}
