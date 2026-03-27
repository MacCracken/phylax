//! Entropy analysis, magic bytes detection, and binary classification.

use crate::types::{FindingCategory, FindingSeverity, ScanTarget, ThreatFinding};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use tracing::{debug, instrument, warn};

// ---------------------------------------------------------------------------
// Entropy analysis
// ---------------------------------------------------------------------------

/// Compute Shannon entropy of a byte slice (bits per byte, 0.0..=8.0).
///
/// Returns 0.0 for empty data.
#[inline]
#[must_use]
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
#[must_use]
pub fn entropy_profile(data: &[u8], block_size: usize) -> Vec<f64> {
    if data.is_empty() || block_size == 0 {
        return vec![];
    }

    data.chunks(block_size).map(shannon_entropy).collect()
}

/// Heuristic: entropy above 7.5 bits/byte is suspicious (likely encrypted or compressed).
#[inline]
#[must_use]
pub fn is_suspicious_entropy(entropy: f64) -> bool {
    entropy > 7.5
}

/// Compute the chi-squared statistic for a byte distribution.
///
/// Measures how much the byte frequency distribution deviates from uniform.
/// For truly random data (encryption), chi² ≈ 256 (degrees of freedom = 255).
/// For compressed data, chi² is typically higher (skewed distribution).
/// For plaintext/code, chi² is much higher (very non-uniform).
///
/// Returns 0.0 for empty data.
#[inline]
#[must_use]
pub fn chi_squared(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }

    let expected = data.len() as f64 / 256.0;
    let mut chi2 = 0.0;

    for &count in &freq {
        let diff = count as f64 - expected;
        chi2 += (diff * diff) / expected;
    }

    chi2
}

/// Classify data randomness based on chi-squared value.
///
/// - `Encrypted`: chi² close to 256 (uniform distribution)
/// - `Compressed`: chi² moderately elevated (slightly skewed)
/// - `Normal`: chi² very high (structured data like text/code)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum RandomnessClass {
    /// Likely encrypted or truly random (chi² roughly 128–512).
    Encrypted,
    /// Likely compressed (chi² roughly 512–4096).
    Compressed,
    /// Normal structured data (chi² > 4096).
    Normal,
}

impl fmt::Display for RandomnessClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encrypted => write!(f, "encrypted"),
            Self::Compressed => write!(f, "compressed"),
            Self::Normal => write!(f, "normal"),
        }
    }
}

/// Classify data based on its chi-squared statistic.
#[inline]
#[must_use]
pub fn classify_randomness(chi2: f64) -> RandomnessClass {
    if chi2 <= 512.0 {
        RandomnessClass::Encrypted
    } else if chi2 <= 4096.0 {
        RandomnessClass::Compressed
    } else {
        RandomnessClass::Normal
    }
}

// ---------------------------------------------------------------------------
// File type detection via magic bytes
// ---------------------------------------------------------------------------

/// Known file types identified by magic bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
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
#[inline]
#[must_use]
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
#[must_use]
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
            if memchr::memmem::find(search_area, sig).is_some() {
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
#[must_use]
pub fn file_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex_encode(&result)
}

#[inline]
fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        let _ = write!(s, "{b:02x}");
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
#[must_use]
#[instrument(skip(data), fields(data_len = data.len()))]
pub fn analyze(data: &[u8]) -> BinaryAnalysis {
    BinaryAnalysis {
        file_type: detect_file_type(data),
        entropy: shannon_entropy(data),
        size: data.len(),
        sha256: file_sha256(data),
    }
}

/// Produce threat findings from a pre-computed analysis.
///
/// Use this when you already have a `BinaryAnalysis` to avoid recomputation.
#[must_use]
pub fn findings_from_analysis(
    data: &[u8],
    analysis: &BinaryAnalysis,
    target: ScanTarget,
) -> Vec<ThreatFinding> {
    let mut findings = Vec::new();

    if is_suspicious_entropy(analysis.entropy) {
        warn!(
            entropy = analysis.entropy,
            "high entropy detected — possible encrypted or compressed content"
        );
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
        f.metadata.insert("sha256".into(), analysis.sha256.clone());
        findings.push(f);
    }

    let poly = detect_polyglot(data);
    if poly.len() > 1 {
        debug!(types = ?poly, "polyglot file detected");
        let types_str: Vec<String> = poly.iter().map(|t| t.to_string()).collect();
        let mut f = ThreatFinding::new(
            target,
            FindingCategory::EmbeddedPayload,
            FindingSeverity::High,
            "polyglot_file",
            format!("Polyglot file detected: {}", types_str.join(", ")),
        );
        f.metadata.insert("file_types".into(), types_str.join(","));
        findings.push(f);
    }

    findings
}

/// Produce threat findings from binary analysis.
///
/// Convenience wrapper that computes analysis internally.
/// Prefer [`findings_from_analysis`] if you already have a [`BinaryAnalysis`].
#[must_use]
#[instrument(skip(data), fields(data_len = data.len()))]
pub fn analyze_findings(data: &[u8], target: ScanTarget) -> Vec<ThreatFinding> {
    let analysis = analyze(data);
    findings_from_analysis(data, &analysis, target)
}

/// Auto-escalate finding severity based on combined signals.
///
/// Rules:
/// - High entropy + polyglot = escalate to Critical
/// - Multiple findings with Medium+ severity = escalate highest to High
/// - Any finding with executable file type = escalate by one level
pub fn escalate_severity(findings: &mut [ThreatFinding], analysis: &BinaryAnalysis) {
    if findings.is_empty() {
        return;
    }

    let has_high_entropy = findings.iter().any(|f| f.rule_name == "high_entropy");
    let has_polyglot = findings.iter().any(|f| f.rule_name == "polyglot_file");
    let is_executable = matches!(
        analysis.file_type,
        FileType::Elf | FileType::Pe | FileType::MachO
    );

    // High entropy + polyglot = critical
    if has_high_entropy && has_polyglot {
        for f in findings.iter_mut() {
            if f.rule_name == "polyglot_file" {
                f.severity = FindingSeverity::Critical;
                f.metadata
                    .insert("escalated_polyglot".into(), "high_entropy+polyglot".into());
            }
        }
    }

    // Executable file type escalates Medium -> High
    if is_executable {
        for f in findings.iter_mut() {
            if f.severity == FindingSeverity::Medium {
                f.severity = FindingSeverity::High;
                f.metadata
                    .insert("escalated_executable".into(), "executable_file_type".into());
            }
        }
    }

    // Multiple Medium+ findings = escalate highest
    let medium_plus_count = findings
        .iter()
        .filter(|f| f.severity >= FindingSeverity::Medium)
        .count();
    if medium_plus_count >= 2 {
        if let Some(highest) = findings.iter_mut().max_by_key(|f| f.severity) {
            if highest.severity == FindingSeverity::High {
                highest.severity = FindingSeverity::Critical;
                highest
                    .metadata
                    .insert("escalated_signals".into(), "multiple_signals".into());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Section entropy analysis
// ---------------------------------------------------------------------------

/// Entropy computed for a named section of a binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionEntropy {
    /// Section name.
    pub name: String,
    /// Shannon entropy of the section's raw data (bits/byte).
    pub entropy: f64,
    /// Size of the section's raw data on disk.
    pub raw_size: usize,
    /// Whether the section is executable.
    pub executable: bool,
    /// Whether the section is writable.
    pub writable: bool,
}

/// Compute entropy for each section of a PE binary.
#[must_use]
pub fn pe_section_entropy(data: &[u8], pe: &crate::pe::PeInfo) -> Vec<SectionEntropy> {
    pe.sections
        .iter()
        .filter_map(|sec| {
            let offset = sec.raw_data_offset as usize;
            let size = sec.raw_data_size as usize;
            if size == 0 || offset >= data.len() {
                return None;
            }
            let end = (offset + size).min(data.len());
            let entropy = shannon_entropy(&data[offset..end]);
            Some(SectionEntropy {
                name: sec.name.clone(),
                entropy,
                raw_size: end - offset,
                executable: sec.is_executable(),
                writable: sec.is_writable(),
            })
        })
        .collect()
}

/// Compute entropy for each section of an ELF binary.
#[must_use]
pub fn elf_section_entropy(data: &[u8], elf: &crate::elf::ElfInfo) -> Vec<SectionEntropy> {
    elf.sections
        .iter()
        .filter_map(|sec| {
            let offset = sec.offset as usize;
            let size = sec.size as usize;
            if size == 0 || offset >= data.len() {
                return None;
            }
            let end = (offset + size).min(data.len());
            let entropy = shannon_entropy(&data[offset..end]);
            Some(SectionEntropy {
                name: sec.name.clone(),
                entropy,
                raw_size: end - offset,
                executable: sec.is_executable(),
                writable: sec.is_writable(),
            })
        })
        .collect()
}

/// Suspicious entropy threshold for code sections (.text, .code).
const CODE_SECTION_ENTROPY_THRESHOLD: f64 = 7.0;

/// Generate findings from per-section entropy analysis.
#[must_use]
pub fn section_entropy_findings(
    sections: &[SectionEntropy],
    target: ScanTarget,
) -> Vec<ThreatFinding> {
    let mut findings = Vec::new();

    for sec in sections {
        let threshold = if sec.executable {
            CODE_SECTION_ENTROPY_THRESHOLD
        } else {
            7.5
        };

        if sec.entropy > threshold {
            let mut f = ThreatFinding::new(
                target.clone(),
                FindingCategory::Suspicious,
                if sec.executable {
                    FindingSeverity::High
                } else {
                    FindingSeverity::Medium
                },
                "high_section_entropy",
                format!(
                    "Section '{}' has high entropy: {:.2} bits/byte (threshold: {:.1})",
                    sec.name, sec.entropy, threshold
                ),
            );
            f.metadata.insert("section".into(), sec.name.clone());
            f.metadata
                .insert("entropy".into(), format!("{:.4}", sec.entropy));
            f.metadata
                .insert("executable".into(), sec.executable.to_string());
            findings.push(f);
        }
    }

    findings
}

// ---------------------------------------------------------------------------
// PE overlay detection
// ---------------------------------------------------------------------------

/// Information about data appended after the last PE section (overlay).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverlayInfo {
    /// Offset where the overlay begins.
    pub offset: usize,
    /// Size of the overlay in bytes.
    pub size: usize,
    /// Shannon entropy of the overlay data.
    pub entropy: f64,
}

/// Detect overlay data in a PE binary (data appended after the last section).
#[must_use]
pub fn detect_pe_overlay(data: &[u8], pe: &crate::pe::PeInfo) -> Option<OverlayInfo> {
    let pe_end = pe
        .sections
        .iter()
        .map(|s| (s.raw_data_offset as usize).saturating_add(s.raw_data_size as usize))
        .max()
        .unwrap_or(0);

    if pe_end == 0 || pe_end >= data.len() {
        return None;
    }

    let overlay_size = data.len() - pe_end;
    // Ignore tiny overlays (alignment padding)
    if overlay_size < 64 {
        return None;
    }

    let entropy = shannon_entropy(&data[pe_end..]);
    Some(OverlayInfo {
        offset: pe_end,
        size: overlay_size,
        entropy,
    })
}

/// Generate findings from PE overlay analysis.
#[must_use]
pub fn overlay_findings(overlay: &OverlayInfo, target: ScanTarget) -> Vec<ThreatFinding> {
    let mut findings = Vec::new();

    let mut f = ThreatFinding::new(
        target,
        FindingCategory::Suspicious,
        if is_suspicious_entropy(overlay.entropy) {
            FindingSeverity::High
        } else {
            FindingSeverity::Low
        },
        "pe_overlay",
        format!(
            "PE overlay detected: {} bytes at offset 0x{:X} (entropy: {:.2})",
            overlay.size, overlay.offset, overlay.entropy
        ),
    );
    f.metadata
        .insert("overlay_offset".into(), format!("0x{:X}", overlay.offset));
    f.metadata
        .insert("overlay_size".into(), overlay.size.to_string());
    f.metadata
        .insert("overlay_entropy".into(), format!("{:.4}", overlay.entropy));
    findings.push(f);

    findings
}

// ---------------------------------------------------------------------------
// Packed binary heuristics
// ---------------------------------------------------------------------------

/// Known packer section names.
const PACKER_SECTIONS: &[&str] = &[
    "UPX0", "UPX1", "UPX2", "UPX!", ".aspack", ".adata", ".vmp0", ".vmp1", ".vmp2", ".themida",
    ".petite", ".nsp0", ".nsp1", ".nsp2", ".packed", ".mpress1", ".mpress2",
];

/// Signals that suggest a binary is packed or encrypted.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PackingSignals {
    /// Known packer section names found.
    pub packer_sections: Vec<String>,
    /// Sections that are both writable and executable (W^X violation).
    pub wx_sections: Vec<String>,
    /// Sections with raw_size = 0 but virtual_size > 0 (unpacking target).
    pub hollow_sections: Vec<String>,
    /// Number of imported functions (very few = suspicious).
    pub import_count: usize,
    /// Whether the entry point is in a high-entropy section.
    pub entry_in_high_entropy: bool,
    /// Whether an overlay with high entropy exists.
    pub has_encrypted_overlay: bool,
}

impl PackingSignals {
    /// How many distinct packing indicators fired.
    #[must_use]
    pub fn signal_count(&self) -> usize {
        let mut count = 0;
        if !self.packer_sections.is_empty() {
            count += 1;
        }
        if !self.wx_sections.is_empty() {
            count += 1;
        }
        if !self.hollow_sections.is_empty() {
            count += 1;
        }
        if self.import_count < 5 && self.import_count > 0 {
            count += 1;
        }
        if self.entry_in_high_entropy {
            count += 1;
        }
        if self.has_encrypted_overlay {
            count += 1;
        }
        count
    }
}

/// Analyze a PE binary for packing indicators.
#[must_use]
pub fn detect_pe_packing(
    pe: &crate::pe::PeInfo,
    section_entropies: &[SectionEntropy],
    overlay: Option<&OverlayInfo>,
) -> PackingSignals {
    let mut signals = PackingSignals::default();

    // Check for known packer section names
    for sec in &pe.sections {
        if PACKER_SECTIONS
            .iter()
            .any(|p| p.eq_ignore_ascii_case(&sec.name))
        {
            signals.packer_sections.push(sec.name.clone());
        }
        // W^X: writable + executable
        if sec.is_writable() && sec.is_executable() {
            signals.wx_sections.push(sec.name.clone());
        }
        // Hollow section: raw_size = 0 but virtual_size > 0
        if sec.raw_data_size == 0 && sec.virtual_size > 0 {
            signals.hollow_sections.push(sec.name.clone());
        }
    }

    // Import count
    signals.import_count = pe.imports.len();

    // Entry point in high-entropy section
    for (sec, ent) in pe.sections.iter().zip(section_entropies.iter()) {
        let sec_start = sec.virtual_address;
        let sec_end = sec_start.saturating_add(sec.virtual_size);
        if pe.entry_point >= sec_start
            && pe.entry_point < sec_end
            && ent.entropy > CODE_SECTION_ENTROPY_THRESHOLD
        {
            signals.entry_in_high_entropy = true;
            break;
        }
    }

    // Encrypted overlay
    if let Some(ov) = overlay {
        if is_suspicious_entropy(ov.entropy) {
            signals.has_encrypted_overlay = true;
        }
    }

    signals
}

/// Generate findings from packing analysis.
#[must_use]
pub fn packing_findings(signals: &PackingSignals, target: ScanTarget) -> Vec<ThreatFinding> {
    let count = signals.signal_count();
    if count == 0 {
        return Vec::new();
    }

    let severity = match count {
        1 => FindingSeverity::Low,
        2 => FindingSeverity::Medium,
        _ => FindingSeverity::High,
    };

    let mut descriptions = Vec::new();
    if !signals.packer_sections.is_empty() {
        descriptions.push(format!(
            "packer sections: {}",
            signals.packer_sections.join(", ")
        ));
    }
    if !signals.wx_sections.is_empty() {
        descriptions.push(format!("W^X sections: {}", signals.wx_sections.join(", ")));
    }
    if !signals.hollow_sections.is_empty() {
        descriptions.push(format!(
            "hollow sections: {}",
            signals.hollow_sections.join(", ")
        ));
    }
    if signals.import_count < 5 && signals.import_count > 0 {
        descriptions.push(format!("few imports ({})", signals.import_count));
    }
    if signals.entry_in_high_entropy {
        descriptions.push("entry point in high-entropy section".into());
    }
    if signals.has_encrypted_overlay {
        descriptions.push("encrypted overlay".into());
    }

    let mut f = ThreatFinding::new(
        target,
        FindingCategory::Suspicious,
        severity,
        "packed_binary",
        format!(
            "Packed/encrypted binary ({} signal{}): {}",
            count,
            if count == 1 { "" } else { "s" },
            descriptions.join("; ")
        ),
    );
    f.metadata.insert("signal_count".into(), count.to_string());
    for (i, desc) in descriptions.iter().enumerate() {
        f.metadata.insert(format!("signal_{i}"), desc.clone());
    }

    vec![f]
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
        assert!(
            (e - 0.0).abs() < 0.001,
            "entropy of zeros should be 0, got {e}"
        );
    }

    #[test]
    fn entropy_of_two_values() {
        let mut data = vec![0u8; 512];
        data.extend(vec![1u8; 512]);
        let e = shannon_entropy(&data);
        assert!(
            (e - 1.0).abs() < 0.01,
            "entropy of two equal values should be ~1.0, got {e}"
        );
    }

    #[test]
    fn entropy_of_uniform_random_high() {
        let mut data = Vec::with_capacity(256 * 100);
        for _ in 0..100 {
            for b in 0..=255u8 {
                data.push(b);
            }
        }
        let e = shannon_entropy(&data);
        assert!(
            e > 7.9 && e <= 8.0,
            "uniform distribution entropy should be ~8.0, got {e}"
        );
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
        assert!(findings.is_empty());
    }

    #[test]
    fn entropy_single_byte() {
        assert_eq!(shannon_entropy(&[42]), 0.0);
    }

    #[test]
    fn sha256_deterministic() {
        let data = b"reproducible";
        assert_eq!(file_sha256(data), file_sha256(data));
    }

    #[test]
    fn detect_polyglot_empty() {
        assert!(detect_polyglot(&[]).is_empty());
    }

    #[test]
    fn detect_polyglot_single_type() {
        let types = detect_polyglot(b"\x7fELF\x00\x00\x00\x00\x00\x00");
        assert_eq!(types.len(), 1);
        assert_eq!(types[0], FileType::Elf);
    }

    #[test]
    fn analyze_findings_high_entropy() {
        // All 256 byte values = max entropy > 7.5
        let mut data = Vec::with_capacity(256 * 4);
        for _ in 0..4 {
            for b in 0..=255u8 {
                data.push(b);
            }
        }
        let findings = analyze_findings(&data, ScanTarget::Memory);
        assert!(findings.iter().any(|f| f.rule_name == "high_entropy"));
    }

    #[test]
    fn binary_analysis_serialization_roundtrip() {
        let a = analyze(b"\x7fELF\x02\x01\x01\x00");
        let json = serde_json::to_string(&a).unwrap();
        let parsed: BinaryAnalysis = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.file_type, a.file_type);
        assert_eq!(parsed.sha256, a.sha256);
        assert_eq!(parsed.size, a.size);
    }

    #[test]
    fn findings_from_precomputed_analysis() {
        // All 256 byte values = max entropy > 7.5
        let mut data = Vec::with_capacity(256 * 4);
        for _ in 0..4 {
            for b in 0..=255u8 {
                data.push(b);
            }
        }
        let analysis = analyze(&data);
        let findings = super::findings_from_analysis(&data, &analysis, ScanTarget::Memory);
        assert!(findings.iter().any(|f| f.rule_name == "high_entropy"));
    }

    #[test]
    fn file_type_display() {
        assert_eq!(FileType::Elf.to_string(), "ELF");
        assert_eq!(FileType::Pe.to_string(), "PE");
        assert_eq!(FileType::Unknown.to_string(), "Unknown");
    }

    #[test]
    fn escalate_entropy_plus_polyglot_to_critical() {
        let analysis = BinaryAnalysis {
            file_type: FileType::Unknown,
            entropy: 7.9,
            size: 1024,
            sha256: "abc".into(),
        };
        let mut findings = vec![
            ThreatFinding::new(
                ScanTarget::Memory,
                FindingCategory::Suspicious,
                FindingSeverity::Medium,
                "high_entropy",
                "high entropy",
            ),
            ThreatFinding::new(
                ScanTarget::Memory,
                FindingCategory::EmbeddedPayload,
                FindingSeverity::High,
                "polyglot_file",
                "polyglot",
            ),
        ];
        escalate_severity(&mut findings, &analysis);
        let polyglot = findings
            .iter()
            .find(|f| f.rule_name == "polyglot_file")
            .unwrap();
        assert_eq!(polyglot.severity, FindingSeverity::Critical);
    }

    #[test]
    fn escalate_executable_medium_to_high() {
        let analysis = BinaryAnalysis {
            file_type: FileType::Elf,
            entropy: 5.0,
            size: 1024,
            sha256: "abc".into(),
        };
        let mut findings = vec![ThreatFinding::new(
            ScanTarget::Memory,
            FindingCategory::CustomRule,
            FindingSeverity::Medium,
            "some_rule",
            "desc",
        )];
        escalate_severity(&mut findings, &analysis);
        assert_eq!(findings[0].severity, FindingSeverity::High);
        assert_eq!(
            findings[0].metadata.get("escalated_executable").unwrap(),
            "executable_file_type"
        );
    }

    #[test]
    fn escalate_cascading_executable_plus_multiple() {
        // Executable escalates Medium→High, then multiple High signals should
        // escalate one to Critical
        let analysis = BinaryAnalysis {
            file_type: FileType::Pe,
            entropy: 7.9,
            size: 1024,
            sha256: "abc".into(),
        };
        let mut findings = vec![
            ThreatFinding::new(
                ScanTarget::Memory,
                FindingCategory::Suspicious,
                FindingSeverity::Medium,
                "high_entropy",
                "high entropy",
            ),
            ThreatFinding::new(
                ScanTarget::Memory,
                FindingCategory::CustomRule,
                FindingSeverity::Medium,
                "packed_binary",
                "UPX packed",
            ),
        ];
        escalate_severity(&mut findings, &analysis);
        // Both should be escalated from Medium to High (executable type)
        assert!(findings.iter().all(|f| f.severity >= FindingSeverity::High));
        // With 2+ High findings, one should be escalated to Critical
        assert!(
            findings
                .iter()
                .any(|f| f.severity == FindingSeverity::Critical)
        );
    }

    #[test]
    fn escalate_metadata_keys_distinct() {
        // Verify that cascading escalations don't overwrite each other's metadata
        let analysis = BinaryAnalysis {
            file_type: FileType::Pe,
            entropy: 7.9,
            size: 1024,
            sha256: "abc".into(),
        };
        let mut findings = vec![
            ThreatFinding::new(
                ScanTarget::Memory,
                FindingCategory::Suspicious,
                FindingSeverity::Medium,
                "high_entropy",
                "high entropy",
            ),
            ThreatFinding::new(
                ScanTarget::Memory,
                FindingCategory::CustomRule,
                FindingSeverity::Medium,
                "packed_binary",
                "UPX packed",
            ),
        ];
        escalate_severity(&mut findings, &analysis);
        // Both should have executable escalation metadata
        for f in &findings {
            assert!(
                f.metadata.contains_key("escalated_executable"),
                "finding {} should have escalated_executable metadata",
                f.rule_name
            );
        }
        // The one escalated to Critical should also have signals metadata
        let critical = findings
            .iter()
            .find(|f| f.severity == FindingSeverity::Critical)
            .expect("one finding should be Critical");
        assert!(
            critical.metadata.contains_key("escalated_signals"),
            "critical finding should have escalated_signals metadata"
        );
    }

    #[test]
    fn escalate_no_change_on_clean() {
        let analysis = BinaryAnalysis {
            file_type: FileType::Unknown,
            entropy: 3.0,
            size: 100,
            sha256: "abc".into(),
        };
        let mut findings: Vec<ThreatFinding> = vec![];
        escalate_severity(&mut findings, &analysis);
        assert!(findings.is_empty());
    }

    // ── Section entropy tests ──────────────────────────────────────────

    #[test]
    fn pe_section_entropy_basic() {
        // Build minimal PE with one section containing known data
        let data = vec![0u8; 1024];
        // Place section raw data at offset 512, size 256, all zeros
        let pe = crate::pe::PeInfo {
            machine: crate::pe::PeMachine::Amd64,
            num_sections: 1,
            timestamp: 0,
            is_dll: false,
            is_64bit: true,
            entry_point: 0x1000,
            sections: vec![crate::pe::PeSection {
                name: ".text".into(),
                virtual_size: 0x1000,
                virtual_address: 0x1000,
                raw_data_size: 256,
                raw_data_offset: 512,
                characteristics: 0x6000_0020, // CODE | EXECUTE | READ
            }],
            imports: vec![],
            import_functions: vec![],
            exports: vec![],
            has_tls_callbacks: false,
            pdb_path: None,
            rich_entries: vec![],
        };

        let entropies = pe_section_entropy(&data, &pe);
        assert_eq!(entropies.len(), 1);
        assert_eq!(entropies[0].name, ".text");
        assert!(entropies[0].entropy < 0.01); // all zeros = ~0 entropy
        assert!(entropies[0].executable);
    }

    #[test]
    fn section_entropy_findings_high_code_entropy() {
        let sections = vec![SectionEntropy {
            name: ".text".into(),
            entropy: 7.5,
            raw_size: 4096,
            executable: true,
            writable: false,
        }];
        let findings = section_entropy_findings(&sections, ScanTarget::Memory);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_name, "high_section_entropy");
        assert_eq!(findings[0].severity, FindingSeverity::High);
    }

    #[test]
    fn section_entropy_findings_normal_code() {
        let sections = vec![SectionEntropy {
            name: ".text".into(),
            entropy: 6.5,
            raw_size: 4096,
            executable: true,
            writable: false,
        }];
        let findings = section_entropy_findings(&sections, ScanTarget::Memory);
        assert!(findings.is_empty()); // 6.5 < 7.0 threshold for code
    }

    #[test]
    fn section_entropy_findings_high_data_entropy() {
        let sections = vec![SectionEntropy {
            name: ".rsrc".into(),
            entropy: 7.8,
            raw_size: 4096,
            executable: false,
            writable: false,
        }];
        let findings = section_entropy_findings(&sections, ScanTarget::Memory);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, FindingSeverity::Medium);
    }

    // ── Overlay detection tests ────────────────────────────────────────

    #[test]
    fn detect_pe_overlay_present() {
        let data = vec![0u8; 2048];
        let pe = crate::pe::PeInfo {
            machine: crate::pe::PeMachine::I386,
            num_sections: 1,
            timestamp: 0,
            is_dll: false,
            is_64bit: false,
            entry_point: 0x1000,
            sections: vec![crate::pe::PeSection {
                name: ".text".into(),
                virtual_size: 0x1000,
                virtual_address: 0x1000,
                raw_data_size: 512,
                raw_data_offset: 512,
                characteristics: 0x6000_0020,
            }],
            imports: vec![],
            import_functions: vec![],
            exports: vec![],
            has_tls_callbacks: false,
            pdb_path: None,
            rich_entries: vec![],
        };
        // PE ends at 512 + 512 = 1024, file is 2048, so 1024 bytes overlay
        let overlay = detect_pe_overlay(&data, &pe);
        assert!(overlay.is_some());
        let ov = overlay.unwrap();
        assert_eq!(ov.offset, 1024);
        assert_eq!(ov.size, 1024);
    }

    #[test]
    fn detect_pe_overlay_none() {
        let data = vec![0u8; 1024];
        let pe = crate::pe::PeInfo {
            machine: crate::pe::PeMachine::I386,
            num_sections: 1,
            timestamp: 0,
            is_dll: false,
            is_64bit: false,
            entry_point: 0x1000,
            sections: vec![crate::pe::PeSection {
                name: ".text".into(),
                virtual_size: 0x1000,
                virtual_address: 0x1000,
                raw_data_size: 512,
                raw_data_offset: 512,
                characteristics: 0x6000_0020,
            }],
            imports: vec![],
            import_functions: vec![],
            exports: vec![],
            has_tls_callbacks: false,
            pdb_path: None,
            rich_entries: vec![],
        };
        // PE ends at 1024 = file size, no overlay
        let overlay = detect_pe_overlay(&data, &pe);
        assert!(overlay.is_none());
    }

    #[test]
    fn overlay_findings_high_entropy() {
        let ov = OverlayInfo {
            offset: 1024,
            size: 1024,
            entropy: 7.9,
        };
        let findings = overlay_findings(&ov, ScanTarget::Memory);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, FindingSeverity::High);
        assert_eq!(findings[0].rule_name, "pe_overlay");
    }

    #[test]
    fn overlay_findings_low_entropy() {
        let ov = OverlayInfo {
            offset: 1024,
            size: 1024,
            entropy: 3.0,
        };
        let findings = overlay_findings(&ov, ScanTarget::Memory);
        assert_eq!(findings[0].severity, FindingSeverity::Low);
    }

    // ── Packing heuristics tests ───────────────────────────────────────

    #[test]
    fn detect_pe_packing_upx() {
        let pe = crate::pe::PeInfo {
            machine: crate::pe::PeMachine::I386,
            num_sections: 3,
            timestamp: 0,
            is_dll: false,
            is_64bit: false,
            entry_point: 0x1000,
            sections: vec![
                crate::pe::PeSection {
                    name: "UPX0".into(),
                    virtual_size: 0x10000,
                    virtual_address: 0x1000,
                    raw_data_size: 0,
                    raw_data_offset: 0,
                    characteristics: 0xE000_0020,
                },
                crate::pe::PeSection {
                    name: "UPX1".into(),
                    virtual_size: 0x5000,
                    virtual_address: 0x11000,
                    raw_data_size: 0x5000,
                    raw_data_offset: 512,
                    characteristics: 0xE000_0020,
                },
            ],
            imports: vec!["kernel32.dll".into()],
            import_functions: vec![],
            exports: vec![],
            has_tls_callbacks: false,
            pdb_path: None,
            rich_entries: vec![],
        };
        let entropies = vec![
            SectionEntropy {
                name: "UPX0".into(),
                entropy: 0.0,
                raw_size: 0,
                executable: true,
                writable: true,
            },
            SectionEntropy {
                name: "UPX1".into(),
                entropy: 7.8,
                raw_size: 0x5000,
                executable: true,
                writable: true,
            },
        ];
        let signals = detect_pe_packing(&pe, &entropies, None);
        assert!(!signals.packer_sections.is_empty());
        assert!(!signals.wx_sections.is_empty());
        assert!(!signals.hollow_sections.is_empty());
        assert!(signals.import_count < 5);
        assert!(signals.signal_count() >= 4);
    }

    #[test]
    fn detect_pe_packing_clean() {
        let pe = crate::pe::PeInfo {
            machine: crate::pe::PeMachine::Amd64,
            num_sections: 2,
            timestamp: 0,
            is_dll: false,
            is_64bit: true,
            entry_point: 0x1000,
            sections: vec![
                crate::pe::PeSection {
                    name: ".text".into(),
                    virtual_size: 0x1000,
                    virtual_address: 0x1000,
                    raw_data_size: 0x1000,
                    raw_data_offset: 512,
                    characteristics: 0x6000_0020, // CODE | EXECUTE | READ (not writable)
                },
                crate::pe::PeSection {
                    name: ".data".into(),
                    virtual_size: 0x1000,
                    virtual_address: 0x2000,
                    raw_data_size: 0x200,
                    raw_data_offset: 0x1200,
                    characteristics: 0xC000_0040, // INITIALIZED | READ | WRITE (not executable)
                },
            ],
            imports: vec![
                "kernel32.dll".into(),
                "user32.dll".into(),
                "ntdll.dll".into(),
                "advapi32.dll".into(),
                "ws2_32.dll".into(),
            ],
            import_functions: vec![],
            exports: vec![],
            has_tls_callbacks: false,
            pdb_path: None,
            rich_entries: vec![],
        };
        let entropies = vec![
            SectionEntropy {
                name: ".text".into(),
                entropy: 6.2,
                raw_size: 0x1000,
                executable: true,
                writable: false,
            },
            SectionEntropy {
                name: ".data".into(),
                entropy: 4.0,
                raw_size: 0x200,
                executable: false,
                writable: true,
            },
        ];
        let signals = detect_pe_packing(&pe, &entropies, None);
        assert_eq!(signals.signal_count(), 0);
    }

    #[test]
    fn packing_findings_severity_scales() {
        let mut signals = PackingSignals::default();
        assert!(packing_findings(&signals, ScanTarget::Memory).is_empty());

        signals.packer_sections = vec!["UPX0".into()];
        let f = packing_findings(&signals, ScanTarget::Memory);
        assert_eq!(f[0].severity, FindingSeverity::Low);

        signals.wx_sections = vec![".text".into()];
        let f = packing_findings(&signals, ScanTarget::Memory);
        assert_eq!(f[0].severity, FindingSeverity::Medium);

        signals.entry_in_high_entropy = true;
        let f = packing_findings(&signals, ScanTarget::Memory);
        assert_eq!(f[0].severity, FindingSeverity::High);
    }

    // ── Chi-squared tests ──────────────────────────────────────────────

    #[test]
    fn chi_squared_empty() {
        assert_eq!(chi_squared(&[]), 0.0);
    }

    #[test]
    fn chi_squared_uniform() {
        // Perfectly uniform distribution: all 256 values equally represented
        let mut data = Vec::with_capacity(256 * 100);
        for _ in 0..100 {
            for b in 0..=255u8 {
                data.push(b);
            }
        }
        let chi2 = chi_squared(&data);
        // Perfectly uniform: chi² should be very close to 0
        assert!(
            chi2 < 1.0,
            "uniform distribution chi² should be ~0, got {chi2}"
        );
    }

    #[test]
    fn chi_squared_single_value() {
        // All zeros — maximally non-uniform
        let data = vec![0u8; 1024];
        let chi2 = chi_squared(&data);
        // Should be very high (one bin has all, 255 bins empty)
        assert!(
            chi2 > 100_000.0,
            "single-value chi² should be very high, got {chi2}"
        );
    }

    #[test]
    fn classify_randomness_ranges() {
        assert_eq!(classify_randomness(200.0), RandomnessClass::Encrypted);
        assert_eq!(classify_randomness(512.0), RandomnessClass::Encrypted);
        assert_eq!(classify_randomness(1000.0), RandomnessClass::Compressed);
        assert_eq!(classify_randomness(4096.0), RandomnessClass::Compressed);
        assert_eq!(classify_randomness(10000.0), RandomnessClass::Normal);
    }
}
