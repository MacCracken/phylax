//! String extraction from binary data.
//!
//! Extracts printable ASCII and UTF-16 strings from raw bytes,
//! commonly used for malware analysis and binary forensics.

use serde::{Deserialize, Serialize};

/// Minimum string length for extraction.
pub const DEFAULT_MIN_LENGTH: usize = 4;

/// Encoding of an extracted string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum StringEncoding {
    Ascii,
    Utf16Le,
}

/// An extracted string with its location and encoding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedString {
    /// The string content.
    pub value: String,
    /// Byte offset in the original data.
    pub offset: usize,
    /// Encoding that was detected.
    pub encoding: StringEncoding,
}

/// Extract printable ASCII strings from binary data.
///
/// Returns strings of at least `min_length` printable ASCII characters.
pub fn extract_ascii(data: &[u8], min_length: usize) -> Vec<ExtractedString> {
    let mut results = Vec::new();
    let mut run_start = 0;
    let mut in_run = false;

    for (i, &b) in data.iter().enumerate() {
        if is_printable_ascii(b) {
            if !in_run {
                run_start = i;
                in_run = true;
            }
        } else if in_run {
            let run_len = i - run_start;
            if run_len >= min_length {
                let value = String::from_utf8(data[run_start..i].to_vec()).unwrap();
                results.push(ExtractedString {
                    value,
                    offset: run_start,
                    encoding: StringEncoding::Ascii,
                });
            }
            in_run = false;
        }
    }

    // Handle string at end of data
    if in_run {
        let run_len = data.len() - run_start;
        if run_len >= min_length {
            let value = String::from_utf8(data[run_start..].to_vec()).unwrap();
            results.push(ExtractedString {
                value,
                offset: run_start,
                encoding: StringEncoding::Ascii,
            });
        }
    }

    results
}

/// Extract UTF-16 LE strings from binary data.
///
/// Looks for sequences of printable ASCII characters interleaved with null bytes
/// (the UTF-16 LE encoding of ASCII text).
pub fn extract_utf16le(data: &[u8], min_length: usize) -> Vec<ExtractedString> {
    let mut results = Vec::new();
    let mut run_start = 0;
    let mut char_count = 0;
    let mut in_run = false;

    let mut i = 0;
    while i + 1 < data.len() {
        let lo = data[i];
        let hi = data[i + 1];

        if is_printable_ascii(lo) && hi == 0 {
            if !in_run {
                run_start = i;
                char_count = 0;
                in_run = true;
            }
            char_count += 1;
        } else {
            if in_run && char_count >= min_length {
                // Extract the ASCII bytes from every other position
                let value: String = data[run_start..run_start + char_count * 2]
                    .chunks(2)
                    .map(|c| c[0] as char)
                    .collect();
                results.push(ExtractedString {
                    value,
                    offset: run_start,
                    encoding: StringEncoding::Utf16Le,
                });
            }
            in_run = false;
        }

        i += 2;
    }

    if in_run && char_count >= min_length {
        let value: String = data[run_start..run_start + char_count * 2]
            .chunks(2)
            .map(|c| c[0] as char)
            .collect();
        results.push(ExtractedString {
            value,
            offset: run_start,
            encoding: StringEncoding::Utf16Le,
        });
    }

    results
}

/// Extract all strings (ASCII + UTF-16 LE) from binary data.
///
/// Results are sorted by offset.
pub fn extract_strings(data: &[u8], min_length: usize) -> Vec<ExtractedString> {
    let mut strings = extract_ascii(data, min_length);
    strings.extend(extract_utf16le(data, min_length));
    strings.sort_by_key(|s| s.offset);
    strings
}

/// Whether a byte is printable ASCII (0x20..=0x7E) or common whitespace (tab, newline, CR).
fn is_printable_ascii(b: u8) -> bool {
    matches!(b, 0x20..=0x7E | 0x09 | 0x0A | 0x0D)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_ascii_basic() {
        let data = b"\x00\x00hello world\x00\x00\x01\x02test\x00";
        let strings = extract_ascii(data, 4);
        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].value, "hello world");
        assert_eq!(strings[0].offset, 2);
        assert_eq!(strings[0].encoding, StringEncoding::Ascii);
        assert_eq!(strings[1].value, "test");
    }

    #[test]
    fn extract_ascii_min_length() {
        let data = b"ab\x00cdef\x00gh\x00";
        let strings = extract_ascii(data, 4);
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].value, "cdef");
    }

    #[test]
    fn extract_ascii_at_end() {
        let data = b"\x00\x00long_string_at_end";
        let strings = extract_ascii(data, 4);
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].value, "long_string_at_end");
    }

    #[test]
    fn extract_ascii_empty() {
        assert!(extract_ascii(b"", 4).is_empty());
        assert!(extract_ascii(b"\x00\x01\x02", 4).is_empty());
    }

    #[test]
    fn extract_ascii_includes_whitespace() {
        let data = b"\x00hello\tworld\n\x00";
        let strings = extract_ascii(data, 4);
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].value, "hello\tworld\n");
    }

    #[test]
    fn extract_utf16le_basic() {
        // "test" in UTF-16 LE = t\0e\0s\0t\0
        let data = b"\x00\x00t\0e\0s\0t\0\x00\x00";
        let strings = extract_utf16le(data, 4);
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].value, "test");
        assert_eq!(strings[0].encoding, StringEncoding::Utf16Le);
    }

    #[test]
    fn extract_utf16le_too_short() {
        let data = b"a\0b\0c\0"; // 3 chars, below min_length=4
        assert!(extract_utf16le(data, 4).is_empty());
    }

    #[test]
    fn extract_utf16le_empty() {
        assert!(extract_utf16le(b"", 4).is_empty());
        assert!(extract_utf16le(b"\x00", 4).is_empty());
    }

    #[test]
    fn extract_strings_combined() {
        let mut data = Vec::new();
        data.extend_from_slice(b"ascii_string\x00\x00");
        // UTF-16 LE "wide" = w\0i\0d\0e\0
        data.extend_from_slice(b"w\0i\0d\0e\0");

        let strings = extract_strings(&data, 4);
        assert!(strings.iter().any(|s| s.value == "ascii_string"));
        assert!(strings.iter().any(|s| s.value == "wide"));
    }

    #[test]
    fn extract_strings_sorted_by_offset() {
        let data = b"\x00\x00BBBB\x00AAAA\x00";
        let strings = extract_strings(data, 4);
        assert!(strings.len() >= 2);
        for w in strings.windows(2) {
            assert!(w[0].offset <= w[1].offset);
        }
    }

    #[test]
    fn is_printable_ascii_checks() {
        assert!(is_printable_ascii(b'A'));
        assert!(is_printable_ascii(b' '));
        assert!(is_printable_ascii(b'~'));
        assert!(is_printable_ascii(b'\t'));
        assert!(is_printable_ascii(b'\n'));
        assert!(!is_printable_ascii(0x00));
        assert!(!is_printable_ascii(0x7F));
        assert!(!is_printable_ascii(0x80));
    }

    #[test]
    fn extracted_string_serialization_roundtrip() {
        let s = ExtractedString {
            value: "kernel32.dll".into(),
            offset: 0x1000,
            encoding: StringEncoding::Ascii,
        };
        let json = serde_json::to_string(&s).unwrap();
        let parsed: ExtractedString = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.value, "kernel32.dll");
        assert_eq!(parsed.offset, 0x1000);
    }
}
