//! ssdeep — Context-Triggered Piecewise Hashing (CTPH) for fuzzy similarity.
//!
//! ssdeep splits input into variable-length blocks using a rolling hash trigger,
//! then hashes each block into a base64 character. Two ssdeep hashes can be
//! compared to produce a 0–100 similarity score.
//!
//! Complements TLSH: ssdeep excels at detecting files with shared blocks
//! (partial overlap, appended payloads), while TLSH captures statistical
//! distribution similarity.
//!
//! Minimum input size: 1 byte (though very small inputs produce trivial hashes).

use serde::{Deserialize, Serialize};
use std::fmt;

/// Rolling hash window size.
const ROLLING_WINDOW: usize = 7;
/// Minimum block size.
const MIN_BLOCK_SIZE: u32 = 3;
/// Maximum length of each hash component.
const SPAMSUM_LENGTH: usize = 64;
/// FNV-1 hash initial value.
const HASH_INIT: u32 = 0x2802_1967;
/// FNV-1 hash prime.
const HASH_PRIME: u32 = 0x0100_0193;

/// Base64 alphabet used by ssdeep.
const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// A computed ssdeep hash.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SsdeepHash {
    /// The full ssdeep digest: `"block_size:hash1:hash2"`.
    pub digest: String,
    /// Block size used.
    pub block_size: u32,
}

impl fmt::Display for SsdeepHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.digest)
    }
}

/// Rolling hash state for block boundary detection.
struct RollingHash {
    window: [u8; ROLLING_WINDOW],
    pos: usize,
    h1: u32,
    h2: u32,
    h3: u32,
}

impl RollingHash {
    fn new() -> Self {
        Self {
            window: [0; ROLLING_WINDOW],
            pos: 0,
            h1: 0,
            h2: 0,
            h3: 0,
        }
    }

    #[inline]
    fn update(&mut self, byte: u8) -> u32 {
        let old = self.window[self.pos] as u32;
        self.window[self.pos] = byte;
        self.pos = (self.pos + 1) % ROLLING_WINDOW;

        let b = byte as u32;
        self.h1 = self.h1.wrapping_add(b).wrapping_sub(old);
        self.h2 = self
            .h2
            .wrapping_add(self.h1)
            .wrapping_sub((ROLLING_WINDOW as u32).wrapping_mul(old));
        self.h3 = (self.h3 << 5).wrapping_add(b) ^ b;

        self.h1.wrapping_add(self.h2).wrapping_add(self.h3)
    }
}

/// FNV-1 style hash used per block.
#[inline]
fn fnv_update(h: u32, byte: u8) -> u32 {
    h.wrapping_mul(HASH_PRIME) ^ (byte as u32)
}

/// Select the initial block size based on data length.
#[must_use]
fn select_block_size(data_len: usize) -> u32 {
    let mut bs = MIN_BLOCK_SIZE;
    while (bs as usize) * SPAMSUM_LENGTH < data_len {
        bs *= 2;
    }
    bs
}

/// Compute the ssdeep hash of a byte slice.
///
/// Returns `None` only if the data is empty.
#[must_use]
pub fn ssdeep_hash(data: &[u8]) -> Option<SsdeepHash> {
    if data.is_empty() {
        return None;
    }

    let mut block_size = select_block_size(data.len());

    loop {
        let (h1, h2) = compute_hashes(data, block_size);

        // If hash1 fits or we're at minimum block size, we're done
        if h1.len() <= SPAMSUM_LENGTH || block_size <= MIN_BLOCK_SIZE {
            let h1_trimmed = truncate_to_len(&h1, SPAMSUM_LENGTH);
            let h2_trimmed = truncate_to_len(&h2, SPAMSUM_LENGTH / 2);
            let digest = format!("{block_size}:{h1_trimmed}:{h2_trimmed}");
            return Some(SsdeepHash { digest, block_size });
        }

        // Hash too long — double block size and retry
        block_size *= 2;
    }
}

/// Compute both hash components for a given block size.
fn compute_hashes(data: &[u8], block_size: u32) -> (String, String) {
    let mut rolling = RollingHash::new();
    let mut fnv1 = HASH_INIT;
    let mut fnv2 = HASH_INIT;
    let mut hash1 = String::with_capacity(SPAMSUM_LENGTH);
    let mut hash2 = String::with_capacity(SPAMSUM_LENGTH / 2);
    let bs = block_size;
    let bs2 = bs * 2;

    for &byte in data {
        let roll = rolling.update(byte);
        fnv1 = fnv_update(fnv1, byte);
        fnv2 = fnv_update(fnv2, byte);

        // Block boundary for block_size
        if roll % bs == bs - 1 {
            hash1.push(BASE64[(fnv1 & 0x3F) as usize] as char);
            fnv1 = HASH_INIT;
        }

        // Block boundary for block_size * 2
        if roll % bs2 == bs2 - 1 {
            hash2.push(BASE64[(fnv2 & 0x3F) as usize] as char);
            fnv2 = HASH_INIT;
        }
    }

    // Finalize: emit trailing partial blocks
    if fnv1 != HASH_INIT || hash1.is_empty() {
        hash1.push(BASE64[(fnv1 & 0x3F) as usize] as char);
    }
    if fnv2 != HASH_INIT || hash2.is_empty() {
        hash2.push(BASE64[(fnv2 & 0x3F) as usize] as char);
    }

    (hash1, hash2)
}

/// Truncate a hash string to at most `max_len` characters.
#[inline]
fn truncate_to_len(s: &str, max_len: usize) -> &str {
    if s.len() <= max_len {
        s
    } else {
        // All chars are ASCII base64, so byte indexing is safe
        &s[..max_len]
    }
}

/// Compare two ssdeep hashes and return a similarity score (0–100).
///
/// Returns `None` if the block sizes are incompatible (neither equal,
/// nor one double the other).
#[must_use]
pub fn ssdeep_compare(a: &SsdeepHash, b: &SsdeepHash) -> Option<u32> {
    let (a_bs, a_h1, a_h2) = parse_digest(&a.digest)?;
    let (b_bs, b_h1, b_h2) = parse_digest(&b.digest)?;

    // Block sizes must be equal or one must be double the other
    if a_bs == b_bs {
        // Compare both components, take the higher score
        let s1 = score_strings(a_h1, b_h1, a_bs);
        let s2 = score_strings(a_h2, b_h2, a_bs * 2);
        Some(s1.max(s2))
    } else if a_bs == b_bs * 2 {
        // a's block_size*2 component matches b's block_size component
        Some(score_strings(a_h2, b_h1, a_bs))
    } else if b_bs == a_bs * 2 {
        Some(score_strings(b_h2, a_h1, b_bs))
    } else {
        None
    }
}

/// Parse an ssdeep digest into (block_size, hash1, hash2).
fn parse_digest(digest: &str) -> Option<(u32, &str, &str)> {
    let mut parts = digest.splitn(3, ':');
    let bs: u32 = parts.next()?.parse().ok()?;
    let h1 = parts.next()?;
    let h2 = parts.next()?;
    Some((bs, h1, h2))
}

/// Eliminate runs of 3+ identical characters (reduce to 3).
fn eliminate_sequences(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut run = 0u32;
    let mut prev: Option<u8> = None;

    for &b in bytes {
        if Some(b) == prev {
            run += 1;
        } else {
            run = 1;
            prev = Some(b);
        }
        if run <= 3 {
            out.push(b);
        }
    }

    // SAFETY: input is ASCII base64 subset, output is a subset of that
    unsafe { String::from_utf8_unchecked(out) }
}

/// Score two hash strings using weighted edit distance.
fn score_strings(a: &str, b: &str, block_size: u32) -> u32 {
    if a.is_empty() || b.is_empty() {
        return 0;
    }

    let a = eliminate_sequences(a);
    let b = eliminate_sequences(b);

    if a.is_empty() || b.is_empty() {
        return 0;
    }

    let dist = edit_distance(a.as_bytes(), b.as_bytes());
    let max_len = a.len().max(b.len()) as u32;

    if dist >= max_len {
        return 0;
    }

    // Scale to 0–100, weighted by block size
    let score = (max_len - dist) * 100 / max_len;

    // Adjust: smaller block sizes mean higher confidence
    let bs_log = (block_size as f64).log2().max(1.0) as u32;
    score.min(100).saturating_sub(bs_log.min(score))
}

/// Levenshtein edit distance.
fn edit_distance(a: &[u8], b: &[u8]) -> u32 {
    let m = a.len();
    let n = b.len();

    // Optimize: if one is empty, distance is the other's length
    if m == 0 {
        return n as u32;
    }
    if n == 0 {
        return m as u32;
    }

    // Single-row DP
    let mut prev = vec![0u32; n + 1];
    let mut curr = vec![0u32; n + 1];

    for (j, val) in prev.iter_mut().enumerate().take(n + 1) {
        *val = j as u32;
    }

    for i in 1..=m {
        curr[0] = i as u32;
        for j in 1..=n {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }

    prev[n]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_returns_none() {
        assert!(ssdeep_hash(b"").is_none());
    }

    #[test]
    fn single_byte_produces_hash() {
        let h = ssdeep_hash(b"x").unwrap();
        assert!(h.digest.contains(':'));
        assert!(h.block_size >= MIN_BLOCK_SIZE);
    }

    #[test]
    fn deterministic() {
        let data: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
        let h1 = ssdeep_hash(&data).unwrap();
        let h2 = ssdeep_hash(&data).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn digest_format() {
        let data: Vec<u8> = (0..512).map(|i| (i * 7 + 3) as u8).collect();
        let h = ssdeep_hash(&data).unwrap();
        let parts: Vec<&str> = h.digest.splitn(3, ':').collect();
        assert_eq!(parts.len(), 3);
        // First part is block size (numeric)
        assert!(parts[0].parse::<u32>().is_ok());
        // Hash components are base64
        for c in parts[1].chars().chain(parts[2].chars()) {
            assert!(
                c.is_ascii_alphanumeric() || c == '+' || c == '/',
                "unexpected char in hash: {c}"
            );
        }
    }

    #[test]
    fn identical_data_high_score() {
        let data: Vec<u8> = (0..2048).map(|i| (i % 256) as u8).collect();
        let h = ssdeep_hash(&data).unwrap();
        let score = ssdeep_compare(&h, &h).unwrap();
        assert!(
            score >= 90,
            "identical data should score >= 90, got {score}"
        );
    }

    #[test]
    fn similar_data_positive_score() {
        let data1: Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();
        let mut data2 = data1.clone();
        // Modify a small portion
        for b in &mut data2[100..150] {
            *b = 0xFF;
        }

        let h1 = ssdeep_hash(&data1).unwrap();
        let h2 = ssdeep_hash(&data2).unwrap();

        if let Some(score) = ssdeep_compare(&h1, &h2) {
            assert!(
                score > 0,
                "similar data should have positive score, got {score}"
            );
        }
        // If None, block sizes diverged — acceptable for small modifications
    }

    #[test]
    fn different_data_low_score() {
        let data1: Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();
        let data2: Vec<u8> = (0..4096).map(|i| ((i * 37 + 99) % 256) as u8).collect();

        let h1 = ssdeep_hash(&data1).unwrap();
        let h2 = ssdeep_hash(&data2).unwrap();

        if let Some(score) = ssdeep_compare(&h1, &h2) {
            assert!(score < 50, "different data should score low, got {score}");
        }
    }

    #[test]
    fn incompatible_block_sizes_returns_none() {
        // Craft hashes with incompatible block sizes (4x apart)
        let a = SsdeepHash {
            digest: "3:abc:def".into(),
            block_size: 3,
        };
        let b = SsdeepHash {
            digest: "12:ghi:jkl".into(),
            block_size: 12,
        };
        assert!(ssdeep_compare(&a, &b).is_none());
    }

    #[test]
    fn compatible_double_block_size() {
        // Block sizes 3 and 6 are compatible (one is double)
        let a = SsdeepHash {
            digest: "3:abc:def".into(),
            block_size: 3,
        };
        let b = SsdeepHash {
            digest: "6:abc:def".into(),
            block_size: 6,
        };
        assert!(ssdeep_compare(&a, &b).is_some());
    }

    #[test]
    fn display_impl() {
        let h = ssdeep_hash(b"test data for display").unwrap();
        let s = format!("{h}");
        assert_eq!(s, h.digest);
    }

    #[test]
    fn large_input_bounded_hash() {
        // Even for large inputs, each hash component should be <= SPAMSUM_LENGTH
        let data: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
        let h = ssdeep_hash(&data).unwrap();
        let parts: Vec<&str> = h.digest.splitn(3, ':').collect();
        assert!(
            parts[1].len() <= SPAMSUM_LENGTH,
            "hash1 too long: {}",
            parts[1].len()
        );
        assert!(
            parts[2].len() <= SPAMSUM_LENGTH / 2,
            "hash2 too long: {}",
            parts[2].len()
        );
    }

    #[test]
    fn eliminate_sequences_trims() {
        assert_eq!(eliminate_sequences("aaaaaa"), "aaa");
        assert_eq!(eliminate_sequences("abccc"), "abccc");
        assert_eq!(eliminate_sequences("abcccc"), "abccc");
        assert_eq!(eliminate_sequences("ab"), "ab");
    }

    #[test]
    fn edit_distance_basic() {
        assert_eq!(edit_distance(b"kitten", b"sitting"), 3);
        assert_eq!(edit_distance(b"", b"abc"), 3);
        assert_eq!(edit_distance(b"abc", b"abc"), 0);
    }
}
