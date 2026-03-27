//! TLSH (Trend Micro Locality Sensitive Hash) for fuzzy similarity detection.
//!
//! TLSH produces a hash that can be compared with a distance function to find
//! similar files even when they differ by insertions, deletions, or modifications.
//!
//! Minimum input size: 50 bytes (below this, TLSH is not meaningful).

use serde::{Deserialize, Serialize};

/// Number of buckets in the TLSH hash.
const NUM_BUCKETS: usize = 256;
/// Sliding window size for Pearson hashing.
const WINDOW_SIZE: usize = 5;
/// Minimum data length for meaningful TLSH.
const MIN_DATA_LEN: usize = 50;

/// Pearson hash table (random permutation of 0..255).
const PEARSON_TABLE: [u8; 256] = [
    1, 87, 49, 12, 176, 178, 102, 166, 121, 193, 6, 84, 249, 230, 44, 163, 14, 197, 213, 181, 161,
    85, 218, 80, 64, 239, 24, 226, 236, 142, 38, 200, 110, 177, 104, 103, 141, 253, 255, 50, 77,
    101, 81, 18, 45, 96, 31, 156, 11, 26, 17, 201, 185, 232, 135, 98, 89, 131, 122, 211, 46, 206,
    52, 188, 57, 83, 53, 241, 144, 172, 115, 55, 70, 118, 71, 240, 228, 234, 97, 137, 9, 125, 207,
    109, 237, 0, 60, 247, 220, 136, 233, 58, 40, 127, 119, 195, 243, 153, 37, 155, 32, 246, 245,
    165, 254, 61, 138, 124, 221, 147, 132, 4, 2, 34, 116, 190, 170, 105, 90, 100, 205, 202, 117,
    95, 54, 93, 16, 76, 92, 248, 123, 111, 219, 146, 27, 15, 171, 244, 183, 222, 157, 187, 175,
    250, 214, 198, 73, 160, 59, 78, 174, 203, 99, 143, 215, 108, 189, 180, 79, 196, 204, 112, 120,
    167, 199, 139, 162, 47, 148, 152, 33, 3, 5, 128, 154, 10, 22, 39, 56, 75, 223, 62, 36, 106, 67,
    91, 191, 126, 113, 13, 216, 238, 7, 169, 68, 145, 184, 186, 43, 114, 242, 235, 251, 23, 28,
    130, 133, 168, 150, 66, 158, 48, 173, 133, 107, 164, 182, 149, 30, 41, 82, 35, 63, 225, 252,
    74, 227, 208, 140, 65, 229, 69, 8, 129, 94, 134, 231, 86, 21, 42, 25, 20, 159, 51, 88, 179,
    194, 29, 19, 192, 72, 217, 210, 151, 209, 0,
];

/// A computed TLSH hash.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TlshHash {
    /// The full TLSH digest as a hex string (e.g. "T1...").
    pub digest: String,
}

impl std::fmt::Display for TlshHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.digest)
    }
}

/// Compute the TLSH hash of a byte slice.
///
/// Returns `None` if the data is too short (< 50 bytes) or has insufficient variance.
#[must_use]
pub fn tlsh_hash(data: &[u8]) -> Option<TlshHash> {
    if data.len() < MIN_DATA_LEN {
        return None;
    }

    // Step 1: Fill buckets using sliding window Pearson hash
    let mut buckets = [0u32; NUM_BUCKETS];
    let mut checksum: u8 = 0;

    if data.len() >= WINDOW_SIZE {
        for i in WINDOW_SIZE - 1..data.len() {
            let w = &data[i + 1 - WINDOW_SIZE..=i];
            // Update checksum
            checksum = PEARSON_TABLE[(checksum ^ w[0]) as usize];

            // Hash triplets from the window into bucket indices
            let h1 = pearson_hash2(w[0], w[1], w[2]);
            let h2 = pearson_hash2(w[0], w[1], w[3]);
            let h3 = pearson_hash2(w[0], w[2], w[3]);
            let h4 = pearson_hash2(w[0], w[1], w[4]);
            let h5 = pearson_hash2(w[0], w[2], w[4]);
            let h6 = pearson_hash2(w[0], w[3], w[4]);

            buckets[h1 as usize] += 1;
            buckets[h2 as usize] += 1;
            buckets[h3 as usize] += 1;
            buckets[h4 as usize] += 1;
            buckets[h5 as usize] += 1;
            buckets[h6 as usize] += 1;
        }
    }

    // Step 2: Compute quartile boundaries
    let mut sorted: Vec<u32> = buckets.iter().copied().filter(|&b| b > 0).collect();
    if sorted.len() < 4 {
        return None; // insufficient variance
    }
    sorted.sort_unstable();
    let q1 = sorted[sorted.len() / 4];
    let q2 = sorted[sorted.len() / 2];
    let q3 = sorted[sorted.len() * 3 / 4];

    // Step 3: Encode buckets as 2-bit quartile values (4 buckets per byte)
    let mut body = [0u8; NUM_BUCKETS / 4]; // 64 bytes
    for i in 0..NUM_BUCKETS {
        let code = if buckets[i] <= q1 {
            0u8
        } else if buckets[i] <= q2 {
            1
        } else if buckets[i] <= q3 {
            2
        } else {
            3
        };
        body[i / 4] |= code << ((i % 4) * 2);
    }

    // Step 4: Encode header (checksum, length, q-ratios)
    let lvalue = length_encode(data.len());
    let q1_ratio = ((q1.saturating_mul(100)) / q2.max(1)).min(15) as u8;
    let q2_ratio = ((q2.saturating_mul(100)) / q3.max(1)).min(15) as u8;

    // Step 5: Build hex digest: "T1" + checksum(2) + length(2) + qratios(2) + body(128)
    use std::fmt::Write;
    let mut digest = String::with_capacity(134);
    digest.push_str("T1");
    let _ = write!(digest, "{checksum:02x}");
    let _ = write!(digest, "{lvalue:02x}");
    let _ = write!(digest, "{:01x}{:01x}", q1_ratio, q2_ratio);
    for &b in &body {
        let _ = write!(digest, "{b:02x}");
    }

    Some(TlshHash { digest })
}

/// Compute the TLSH distance between two hashes (lower = more similar).
///
/// Returns `None` if either hash is invalid or not a TLSH digest.
#[must_use]
pub fn tlsh_distance(a: &TlshHash, b: &TlshHash) -> Option<u32> {
    if a.digest.len() != b.digest.len() || !a.digest.starts_with("T1") {
        return None;
    }

    let a_bytes = hex_decode(&a.digest[2..])?;
    let b_bytes = hex_decode(&b.digest[2..])?;

    if a_bytes.len() != b_bytes.len() || a_bytes.len() < 3 {
        return None;
    }

    let mut dist = 0u32;

    // Header distance (checksum, length, q-ratios)
    dist += diff_byte(a_bytes[0], b_bytes[0]); // checksum
    dist += diff_byte(a_bytes[1], b_bytes[1]); // length
    dist += diff_nibble(a_bytes[2], b_bytes[2]); // q-ratio

    // Body distance (hamming-like on quartile codes)
    for i in 3..a_bytes.len() {
        for shift in (0..8).step_by(2) {
            let qa = (a_bytes[i] >> shift) & 0x3;
            let qb = (b_bytes[i] >> shift) & 0x3;
            let d = (qa as i16 - qb as i16).unsigned_abs() as u32;
            dist += if d == 3 { 6 } else { d };
        }
    }

    Some(dist)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[inline]
fn pearson_hash2(a: u8, b: u8, c: u8) -> u8 {
    PEARSON_TABLE[(PEARSON_TABLE[(a ^ b) as usize] ^ c) as usize]
}

fn length_encode(len: usize) -> u8 {
    // Log-based length encoding to 8 bits
    if len == 0 {
        return 0;
    }
    let log = (len as f64).log2();
    (log * 8.0).min(255.0) as u8
}

fn diff_byte(a: u8, b: u8) -> u32 {
    (a as i16 - b as i16).unsigned_abs() as u32
}

fn diff_nibble(a: u8, b: u8) -> u32 {
    let lo = ((a & 0xF) as i16 - (b & 0xF) as i16).unsigned_abs() as u32;
    let hi = ((a >> 4) as i16 - (b >> 4) as i16).unsigned_abs() as u32;
    lo + hi
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tlsh_too_short() {
        assert!(tlsh_hash(b"short").is_none());
        assert!(tlsh_hash(&[0u8; 49]).is_none());
    }

    #[test]
    fn tlsh_minimum_length() {
        // 50 bytes of varied data should produce a hash
        let data: Vec<u8> = (0..50).map(|i| (i * 7 + 13) as u8).collect();
        let hash = tlsh_hash(&data);
        assert!(hash.is_some());
        let h = hash.unwrap();
        assert!(h.digest.starts_with("T1"));
        assert!(h.digest.len() > 10);
    }

    #[test]
    fn tlsh_deterministic() {
        let data: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let h1 = tlsh_hash(&data).unwrap();
        let h2 = tlsh_hash(&data).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn tlsh_similar_data_close_distance() {
        let data1: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
        let mut data2 = data1.clone();
        // Modify a few bytes
        data2[100] = 0xFF;
        data2[200] = 0xFF;
        data2[300] = 0xFF;

        let h1 = tlsh_hash(&data1).unwrap();
        let h2 = tlsh_hash(&data2).unwrap();
        let dist = tlsh_distance(&h1, &h2).unwrap();

        // Similar data should have lower distance than completely different data
        let data3: Vec<u8> = (0..1024).map(|i| ((i * 37 + 99) % 256) as u8).collect();
        let h3 = tlsh_hash(&data3).unwrap();
        let dist_far = tlsh_distance(&h1, &h3).unwrap();
        assert!(
            dist < dist_far,
            "similar distance ({dist}) should be less than different distance ({dist_far})"
        );
    }

    #[test]
    fn tlsh_different_data_far_distance() {
        let data1: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
        let data2: Vec<u8> = (0..1024).map(|i| ((i * 37 + 99) % 256) as u8).collect();

        let h1 = tlsh_hash(&data1).unwrap();
        let h2 = tlsh_hash(&data2).unwrap();
        let dist = tlsh_distance(&h1, &h2).unwrap();

        // Very different data should have higher distance
        assert!(
            dist > 50,
            "different data distance should be higher, got {dist}"
        );
    }

    #[test]
    fn tlsh_identical_zero_distance() {
        let data: Vec<u8> = (0..512).map(|i| (i % 256) as u8).collect();
        let h = tlsh_hash(&data).unwrap();
        let dist = tlsh_distance(&h, &h).unwrap();
        assert_eq!(dist, 0);
    }

    #[test]
    fn tlsh_display() {
        let data: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let h = tlsh_hash(&data).unwrap();
        assert!(h.to_string().starts_with("T1"));
    }

    #[test]
    fn tlsh_uniform_data_no_hash() {
        // All zeros — no variance — should return None
        assert!(tlsh_hash(&[0u8; 200]).is_none());
    }
}
