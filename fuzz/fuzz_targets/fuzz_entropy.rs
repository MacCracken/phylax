#![no_main]

use libfuzzer_sys::fuzz_target;
use phylax_analyze::{entropy_profile, is_suspicious_entropy, shannon_entropy};

fuzz_target!(|data: &[u8]| {
    let entropy = shannon_entropy(data);

    // Entropy must always be in [0.0, 8.0]
    assert!(entropy >= 0.0 && entropy <= 8.0, "entropy out of range: {entropy}");

    // Suspicion check must never panic
    let _ = is_suspicious_entropy(entropy);

    // Entropy profile with various block sizes must never panic
    for block_size in [64, 256, 1024, 4096] {
        let profile = entropy_profile(data, block_size);
        for val in &profile {
            assert!(*val >= 0.0 && *val <= 8.0, "block entropy out of range: {val}");
        }
    }
});
