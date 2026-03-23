#![no_main]

use libfuzzer_sys::fuzz_target;
use phylax::analyze::{analyze, detect_file_type, detect_polyglot};
use phylax::core::ScanTarget;

fuzz_target!(|data: &[u8]| {
    // File type detection must never panic
    let _ = detect_file_type(data);

    // Polyglot detection must never panic
    let _ = detect_polyglot(data);

    // Full analysis must never panic
    let _ = analyze(data);

    // Finding generation must never panic
    let _ = phylax::analyze::analyze_findings(data, ScanTarget::Memory);
});
