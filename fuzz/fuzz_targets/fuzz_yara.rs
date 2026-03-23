#![no_main]

use libfuzzer_sys::fuzz_target;
use phylax_yara::YaraEngine;

fuzz_target!(|data: &[u8]| {
    // Fuzz TOML rule parsing with arbitrary input
    if let Ok(toml_str) = std::str::from_utf8(data) {
        let mut engine = YaraEngine::new();
        let _ = engine.load_rules_toml(toml_str);
    }

    // Fuzz scanning with arbitrary data against a known rule set
    let mut engine = YaraEngine::new();
    let _ = engine.load_rules_toml(
        r#"
        [[rule]]
        name = "fuzz_test"
        severity = "low"
        condition = "any"
        [[rule.patterns]]
        id = "$a"
        type = "hex"
        value = "deadbeef"
        "#,
    );
    let _ = engine.scan(data);
});
