use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};

use phylax_analyze::{
    analyze, analyze_findings, detect_file_type, detect_polyglot, entropy_profile, file_sha256,
    is_suspicious_entropy, shannon_entropy,
};
use phylax_core::ScanTarget;
use phylax_yara::YaraEngine;

// ---------------------------------------------------------------------------
// Test data generators
// ---------------------------------------------------------------------------

fn random_bytes(len: usize) -> Vec<u8> {
    // Deterministic pseudo-random for reproducible benchmarks
    let mut data = vec![0u8; len];
    let mut state: u64 = 0xdeadbeef;
    for byte in data.iter_mut() {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        *byte = (state >> 33) as u8;
    }
    data
}

fn high_entropy_bytes(len: usize) -> Vec<u8> {
    // Simulates encrypted/compressed content
    random_bytes(len)
}

fn low_entropy_bytes(len: usize) -> Vec<u8> {
    // Simulates repetitive plaintext
    let mut data = vec![0u8; len];
    for (i, byte) in data.iter_mut().enumerate() {
        *byte = b'A' + (i % 26) as u8;
    }
    data
}

fn elf_binary(len: usize) -> Vec<u8> {
    let mut data = random_bytes(len);
    // ELF magic header
    if data.len() >= 4 {
        data[0] = 0x7f;
        data[1] = 0x45;
        data[2] = 0x4c;
        data[3] = 0x46;
    }
    data
}

fn sample_rules_toml() -> &'static str {
    r#"
[[rule]]
name = "detect_elf"
description = "ELF binary detection"
severity = "medium"
tags = ["elf", "linux"]
condition = "any"

[[rule.patterns]]
id = "$magic"
type = "hex"
value = "7f454c46"

[[rule]]
name = "detect_pe"
description = "PE binary detection"
severity = "medium"
tags = ["pe", "windows"]
condition = "any"

[[rule.patterns]]
id = "$mz"
type = "hex"
value = "4d5a"

[[rule]]
name = "detect_shebang"
description = "Script detection"
severity = "low"
tags = ["script"]
condition = "any"

[[rule.patterns]]
id = "$shebang"
type = "regex"
value = "^#!"

[[rule]]
name = "suspicious_strings"
description = "Suspicious string patterns"
severity = "high"
tags = ["malware", "strings"]
condition = "any"

[[rule.patterns]]
id = "$cmd"
type = "literal"
value = "/bin/sh"

[[rule.patterns]]
id = "$eval"
type = "literal"
value = "eval("

[[rule]]
name = "packed_binary"
description = "UPX-packed binary"
severity = "high"
tags = ["packed", "upx"]
condition = "all"

[[rule.patterns]]
id = "$upx0"
type = "literal"
value = "UPX0"

[[rule.patterns]]
id = "$upx1"
type = "literal"
value = "UPX1"
"#
}

// ---------------------------------------------------------------------------
// Entropy benchmarks
// ---------------------------------------------------------------------------

fn bench_entropy(c: &mut Criterion) {
    let mut group = c.benchmark_group("entropy");

    for size in [1024, 4096, 65536, 1_048_576] {
        let data = random_bytes(size);
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("shannon", size), &data, |b, data| {
            b.iter(|| shannon_entropy(black_box(data)));
        });

        group.bench_with_input(BenchmarkId::new("is_suspicious", size), &data, |b, data| {
            let e = shannon_entropy(data);
            b.iter(|| is_suspicious_entropy(black_box(e)));
        });
    }

    group.finish();
}

fn bench_entropy_profile(c: &mut Criterion) {
    let mut group = c.benchmark_group("entropy_profile");

    let data = random_bytes(1_048_576);
    group.throughput(Throughput::Bytes(1_048_576));

    for block_size in [256, 1024, 4096] {
        group.bench_with_input(
            BenchmarkId::new("block", block_size),
            &block_size,
            |b, &bs| {
                b.iter(|| entropy_profile(black_box(&data), bs));
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// File detection benchmarks
// ---------------------------------------------------------------------------

fn bench_file_detection(c: &mut Criterion) {
    let mut group = c.benchmark_group("file_detection");

    let elf = elf_binary(4096);
    let random = random_bytes(4096);
    group.throughput(Throughput::Bytes(4096));

    group.bench_function("detect_type_elf", |b| {
        b.iter(|| detect_file_type(black_box(&elf)));
    });

    group.bench_function("detect_type_unknown", |b| {
        b.iter(|| detect_file_type(black_box(&random)));
    });

    group.bench_function("detect_polyglot", |b| {
        b.iter(|| detect_polyglot(black_box(&elf)));
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Hashing benchmarks
// ---------------------------------------------------------------------------

fn bench_hashing(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha256");

    for size in [1024, 65536, 1_048_576] {
        let data = random_bytes(size);
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("hash", size), &data, |b, data| {
            b.iter(|| file_sha256(black_box(data)));
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Full analysis pipeline benchmarks
// ---------------------------------------------------------------------------

fn bench_analyze(c: &mut Criterion) {
    let mut group = c.benchmark_group("analyze");

    for size in [1024, 65536, 1_048_576] {
        let data = random_bytes(size);
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(
            BenchmarkId::new("binary_analysis", size),
            &data,
            |b, data| {
                b.iter(|| analyze(black_box(data)));
            },
        );

        group.bench_with_input(
            BenchmarkId::new("analyze_findings", size),
            &data,
            |b, data| {
                b.iter(|| analyze_findings(black_box(data), ScanTarget::Memory));
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// YARA engine benchmarks
// ---------------------------------------------------------------------------

fn bench_yara(c: &mut Criterion) {
    let mut group = c.benchmark_group("yara");

    // Rule loading throughput
    let toml = sample_rules_toml();
    group.bench_function("load_rules", |b| {
        b.iter(|| {
            let mut engine = YaraEngine::new();
            engine.load_rules_toml(black_box(toml)).unwrap();
        });
    });

    // Scanning throughput at various file sizes
    let mut engine = YaraEngine::new();
    engine.load_rules_toml(toml).unwrap();

    for size in [1024, 65536, 1_048_576] {
        let data = random_bytes(size);
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("scan_random", size), &data, |b, data| {
            b.iter(|| engine.scan(black_box(data)));
        });
    }

    // Scan with matching content (ELF triggers rule)
    let elf = elf_binary(65536);
    group.throughput(Throughput::Bytes(65536));
    group.bench_function("scan_with_match", |b| {
        b.iter(|| engine.scan(black_box(&elf)));
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// End-to-end scan pipeline benchmarks
// ---------------------------------------------------------------------------

fn bench_full_scan(c: &mut Criterion) {
    let mut group = c.benchmark_group("full_scan");

    let toml = sample_rules_toml();
    let mut engine = YaraEngine::new();
    engine.load_rules_toml(toml).unwrap();

    for size in [4096, 65536, 1_048_576] {
        let data = random_bytes(size);
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("pipeline", size), &data, |b, data| {
            b.iter(|| {
                let _ = detect_file_type(black_box(data));
                let _ = shannon_entropy(black_box(data));
                let _ = entropy_profile(black_box(data), 4096);
                let _ = file_sha256(black_box(data));
                let _ = engine.scan(black_box(data));
                let _ = analyze_findings(black_box(data), ScanTarget::Memory);
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Entropy quality benchmarks (high vs low entropy data)
// ---------------------------------------------------------------------------

fn bench_entropy_quality(c: &mut Criterion) {
    let mut group = c.benchmark_group("entropy_quality");
    let size = 65536;
    group.throughput(Throughput::Bytes(size as u64));

    let high = high_entropy_bytes(size);
    let low = low_entropy_bytes(size);

    group.bench_function("high_entropy", |b| {
        b.iter(|| shannon_entropy(black_box(&high)));
    });

    group.bench_function("low_entropy", |b| {
        b.iter(|| shannon_entropy(black_box(&low)));
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_entropy,
    bench_entropy_profile,
    bench_file_detection,
    bench_hashing,
    bench_analyze,
    bench_yara,
    bench_full_scan,
    bench_entropy_quality,
);
criterion_main!(benches);
