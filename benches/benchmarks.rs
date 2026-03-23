use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};

use phylax::analyze::{
    analyze, analyze_findings, detect_file_type, detect_polyglot, entropy_profile, file_sha256,
    is_suspicious_entropy, shannon_entropy,
};
use phylax::core::ScanTarget;
use phylax::yara::YaraEngine;

// ---------------------------------------------------------------------------
// Test data generators
// ---------------------------------------------------------------------------

fn random_bytes(len: usize) -> Vec<u8> {
    let mut data = vec![0u8; len];
    let mut state: u64 = 0xdeadbeef;
    for byte in data.iter_mut() {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        *byte = (state >> 33) as u8;
    }
    data
}

fn high_entropy_bytes(len: usize) -> Vec<u8> {
    random_bytes(len)
}

fn low_entropy_bytes(len: usize) -> Vec<u8> {
    let mut data = vec![0u8; len];
    for (i, byte) in data.iter_mut().enumerate() {
        *byte = b'A' + (i % 26) as u8;
    }
    data
}

fn elf_binary(len: usize) -> Vec<u8> {
    let mut data = random_bytes(len);
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

    let toml = sample_rules_toml();
    group.bench_function("load_rules", |b| {
        b.iter(|| {
            let mut engine = YaraEngine::new();
            engine.load_rules_toml(black_box(toml)).unwrap();
        });
    });

    let mut engine = YaraEngine::new();
    engine.load_rules_toml(toml).unwrap();

    for size in [1024, 65536, 1_048_576] {
        let data = random_bytes(size);
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("scan_random", size), &data, |b, data| {
            b.iter(|| engine.scan(black_box(data)));
        });
    }

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

// ---------------------------------------------------------------------------
// Polyglot detection throughput
// ---------------------------------------------------------------------------

fn bench_polyglot(c: &mut Criterion) {
    let mut group = c.benchmark_group("polyglot");

    for size in [1024, 65536, 1_048_576] {
        let data = random_bytes(size);
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("detect", size), &data, |b, data| {
            b.iter(|| detect_polyglot(black_box(data)));
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Pattern matching micro benchmarks
// ---------------------------------------------------------------------------

fn bench_pattern_match(c: &mut Criterion) {
    let mut group = c.benchmark_group("pattern_match");
    let data = random_bytes(65536);
    group.throughput(Throughput::Bytes(65536));

    // Literal — short needle
    let lit_short = phylax::yara::YaraPattern::Literal(b"MZ".to_vec());
    group.bench_function("literal_2byte", |b| {
        b.iter(|| lit_short.matches(black_box(&data)));
    });

    // Literal — longer needle
    let lit_long = phylax::yara::YaraPattern::Literal(b"This is a longer pattern string".to_vec());
    group.bench_function("literal_31byte", |b| {
        b.iter(|| lit_long.matches(black_box(&data)));
    });

    // Hex — 4 byte
    let hex_pat = phylax::yara::YaraPattern::Hex(vec![0x7f, 0x45, 0x4c, 0x46]);
    group.bench_function("hex_4byte", |b| {
        b.iter(|| hex_pat.matches(black_box(&data)));
    });

    // Regex — simple
    let regex_simple = phylax::yara::YaraPattern::regex(r"(?-u)\x7fELF").unwrap();
    group.bench_function("regex_simple", |b| {
        b.iter(|| regex_simple.matches(black_box(&data)));
    });

    // Regex — alternation
    let regex_alt = phylax::yara::YaraPattern::regex(r"(?-u)(\x7fELF|MZ|%PDF|PK\x03\x04)").unwrap();
    group.bench_function("regex_alternation", |b| {
        b.iter(|| regex_alt.matches(black_box(&data)));
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// findings_from_analysis vs analyze_findings (showing no double-compute)
// ---------------------------------------------------------------------------

fn bench_findings(c: &mut Criterion) {
    let mut group = c.benchmark_group("findings");
    let data = random_bytes(65536);
    group.throughput(Throughput::Bytes(65536));

    group.bench_function("analyze_findings", |b| {
        b.iter(|| {
            phylax::analyze::analyze_findings(black_box(&data), ScanTarget::Memory);
        });
    });

    group.bench_function("precomputed_findings", |b| {
        let analysis = analyze(&data);
        b.iter(|| {
            phylax::analyze::findings_from_analysis(
                black_box(&data),
                black_box(&analysis),
                ScanTarget::Memory,
            );
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// String extraction throughput
// ---------------------------------------------------------------------------

fn bench_strings(c: &mut Criterion) {
    let mut group = c.benchmark_group("strings");

    for size in [1024, 65536, 1_048_576] {
        // Mix of ASCII strings and binary noise
        let mut data = random_bytes(size);
        // Embed some ASCII strings
        for chunk in data.chunks_mut(128) {
            if chunk.len() >= 20 {
                chunk[..20].copy_from_slice(b"embedded_string_here");
            }
        }
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("ascii", size), &data, |b, data| {
            b.iter(|| phylax::strings::extract_ascii(black_box(data), 4));
        });

        group.bench_with_input(BenchmarkId::new("utf16le", size), &data, |b, data| {
            b.iter(|| phylax::strings::extract_utf16le(black_box(data), 4));
        });

        group.bench_with_input(BenchmarkId::new("all", size), &data, |b, data| {
            b.iter(|| phylax::strings::extract_strings(black_box(data), 4));
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// PE/ELF parsing throughput
// ---------------------------------------------------------------------------

fn bench_pe_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("pe_parse");

    // Build a minimal PE
    let mut pe_data = vec![0u8; 512];
    pe_data[0] = 0x4d;
    pe_data[1] = 0x5a;
    pe_data[0x3C] = 0x80;
    pe_data[0x80] = 0x50;
    pe_data[0x81] = 0x45;
    pe_data[0x84] = 0x4c;
    pe_data[0x85] = 0x01;
    pe_data[0x86] = 0x02; // 2 sections
    pe_data[0x94] = 0x70;
    pe_data[0x98] = 0x0b;
    pe_data[0x99] = 0x01;

    group.bench_function("minimal_pe", |b| {
        b.iter(|| phylax::pe::parse_pe(black_box(&pe_data)));
    });

    // Non-PE data (fast reject)
    let not_pe = random_bytes(512);
    group.bench_function("reject_non_pe", |b| {
        b.iter(|| phylax::pe::parse_pe(black_box(&not_pe)));
    });

    group.finish();
}

fn bench_elf_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("elf_parse");

    // Build a minimal ELF
    let mut elf_data = vec![0u8; 128];
    elf_data[0] = 0x7f;
    elf_data[1] = 0x45;
    elf_data[2] = 0x4c;
    elf_data[3] = 0x46;
    elf_data[4] = 2; // 64-bit
    elf_data[5] = 1; // little-endian
    elf_data[6] = 1;
    elf_data[16] = 2; // executable
    elf_data[18] = 62; // x86_64

    group.bench_function("minimal_elf", |b| {
        b.iter(|| phylax::elf::parse_elf(black_box(&elf_data)));
    });

    let not_elf = random_bytes(128);
    group.bench_function("reject_non_elf", |b| {
        b.iter(|| phylax::elf::parse_elf(black_box(&not_elf)));
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Queue throughput
// ---------------------------------------------------------------------------

fn bench_queue(c: &mut Criterion) {
    let mut group = c.benchmark_group("queue");

    group.bench_function("enqueue_dequeue_1000", |b| {
        b.iter(|| {
            let q = phylax::queue::ScanQueue::new(1000);
            for _ in 0..1000 {
                q.enqueue(ScanTarget::Memory, phylax::queue::ScanPriority::Normal);
            }
            for _ in 0..1000 {
                black_box(q.dequeue());
            }
        });
    });

    group.bench_function("mixed_priorities_1000", |b| {
        b.iter(|| {
            let q = phylax::queue::ScanQueue::new(1000);
            let priorities = [
                phylax::queue::ScanPriority::Low,
                phylax::queue::ScanPriority::Normal,
                phylax::queue::ScanPriority::High,
                phylax::queue::ScanPriority::Critical,
            ];
            for i in 0..1000u64 {
                q.enqueue(ScanTarget::Memory, priorities[(i % 4) as usize]);
            }
            for _ in 0..1000 {
                black_box(q.dequeue());
            }
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Report rendering
// ---------------------------------------------------------------------------

fn bench_report(c: &mut Criterion) {
    use phylax::core::{FindingCategory, FindingSeverity, ScanResult, ThreatFinding};
    use phylax::report::{ReportFormat, ThreatReport};

    let mut group = c.benchmark_group("report");

    // Build sample results
    let results: Vec<ScanResult> = (0..10)
        .map(|i| ScanResult {
            target: ScanTarget::File(format!("/tmp/file_{i}.bin").into()),
            findings: (0..5)
                .map(|j| {
                    ThreatFinding::new(
                        ScanTarget::File(format!("/tmp/file_{i}.bin").into()),
                        FindingCategory::Suspicious,
                        FindingSeverity::Medium,
                        format!("rule_{j}"),
                        format!("finding {j} for file {i}"),
                    )
                })
                .collect(),
            scan_duration: std::time::Duration::from_millis(50),
            scanner_version: "0.1.0".into(),
        })
        .collect();

    let report = ThreatReport::from_results(results);

    group.bench_function("render_json", |b| {
        b.iter(|| black_box(report.render(ReportFormat::Json)));
    });

    group.bench_function("render_markdown", |b| {
        b.iter(|| black_box(report.render(ReportFormat::Markdown)));
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
    bench_polyglot,
    bench_pattern_match,
    bench_findings,
    bench_strings,
    bench_pe_parse,
    bench_elf_parse,
    bench_queue,
    bench_report,
);
criterion_main!(benches);
