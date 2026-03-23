//! Phylax CLI — threat detection engine for AGNOS.

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use phylax::analyze::{
    analyze, entropy_profile, escalate_severity, findings_from_analysis, is_suspicious_entropy,
};
use phylax::core::{ScanConfig, ScanResult, ScanTarget, VERSION};
use phylax::report::{ReportFormat, ThreatReport};
use phylax::yara::YaraEngine;

#[derive(Parser)]
#[command(
    name = "phylax",
    about = "Phylax — AI-native threat detection engine",
    version = VERSION,
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a file for threats
    Scan {
        /// Path to the file to scan
        path: PathBuf,

        /// TOML file containing YARA rules
        #[arg(short, long)]
        rules: Option<PathBuf>,

        /// Block size for entropy profile (bytes)
        #[arg(long, default_value = "4096")]
        block_size: usize,
    },

    /// Run as a background daemon
    Daemon {
        /// Unix socket path
        #[arg(long, default_value = "/run/agnos/phylax.sock")]
        socket: PathBuf,
    },

    /// Generate a threat report from a scan
    Report {
        /// File to scan and report on
        path: PathBuf,

        /// Output format: json or markdown
        #[arg(short, long, default_value = "json")]
        format: String,

        /// TOML file containing YARA rules
        #[arg(short, long)]
        rules: Option<PathBuf>,
    },

    /// Manage YARA rules
    Rules {
        #[command(subcommand)]
        action: RulesAction,
    },

    /// Show engine status
    Status,
}

#[derive(Subcommand)]
enum RulesAction {
    /// List all loaded rules
    List {
        /// TOML file containing rules
        #[arg(short, long)]
        file: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    // Supports RUST_LOG and PHYLAX_LOG env vars for log filtering.
    let env_filter = EnvFilter::try_from_env("PHYLAX_LOG")
        .or_else(|_| EnvFilter::try_from_default_env())
        .unwrap_or_else(|_| EnvFilter::new("warn"));

    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            path,
            rules,
            block_size,
        } => cmd_scan(&path, rules.as_deref(), block_size),
        Commands::Daemon { socket } => cmd_daemon(&socket),
        Commands::Report {
            path,
            format,
            rules,
        } => cmd_report(&path, &format, rules.as_deref()),
        Commands::Rules { action } => match action {
            RulesAction::List { file } => cmd_rules_list(file.as_deref()),
        },
        Commands::Status => cmd_status(),
    }
}

fn cmd_scan(path: &PathBuf, rules_path: Option<&std::path::Path>, block_size: usize) -> Result<()> {
    let config = ScanConfig::default();

    // Read the file
    let metadata = std::fs::metadata(path)?;
    if metadata.len() > config.max_file_size {
        error!(
            size = metadata.len(),
            max = config.max_file_size,
            path = %path.display(),
            "file exceeds maximum scan size"
        );
        anyhow::bail!(
            "File too large: {} bytes (max {})",
            metadata.len(),
            config.max_file_size
        );
    }

    info!(path = %path.display(), size = metadata.len(), "starting scan");

    let data = std::fs::read(path)?;
    let start = std::time::Instant::now();

    println!("Scanning: {}", path.display());
    println!("Size: {} bytes", data.len());
    println!();

    // Binary analysis (computes file type, entropy, SHA-256 in one pass)
    let analysis = analyze(&data);
    println!("[Magic Bytes] File type: {}", analysis.file_type);
    println!("[SHA-256]     {}", analysis.sha256);

    let entropy = analysis.entropy;
    let suspicious = is_suspicious_entropy(entropy);
    println!(
        "[Entropy]     {entropy:.4} bits/byte {}",
        if suspicious {
            "(SUSPICIOUS)"
        } else {
            "(normal)"
        }
    );

    // Entropy profile
    let profile = entropy_profile(&data, block_size);
    if !profile.is_empty() {
        let max_block = profile
            .iter()
            .enumerate()
            .max_by(|a, b| a.1.total_cmp(b.1))
            .unwrap();
        println!(
            "[Profile]     {} blocks, max entropy {:.4} at block {}",
            profile.len(),
            max_block.1,
            max_block.0,
        );
    }

    // YARA rules
    let mut engine = YaraEngine::new();
    if let Some(rp) = rules_path {
        let rules_str = std::fs::read_to_string(rp)?;
        let count = engine.load_rules_toml(&rules_str)?;
        println!("[YARA]        Loaded {count} rules from {}", rp.display());
    }

    let yara_findings = engine.scan(&data);
    let mut analyze_findings =
        findings_from_analysis(&data, &analysis, ScanTarget::File(path.clone()));
    escalate_severity(&mut analyze_findings, &analysis);

    let total_findings = yara_findings.len() + analyze_findings.len();
    let duration = start.elapsed();

    println!();
    if total_findings == 0 {
        info!(duration = ?duration, "scan complete — clean");
        println!("Result: CLEAN ({duration:.2?})");
    } else {
        info!(duration = ?duration, findings = total_findings, "scan complete — threats detected");
        println!("Result: {} FINDING(S) ({duration:.2?})", total_findings);
        println!();
        for f in yara_findings.iter().chain(analyze_findings.iter()) {
            println!(
                "  [{severity}] {rule}: {desc}",
                severity = f.severity,
                rule = f.rule_name,
                desc = f.description,
            );
        }
    }

    Ok(())
}

fn cmd_daemon(socket: &Path) -> Result<()> {
    println!("Phylax daemon v{VERSION}");
    println!("Listening on: {}", socket.display());
    println!();

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        // Remove stale socket
        let _ = std::fs::remove_file(socket);
        if let Some(parent) = socket.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let listener = tokio::net::UnixListener::bind(socket)?;
        info!(path = %socket.display(), "daemon listening");

        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    info!("client connected");
                    tokio::spawn(async move {
                        if let Err(e) = handle_client(stream).await {
                            warn!(error = %e, "client handler error");
                        }
                    });
                }
                Err(e) => {
                    error!(error = %e, "accept error");
                }
            }
        }
    })
}

async fn handle_client(stream: tokio::net::UnixStream) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    const MAX_LINE_LEN: usize = 4096;

    let (reader, mut writer) = stream.into_split();
    let mut buf_reader = BufReader::new(reader);
    let mut line_buf = String::new();

    loop {
        line_buf.clear();
        let n = buf_reader.read_line(&mut line_buf).await?;
        if n == 0 {
            break; // EOF
        }
        if n > MAX_LINE_LEN {
            let err = serde_json::json!({"error": "request line too long"}).to_string();
            writer.write_all(err.as_bytes()).await?;
            writer.write_all(b"\n").await?;
            continue;
        }

        let line = line_buf.trim().to_string();
        if line.is_empty() {
            continue;
        }

        debug!(request = %line, "received scan request");

        // Canonicalize to prevent path traversal
        let path = match std::fs::canonicalize(&line) {
            Ok(p) => p,
            Err(e) => {
                let err = serde_json::json!({"error": format!("invalid path: {e}")}).to_string();
                writer.write_all(err.as_bytes()).await?;
                writer.write_all(b"\n").await?;
                continue;
            }
        };
        let response = match scan_file_for_daemon(&path) {
            Ok(json) => json,
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        };

        writer.write_all(response.as_bytes()).await?;
        writer.write_all(b"\n").await?;
    }

    Ok(())
}

fn scan_file_for_daemon(path: &Path) -> Result<String> {
    let config = ScanConfig::default();
    let metadata = std::fs::metadata(path)?;
    if metadata.len() > config.max_file_size {
        anyhow::bail!("file too large: {} bytes", metadata.len());
    }

    let data = std::fs::read(path)?;
    let start = std::time::Instant::now();
    let analysis = analyze(&data);
    let engine = YaraEngine::new();
    let yara_findings = engine.scan(&data);
    let mut analyze_findings =
        findings_from_analysis(&data, &analysis, ScanTarget::File(path.to_path_buf()));
    escalate_severity(&mut analyze_findings, &analysis);

    let mut all_findings = yara_findings;
    all_findings.extend(analyze_findings);
    let duration = start.elapsed();

    let result = ScanResult {
        target: ScanTarget::File(path.to_path_buf()),
        findings: all_findings,
        scan_duration: duration,
        scanner_version: VERSION.to_string(),
    };

    Ok(serde_json::to_string(&result)?)
}

use std::path::Path;
use tracing::{debug, warn};

fn cmd_report(path: &PathBuf, format: &str, rules_path: Option<&std::path::Path>) -> Result<()> {
    let config = ScanConfig::default();
    let metadata = std::fs::metadata(path)?;
    if metadata.len() > config.max_file_size {
        anyhow::bail!(
            "File too large: {} bytes (max {})",
            metadata.len(),
            config.max_file_size
        );
    }

    let data = std::fs::read(path)?;
    let start = std::time::Instant::now();
    let analysis = analyze(&data);

    let mut engine = YaraEngine::new();
    if let Some(rp) = rules_path {
        let rules_str = std::fs::read_to_string(rp)?;
        engine.load_rules_toml(&rules_str)?;
    }

    let yara_findings = engine.scan(&data);
    let mut analyze_findings =
        findings_from_analysis(&data, &analysis, ScanTarget::File(path.clone()));
    escalate_severity(&mut analyze_findings, &analysis);

    let mut all_findings = yara_findings;
    all_findings.extend(analyze_findings);
    let duration = start.elapsed();

    let result = ScanResult {
        target: ScanTarget::File(path.clone()),
        findings: all_findings,
        scan_duration: duration,
        scanner_version: VERSION.to_string(),
    };

    let report = ThreatReport::from_results(vec![result]);
    let fmt = match format {
        "markdown" | "md" => ReportFormat::Markdown,
        _ => ReportFormat::Json,
    };
    println!("{}", report.render(fmt));

    Ok(())
}

fn cmd_rules_list(file: Option<&std::path::Path>) -> Result<()> {
    let mut engine = YaraEngine::new();

    if let Some(path) = file {
        let content = std::fs::read_to_string(path)?;
        engine.load_rules_toml(&content)?;
    }

    let rules = engine.rules();
    if rules.is_empty() {
        println!("No rules loaded.");
        println!("Use --file <path.toml> to load a rules file.");
        return Ok(());
    }

    println!("Loaded {} rule(s):", rules.len());
    println!();
    for rule in rules {
        println!(
            "  {name} [{severity}] — {desc} ({n} pattern(s), tags: {tags})",
            name = rule.name,
            severity = rule.severity,
            desc = if rule.description.is_empty() {
                "(no description)"
            } else {
                &rule.description
            },
            n = rule.patterns.len(),
            tags = if rule.tags.is_empty() {
                "none".to_string()
            } else {
                rule.tags.join(", ")
            },
        );
    }

    Ok(())
}

fn cmd_status() -> Result<()> {
    println!("Phylax Threat Detection Engine v{VERSION}");
    println!();
    println!("Status:       ready");
    println!("Analyzers:    entropy, magic_bytes, yara, polyglot");
    println!("AI backend:   hoosh (port 8088)");
    println!("Orchestrator: daimon (port 8090)");
    Ok(())
}
