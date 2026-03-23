//! Phylax CLI — threat detection engine for AGNOS.

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use phylax::analyze::{analyze, entropy_profile, findings_from_analysis, is_suspicious_entropy};
use phylax::core::{ScanConfig, ScanTarget, VERSION};
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
    Daemon,

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
        Commands::Daemon => cmd_daemon(),
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
    let analyze_findings = findings_from_analysis(&data, &analysis, ScanTarget::File(path.clone()));

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

fn cmd_daemon() -> Result<()> {
    println!("Phylax daemon v{VERSION}");
    println!("Starting threat detection daemon...");
    println!("Listening for scan requests on /run/agnos/phylax.sock");
    println!("Daemon mode not yet fully implemented. Use 'phylax scan' for direct scanning.");
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
