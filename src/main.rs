//! Phylax CLI — threat detection engine for AGNOS.

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

use phylax::analyze::{
    analyze, entropy_profile, escalate_severity, findings_from_analysis, is_suspicious_entropy,
};
use phylax::hoosh::HooshClient;
use phylax::report::{ReportFormat, ThreatReport};
use phylax::types::{ScanConfig, ScanResult, ScanTarget, ThreatFinding, VERSION};
use phylax::yara::YaraEngine;

#[derive(Parser)]
#[command(
    name = "phylax",
    about = "Phylax — AI-native threat detection engine",
    version = VERSION,
)]
struct Cli {
    /// Log output format: text or json (for SIEM ingestion)
    #[arg(long, global = true, default_value = "text")]
    log_format: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan files or directories for threats
    Scan {
        /// Paths to scan (files or directories)
        paths: Vec<PathBuf>,

        /// TOML file containing YARA rules
        #[arg(short, long)]
        rules: Option<PathBuf>,

        /// Block size for entropy profile (bytes)
        #[arg(long, default_value = "4096")]
        block_size: usize,

        /// Send findings to hoosh for LLM triage
        #[arg(long)]
        triage: bool,

        /// Hoosh endpoint URL
        #[arg(long, default_value = phylax::hoosh::HOOSH_DEFAULT_URL)]
        hoosh_url: String,

        /// LLM model for triage
        #[arg(long, default_value = phylax::hoosh::HOOSH_DEFAULT_MODEL)]
        hoosh_model: String,

        /// Exit code when findings are detected (default: 1, 0 to always succeed)
        #[arg(long, default_value = "1")]
        exit_code: i32,

        /// Minimum severity to trigger non-zero exit (info, low, medium, high, critical)
        #[arg(long, default_value = "info")]
        severity_threshold: String,
    },

    /// Run as a background daemon (Unix only)
    #[cfg(unix)]
    Daemon {
        /// Unix socket path
        #[arg(long, default_value = "/run/agnos/phylax.sock")]
        socket: PathBuf,

        /// Enable hoosh triage for daemon scans
        #[arg(long)]
        triage: bool,

        /// Hoosh endpoint URL
        #[arg(long, default_value = phylax::hoosh::HOOSH_DEFAULT_URL)]
        hoosh_url: String,

        /// Register with daimon orchestrator
        #[arg(long)]
        register: bool,

        /// Daimon endpoint URL
        #[arg(long, default_value = phylax::daimon::DAIMON_DEFAULT_URL)]
        daimon_url: String,
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

        /// Send findings to hoosh for LLM triage
        #[arg(long)]
        triage: bool,

        /// Hoosh endpoint URL
        #[arg(long, default_value = phylax::hoosh::HOOSH_DEFAULT_URL)]
        hoosh_url: String,
    },

    /// Watch directories for file changes and auto-scan
    Watch {
        /// Directories to watch
        paths: Vec<PathBuf>,

        /// Watch subdirectories recursively
        #[arg(long, default_value = "true")]
        recursive: bool,

        /// Only scan files with these extensions (comma-separated, e.g. "bin,exe,dll")
        #[arg(long)]
        extensions: Option<String>,

        /// TOML file containing YARA rules
        #[arg(short, long)]
        rules: Option<PathBuf>,

        /// Send findings to hoosh for LLM triage
        #[arg(long)]
        triage: bool,

        /// Hoosh endpoint URL
        #[arg(long, default_value = phylax::hoosh::HOOSH_DEFAULT_URL)]
        hoosh_url: String,
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
    let cli = Cli::parse();

    let env_filter = EnvFilter::try_from_env("PHYLAX_LOG")
        .or_else(|_| EnvFilter::try_from_default_env())
        .unwrap_or_else(|_| EnvFilter::new("warn"));

    if cli.log_format == "json" {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(env_filter)
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(env_filter).init();
    }

    match cli.command {
        Commands::Scan {
            paths,
            rules,
            block_size,
            triage,
            hoosh_url,
            hoosh_model,
            exit_code,
            severity_threshold,
        } => {
            let threshold = severity_threshold
                .parse::<phylax::types::FindingSeverity>()
                .unwrap_or(phylax::types::FindingSeverity::Info);
            let highest = cmd_scan(
                &paths,
                rules.as_deref(),
                block_size,
                triage,
                &hoosh_url,
                &hoosh_model,
            )?;
            if let Some(sev) = highest {
                if sev >= threshold && exit_code != 0 {
                    std::process::exit(exit_code);
                }
            }
            Ok(())
        }
        #[cfg(unix)]
        Commands::Daemon {
            socket,
            triage,
            hoosh_url,
            register,
            daimon_url,
        } => cmd_daemon(&socket, triage, &hoosh_url, register, &daimon_url),
        Commands::Report {
            path,
            format,
            rules,
            triage,
            hoosh_url,
        } => cmd_report(&path, &format, rules.as_deref(), triage, &hoosh_url),
        Commands::Watch {
            paths,
            recursive,
            extensions,
            rules,
            triage,
            hoosh_url,
        } => cmd_watch(
            &paths,
            recursive,
            extensions.as_deref(),
            rules.as_deref(),
            triage,
            &hoosh_url,
        ),
        Commands::Rules { action } => match action {
            RulesAction::List { file } => cmd_rules_list(file.as_deref()),
        },
        Commands::Status => cmd_status(),
    }
}

// ---------------------------------------------------------------------------
// Shared scan logic
// ---------------------------------------------------------------------------

/// Collect all scannable files from a list of paths (files or directories).
///
/// Skips symlinks to prevent directory traversal attacks and infinite loops.
fn collect_files(paths: &[PathBuf], max_file_size: u64) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for path in paths {
        // Skip symlinks to prevent directory traversal and loops
        if path
            .symlink_metadata()
            .is_ok_and(|m| m.file_type().is_symlink())
        {
            debug!(path = %path.display(), "skipping symlink");
            continue;
        }

        if path.is_file() {
            if let Ok(meta) = std::fs::metadata(path) {
                if meta.len() <= max_file_size {
                    files.push(path.clone());
                } else {
                    warn!(path = %path.display(), size = meta.len(), "skipping oversized file");
                }
            }
        } else if path.is_dir() {
            if let Ok(entries) = std::fs::read_dir(path) {
                let mut subpaths: Vec<PathBuf> =
                    entries.filter_map(|e| e.ok().map(|e| e.path())).collect();
                subpaths.sort();
                files.extend(collect_files(&subpaths, max_file_size));
            }
        }
    }
    files
}

/// Load YARA rules from a file, or return an empty engine.
fn load_yara_engine(rules_path: Option<&Path>) -> Result<YaraEngine> {
    let mut engine = YaraEngine::new();
    if let Some(rp) = rules_path {
        let rules_str = std::fs::read_to_string(rp)?;
        engine.load_rules_toml(&rules_str)?;
    }
    Ok(engine)
}

/// Run a complete scan on a file using a pre-loaded YARA engine.
fn run_scan_with_engine(
    path: &Path,
    engine: &YaraEngine,
    session_id: uuid::Uuid,
) -> Result<ScanResult> {
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
    scan_data(&data, path, engine, session_id)
}

/// Run a complete scan on already-loaded data using a pre-loaded YARA engine.
///
/// Use this when you already have the file data in memory to avoid a redundant read.
fn scan_data(
    data: &[u8],
    path: &Path,
    engine: &YaraEngine,
    session_id: uuid::Uuid,
) -> Result<ScanResult> {
    let start = std::time::Instant::now();
    let analysis = analyze(data);

    let yara_findings = engine.scan(data);
    let mut analyze_findings =
        findings_from_analysis(data, &analysis, ScanTarget::File(path.to_path_buf()));
    escalate_severity(&mut analyze_findings, &analysis);

    let mut all_findings = yara_findings;
    all_findings.extend(analyze_findings);

    Ok(ScanResult {
        session_id,
        target: ScanTarget::File(path.to_path_buf()),
        findings: all_findings,
        scan_duration: start.elapsed(),
        scanner_version: VERSION.to_string(),
    })
}

/// Convenience: load rules and scan a single file.
fn run_scan(path: &Path, rules_path: Option<&Path>) -> Result<ScanResult> {
    let engine = load_yara_engine(rules_path)?;
    run_scan_with_engine(path, &engine, uuid::Uuid::new_v4())
}

/// Send findings to hoosh for LLM triage and print results.
async fn triage_findings(findings: &[ThreatFinding], hoosh_url: &str, model: &str) {
    if findings.is_empty() {
        return;
    }

    let client = match HooshClient::new(hoosh_url) {
        Ok(c) => c.with_model(model),
        Err(e) => {
            eprintln!("[Triage]      Failed to create hoosh client: {e}");
            return;
        }
    };
    println!();
    println!(
        "[Triage]      Sending {} finding(s) to hoosh ({hoosh_url})...",
        findings.len()
    );

    for finding in findings {
        match client.triage_finding(finding).await {
            Ok(result) => {
                println!(
                    "  {} → {} (confidence: {:.0}%): {}",
                    finding.rule_name,
                    result.classification,
                    result.confidence * 100.0,
                    result.explanation,
                );
            }
            Err(e) => {
                warn!(finding = %finding.rule_name, error = %e, "triage failed");
                println!("  {} → triage error: {e}", finding.rule_name);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// CLI commands
// ---------------------------------------------------------------------------

/// Returns the highest severity found across all scan results, or None if clean.
fn cmd_scan(
    paths: &[PathBuf],
    rules_path: Option<&Path>,
    block_size: usize,
    do_triage: bool,
    hoosh_url: &str,
    hoosh_model: &str,
) -> Result<Option<phylax::types::FindingSeverity>> {
    let config = ScanConfig::default();
    let files = collect_files(paths, config.max_file_size);

    if files.is_empty() {
        println!("No scannable files found.");
        return Ok(None);
    }

    let multi = files.len() > 1;
    if multi {
        println!("Scanning {} file(s)...", files.len());
        println!();
    }

    // Load YARA rules once for all files
    let engine = load_yara_engine(rules_path)?;
    let session_id = uuid::Uuid::new_v4();

    let overall_start = std::time::Instant::now();

    // Single-file mode: verbose output with analysis details
    if !multi {
        let file = &files[0];
        let data = std::fs::read(file)?;

        println!("Scanning: {}", file.display());
        println!("Size: {} bytes", data.len());
        println!();

        let analysis = analyze(&data);
        println!("[Magic Bytes] File type: {}", analysis.file_type);
        println!("[SHA-256]     {}", analysis.sha256);

        let entropy = analysis.entropy;
        println!(
            "[Entropy]     {entropy:.4} bits/byte {}",
            if is_suspicious_entropy(entropy) {
                "(SUSPICIOUS)"
            } else {
                "(normal)"
            }
        );

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

        if let Some(rp) = rules_path {
            println!("[YARA]        Rules from {}", rp.display());
        }

        let result = scan_data(&data, file, &engine, session_id)?;
        let n = result.findings.len();
        println!();
        if n == 0 {
            println!("Result: CLEAN ({:.2?})", result.scan_duration);
        } else {
            println!("Result: {n} FINDING(S) ({:.2?})", result.scan_duration);
            println!();
            for f in &result.findings {
                println!(
                    "  [{severity}] {rule}: {desc}",
                    severity = f.severity,
                    rule = f.rule_name,
                    desc = f.description,
                );
            }
        }

        if do_triage && n > 0 {
            let rt = tokio::runtime::Runtime::new()?;
            let owned: Vec<ThreatFinding> = result.findings.clone();
            rt.block_on(triage_findings(&owned, hoosh_url, hoosh_model));
        }

        return Ok(result.highest_severity());
    }

    // Multi-file mode: parallel scanning with rayon
    use rayon::prelude::*;

    let scan_results: Vec<(PathBuf, std::result::Result<ScanResult, String>)> = files
        .par_iter()
        .map(|file| {
            let result = run_scan_with_engine(file, &engine, session_id).map_err(|e| e.to_string());
            (file.clone(), result)
        })
        .collect();

    // Print results (sequential for stable output order)
    let mut total_findings = 0usize;
    let mut total_clean = 0usize;
    let mut all_results = Vec::new();

    for (file, result) in &scan_results {
        match result {
            Ok(result) => {
                let n = result.findings.len();
                if n == 0 {
                    println!(
                        "  {} — clean ({:.2?})",
                        file.display(),
                        result.scan_duration
                    );
                    total_clean += 1;
                } else {
                    println!(
                        "  {} — {} finding(s) ({:.2?})",
                        file.display(),
                        n,
                        result.scan_duration
                    );
                    for f in &result.findings {
                        println!(
                            "    [{severity}] {rule}: {desc}",
                            severity = f.severity,
                            rule = f.rule_name,
                            desc = f.description,
                        );
                    }
                }
                total_findings += n;
                all_results.push(result);
            }
            Err(e) => {
                println!("  {} — error: {e}", file.display());
            }
        }
    }

    let elapsed = overall_start.elapsed();
    println!();
    println!(
        "Summary: {} file(s) scanned, {} clean, {} with findings ({elapsed:.2?})",
        files.len(),
        total_clean,
        files.len() - total_clean,
    );

    // Triage all findings
    if do_triage && total_findings > 0 {
        let all_findings: Vec<_> = all_results.iter().flat_map(|r| &r.findings).collect();
        let rt = tokio::runtime::Runtime::new()?;
        // Clone findings for triage (need owned refs)
        let owned: Vec<ThreatFinding> = all_findings.into_iter().cloned().collect();
        rt.block_on(triage_findings(&owned, hoosh_url, hoosh_model));
    }

    let highest = all_results
        .iter()
        .filter_map(|r| r.highest_severity())
        .max();
    Ok(highest)
}

#[cfg(unix)]
fn cmd_daemon(
    socket: &Path,
    do_triage: bool,
    hoosh_url: &str,
    do_register: bool,
    daimon_url: &str,
) -> Result<()> {
    use phylax::daimon::{DaimonClient, HEARTBEAT_INTERVAL};

    println!("Phylax daemon v{VERSION}");
    println!("Listening on: {}", socket.display());
    if do_triage {
        println!("Triage:       enabled ({hoosh_url})");
    }
    if do_register {
        println!("Daimon:       registering ({daimon_url})");
    }
    println!();

    let hoosh_url = hoosh_url.to_string();
    let daimon_url = daimon_url.to_string();

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        // Register with daimon if requested
        let daimon_handle = if do_register {
            let client = DaimonClient::new(&daimon_url)?;
            match client.start_lifecycle(HEARTBEAT_INTERVAL).await {
                Ok(handle) => {
                    println!("Daimon:       registered (agent_id: {})", handle.agent_id());
                    Some(handle)
                }
                Err(e) => {
                    warn!(error = %e, "failed to register with daimon — continuing without");
                    None
                }
            }
        } else {
            None
        };

        let _ = std::fs::remove_file(socket);
        if let Some(parent) = socket.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let listener = tokio::net::UnixListener::bind(socket)?;
        info!(path = %socket.display(), "daemon listening");

        // Handle ctrl-c for graceful shutdown
        let accept_result: anyhow::Result<()> = async {
            loop {
                match listener.accept().await {
                    Ok((stream, _addr)) => {
                        info!("client connected");
                        let hoosh_url = hoosh_url.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_client(stream, do_triage, &hoosh_url).await {
                                warn!(error = %e, "client handler error");
                            }
                        });
                    }
                    Err(e) => {
                        error!(error = %e, "accept error");
                    }
                }
            }
        }
        .await;

        // Graceful shutdown: deregister from daimon
        if let Some(handle) = daimon_handle {
            handle.shutdown().await;
        }

        accept_result
    })
}

#[cfg(unix)]
async fn handle_client(
    stream: tokio::net::UnixStream,
    do_triage: bool,
    hoosh_url: &str,
) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    const MAX_LINE_LEN: usize = 4096;

    let (reader, mut writer) = stream.into_split();
    let mut buf_reader = BufReader::new(reader);
    let mut line_buf = String::new();

    // Reuse one client for all requests on this connection
    let hoosh_client = if do_triage {
        match HooshClient::new(hoosh_url) {
            Ok(c) => Some(c),
            Err(e) => {
                warn!(error = %e, "failed to create hoosh client");
                None
            }
        }
    } else {
        None
    };

    loop {
        line_buf.clear();
        let n = buf_reader.read_line(&mut line_buf).await?;
        if n == 0 {
            break;
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

        let path = match std::fs::canonicalize(&line) {
            Ok(p) => p,
            Err(e) => {
                let err = serde_json::json!({"error": format!("invalid path: {e}")}).to_string();
                writer.write_all(err.as_bytes()).await?;
                writer.write_all(b"\n").await?;
                continue;
            }
        };

        let mut result = match run_scan(&path, None) {
            Ok(r) => r,
            Err(e) => {
                let err = serde_json::json!({"error": e.to_string()}).to_string();
                writer.write_all(err.as_bytes()).await?;
                writer.write_all(b"\n").await?;
                continue;
            }
        };

        // Run hoosh triage on findings if enabled
        if let Some(ref client) = hoosh_client {
            for finding in &mut result.findings {
                match client.triage_finding(finding).await {
                    Ok(triage) => {
                        finding
                            .metadata
                            .insert("triage_classification".into(), triage.classification);
                        finding.metadata.insert(
                            "triage_confidence".into(),
                            format!("{:.2}", triage.confidence),
                        );
                        finding
                            .metadata
                            .insert("triage_explanation".into(), triage.explanation);
                    }
                    Err(e) => {
                        finding
                            .metadata
                            .insert("triage_error".into(), e.to_string());
                    }
                }
            }
        }

        let response = serde_json::to_string(&result)
            .unwrap_or_else(|e| serde_json::json!({"error": e.to_string()}).to_string());
        writer.write_all(response.as_bytes()).await?;
        writer.write_all(b"\n").await?;
    }

    Ok(())
}

fn cmd_report(
    path: &Path,
    format: &str,
    rules_path: Option<&Path>,
    do_triage: bool,
    hoosh_url: &str,
) -> Result<()> {
    let mut result = run_scan(path, rules_path)?;

    // Triage findings via hoosh if requested
    if do_triage && !result.findings.is_empty() {
        let rt = tokio::runtime::Runtime::new()?;
        let client = HooshClient::new(hoosh_url)?;
        rt.block_on(async {
            for finding in &mut result.findings {
                match client.triage_finding(finding).await {
                    Ok(triage) => {
                        finding
                            .metadata
                            .insert("triage_classification".into(), triage.classification);
                        finding.metadata.insert(
                            "triage_confidence".into(),
                            format!("{:.2}", triage.confidence),
                        );
                    }
                    Err(e) => {
                        warn!(finding = %finding.rule_name, error = %e, "triage failed");
                    }
                }
            }
        });
    }

    let report = ThreatReport::from_results(result.session_id, vec![result]);
    let fmt = match format {
        "markdown" | "md" => ReportFormat::Markdown,
        "sarif" => ReportFormat::Sarif,
        _ => ReportFormat::Json,
    };
    println!("{}", report.render(fmt));
    Ok(())
}

fn cmd_watch(
    paths: &[PathBuf],
    recursive: bool,
    extensions: Option<&str>,
    rules_path: Option<&Path>,
    do_triage: bool,
    hoosh_url: &str,
) -> Result<()> {
    use phylax::watch::{WatchConfig, WatchEvent};

    let ext_list: Vec<String> = extensions
        .map(|e| e.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_default();

    let config = WatchConfig {
        paths: paths.to_vec(),
        recursive,
        extensions: ext_list,
        ..Default::default()
    };

    println!("Phylax Watch Mode v{VERSION}");
    println!("Watching {} path(s):", paths.len());
    for p in paths {
        println!("  {}", p.display());
    }
    if do_triage {
        println!("Triage: enabled ({hoosh_url})");
    }
    println!();

    let (_handle, rx) = phylax::watch::start_watch(&config)?;

    // Create tokio runtime once for triage (reused across events)
    let rt = if do_triage {
        Some(tokio::runtime::Runtime::new()?)
    } else {
        None
    };

    // Track recently scanned files to debounce
    let mut last_scanned: std::collections::HashMap<PathBuf, std::time::Instant> =
        std::collections::HashMap::new();
    let debounce = config.debounce;
    let mut scan_count: u64 = 0;

    loop {
        match rx.recv() {
            Ok(WatchEvent::FileChanged(path)) => {
                // Debounce: skip if scanned within debounce window
                let now = std::time::Instant::now();
                if let Some(last) = last_scanned.get(&path) {
                    if now.duration_since(*last) < debounce {
                        continue;
                    }
                }
                last_scanned.insert(path.clone(), now);

                // Periodic cleanup: evict entries older than 60s every 100 scans
                scan_count += 1;
                if scan_count % 100 == 0 {
                    last_scanned
                        .retain(|_, t| now.duration_since(*t) < std::time::Duration::from_secs(60));
                }

                println!("[WATCH] File changed: {}", path.display());
                match run_scan(&path, rules_path) {
                    Ok(result) => {
                        if result.findings.is_empty() {
                            println!("[WATCH] {} — clean", path.display());
                        } else {
                            println!(
                                "[WATCH] {} — {} FINDING(S):",
                                path.display(),
                                result.findings.len()
                            );
                            for f in &result.findings {
                                println!(
                                    "  [{severity}] {rule}: {desc}",
                                    severity = f.severity,
                                    rule = f.rule_name,
                                    desc = f.description,
                                );
                            }

                            if let Some(ref rt) = rt {
                                rt.block_on(triage_findings(
                                    &result.findings,
                                    hoosh_url,
                                    phylax::hoosh::HOOSH_DEFAULT_MODEL,
                                ));
                            }
                        }
                    }
                    Err(e) => {
                        warn!(path = %path.display(), error = %e, "scan failed");
                        println!("[WATCH] {} — scan error: {e}", path.display());
                    }
                }
                println!();
            }
            Ok(WatchEvent::FileRemoved(path)) => {
                debug!(path = %path.display(), "file removed");
            }
            Ok(WatchEvent::Error(e)) => {
                error!(error = %e, "watch error");
            }
            Ok(_) => {}
            Err(_) => {
                // Channel closed — watcher dropped
                break;
            }
        }
    }

    Ok(())
}

fn cmd_rules_list(file: Option<&Path>) -> Result<()> {
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
    println!("Analyzers:    entropy, magic_bytes, yara, polyglot, pe, elf, strings");
    println!("AI backend:   hoosh (port 8088)");
    println!("Orchestrator: daimon (port 8090)");
    Ok(())
}
