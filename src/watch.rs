//! Filesystem watch mode.
//!
//! Monitors directories for file creation and modification events,
//! automatically triggering scans on changed files.

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Configuration for watch mode.
#[derive(Debug, Clone)]
pub struct WatchConfig {
    /// Directories to watch.
    pub paths: Vec<PathBuf>,
    /// Whether to watch subdirectories recursively.
    pub recursive: bool,
    /// Debounce duration — ignore duplicate events within this window.
    pub debounce: Duration,
    /// File extensions to include (empty = all files).
    pub extensions: Vec<String>,
    /// Maximum file size to scan (bytes).
    pub max_file_size: u64,
}

impl Default for WatchConfig {
    fn default() -> Self {
        Self {
            paths: vec![],
            recursive: true,
            debounce: Duration::from_millis(500),
            extensions: vec![],
            max_file_size: 50 * 1024 * 1024,
        }
    }
}

/// Events emitted by the watcher.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum WatchEvent {
    /// A file was created or modified and should be scanned.
    FileChanged(PathBuf),
    /// A file was removed.
    FileRemoved(PathBuf),
    /// A watch error occurred.
    Error(String),
}

/// Start watching directories and emit events for scannable file changes.
///
/// Returns a receiver that yields `WatchEvent`s. The watcher runs until
/// the returned `WatchHandle` is dropped.
///
/// # Errors
/// Returns an error if the underlying filesystem watcher cannot be created
/// or a watch path cannot be registered.
pub fn start_watch(
    config: &WatchConfig,
) -> anyhow::Result<(WatchHandle, mpsc::Receiver<WatchEvent>)> {
    let (event_tx, rx) = mpsc::channel();
    let extensions = config.extensions.clone();
    let max_size = config.max_file_size;

    let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
        match res {
            Ok(event) => {
                let dominated_events = match event.kind {
                    EventKind::Create(_) | EventKind::Modify(_) => {
                        event.paths.into_iter().filter_map(|p| {
                            if !p.is_file() {
                                return None;
                            }
                            if !extensions.is_empty() {
                                let ext = p.extension()
                                    .and_then(|e| e.to_str())
                                    .unwrap_or("");
                                if !extensions.iter().any(|e| e == ext) {
                                    return None;
                                }
                            }
                            // Check file size
                            if let Ok(meta) = std::fs::metadata(&p) {
                                if meta.len() > max_size {
                                    debug!(path = %p.display(), size = meta.len(), "skipping oversized file");
                                    return None;
                                }
                            }
                            debug!(path = %p.display(), "file change detected");
                            Some(WatchEvent::FileChanged(p))
                        }).collect::<Vec<_>>()
                    }
                    EventKind::Remove(_) => event
                        .paths
                        .into_iter()
                        .map(|p| {
                            debug!(path = %p.display(), "file removal detected");
                            WatchEvent::FileRemoved(p)
                        })
                        .collect(),
                    _ => vec![],
                };
                for evt in dominated_events {
                    let _ = event_tx.send(evt);
                }
            }
            Err(e) => {
                let _ = event_tx.send(WatchEvent::Error(e.to_string()));
            }
        }
    })?;

    let mode = if config.recursive {
        RecursiveMode::Recursive
    } else {
        RecursiveMode::NonRecursive
    };

    for path in &config.paths {
        if !path.exists() {
            warn!(path = %path.display(), "watch path does not exist, skipping");
            continue;
        }
        watcher.watch(path, mode)?;
        info!(path = %path.display(), recursive = config.recursive, "watching directory");
    }

    Ok((WatchHandle { _watcher: watcher }, rx))
}

/// Handle that keeps the watcher alive. Drop to stop watching.
pub struct WatchHandle {
    _watcher: RecommendedWatcher,
}

impl std::fmt::Debug for WatchHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WatchHandle").finish()
    }
}

/// Convenience: watch a single directory.
///
/// # Errors
/// Returns an error if the watcher cannot be created or the path cannot be watched.
pub fn watch_directory(path: &Path) -> anyhow::Result<(WatchHandle, mpsc::Receiver<WatchEvent>)> {
    let config = WatchConfig {
        paths: vec![path.to_path_buf()],
        ..Default::default()
    };
    start_watch(&config)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn watch_config_defaults() {
        let cfg = WatchConfig::default();
        assert!(cfg.recursive);
        assert_eq!(cfg.debounce, Duration::from_millis(500));
        assert!(cfg.extensions.is_empty());
        assert_eq!(cfg.max_file_size, 50 * 1024 * 1024);
    }

    #[test]
    fn watch_detects_new_file() {
        let dir = TempDir::new().unwrap();
        let (handle, rx) = watch_directory(dir.path()).unwrap();

        // Small delay for watcher to initialize
        std::thread::sleep(Duration::from_millis(100));

        // Create a file
        let file_path = dir.path().join("test.bin");
        let mut f = fs::File::create(&file_path).unwrap();
        f.write_all(b"new file content").unwrap();
        drop(f);

        // Wait for event
        let event = rx.recv_timeout(Duration::from_secs(2));
        assert!(event.is_ok(), "expected file change event, got timeout");
        match event.unwrap() {
            WatchEvent::FileChanged(p) => {
                assert_eq!(p.file_name().unwrap(), "test.bin");
            }
            other => panic!("expected FileChanged, got {other:?}"),
        }

        drop(handle);
    }

    #[test]
    fn watch_detects_modified_file() {
        let dir = TempDir::new().unwrap();

        // Create file before watching
        let file_path = dir.path().join("existing.txt");
        fs::write(&file_path, b"original").unwrap();

        let (handle, rx) = watch_directory(dir.path()).unwrap();
        std::thread::sleep(Duration::from_millis(100));

        // Modify the file
        fs::write(&file_path, b"modified content").unwrap();

        let event = rx.recv_timeout(Duration::from_secs(2));
        assert!(event.is_ok(), "expected modify event");

        drop(handle);
    }

    #[test]
    fn watch_filters_by_extension() {
        let dir = TempDir::new().unwrap();
        let config = WatchConfig {
            paths: vec![dir.path().to_path_buf()],
            extensions: vec!["bin".into(), "exe".into()],
            ..Default::default()
        };
        let (handle, rx) = start_watch(&config).unwrap();
        std::thread::sleep(Duration::from_millis(100));

        // Create a .txt file (should be filtered out)
        fs::write(dir.path().join("ignored.txt"), b"text").unwrap();
        // Create a .bin file (should be detected)
        fs::write(dir.path().join("detected.bin"), b"binary").unwrap();

        // Collect events for a bit
        std::thread::sleep(Duration::from_millis(500));
        let mut events = vec![];
        while let Ok(evt) = rx.try_recv() {
            events.push(evt);
        }

        let changed_files: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                WatchEvent::FileChanged(p) => Some(p.clone()),
                _ => None,
            })
            .collect();

        assert!(
            changed_files
                .iter()
                .any(|p| p.extension().and_then(|e| e.to_str()) == Some("bin")),
            "expected .bin file event, got: {changed_files:?}"
        );
        assert!(
            !changed_files
                .iter()
                .any(|p| p.extension().and_then(|e| e.to_str()) == Some("txt")),
            "should not have .txt event"
        );

        drop(handle);
    }

    #[test]
    fn watch_nonexistent_path_skipped() {
        let config = WatchConfig {
            paths: vec![PathBuf::from("/nonexistent/watch/path")],
            ..Default::default()
        };
        // Should not error — just skips the path
        let result = start_watch(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn watch_handle_debug() {
        let dir = TempDir::new().unwrap();
        let (handle, _rx) = watch_directory(dir.path()).unwrap();
        let debug = format!("{handle:?}");
        assert!(debug.contains("WatchHandle"));
    }

    #[test]
    fn watch_skips_oversized_files() {
        let dir = TempDir::new().unwrap();
        let config = WatchConfig {
            paths: vec![dir.path().to_path_buf()],
            max_file_size: 10, // 10 bytes max
            ..Default::default()
        };
        let (_handle, rx) = start_watch(&config).unwrap();
        std::thread::sleep(Duration::from_millis(100));

        // Create a file larger than max
        let big = vec![0u8; 100];
        fs::write(dir.path().join("big.bin"), &big).unwrap();

        // Create a small file
        fs::write(dir.path().join("small.bin"), b"tiny").unwrap();

        std::thread::sleep(Duration::from_millis(500));
        let mut events = vec![];
        while let Ok(evt) = rx.try_recv() {
            events.push(evt);
        }

        let changed: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                WatchEvent::FileChanged(p) => {
                    Some(p.file_name().unwrap().to_str().unwrap().to_string())
                }
                _ => None,
            })
            .collect();

        // Small file should be detected, big file should be filtered
        assert!(
            changed.iter().any(|n| n == "small.bin"),
            "expected small.bin event, got: {changed:?}"
        );
        assert!(
            !changed.iter().any(|n| n == "big.bin"),
            "big.bin should have been filtered"
        );
    }

    #[test]
    fn watch_config_custom() {
        let cfg = WatchConfig {
            paths: vec![PathBuf::from("/tmp")],
            recursive: false,
            debounce: Duration::from_secs(1),
            extensions: vec!["exe".into()],
            max_file_size: 1024,
        };
        assert!(!cfg.recursive);
        assert_eq!(cfg.debounce, Duration::from_secs(1));
        assert_eq!(cfg.extensions, vec!["exe"]);
        assert_eq!(cfg.max_file_size, 1024);
    }

    #[test]
    fn watch_event_variants() {
        let changed = WatchEvent::FileChanged(PathBuf::from("/tmp/test"));
        let removed = WatchEvent::FileRemoved(PathBuf::from("/tmp/test"));
        let error = WatchEvent::Error("oops".into());

        // Just verify they exist and are Debug
        assert!(format!("{changed:?}").contains("FileChanged"));
        assert!(format!("{removed:?}").contains("FileRemoved"));
        assert!(format!("{error:?}").contains("Error"));
    }
}
