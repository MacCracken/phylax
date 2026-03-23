//! Quarantine directory management.
//!
//! Moves suspicious files to a quarantine directory, tracks metadata,
//! and supports release (restore) operations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// Metadata for a quarantined file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    /// Unique quarantine ID.
    pub id: String,
    /// Original file path before quarantine.
    pub original_path: PathBuf,
    /// Path inside the quarantine directory.
    pub quarantine_path: PathBuf,
    /// Reason for quarantine.
    pub reason: String,
    /// When the file was quarantined.
    pub quarantined_at: DateTime<Utc>,
    /// SHA-256 hash of the file at quarantine time.
    pub sha256: String,
    /// File size in bytes.
    pub size: u64,
}

/// Manages a quarantine directory.
#[derive(Debug)]
pub struct QuarantineManager {
    /// Root directory for quarantined files.
    dir: PathBuf,
    /// In-memory index of quarantined files.
    entries: HashMap<String, QuarantineEntry>,
}

impl QuarantineManager {
    /// Create a new manager for the given quarantine directory.
    ///
    /// Creates the directory if it doesn't exist.
    pub fn new(dir: impl Into<PathBuf>) -> std::io::Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;

        let mut mgr = Self {
            dir,
            entries: HashMap::new(),
        };
        mgr.load_index();
        Ok(mgr)
    }

    /// Quarantine a file: move it into the quarantine directory.
    ///
    /// Returns the quarantine ID on success.
    pub fn quarantine(
        &mut self,
        source: &Path,
        reason: impl Into<String>,
    ) -> std::io::Result<String> {
        let metadata = fs::metadata(source)?;
        let data = fs::read(source)?;
        let sha256 = crate::analyze::file_sha256(&data);

        let id = uuid::Uuid::new_v4().to_string();
        let quarantine_path = self.dir.join(&id);

        fs::rename(source, &quarantine_path)?;
        info!(
            id = %id,
            original = %source.display(),
            "file quarantined"
        );

        let entry = QuarantineEntry {
            id: id.clone(),
            original_path: source.to_path_buf(),
            quarantine_path,
            reason: reason.into(),
            quarantined_at: Utc::now(),
            sha256,
            size: metadata.len(),
        };

        self.entries.insert(id.clone(), entry);
        self.save_index();

        Ok(id)
    }

    /// Release a quarantined file: move it back to its original location.
    pub fn release(&mut self, id: &str) -> std::io::Result<PathBuf> {
        let entry = self
            .entries
            .get(id)
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "unknown quarantine ID")
            })?
            .clone();

        // Ensure parent directory exists
        if let Some(parent) = entry.original_path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::rename(&entry.quarantine_path, &entry.original_path)?;
        info!(
            id = %id,
            restored = %entry.original_path.display(),
            "file released from quarantine"
        );

        self.entries.remove(id);
        self.save_index();

        Ok(entry.original_path)
    }

    /// List all quarantined files.
    pub fn list(&self) -> Vec<&QuarantineEntry> {
        let mut entries: Vec<_> = self.entries.values().collect();
        entries.sort_by(|a, b| b.quarantined_at.cmp(&a.quarantined_at));
        entries
    }

    /// Get a specific quarantine entry.
    pub fn get(&self, id: &str) -> Option<&QuarantineEntry> {
        self.entries.get(id)
    }

    /// Number of quarantined files.
    pub fn count(&self) -> usize {
        self.entries.len()
    }

    /// Path to the quarantine directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Load the index file from disk.
    fn load_index(&mut self) {
        let index_path = self.dir.join("index.json");
        if let Ok(data) = fs::read_to_string(&index_path) {
            match serde_json::from_str::<Vec<QuarantineEntry>>(&data) {
                Ok(entries) => {
                    for entry in entries {
                        self.entries.insert(entry.id.clone(), entry);
                    }
                    debug!(count = self.entries.len(), "loaded quarantine index");
                }
                Err(e) => {
                    warn!(error = %e, "failed to parse quarantine index");
                }
            }
        }
    }

    /// Save the index file to disk.
    fn save_index(&self) {
        let index_path = self.dir.join("index.json");
        let entries: Vec<_> = self.entries.values().collect();
        match serde_json::to_string_pretty(&entries) {
            Ok(json) => {
                if let Err(e) = fs::write(&index_path, json) {
                    warn!(error = %e, path = %index_path.display(), "failed to write quarantine index");
                }
            }
            Err(e) => {
                warn!(error = %e, "failed to serialize quarantine index");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn temp_quarantine() -> (TempDir, QuarantineManager) {
        let dir = TempDir::new().unwrap();
        let qdir = dir.path().join("quarantine");
        let mgr = QuarantineManager::new(&qdir).unwrap();
        (dir, mgr)
    }

    fn create_test_file(dir: &Path, name: &str, content: &[u8]) -> PathBuf {
        let path = dir.join(name);
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(content).unwrap();
        path
    }

    #[test]
    fn quarantine_and_release() {
        let (tmpdir, mut mgr) = temp_quarantine();
        let file = create_test_file(tmpdir.path(), "suspect.bin", b"malicious content");

        // Quarantine
        let id = mgr.quarantine(&file, "high entropy").unwrap();
        assert!(!file.exists(), "original should be moved");
        assert_eq!(mgr.count(), 1);

        let entry = mgr.get(&id).unwrap();
        assert_eq!(entry.reason, "high entropy");
        assert_eq!(entry.size, 17);

        // Release
        let restored = mgr.release(&id).unwrap();
        assert!(restored.exists(), "file should be restored");
        assert_eq!(mgr.count(), 0);
        assert_eq!(fs::read(&restored).unwrap(), b"malicious content");
    }

    #[test]
    fn quarantine_list() {
        let (tmpdir, mut mgr) = temp_quarantine();
        let f1 = create_test_file(tmpdir.path(), "a.bin", b"aaa");
        let f2 = create_test_file(tmpdir.path(), "b.bin", b"bbb");

        mgr.quarantine(&f1, "reason a").unwrap();
        mgr.quarantine(&f2, "reason b").unwrap();

        let list = mgr.list();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn release_unknown_id() {
        let (_tmpdir, mut mgr) = temp_quarantine();
        assert!(mgr.release("nonexistent").is_err());
    }

    #[test]
    fn quarantine_entry_serialization() {
        let entry = QuarantineEntry {
            id: "test-id".into(),
            original_path: "/tmp/test.bin".into(),
            quarantine_path: "/quarantine/test-id".into(),
            reason: "suspicious".into(),
            quarantined_at: Utc::now(),
            sha256: "abc123".into(),
            size: 1024,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: QuarantineEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, "test-id");
        assert_eq!(parsed.reason, "suspicious");
    }

    #[test]
    fn quarantine_index_persists() {
        let tmpdir = TempDir::new().unwrap();
        let qdir = tmpdir.path().join("quarantine");

        // Quarantine a file with one manager
        let file = create_test_file(tmpdir.path(), "persist.bin", b"data");
        let id = {
            let mut mgr = QuarantineManager::new(&qdir).unwrap();
            mgr.quarantine(&file, "test persistence").unwrap()
        };
        // Drop mgr — index should be saved

        // Create a new manager from the same directory — should reload
        let mgr2 = QuarantineManager::new(&qdir).unwrap();
        assert_eq!(mgr2.count(), 1);
        let entry = mgr2.get(&id).unwrap();
        assert_eq!(entry.reason, "test persistence");
    }

    #[test]
    fn quarantine_sha256_correct() {
        let (tmpdir, mut mgr) = temp_quarantine();
        let content = b"known content for hashing";
        let file = create_test_file(tmpdir.path(), "hash.bin", content);

        let expected_hash = crate::analyze::file_sha256(content);
        let id = mgr.quarantine(&file, "hash check").unwrap();
        let entry = mgr.get(&id).unwrap();
        assert_eq!(entry.sha256, expected_hash);
    }

    #[test]
    fn quarantine_nonexistent_file() {
        let (_tmpdir, mut mgr) = temp_quarantine();
        let result = mgr.quarantine(Path::new("/nonexistent/file.bin"), "test");
        assert!(result.is_err());
    }

    #[test]
    fn quarantine_multiple_files() {
        let (tmpdir, mut mgr) = temp_quarantine();
        let f1 = create_test_file(tmpdir.path(), "a.bin", b"aaa");
        let f2 = create_test_file(tmpdir.path(), "b.bin", b"bbb");
        let f3 = create_test_file(tmpdir.path(), "c.bin", b"ccc");

        let id1 = mgr.quarantine(&f1, "r1").unwrap();
        let id2 = mgr.quarantine(&f2, "r2").unwrap();
        let id3 = mgr.quarantine(&f3, "r3").unwrap();
        assert_eq!(mgr.count(), 3);

        // Release middle one
        mgr.release(&id2).unwrap();
        assert_eq!(mgr.count(), 2);
        assert!(mgr.get(&id1).is_some());
        assert!(mgr.get(&id2).is_none());
        assert!(mgr.get(&id3).is_some());
    }

    #[test]
    fn quarantine_dir_created() {
        let tmpdir = TempDir::new().unwrap();
        let qdir = tmpdir.path().join("deep").join("quarantine");
        assert!(!qdir.exists());
        let _mgr = QuarantineManager::new(&qdir).unwrap();
        assert!(qdir.exists());
    }
}
