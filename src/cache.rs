use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::scanner::finding::Finding;

/// Cache key: file path + modification time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub path: String,
    pub mtime_secs: u64,
}

/// Scan cache mapping file keys to cached findings.
#[derive(Debug, Serialize, Deserialize)]
pub struct ScanCache {
    pub version: u8,
    pub entries: HashMap<String, CacheEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CacheEntry {
    pub mtime_secs: u64,
    pub findings: Vec<Finding>,
}

impl ScanCache {
    pub fn new() -> Self {
        Self {
            version: 1,
            entries: HashMap::new(),
        }
    }

    /// Look up cached findings for a file path + mtime.
    pub fn lookup(&self, file_path: &Path, mtime_secs: u64) -> Option<Vec<Finding>> {
        let key = file_path.to_string_lossy().to_string();
        if let Some(entry) = self.entries.get(&key) {
            if entry.mtime_secs == mtime_secs {
                return Some(entry.findings.clone());
            }
        }
        None
    }

    /// Store findings for a file.
    pub fn store(&mut self, file_path: PathBuf, mtime_secs: u64, findings: Vec<Finding>) {
        let key = file_path.to_string_lossy().to_string();
        self.entries.insert(
            key,
            CacheEntry {
                mtime_secs,
                findings,
            },
        );
    }
}

/// Load cache from a JSON file. Returns empty cache if file doesn't exist or is invalid.
pub fn load_cache(path: &Path) -> ScanCache {
    if !path.exists() {
        return ScanCache::new();
    }

    match std::fs::read_to_string(path) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_else(|_| ScanCache::new()),
        Err(_) => ScanCache::new(),
    }
}

/// Save cache to a JSON file.
pub fn save_cache(cache: &ScanCache, path: &Path) -> anyhow::Result<()> {
    let json = serde_json::to_string(cache)?;
    std::fs::write(path, json)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::finding::*;

    fn make_finding() -> Finding {
        Finding {
            detector_id: "SOL-001".to_string(),
            name: "test".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            message: "test finding".to_string(),
            file: PathBuf::from("test.rs"),
            line: 10,
            column: 1,
            snippet: "let x = 1;".to_string(),
            recommendation: "fix".to_string(),
            chain: Chain::Solana,
        }
    }

    #[test]
    fn test_cache_miss_on_empty() {
        let cache = ScanCache::new();
        assert!(cache.lookup(Path::new("test.rs"), 12345).is_none());
    }

    #[test]
    fn test_cache_hit_same_mtime() {
        let mut cache = ScanCache::new();
        let findings = vec![make_finding()];
        cache.store(PathBuf::from("test.rs"), 12345, findings.clone());

        let result = cache.lookup(Path::new("test.rs"), 12345);
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 1);
    }

    #[test]
    fn test_cache_miss_different_mtime() {
        let mut cache = ScanCache::new();
        cache.store(PathBuf::from("test.rs"), 12345, vec![make_finding()]);

        assert!(cache.lookup(Path::new("test.rs"), 99999).is_none());
    }

    #[test]
    fn test_cache_roundtrip() {
        let mut cache = ScanCache::new();
        cache.store(PathBuf::from("test.rs"), 12345, vec![make_finding()]);

        let tmp = std::env::temp_dir().join("rustdefend_cache_test.json");
        save_cache(&cache, &tmp).unwrap();
        let loaded = load_cache(&tmp);

        let result = loaded.lookup(Path::new("test.rs"), 12345);
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 1);

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_load_nonexistent_cache() {
        let cache = load_cache(Path::new("/nonexistent/cache.json"));
        assert!(cache.entries.is_empty());
    }
}
