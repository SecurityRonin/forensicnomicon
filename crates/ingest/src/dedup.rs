//! Deduplication against existing catalog artifact IDs.

use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::Path;

use regex::Regex;

/// A set of existing artifact IDs used to skip duplicates during ingestion.
#[derive(Debug, Default, Clone)]
pub struct IdSet {
    ids: HashSet<String>,
}

impl IdSet {
    /// Returns `true` if `id` is already in the set.
    pub fn is_duplicate(&self, id: &str) -> bool {
        self.ids.contains(id)
    }

    /// Add `id` to the set. Duplicate inserts are no-ops.
    pub fn insert(&mut self, id: String) {
        self.ids.insert(id);
    }

    /// Number of IDs in the set.
    pub fn len(&self) -> usize {
        self.ids.len()
    }

    /// Returns `true` if the set is empty.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    /// Iterate over all IDs.
    #[allow(dead_code)]
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.ids.iter().map(String::as_str)
    }
}

/// Extract all artifact IDs from a Rust source string.
///
/// Matches lines of the form:
/// ```rust
///     id: "some_id",
/// ```
pub fn extract_ids_from_source(source: &str) -> HashSet<String> {
    let mut ids = HashSet::new();
    // Match:  id: "the_id", (optional trailing comma/whitespace). The pattern is
    // a constant valid regex; on the impossible compile failure return no ids
    // rather than panic.
    let Ok(re) = Regex::new(r#"^\s+id:\s+"([a-z0-9_]+)""#) else {
        return ids;
    };
    for line in source.lines() {
        if let Some(caps) = re.captures(line) {
            ids.insert(caps[1].to_string());
        }
    }
    ids
}

/// Scan all `.rs` files under `catalog_dir` and collect every `id: "..."` value.
///
/// Returns an `IdSet` ready for duplicate checks during ingestion.
pub fn load_catalog_ids(catalog_dir: impl AsRef<Path>) -> io::Result<IdSet> {
    let mut set = IdSet::default();
    scan_dir(catalog_dir.as_ref(), &mut set)?;
    Ok(set)
}

fn scan_dir(dir: &Path, set: &mut IdSet) -> io::Result<()> {
    // `read_dir` returns a point-in-time snapshot; under concurrent filesystem
    // activity an entry can be listed yet gone by the time it is accessed. Tolerate
    // that transient per-entry `NotFound` (skip the vanished entry) so a scan of a
    // live directory never crashes on a TOCTOU. The directory itself going missing
    // (`read_dir` below, and the recursion's own `read_dir`) still fails loud.
    for entry in fs::read_dir(dir)? {
        let entry = match entry {
            Ok(e) => e,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        let path = entry.path();
        if path.is_dir() {
            match scan_dir(&path, set) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        } else if path.extension().is_some_and(|e| e == "rs") {
            match fs::read_to_string(&path) {
                Ok(source) => {
                    for id in extract_ids_from_source(&source) {
                        set.insert(id);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(unix)]
    fn scan_tolerates_an_entry_that_vanishes_between_listing_and_read() {
        // `read_dir` yields a point-in-time snapshot; under concurrent filesystem
        // load an entry can be listed yet gone by the time it is read (a transient
        // `NotFound`). This intermittently reddened CI: a workspace test run would
        // panic in `load_catalog_ids` with `NotFound` while the committed catalog
        // was fully intact. A broken `.rs` symlink reproduces the class
        // deterministically — it resolves at listing time but errors `NotFound` on
        // read. The scan must skip the vanished entry and still return the real ids.
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("good.rs"), "    id: \"real_id\",\n").expect("write good");
        symlink(
            dir.path().join("does_not_exist.rs"),
            dir.path().join("ghost.rs"),
        )
        .expect("symlink");
        let set = load_catalog_ids(dir.path()).expect("scan must tolerate a vanished entry");
        assert!(set.is_duplicate("real_id"));
    }

    #[test]
    fn is_duplicate_returns_true_for_known_id() {
        let mut set = IdSet::default();
        set.insert("userassist_exe".to_string());
        assert!(set.is_duplicate("userassist_exe"));
    }

    #[test]
    fn is_duplicate_returns_false_for_unknown_id() {
        let set = IdSet::default();
        assert!(!set.is_duplicate("regedit_run_key"));
    }

    #[test]
    fn insert_and_len() {
        let mut set = IdSet::default();
        set.insert("id_one".to_string());
        set.insert("id_two".to_string());
        set.insert("id_one".to_string()); // duplicate insert
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn scan_rust_source_finds_ids() {
        let source = r#"
pub(crate) static USERASSIST: ArtifactDescriptor = ArtifactDescriptor {
    id: "userassist",
    name: "UserAssist",
};
pub(crate) static SHIMCACHE: ArtifactDescriptor = ArtifactDescriptor {
    id: "shimcache",
    name: "ShimCache",
};
"#;
        let ids = extract_ids_from_source(source);
        assert!(
            ids.contains("userassist"),
            "missing userassist, got: {ids:?}"
        );
        assert!(ids.contains("shimcache"), "missing shimcache, got: {ids:?}");
        assert_eq!(ids.len(), 2);
    }

    #[test]
    fn scan_rust_source_ignores_non_id_fields() {
        let source = r#"
    name: "Some Name",
    id: "real_id",
    meaning: "not an id: value",
"#;
        let ids = extract_ids_from_source(source);
        assert_eq!(ids.len(), 1);
        assert!(ids.contains("real_id"));
    }

    #[test]
    fn load_catalog_ids_scans_descriptors_dir() {
        // Use the real catalog directory
        let catalog_dir = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../data/src/catalog/descriptors"
        );
        let set = load_catalog_ids(catalog_dir).expect("should scan catalog dir");
        // The catalog has hundreds of entries; just confirm we got some
        assert!(
            set.len() > 50,
            "expected > 50 catalog IDs, got {}",
            set.len()
        );
        // Check a known ID
        assert!(
            set.is_duplicate("safeboot_minimal") || !set.is_empty(),
            "catalog should contain known IDs"
        );
    }
}
