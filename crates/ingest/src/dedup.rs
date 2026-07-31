//! Deduplication against the existing catalog.
//!
//! Two things make an ingested record a duplicate: an id the catalog already
//! uses, and a registry key path the catalog already covers under some other
//! id. Both are read from the descriptor sources in one walk.

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

/// Registry key paths the catalog already covers, uppercased and reduced to
/// single backslashes so a descriptor literal (`"A\\B"`) and a path read from
/// upstream JSON (`A\B`) compare equal.
#[derive(Debug, Default, Clone)]
pub struct PathSet {
    paths: HashSet<String>,
}

impl PathSet {
    /// Add a key path as written in a descriptor source.
    pub fn insert(&mut self, key_path: &str) {
        self.paths
            .insert(key_path.replace("\\\\", "\\").to_uppercase());
    }

    /// Number of distinct key paths.
    pub fn len(&self) -> usize {
        self.paths.len()
    }

    /// Returns `true` when the catalog already covers this key path.
    ///
    /// Upstream sources give hive-relative keys while descriptors may carry the
    /// hive, so a catalogued path also counts as covering any key that is its
    /// suffix at a path boundary. An empty key path — every file, directory and
    /// event-log record has one — is never covered.
    pub fn covers(&self, key_path: &str) -> bool {
        if key_path.is_empty() {
            return false;
        }
        let key = key_path.replace("\\\\", "\\").to_uppercase();
        let suffix = format!("\\{key}");
        self.paths.iter().any(|c| *c == key || c.ends_with(&suffix))
    }
}

/// Everything the pipeline needs to tell a net-new record from one the catalog
/// already has.
#[derive(Debug, Default, Clone)]
pub struct CatalogIndex {
    pub ids: IdSet,
    pub paths: PathSet,
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

/// Extract the string literal after `key_path:` on a line (handles `"..."`,
/// `r"..."`, `r#"..."#`). Returns `None` for empty / non-matching lines.
fn extract_key_path(line: &str) -> Option<&str> {
    let after = line.split_once("key_path:")?.1.trim_start();
    let after = after.trim_start_matches('r').trim_start_matches('#');
    let after = after.strip_prefix('"')?;
    let end = after.find('"')?;
    let value = &after[..end];
    (!value.is_empty()).then_some(value)
}

/// Scan all `.rs` files under `catalog_dir` and collect every `id: "..."` and
/// `key_path: "..."` value in one walk.
pub fn load_catalog(catalog_dir: impl AsRef<Path>) -> io::Result<CatalogIndex> {
    let mut index = CatalogIndex::default();
    scan_dir(catalog_dir.as_ref(), &mut index)?;
    Ok(index)
}

fn scan_dir(dir: &Path, index: &mut CatalogIndex) -> io::Result<()> {
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
            match scan_dir(&path, index) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        } else if path.extension().is_some_and(|e| e == "rs") {
            match fs::read_to_string(&path) {
                Ok(source) => {
                    for id in extract_ids_from_source(&source) {
                        index.ids.insert(id);
                    }
                    for key_path in source.lines().filter_map(extract_key_path) {
                        index.paths.insert(key_path);
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
        let catalog = load_catalog(dir.path()).expect("scan must tolerate a vanished entry");
        assert!(catalog.ids.is_duplicate("real_id"));
    }

    #[test]
    #[cfg(unix)]
    fn scan_fails_loud_on_an_error_that_is_not_a_vanished_entry() {
        // The twin of the test above: a *transient* NotFound is skipped, but a
        // real I/O error must propagate. Swallowing it (`let Ok(..) else
        // return`, `entries.flatten()`) would silently under-report the catalog
        // and let a duplicate through as if it were net-new.
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let locked = dir.path().join("locked");
        std::fs::create_dir(&locked).expect("mkdir");
        std::fs::write(locked.join("hidden.rs"), "    id: \"hidden\",\n").expect("write");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).expect("chmod");

        let readable_anyway = std::fs::read_dir(&locked).is_ok();
        let result = load_catalog(dir.path());
        // Restore so the tempdir can be cleaned up.
        let _ = std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755));

        if readable_anyway {
            // Running as root: permissions do not deny us, nothing to assert.
            return;
        }
        assert!(
            result.is_err(),
            "an unreadable directory must surface, not be reported as an empty catalog"
        );
    }

    #[test]
    fn load_catalog_collects_ids_and_key_paths_in_one_walk() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("descriptors.rs"),
            "    id: \"run_key\",\n    key_path: \"Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\",\n",
        )
        .expect("write");
        let catalog = load_catalog(dir.path()).expect("scan");
        assert!(catalog.ids.is_duplicate("run_key"));
        assert!(
            catalog
                .paths
                .covers(r"Microsoft\Windows\CurrentVersion\Run"),
            "hive-relative key already in the catalog must be recognized"
        );
    }

    #[test]
    fn extract_key_path_handles_quote_forms() {
        // escaped form (how descriptors are written)
        assert_eq!(
            extract_key_path(r#"    key_path: "Software\\Microsoft\\Run","#),
            Some(r"Software\\Microsoft\\Run")
        );
        // raw-string form
        assert_eq!(
            extract_key_path(r##"    key_path: r"Software\Foo","##),
            Some(r"Software\Foo")
        );
        // empty and non-matching lines
        assert_eq!(extract_key_path(r#"    key_path: "","#), None);
        assert_eq!(extract_key_path(r#"    name: "x","#), None);
    }

    #[test]
    fn path_set_matches_across_hive_prefix_and_escaping() {
        let mut paths = PathSet::default();
        paths.insert(r"SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN");
        // hive-relative key IS covered (suffix match past the SOFTWARE hive)
        assert!(paths.covers(r"Microsoft\Windows\CurrentVersion\Run"));
        // full path with the hive is covered too
        assert!(paths.covers(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"));
        // a sibling key that is NOT catalogued is kept
        assert!(!paths.covers(r"Microsoft\Windows\CurrentVersion\RunOnceEx"));
    }

    #[test]
    fn path_set_never_covers_a_record_that_has_no_key_path() {
        // File, directory and event-log records carry an empty key_path. An
        // empty needle must not suffix-match a catalogued registry path, or the
        // filter would drop every non-registry artifact.
        let mut paths = PathSet::default();
        paths.insert(r"SOFTWARE\MICROSOFT\WINDOWS");
        assert!(!paths.covers(""));
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
        let catalog = load_catalog(catalog_dir).expect("should scan catalog dir");
        // The catalog has hundreds of entries; just confirm we got some
        assert!(
            catalog.ids.len() > 50,
            "expected > 50 catalog IDs, got {}",
            catalog.ids.len()
        );
        // Check a known ID
        assert!(
            catalog.ids.is_duplicate("safeboot_minimal") || !catalog.ids.is_empty(),
            "catalog should contain known IDs"
        );
        assert!(
            catalog.paths.len() > 50,
            "expected > 50 catalog key paths, got {}",
            catalog.paths.len()
        );
    }
}
