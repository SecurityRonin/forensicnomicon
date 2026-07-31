//! Registry hive knowledge — one home for the three mappings the pipeline needs.
//!
//! A hive is named three different ways along the pipeline, so three tables
//! live here rather than in the layers that consume them:
//!
//! | From | To | Function | Used by |
//! |---|---|---|---|
//! | a full registry path | canonical hive | [`detect_hive`] | fa, velociraptor |
//! | a `HiveType` label | canonical hive | [`map_hive_type`] | regedit |
//! | canonical hive | `HiveTarget` variant | [`target_variant`] | codegen |
//!
//! The *canonical hive* is the string stored in `IngestRecord::hive`; it is the
//! join between the source adapters and code generation, which is why all three
//! tables are pinned to the same constants below.

/// Canonical hive strings. These are the only values that should ever reach
/// `IngestRecord::hive`.
const HKLM_SYSTEM: &str = r"HKLM\SYSTEM";
const HKLM_SOFTWARE: &str = r"HKLM\SOFTWARE";
const HKLM_SAM: &str = r"HKLM\SAM";
const HKLM_SECURITY: &str = r"HKLM\SECURITY";
const HKLM: &str = "HKLM";
const HKCU: &str = "HKCU";
const USR_CLASS: &str = r"HKCU\Software\Classes";
const AMCACHE: &str = "Amcache";
const BCD: &str = "BCD";

/// Registry-path prefixes (uppercase) that identify a hive, most specific
/// first.
///
/// A path under HKLM that names none of the four sub-hives is attributed to
/// `HKLM\SOFTWARE`: an HKLM path written without its sub-hive is overwhelmingly
/// a SOFTWARE path in the upstream corpora.
const PATH_PREFIXES: &[(&str, &str)] = &[
    (r"HKEY_LOCAL_MACHINE\SYSTEM", HKLM_SYSTEM),
    (r"HKLM\SYSTEM", HKLM_SYSTEM),
    (r"HKEY_LOCAL_MACHINE\SOFTWARE", HKLM_SOFTWARE),
    (r"HKLM\SOFTWARE", HKLM_SOFTWARE),
    (r"HKEY_LOCAL_MACHINE\SAM", HKLM_SAM),
    (r"HKLM\SAM", HKLM_SAM),
    (r"HKEY_LOCAL_MACHINE\SECURITY", HKLM_SECURITY),
    (r"HKLM\SECURITY", HKLM_SECURITY),
    ("HKEY_LOCAL_MACHINE", HKLM_SOFTWARE),
    ("HKLM", HKLM_SOFTWARE),
    (r"HKEY_CURRENT_USER\SOFTWARE\CLASSES", USR_CLASS),
    (r"HKCU\SOFTWARE\CLASSES", USR_CLASS),
    ("HKEY_CURRENT_USER", HKCU),
    ("HKCU", HKCU),
];

/// Hive-root prefixes stripped from a registry path to leave the hive-relative
/// `key_path`.
///
/// Exactly the roots [`detect_hive`] captures into the `hive` field — stripping
/// a root whose hive was not captured (`HKU\`, `HKCR\`) would drop the only
/// record of which hive the key lives in.
const KEY_PATH_ROOTS: &[&str] = &[
    r"HKEY_LOCAL_MACHINE\",
    r"HKEY_CURRENT_USER\",
    r"HKLM\",
    r"HKCU\",
];

/// `HiveType` labels used by RECmd batch files, mapped to a canonical hive.
const HIVE_TYPE_LABELS: &[(&str, &str)] = &[
    ("NTUSER", HKCU),
    ("HKCU", HKCU),
    ("HKEY_CURRENT_USER", HKCU),
    ("HKLM", HKLM),
    ("HKEY_LOCAL_MACHINE", HKLM),
    ("SYSTEM", HKLM_SYSTEM),
    ("SOFTWARE", HKLM_SOFTWARE),
    ("SAM", HKLM_SAM),
    ("SECURITY", HKLM_SECURITY),
    ("USRCLASS", USR_CLASS),
    ("HKCR", USR_CLASS),
    ("HKEY_CLASSES_ROOT", USR_CLASS),
    ("BCD", BCD),
    ("AMCACHE", AMCACHE),
];

/// Substrings of a canonical hive that select a `HiveTarget` variant, most
/// specific first.
///
/// Note the gap: a bare `HKLM` matches no marker and yields `None`. Only
/// [`map_hive_type`] can produce a bare `HKLM` (from a `HiveType: HKLM` label),
/// and no upstream RECmd batch file uses that label — every entry names its
/// sub-hive. Left as-is so this change does not move generated output; fixing
/// it needs a `HiveTarget::Hklm` variant in the catalog types.
const HIVE_TARGET_MARKERS: &[(&str, &str)] = &[
    (r"HKLM\SYSTEM", "HklmSystem"),
    (r"HKEY_LOCAL_MACHINE\SYSTEM", "HklmSystem"),
    (r"HKLM\SOFTWARE", "HklmSoftware"),
    (r"HKEY_LOCAL_MACHINE\SOFTWARE", "HklmSoftware"),
    (r"HKLM\SAM", "HklmSam"),
    (r"HKEY_LOCAL_MACHINE\SAM", "HklmSam"),
    (r"HKLM\SECURITY", "HklmSecurity"),
    (r"HKEY_LOCAL_MACHINE\SECURITY", "HklmSecurity"),
    (r"HKCU\SOFTWARE\CLASSES", "UsrClass"),
    (r"HKEY_CURRENT_USER\SOFTWARE\CLASSES", "UsrClass"),
    ("HKCU", "NtUser"),
    ("HKEY_CURRENT_USER", "NtUser"),
    ("NTUSER", "NtUser"),
    ("AMCACHE", "Amcache"),
    ("BCD", "Bcd"),
];

/// Canonical hive for a full registry path, or `None` when the path names no
/// recognized hive root.
pub fn detect_hive(path: &str) -> Option<&'static str> {
    let upper = path.to_ascii_uppercase();
    PATH_PREFIXES
        .iter()
        .find(|(prefix, _)| upper.starts_with(prefix))
        .map(|(_, canonical)| *canonical)
}

/// Strip the hive root from a registry path, leaving the hive-relative key path.
/// Paths with no recognized root are returned unchanged.
pub fn strip_hive_from_path(path: &str) -> String {
    let upper = path.to_ascii_uppercase();
    for root in KEY_PATH_ROOTS {
        if upper.starts_with(root) {
            return path[root.len()..].to_string();
        }
    }
    path.to_string()
}

/// Canonical hive for a `HiveType` label, or `None` for an unrecognized label.
pub fn map_hive_type(hive_type: &str) -> Option<&'static str> {
    let upper = hive_type.trim().to_ascii_uppercase();
    HIVE_TYPE_LABELS
        .iter()
        .find(|(label, _)| *label == upper)
        .map(|(_, canonical)| *canonical)
}

/// `HiveTarget` variant name for a canonical hive string.
///
/// Returns `"None"` for a hive this pipeline cannot place — non-registry
/// artifacts and unrecognized hive spellings alike.
pub fn target_variant(hive: &str) -> &'static str {
    let upper = hive.to_ascii_uppercase();
    HIVE_TARGET_MARKERS
        .iter()
        .find(|(marker, _)| upper.contains(marker))
        .map_or("None", |(_, variant)| *variant)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_hive_names_the_hklm_sub_hive() {
        assert_eq!(
            detect_hive(r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services"),
            Some(r"HKLM\SYSTEM")
        );
        assert_eq!(
            detect_hive(r"HKLM\SOFTWARE\Microsoft\Windows"),
            Some(r"HKLM\SOFTWARE")
        );
        assert_eq!(detect_hive(r"HKLM\SAM\SAM\Domains"), Some(r"HKLM\SAM"));
        assert_eq!(detect_hive(r"HKLM\SECURITY\Policy"), Some(r"HKLM\SECURITY"));
    }

    #[test]
    fn detect_hive_falls_back_to_software_for_a_bare_hklm_path() {
        assert_eq!(
            detect_hive(r"HKLM\Microsoft\Windows"),
            Some(r"HKLM\SOFTWARE")
        );
    }

    #[test]
    fn detect_hive_separates_usrclass_from_ntuser() {
        assert_eq!(
            detect_hive(r"HKCU\Software\Classes\.exe"),
            Some(r"HKCU\Software\Classes")
        );
        assert_eq!(detect_hive(r"HKCU\Software\Microsoft"), Some("HKCU"));
    }

    #[test]
    fn detect_hive_is_case_insensitive_and_rejects_unknown_roots() {
        assert_eq!(detect_hive(r"hklm\system\Select"), Some(r"HKLM\SYSTEM"));
        assert_eq!(detect_hive(r"HKU\S-1-5-21\Software"), None);
        assert_eq!(detect_hive(r"C:\Windows\System32"), None);
    }

    #[test]
    fn strip_hive_from_path_removes_only_captured_roots() {
        assert_eq!(
            strip_hive_from_path(r"HKEY_LOCAL_MACHINE\SYSTEM\Select"),
            r"SYSTEM\Select"
        );
        assert_eq!(strip_hive_from_path(r"HKCU\Software\Run"), r"Software\Run");
        // HKU / HKCR hives are not captured into `hive`, so their root stays in
        // the key path rather than being silently lost.
        assert_eq!(
            strip_hive_from_path(r"HKU\S-1-5-21\Software"),
            r"HKU\S-1-5-21\Software"
        );
    }

    #[test]
    fn map_hive_type_reads_recmd_labels() {
        assert_eq!(map_hive_type("NTUSER"), Some("HKCU"));
        assert_eq!(map_hive_type(" system "), Some(r"HKLM\SYSTEM"));
        assert_eq!(map_hive_type("UsrClass"), Some(r"HKCU\Software\Classes"));
        assert_eq!(map_hive_type("Amcache"), Some("Amcache"));
        assert_eq!(map_hive_type("NOT_A_HIVE"), None);
    }

    #[test]
    fn target_variant_maps_every_canonical_hive_a_source_can_produce() {
        assert_eq!(target_variant(r"HKLM\SYSTEM"), "HklmSystem");
        assert_eq!(target_variant(r"HKLM\SOFTWARE"), "HklmSoftware");
        assert_eq!(target_variant(r"HKLM\SAM"), "HklmSam");
        assert_eq!(target_variant(r"HKLM\SECURITY"), "HklmSecurity");
        assert_eq!(target_variant(r"HKCU\Software\Classes"), "UsrClass");
        assert_eq!(target_variant("HKCU"), "NtUser");
        assert_eq!(target_variant("NTUSER.DAT"), "NtUser");
        assert_eq!(target_variant("Amcache"), "Amcache");
        assert_eq!(target_variant("BCD"), "Bcd");
    }

    #[test]
    fn every_path_prefix_and_label_resolves_to_a_known_canonical_hive() {
        // The three tables must agree on the canonical vocabulary, or a hive
        // detected by one layer would be unreadable by the next.
        let known = [
            HKLM_SYSTEM,
            HKLM_SOFTWARE,
            HKLM_SAM,
            HKLM_SECURITY,
            HKLM,
            HKCU,
            USR_CLASS,
            AMCACHE,
            BCD,
        ];
        for (prefix, canonical) in PATH_PREFIXES {
            assert!(
                known.contains(canonical),
                "{prefix} yields unknown hive {canonical}"
            );
        }
        for (label, canonical) in HIVE_TYPE_LABELS {
            assert!(
                known.contains(canonical),
                "{label} yields unknown hive {canonical}"
            );
        }
    }

    #[test]
    fn a_bare_hklm_hive_has_no_target_variant() {
        // Pins the documented gap so a future HiveTarget::Hklm is a deliberate,
        // visible change rather than a surprise.
        assert_eq!(target_variant("HKLM"), "None");
    }

    #[test]
    fn non_registry_hives_yield_none() {
        assert_eq!(target_variant(""), "None");
        assert_eq!(target_variant("SOFTWARE"), "None");
    }
}
