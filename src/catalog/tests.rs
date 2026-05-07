//! Tests for the forensic artifact catalog.
//!
//! These tests were originally in `src/artifact.rs` and are preserved verbatim
//! after the module was split into `src/catalog/`.

// Bring all catalog public and pub(crate) items into scope so that sub-modules
// using `use super::*` see them without qualification.
#[allow(unused_imports)]
use crate::catalog::*;

#[cfg(test)]
mod catalog_integrity {
    use super::*;

    #[test]
    fn no_duplicate_ids() {
        let mut seen = std::collections::HashSet::new();
        for d in CATALOG.list() {
            assert!(seen.insert(d.id), "duplicate artifact id: {}", d.id);
        }
    }

    #[test]
    fn all_related_artifacts_exist() {
        let ids: std::collections::HashSet<&str> = CATALOG.list().iter().map(|d| d.id).collect();
        for d in CATALOG.list() {
            for related in d.related_artifacts {
                assert!(
                    ids.contains(related),
                    "artifact '{}' references unknown related artifact '{}'",
                    d.id,
                    related
                );
            }
        }
    }

    #[test]
    fn all_mitre_ids_match_pattern() {
        // Valid: T1234 or T1234.001
        let valid = |s: &str| -> bool {
            let bytes = s.as_bytes();
            if bytes.len() < 5 {
                return false;
            }
            if bytes[0] != b'T' {
                return false;
            }
            let digits: &[u8] = if bytes.len() == 5 {
                &bytes[1..5]
            } else if bytes.len() == 9 && bytes[5] == b'.' {
                // check sub-technique: T1234.001
                let sub = &bytes[6..9];
                if !sub.iter().all(|b| b.is_ascii_digit()) {
                    return false;
                }
                &bytes[1..5]
            } else {
                return false;
            };
            digits.iter().all(|b| b.is_ascii_digit())
        };
        for d in CATALOG.list() {
            for technique in d.mitre_techniques {
                assert!(
                    valid(technique),
                    "artifact '{}' has invalid MITRE technique id '{}'",
                    d.id,
                    technique
                );
            }
        }
    }

    #[test]
    fn all_entries_have_sources() {
        for d in CATALOG.list() {
            assert!(!d.sources.is_empty(), "artifact '{}' has no sources", d.id);
        }
    }

    #[test]
    fn no_empty_meanings() {
        for d in CATALOG.list() {
            assert!(
                !d.meaning.is_empty(),
                "artifact '{}' has empty meaning",
                d.id
            );
        }
    }

    #[test]
    fn all_sources_are_https_urls() {
        for d in CATALOG.list() {
            for src in d.sources {
                assert!(
                    src.starts_with("https://") || src.starts_with("http://"),
                    "artifact '{}' has non-URL source: {}",
                    d.id,
                    src
                );
            }
        }
    }

    #[test]
    fn no_mitre_urls_in_sources() {
        // mitre_techniques[] already expresses the ATT&CK relationship.
        // sources[] is for documents that informed the artifact model.
        // See CLAUDE.md accuracy standard #7.
        let mut violations: Vec<(&str, &str)> = Vec::new();
        for d in CATALOG.list() {
            for src in d.sources {
                if src.contains("attack.mitre.org") {
                    violations.push((d.id, src));
                }
            }
        }
        assert!(
            violations.is_empty(),
            "sources[] must not contain MITRE URLs ({} violation{}):\n{}",
            violations.len(),
            if violations.len() == 1 { "" } else { "s" },
            violations
                .iter()
                .map(|(id, url)| format!("  {id}: {url}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    /// The pberba "systemd-timers-cron" post documents cron and systemd timer
    /// persistence.  It must NOT appear in sources[] of artifacts that are
    /// unrelated to those mechanisms (PAM, sudoers, udev, MOTD, kernel module
    /// boot config).  Those artifacts were incorrectly assigned that citation
    /// by bulk sibling-borrowing.
    #[test]
    fn cron_post_only_on_cron_and_systemd_artifacts() {
        const CRON_POST: &str =
            "pberba.github.io/security/2022/01/30/linux-threat-hunting-for-persistence-systemd-timers-cron";
        // Artifact IDs where the cron post is a legitimate citation.
        // linux_at_queue uses `at` (T1053.001) — same scheduled-task family as
        // cron (T1053.003) and systemd timers (T1053.006); pberba covers all three.
        const ALLOWED: &[&str] = &[
            "linux_crontab_system",
            "linux_cron_d",
            "linux_cron_periodic",
            "linux_user_crontab",
            "linux_anacrontab",
            "linux_systemd_system_unit",
            "linux_systemd_user_unit",
            "linux_systemd_timer",
            "linux_at_queue",
        ];
        let mut violations: Vec<(&str, &str)> = Vec::new();
        for d in CATALOG.list() {
            for src in d.sources {
                if src.contains(CRON_POST) && !ALLOWED.contains(&d.id) {
                    violations.push((d.id, src));
                }
            }
        }
        assert!(
            violations.is_empty(),
            "pberba cron/systemd post cited in non-cron artifact ({} violation{}):\n{}",
            violations.len(),
            if violations.len() == 1 { "" } else { "s" },
            violations
                .iter()
                .map(|(id, url)| format!("  {id}: {url}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    /// The SANS "/blog/linux-forensics-artifacts/" URL returns HTTP 404.
    /// It must not appear in any sources[] array.
    #[test]
    fn no_sans_linux_forensics_artifacts_404_url() {
        const BROKEN: &str = "sans.org/blog/linux-forensics-artifacts/";
        let mut violations: Vec<(&str, &str)> = Vec::new();
        for d in CATALOG.list() {
            for src in d.sources {
                if src.contains(BROKEN) {
                    violations.push((d.id, src));
                }
            }
        }
        assert!(
            violations.is_empty(),
            "broken SANS URL (HTTP 404) in sources[] ({} violation{}):\n{}",
            violations.len(),
            if violations.len() == 1 { "" } else { "s" },
            violations
                .iter()
                .map(|(id, url)| format!("  {id}: {url}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
}

#[cfg(test)]
mod decode_tests {
    use super::*;

    // ── FILETIME conversion ──────────────────────────────────────────────

    #[test]
    fn filetime_zero_returns_none() {
        assert_eq!(filetime_to_iso8601(0), None);
    }

    #[test]
    fn filetime_before_unix_epoch_returns_none() {
        // 1600-01-01 is before the Unix epoch offset.
        assert_eq!(filetime_to_iso8601(1), None);
    }

    #[test]
    fn filetime_unix_epoch_is_1970() {
        // Exactly the Unix epoch: 1970-01-01T00:00:00Z
        let ft: u64 = 116_444_736_000_000_000;
        assert_eq!(
            filetime_to_iso8601(ft),
            Some("1970-01-01T00:00:00Z".to_string())
        );
    }

    #[test]
    fn filetime_known_date_2023() {
        // 2023-01-15T10:30:00Z
        // Unix timestamp: 1673778600
        // FILETIME = 1673778600 * 10_000_000 + 116_444_736_000_000_000
        let unix_ts: u64 = 1_673_778_600;
        let ft = unix_ts * 10_000_000 + 116_444_736_000_000_000;
        assert_eq!(
            filetime_to_iso8601(ft),
            Some("2023-01-15T10:30:00Z".to_string())
        );
    }

    // ── ROT13 ────────────────────────────────────────────────────────────

    #[test]
    fn rot13_roundtrip() {
        let s = "Hello, World!";
        assert_eq!(rot13(&rot13(s)), s);
    }

    #[test]
    fn rot13_known_value() {
        assert_eq!(rot13("URYYB"), "HELLO");
    }

    #[test]
    fn rot13_numbers_unchanged() {
        assert_eq!(rot13("12345"), "12345");
    }

    // ── Catalog queries ──────────────────────────────────────────────────

    #[test]
    fn catalog_has_entries() {
        assert!(!CATALOG.list().is_empty());
        assert_eq!(CATALOG.list().len(), 6624);
    }

    #[test]
    fn catalog_by_id_userassist() {
        let desc = CATALOG.by_id("userassist_exe").unwrap();
        assert_eq!(desc.name, "UserAssist (EXE)");
        assert_eq!(desc.hive, Some(HiveTarget::NtUser));
        assert_eq!(desc.scope, DataScope::User);
    }

    #[test]
    fn catalog_by_id_missing_returns_none() {
        assert!(CATALOG.by_id("nonexistent").is_none());
    }

    #[test]
    fn catalog_filter_by_hive_ntuser() {
        let q = ArtifactQuery {
            hive: Some(HiveTarget::NtUser),
            ..Default::default()
        };
        let results = CATALOG.filter(&q);
        assert!(results.len() >= 2); // userassist + typed_urls
        assert!(results.iter().all(|d| d.hive == Some(HiveTarget::NtUser)));
    }

    #[test]
    fn catalog_filter_by_scope_system() {
        let q = ArtifactQuery {
            scope: Some(DataScope::System),
            ..Default::default()
        };
        let results = CATALOG.filter(&q);
        assert!(results.iter().all(|d| d.scope == DataScope::System));
    }

    #[test]
    fn catalog_filter_by_mitre_technique() {
        let q = ArtifactQuery {
            mitre_technique: Some("T1547.001"),
            ..Default::default()
        };
        let results = CATALOG.filter(&q);
        assert!(!results.is_empty());
        assert!(results
            .iter()
            .all(|d| d.mitre_techniques.contains(&"T1547.001")));
    }

    #[test]
    fn catalog_filter_by_artifact_type_file() {
        let q = ArtifactQuery {
            artifact_type: Some(ArtifactType::File),
            ..Default::default()
        };
        let results = CATALOG.filter(&q);
        // Multiple File artifacts now exist (PCA, SRUM, Timeline, PowerShell history,
        // NTDS.dit, Chrome Login Data, Firefox logins, Windows Search DB).
        assert!(!results.is_empty());
        // PCA must still be present.
        assert!(results.iter().any(|d| d.id == "pca_applaunch_dic"));
    }

    #[test]
    fn catalog_filter_empty_query_returns_all() {
        let q = ArtifactQuery::default();
        assert_eq!(CATALOG.filter(&q).len(), CATALOG.list().len());
    }

    #[test]
    fn catalog_filter_by_id() {
        let q = ArtifactQuery {
            id: Some("typed_urls"),
            ..Default::default()
        };
        let results = CATALOG.filter(&q);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "typed_urls");
    }

    #[test]
    fn catalog_filter_combined_scope_and_hive() {
        let q = ArtifactQuery {
            scope: Some(DataScope::User),
            hive: Some(HiveTarget::NtUser),
            ..Default::default()
        };
        let results = CATALOG.filter(&q);
        assert!(results.len() >= 2);
    }

    // ── Decoder: Identity ────────────────────────────────────────────────

    #[test]
    fn decode_identity_utf8() {
        let rec = CATALOG
            .decode(&RUN_KEY_HKLM_RUN, "MyApp", b"C:\\Program Files\\app.exe")
            .unwrap();
        assert_eq!(rec.artifact_id, "run_key_hklm");
        assert_eq!(
            rec.fields,
            vec![(
                "value",
                ArtifactValue::Text("C:\\Program Files\\app.exe".to_string())
            )]
        );
    }

    #[test]
    fn decode_identity_empty_raw() {
        let rec = CATALOG.decode(&RUN_KEY_HKLM_RUN, "", b"").unwrap();
        assert_eq!(
            rec.fields,
            vec![("value", ArtifactValue::Text(String::new()))]
        );
    }

    #[test]
    fn decode_identity_invalid_utf8() {
        let err = CATALOG
            .decode(&RUN_KEY_HKLM_RUN, "", &[0xFF, 0xFE, 0x80])
            .unwrap_err();
        assert_eq!(err, DecodeError::InvalidUtf8);
    }

    // ── Decoder: Rot13NameWithBinaryValue (UserAssist) ───────────────────

    #[test]
    fn decode_userassist_valid() {
        // Build a 72-byte UserAssist binary value:
        // bytes 4-7: run_count = 5
        // bytes 8-11: focus_count = 3
        // bytes 12-15: focus_duration_ms = 10000
        // bytes 60-67: FILETIME for 2023-01-15T10:30:00Z
        let mut raw = vec![0u8; 72];
        raw[4..8].copy_from_slice(&5u32.to_le_bytes());
        raw[8..12].copy_from_slice(&3u32.to_le_bytes());
        raw[12..16].copy_from_slice(&10000u32.to_le_bytes());
        let ft: u64 = 1_673_778_600 * 10_000_000 + 116_444_736_000_000_000;
        raw[60..68].copy_from_slice(&ft.to_le_bytes());

        let rot13_name = rot13("C:\\Program Files\\notepad.exe");
        let rec = CATALOG.decode(&USERASSIST_EXE, &rot13_name, &raw).unwrap();

        assert_eq!(rec.artifact_id, "userassist_exe");
        assert_eq!(rec.scope, DataScope::User);
        assert_eq!(
            rec.fields[0],
            (
                "program",
                ArtifactValue::Text("C:\\Program Files\\notepad.exe".to_string())
            )
        );
        assert_eq!(rec.fields[1], ("run_count", ArtifactValue::UnsignedInt(5)));
        assert_eq!(
            rec.fields[2],
            ("focus_count", ArtifactValue::UnsignedInt(3))
        );
        assert_eq!(
            rec.fields[3],
            ("focus_duration_ms", ArtifactValue::UnsignedInt(10000))
        );
        assert_eq!(
            rec.fields[4],
            (
                "last_run",
                ArtifactValue::Timestamp("2023-01-15T10:30:00Z".to_string())
            )
        );
        assert_eq!(rec.timestamp, Some("2023-01-15T10:30:00Z".to_string()));
    }

    #[test]
    fn decode_userassist_buffer_too_short() {
        let raw = vec![0u8; 16]; // need at least 68 for last_run field
        let err = CATALOG.decode(&USERASSIST_EXE, "test", &raw).unwrap_err();
        match err {
            DecodeError::FieldOutOfBounds { field, .. } => {
                assert_eq!(field, "last_run");
            }
            other => panic!("expected FieldOutOfBounds, got: {other:?}"),
        }
    }

    #[test]
    fn decode_userassist_zero_filetime() {
        // All zeros: FILETIME at offset 60 is zero -> Null
        let raw = vec![0u8; 72];
        let rec = CATALOG.decode(&USERASSIST_EXE, "grfg", &raw).unwrap();
        assert_eq!(rec.fields[4], ("last_run", ArtifactValue::Null));
        assert_eq!(rec.timestamp, None);
    }

    // ── Decoder: PipeDelimited ───────────────────────────────────────────

    #[test]
    fn decode_pipe_delimited_from_name() {
        let rec = CATALOG
            .decode(
                &PCA_APPLAUNCH_DIC,
                r"C:\Windows\notepad.exe|2023-01-15 10:30:00",
                b"",
            )
            .unwrap();
        assert_eq!(rec.artifact_id, "pca_applaunch_dic");
        assert_eq!(
            rec.fields[0],
            (
                "exe_path",
                ArtifactValue::Text(r"C:\Windows\notepad.exe".to_string())
            )
        );
        assert_eq!(
            rec.fields[1],
            (
                "timestamp",
                ArtifactValue::Text("2023-01-15 10:30:00".to_string())
            )
        );
    }

    #[test]
    fn decode_pipe_delimited_fewer_fields_than_schema() {
        // Only one field in the pipe string, but schema expects two.
        let rec = CATALOG
            .decode(&PCA_APPLAUNCH_DIC, r"C:\app.exe", b"")
            .unwrap();
        assert_eq!(
            rec.fields[0],
            ("exe_path", ArtifactValue::Text(r"C:\app.exe".to_string()))
        );
        // Second field should be Null (missing).
        assert_eq!(rec.fields[1], ("timestamp", ArtifactValue::Null));
    }

    #[test]
    fn decode_pipe_delimited_from_raw_when_name_empty() {
        let raw = b"C:\\tool.exe|2024-06-01";
        let rec = CATALOG.decode(&PCA_APPLAUNCH_DIC, "", raw).unwrap();
        assert_eq!(
            rec.fields[0],
            ("exe_path", ArtifactValue::Text("C:\\tool.exe".to_string()))
        );
    }

    // ── Decoder: DwordLe ─────────────────────────────────────────────────

    #[test]
    fn decode_dword_le() {
        // Build a minimal descriptor with DwordLe decoder.
        static DWORD_DESC: ArtifactDescriptor = ArtifactDescriptor {
            id: "test_dword",
            name: "Test DWORD",
            artifact_type: ArtifactType::RegistryValue,
            hive: Some(HiveTarget::HklmSoftware),
            key_path: "Test",
            value_name: None,
            file_path: None,
            scope: DataScope::System,
            os_scope: OsScope::All,
            decoder: Decoder::DwordLe,
            meaning: "test",
            mitre_techniques: &[],
            fields: &[],
            retention: None,
            triage_priority: TriagePriority::Low,
            related_artifacts: &[],
            sources: &[],
        };
        let raw = 42u32.to_le_bytes();
        let rec = CATALOG.decode(&DWORD_DESC, "val", &raw).unwrap();
        assert_eq!(rec.fields, vec![("value", ArtifactValue::UnsignedInt(42))]);
    }

    #[test]
    fn decode_dword_le_too_short() {
        static DWORD_DESC: ArtifactDescriptor = ArtifactDescriptor {
            id: "test_dword2",
            name: "Test DWORD 2",
            artifact_type: ArtifactType::RegistryValue,
            hive: Some(HiveTarget::HklmSoftware),
            key_path: "Test",
            value_name: None,
            file_path: None,
            scope: DataScope::System,
            os_scope: OsScope::All,
            decoder: Decoder::DwordLe,
            meaning: "test",
            mitre_techniques: &[],
            fields: &[],
            retention: None,
            triage_priority: TriagePriority::Low,
            related_artifacts: &[],
            sources: &[],
        };
        let err = CATALOG.decode(&DWORD_DESC, "v", &[1, 2]).unwrap_err();
        assert_eq!(
            err,
            DecodeError::BufferTooShort {
                expected: 4,
                actual: 2
            }
        );
    }

    // ── Decoder: Utf16Le ─────────────────────────────────────────────────

    #[test]
    fn decode_utf16le() {
        static UTF16_DESC: ArtifactDescriptor = ArtifactDescriptor {
            id: "test_utf16",
            name: "Test UTF-16",
            artifact_type: ArtifactType::RegistryValue,
            hive: Some(HiveTarget::NtUser),
            key_path: "Test",
            value_name: None,
            file_path: None,
            scope: DataScope::User,
            os_scope: OsScope::All,
            decoder: Decoder::Utf16Le,
            meaning: "test",
            mitre_techniques: &[],
            fields: &[],
            retention: None,
            triage_priority: TriagePriority::Low,
            related_artifacts: &[],
            sources: &[],
        };
        // "Hi" in UTF-16LE + NUL terminator
        let raw: &[u8] = &[0x48, 0x00, 0x69, 0x00, 0x00, 0x00];
        let rec = CATALOG.decode(&UTF16_DESC, "", raw).unwrap();
        assert_eq!(
            rec.fields,
            vec![("value", ArtifactValue::Text("Hi".to_string()))]
        );
    }

    #[test]
    fn decode_utf16le_odd_length() {
        static UTF16_DESC: ArtifactDescriptor = ArtifactDescriptor {
            id: "test_utf16_odd",
            name: "Test UTF-16 odd",
            artifact_type: ArtifactType::RegistryValue,
            hive: Some(HiveTarget::NtUser),
            key_path: "Test",
            value_name: None,
            file_path: None,
            scope: DataScope::User,
            os_scope: OsScope::All,
            decoder: Decoder::Utf16Le,
            meaning: "test",
            mitre_techniques: &[],
            fields: &[],
            retention: None,
            triage_priority: TriagePriority::Low,
            related_artifacts: &[],
            sources: &[],
        };
        let err = CATALOG
            .decode(&UTF16_DESC, "", &[0x48, 0x00, 0x69])
            .unwrap_err();
        assert_eq!(err, DecodeError::InvalidUtf16);
    }

    // ── Decoder: MultiSz ─────────────────────────────────────────────────

    #[test]
    fn decode_multi_sz() {
        static MSZ_DESC: ArtifactDescriptor = ArtifactDescriptor {
            id: "test_msz",
            name: "Test MultiSz",
            artifact_type: ArtifactType::RegistryValue,
            hive: Some(HiveTarget::HklmSoftware),
            key_path: "Test",
            value_name: None,
            file_path: None,
            scope: DataScope::System,
            os_scope: OsScope::All,
            decoder: Decoder::MultiSz,
            meaning: "test",
            mitre_techniques: &[],
            fields: &[],
            retention: None,
            triage_priority: TriagePriority::Low,
            related_artifacts: &[],
            sources: &[],
        };
        // "AB\0CD\0\0" in UTF-16LE
        let raw: &[u8] = &[
            0x41, 0x00, 0x42, 0x00, // "AB"
            0x00, 0x00, // NUL separator
            0x43, 0x00, 0x44, 0x00, // "CD"
            0x00, 0x00, // NUL terminator
            0x00, 0x00, // double NUL
        ];
        let rec = CATALOG.decode(&MSZ_DESC, "", raw).unwrap();
        assert_eq!(
            rec.fields,
            vec![(
                "values",
                ArtifactValue::List(vec![
                    ArtifactValue::Text("AB".to_string()),
                    ArtifactValue::Text("CD".to_string()),
                ])
            )]
        );
    }

    #[test]
    fn decode_multi_sz_empty() {
        static MSZ_DESC: ArtifactDescriptor = ArtifactDescriptor {
            id: "test_msz_empty",
            name: "Test MultiSz empty",
            artifact_type: ArtifactType::RegistryValue,
            hive: Some(HiveTarget::HklmSoftware),
            key_path: "Test",
            value_name: None,
            file_path: None,
            scope: DataScope::System,
            os_scope: OsScope::All,
            decoder: Decoder::MultiSz,
            meaning: "test",
            mitre_techniques: &[],
            fields: &[],
            retention: None,
            triage_priority: TriagePriority::Low,
            related_artifacts: &[],
            sources: &[],
        };
        let rec = CATALOG.decode(&MSZ_DESC, "", &[]).unwrap();
        assert_eq!(rec.fields, vec![("values", ArtifactValue::List(vec![]))]);
    }

    // ── Decoder: MruListEx ───────────────────────────────────────────────

    #[test]
    fn decode_mrulistex() {
        static MRU_DESC: ArtifactDescriptor = ArtifactDescriptor {
            id: "test_mru",
            name: "Test MRUListEx",
            artifact_type: ArtifactType::RegistryValue,
            hive: Some(HiveTarget::NtUser),
            key_path: "Test",
            value_name: None,
            file_path: None,
            scope: DataScope::User,
            os_scope: OsScope::All,
            decoder: Decoder::MruListEx,
            meaning: "test",
            mitre_techniques: &[],
            fields: &[],
            retention: None,
            triage_priority: TriagePriority::Low,
            related_artifacts: &[],
            sources: &[],
        };
        // [2, 0, 1, 0xFFFFFFFF]
        let mut raw = Vec::new();
        raw.extend_from_slice(&2u32.to_le_bytes());
        raw.extend_from_slice(&0u32.to_le_bytes());
        raw.extend_from_slice(&1u32.to_le_bytes());
        raw.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        let rec = CATALOG.decode(&MRU_DESC, "", &raw).unwrap();
        assert_eq!(
            rec.fields,
            vec![(
                "indices",
                ArtifactValue::List(vec![
                    ArtifactValue::UnsignedInt(2),
                    ArtifactValue::UnsignedInt(0),
                    ArtifactValue::UnsignedInt(1),
                ])
            )]
        );
    }

    #[test]
    fn decode_mrulistex_empty() {
        static MRU_DESC: ArtifactDescriptor = ArtifactDescriptor {
            id: "test_mru_empty",
            name: "Test MRUListEx empty",
            artifact_type: ArtifactType::RegistryValue,
            hive: Some(HiveTarget::NtUser),
            key_path: "Test",
            value_name: None,
            file_path: None,
            scope: DataScope::User,
            os_scope: OsScope::All,
            decoder: Decoder::MruListEx,
            meaning: "test",
            mitre_techniques: &[],
            fields: &[],
            retention: None,
            triage_priority: TriagePriority::Low,
            related_artifacts: &[],
            sources: &[],
        };
        let rec = CATALOG.decode(&MRU_DESC, "", &[]).unwrap();
        assert_eq!(rec.fields, vec![("indices", ArtifactValue::List(vec![]))]);
    }

    // ── Decoder: FiletimeAt ──────────────────────────────────────────────

    #[test]
    fn decode_filetime_at() {
        static FT_DESC: ArtifactDescriptor = ArtifactDescriptor {
            id: "test_ft",
            name: "Test FiletimeAt",
            artifact_type: ArtifactType::RegistryValue,
            hive: Some(HiveTarget::NtUser),
            key_path: "Test",
            value_name: None,
            file_path: None,
            scope: DataScope::User,
            os_scope: OsScope::All,
            decoder: Decoder::FiletimeAt { offset: 0 },
            meaning: "test",
            mitre_techniques: &[],
            fields: &[],
            retention: None,
            triage_priority: TriagePriority::Low,
            related_artifacts: &[],
            sources: &[],
        };
        let ft: u64 = 116_444_736_000_000_000; // Unix epoch
        let raw = ft.to_le_bytes();
        let rec = CATALOG.decode(&FT_DESC, "", &raw).unwrap();
        assert_eq!(
            rec.fields,
            vec![(
                "timestamp",
                ArtifactValue::Timestamp("1970-01-01T00:00:00Z".to_string())
            )]
        );
        assert_eq!(rec.timestamp, Some("1970-01-01T00:00:00Z".to_string()));
    }

    #[test]
    fn decode_filetime_at_buffer_too_short() {
        static FT_DESC: ArtifactDescriptor = ArtifactDescriptor {
            id: "test_ft_short",
            name: "Test FiletimeAt short",
            artifact_type: ArtifactType::RegistryValue,
            hive: Some(HiveTarget::NtUser),
            key_path: "Test",
            value_name: None,
            file_path: None,
            scope: DataScope::User,
            os_scope: OsScope::All,
            decoder: Decoder::FiletimeAt { offset: 4 },
            meaning: "test",
            mitre_techniques: &[],
            fields: &[],
            retention: None,
            triage_priority: TriagePriority::Low,
            related_artifacts: &[],
            sources: &[],
        };
        let err = CATALOG.decode(&FT_DESC, "", &[0; 8]).unwrap_err();
        assert_eq!(
            err,
            DecodeError::BufferTooShort {
                expected: 12,
                actual: 8
            }
        );
    }

    // ── UID generation ───────────────────────────────────────────────────

    #[test]
    fn uid_registry_with_name() {
        let rec = CATALOG
            .decode(&RUN_KEY_HKLM_RUN, "MyApp", b"cmd.exe")
            .unwrap();
        assert!(rec.uid.starts_with("winreg://HKLM\\SOFTWARE/"));
        assert!(rec.uid.contains("MyApp"));
    }

    #[test]
    fn uid_file_artifact() {
        let rec = CATALOG.decode(&PCA_APPLAUNCH_DIC, "line1", b"").unwrap();
        assert!(rec.uid.starts_with("file://"));
        assert!(rec.uid.contains("AppLaunch.dic"));
    }

    // ── DecodeError Display ──────────────────────────────────────────────

    #[test]
    fn decode_error_display_buffer_too_short() {
        let e = DecodeError::BufferTooShort {
            expected: 8,
            actual: 4,
        };
        assert_eq!(e.to_string(), "buffer too short: need 8 bytes, got 4");
    }

    #[test]
    fn decode_error_display_field_out_of_bounds() {
        let e = DecodeError::FieldOutOfBounds {
            field: "last_run",
            offset: 60,
            size: 8,
            buf_len: 16,
        };
        assert!(e.to_string().contains("last_run"));
    }

    // ── ArtifactDescriptor field coverage ────────────────────────────────

    #[test]
    fn userassist_descriptor_has_correct_metadata() {
        assert_eq!(USERASSIST_EXE.id, "userassist_exe");
        assert_eq!(USERASSIST_EXE.hive, Some(HiveTarget::NtUser));
        assert_eq!(USERASSIST_EXE.scope, DataScope::User);
        assert_eq!(USERASSIST_EXE.os_scope, OsScope::Win7Plus);
        assert!(!USERASSIST_EXE.mitre_techniques.is_empty());
        assert!(!USERASSIST_EXE.fields.is_empty());
        assert!(USERASSIST_EXE.key_path.contains("UserAssist"));
    }

    #[test]
    fn pca_descriptor_has_correct_metadata() {
        assert_eq!(PCA_APPLAUNCH_DIC.id, "pca_applaunch_dic");
        assert_eq!(PCA_APPLAUNCH_DIC.artifact_type, ArtifactType::File);
        assert_eq!(PCA_APPLAUNCH_DIC.hive, None);
        assert_eq!(PCA_APPLAUNCH_DIC.os_scope, OsScope::Win11_22H2);
        assert!(PCA_APPLAUNCH_DIC.file_path.is_some());
    }

    #[test]
    fn run_key_descriptor_has_correct_metadata() {
        assert_eq!(RUN_KEY_HKLM_RUN.scope, DataScope::System);
        assert!(RUN_KEY_HKLM_RUN.mitre_techniques.contains(&"T1547.001"));
    }

    // ── ArtifactRecord confidence default ────────────────────────────────

    #[test]
    fn decoded_record_has_default_confidence() {
        let rec = CATALOG.decode(&RUN_KEY_HKLM_RUN, "x", b"y").unwrap();
        assert!((rec.confidence - 1.0).abs() < f32::EPSILON);
    }

    // ── BinaryField edge cases ───────────────────────────────────────────

    #[test]
    fn binary_record_exact_size_boundary() {
        // A record with a single U32Le at offset 0 -- exactly 4 bytes.
        static FIELDS: &[BinaryField] = &[BinaryField {
            name: "val",
            offset: 0,
            field_type: BinaryFieldType::U32Le,
            description: "test",
        }];
        static DESC: ArtifactDescriptor = ArtifactDescriptor {
            id: "test_exact",
            name: "Test exact",
            artifact_type: ArtifactType::RegistryValue,
            hive: Some(HiveTarget::HklmSoftware),
            key_path: "Test",
            value_name: None,
            file_path: None,
            scope: DataScope::System,
            os_scope: OsScope::All,
            decoder: Decoder::BinaryRecord(FIELDS),
            meaning: "test",
            mitre_techniques: &[],
            fields: &[],
            retention: None,
            triage_priority: TriagePriority::Low,
            related_artifacts: &[],
            sources: &[],
        };
        let raw = 99u32.to_le_bytes();
        let rec = CATALOG.decode(&DESC, "", &raw).unwrap();
        assert_eq!(rec.fields, vec![("val", ArtifactValue::UnsignedInt(99))]);
    }

    #[test]
    fn binary_record_bytes_field() {
        static FIELDS: &[BinaryField] = &[BinaryField {
            name: "header",
            offset: 0,
            field_type: BinaryFieldType::Bytes { len: 4 },
            description: "test header",
        }];
        static DESC: ArtifactDescriptor = ArtifactDescriptor {
            id: "test_bytes",
            name: "Test bytes",
            artifact_type: ArtifactType::RegistryValue,
            hive: Some(HiveTarget::HklmSoftware),
            key_path: "Test",
            value_name: None,
            file_path: None,
            scope: DataScope::System,
            os_scope: OsScope::All,
            decoder: Decoder::BinaryRecord(FIELDS),
            meaning: "test",
            mitre_techniques: &[],
            fields: &[],
            retention: None,
            triage_priority: TriagePriority::Low,
            related_artifacts: &[],
            sources: &[],
        };
        let raw = [0xDE, 0xAD, 0xBE, 0xEF];
        let rec = CATALOG.decode(&DESC, "", &raw).unwrap();
        assert_eq!(
            rec.fields,
            vec![("header", ArtifactValue::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]))]
        );
    }
}

// ── Tests for new batch-A/B descriptors ──────────────────────────────────────

#[cfg(test)]
mod tests_new_descriptors {
    use super::*;

    // ── Run key variants ─────────────────────────────────────────────────

    #[test]
    fn run_key_hkcu_run_metadata() {
        assert_eq!(RUN_KEY_HKCU_RUN.id, "run_key_hkcu");
        assert_eq!(RUN_KEY_HKCU_RUN.hive, Some(HiveTarget::NtUser));
        assert_eq!(RUN_KEY_HKCU_RUN.scope, DataScope::User);
        assert!(RUN_KEY_HKCU_RUN.mitre_techniques.contains(&"T1547.001"));
        assert!(RUN_KEY_HKCU_RUN.key_path.contains("Run"));
    }

    #[test]
    fn run_key_hkcu_runonce_metadata() {
        assert_eq!(RUN_KEY_HKCU_RUNONCE.id, "run_key_hkcu_once");
        assert_eq!(RUN_KEY_HKCU_RUNONCE.hive, Some(HiveTarget::NtUser));
        assert_eq!(RUN_KEY_HKCU_RUNONCE.scope, DataScope::User);
        assert!(RUN_KEY_HKCU_RUNONCE.key_path.contains("RunOnce"));
    }

    #[test]
    fn run_key_hklm_runonce_metadata() {
        assert_eq!(RUN_KEY_HKLM_RUNONCE.id, "run_key_hklm_once");
        assert_eq!(RUN_KEY_HKLM_RUNONCE.hive, Some(HiveTarget::HklmSoftware));
        assert_eq!(RUN_KEY_HKLM_RUNONCE.scope, DataScope::System);
        assert!(RUN_KEY_HKLM_RUNONCE.key_path.contains("RunOnce"));
    }

    // ── IFEO ─────────────────────────────────────────────────────────────

    #[test]
    fn ifeo_debugger_metadata() {
        assert_eq!(IFEO_DEBUGGER.id, "ifeo_debugger");
        assert_eq!(IFEO_DEBUGGER.hive, Some(HiveTarget::HklmSoftware));
        assert_eq!(IFEO_DEBUGGER.scope, DataScope::System);
        assert!(IFEO_DEBUGGER.mitre_techniques.contains(&"T1546.012"));
        assert!(IFEO_DEBUGGER
            .key_path
            .contains("Image File Execution Options"));
    }

    // ── UserAssist folder/shortcut GUID ──────────────────────────────────

    #[test]
    fn userassist_folder_metadata() {
        assert_eq!(USERASSIST_FOLDER.id, "userassist_folder");
        assert_eq!(USERASSIST_FOLDER.hive, Some(HiveTarget::NtUser));
        assert_eq!(USERASSIST_FOLDER.scope, DataScope::User);
        assert!(USERASSIST_FOLDER.key_path.contains("UserAssist"));
    }

    /// Per Magnet Forensics artifact profile, {F4E57C4B-...} tracks
    /// shortcut-initiated launches (.lnk), not folder navigation.
    /// Source: https://www.magnetforensics.com/blog/artifact-profile-userassist/
    #[test]
    fn userassist_folder_guid_tracks_shortcut_launches_not_folders() {
        // The Magnet Forensics article clarifies: {F4E57C4B-...} corresponds
        // to "launches initiated via shortcuts, which includes clicks on .lnk files"
        // Our name must not describe it solely as "Folder" navigation.
        assert!(
            USERASSIST_FOLDER.name.contains("Shortcut")
                || USERASSIST_FOLDER.name.contains("LNK")
                || USERASSIST_FOLDER
                    .meaning
                    .to_lowercase()
                    .contains("shortcut"),
            "USERASSIST_FOLDER should describe shortcut-initiated launches, \
             not folder navigation. Got name={:?} meaning={:?}",
            USERASSIST_FOLDER.name,
            USERASSIST_FOLDER.meaning,
        );
    }

    // ── UserAssist XP-era GUIDs (pre-Vista) ──────────────────────────────

    /// {75048700-EF1F-11D0-9888-006097DEACF9} — Applications, files, links,
    /// and other objects accessed on Windows XP/2000.
    /// Source: https://www.magnetforensics.com/blog/artifact-profile-userassist/
    #[test]
    fn userassist_xp_exe_exists_in_catalog() {
        let d = CATALOG.by_id("userassist_xp_exe").expect(
            "userassist_xp_exe must exist — Windows XP application-launch GUID \
             {75048700-EF1F-11D0-9888-006097DEACF9} documented by Magnet Forensics",
        );
        assert!(
            d.key_path.contains("75048700-EF1F-11D0-9888-006097DEACF9"),
            "key_path must include the XP EXE GUID"
        );
        assert_eq!(d.hive, Some(HiveTarget::NtUser));
    }

    /// {5E6AB780-7743-11CF-A12B-00AA004AE837} — IE Favorites and IE toolbar
    /// objects on Windows XP.
    /// Source: https://www.magnetforensics.com/blog/artifact-profile-userassist/
    #[test]
    fn userassist_xp_ie_favorites_exists_in_catalog() {
        let d = CATALOG.by_id("userassist_xp_ie_favorites").expect(
            "userassist_xp_ie_favorites must exist — Windows XP IE Favorites GUID \
             {5E6AB780-7743-11CF-A12B-00AA004AE837} documented by Magnet Forensics",
        );
        assert!(
            d.key_path.contains("5E6AB780-7743-11CF-A12B-00AA004AE837"),
            "key_path must include the XP IE Favorites GUID"
        );
    }

    /// {0D6D4F41-2994-4BA0-8FEF-620E43CD2812} — IE7-specific UserAssist GUID
    /// on Windows XP with IE7 installed.
    /// Source: https://www.magnetforensics.com/blog/artifact-profile-userassist/
    #[test]
    fn userassist_xp_ie7_exists_in_catalog() {
        let d = CATALOG.by_id("userassist_xp_ie7").expect(
            "userassist_xp_ie7 must exist — Windows XP IE7 GUID \
             {0D6D4F41-2994-4BA0-8FEF-620E43CD2812} documented by Magnet Forensics",
        );
        assert!(
            d.key_path.contains("0D6D4F41-2994-4BA0-8FEF-620E43CD2812"),
            "key_path must include the XP IE7 GUID"
        );
    }

    // ── Shellbags ────────────────────────────────────────────────────────

    #[test]
    fn shellbags_user_metadata() {
        assert_eq!(SHELLBAGS_USER.id, "shellbags_user");
        assert_eq!(SHELLBAGS_USER.hive, Some(HiveTarget::UsrClass));
        assert_eq!(SHELLBAGS_USER.scope, DataScope::User);
        assert!(SHELLBAGS_USER.mitre_techniques.contains(&"T1083"));
        assert!(SHELLBAGS_USER.key_path.contains("Shell"));
    }

    // ── Amcache ──────────────────────────────────────────────────────────

    #[test]
    fn amcache_app_file_metadata() {
        assert_eq!(AMCACHE_APP_FILE.id, "amcache_app_file");
        assert_eq!(AMCACHE_APP_FILE.hive, Some(HiveTarget::Amcache));
        assert_eq!(AMCACHE_APP_FILE.scope, DataScope::System);
        assert!(AMCACHE_APP_FILE.mitre_techniques.contains(&"T1218"));
    }

    // ── ShimCache ────────────────────────────────────────────────────────

    #[test]
    fn shimcache_metadata() {
        assert_eq!(SHIMCACHE.id, "shimcache");
        assert_eq!(SHIMCACHE.hive, Some(HiveTarget::HklmSystem));
        assert_eq!(SHIMCACHE.scope, DataScope::System);
        assert!(SHIMCACHE.mitre_techniques.contains(&"T1218"));
        assert!(SHIMCACHE.key_path.contains("AppCompatCache"));
    }

    // ── BAM / DAM ────────────────────────────────────────────────────────

    #[test]
    fn bam_user_metadata() {
        assert_eq!(BAM_USER.id, "bam_user");
        assert_eq!(BAM_USER.hive, Some(HiveTarget::HklmSystem));
        assert_eq!(BAM_USER.scope, DataScope::Mixed);
        assert_eq!(BAM_USER.os_scope, OsScope::Win10Plus);
        assert!(BAM_USER.key_path.contains("bam"));
    }

    #[test]
    fn dam_user_metadata() {
        assert_eq!(DAM_USER.id, "dam_user");
        assert_eq!(DAM_USER.hive, Some(HiveTarget::HklmSystem));
        assert_eq!(DAM_USER.scope, DataScope::Mixed);
        assert_eq!(DAM_USER.os_scope, OsScope::Win10Plus);
        assert!(DAM_USER.key_path.contains("dam"));
    }

    // ── SAM ──────────────────────────────────────────────────────────────

    #[test]
    fn sam_users_metadata() {
        assert_eq!(SAM_USERS.id, "sam_users");
        assert_eq!(SAM_USERS.hive, Some(HiveTarget::HklmSam));
        assert_eq!(SAM_USERS.scope, DataScope::System);
        assert!(SAM_USERS.key_path.contains("Users"));
        assert!(SAM_USERS.mitre_techniques.contains(&"T1003.002"));
    }

    // ── LSA ──────────────────────────────────────────────────────────────

    #[test]
    fn lsa_secrets_metadata() {
        assert_eq!(LSA_SECRETS.id, "lsa_secrets");
        assert_eq!(LSA_SECRETS.hive, Some(HiveTarget::HklmSecurity));
        assert_eq!(LSA_SECRETS.scope, DataScope::System);
        assert!(LSA_SECRETS.key_path.contains("Secrets"));
        assert!(LSA_SECRETS.mitre_techniques.contains(&"T1003.004"));
    }

    #[test]
    fn dcc2_cache_metadata() {
        assert_eq!(DCC2_CACHE.id, "dcc2_cache");
        assert_eq!(DCC2_CACHE.hive, Some(HiveTarget::HklmSecurity));
        assert_eq!(DCC2_CACHE.scope, DataScope::System);
        assert!(DCC2_CACHE.mitre_techniques.contains(&"T1003.005"));
    }

    // ── TypedURLsTime ────────────────────────────────────────────────────

    #[test]
    fn typed_urls_time_metadata() {
        assert_eq!(TYPED_URLS_TIME.id, "typed_urls_time");
        assert_eq!(TYPED_URLS_TIME.hive, Some(HiveTarget::NtUser));
        assert_eq!(TYPED_URLS_TIME.scope, DataScope::User);
        assert!(TYPED_URLS_TIME.key_path.contains("TypedURLsTime"));
    }

    // ── MRU RecentDocs ───────────────────────────────────────────────────

    #[test]
    fn mru_recent_docs_metadata() {
        assert_eq!(MRU_RECENT_DOCS.id, "mru_recent_docs");
        assert_eq!(MRU_RECENT_DOCS.hive, Some(HiveTarget::NtUser));
        assert_eq!(MRU_RECENT_DOCS.scope, DataScope::User);
        assert!(MRU_RECENT_DOCS.key_path.contains("RecentDocs"));
    }

    // ── USB ──────────────────────────────────────────────────────────────

    #[test]
    fn usb_enum_metadata() {
        assert_eq!(USB_ENUM.id, "usb_enum");
        assert_eq!(USB_ENUM.hive, Some(HiveTarget::HklmSystem));
        assert_eq!(USB_ENUM.scope, DataScope::System);
        assert!(USB_ENUM.mitre_techniques.contains(&"T1200"));
        assert!(USB_ENUM.key_path.contains("USBSTOR"));
    }

    // ── MUICache ─────────────────────────────────────────────────────────

    #[test]
    fn muicache_metadata() {
        assert_eq!(MUICACHE.id, "muicache");
        assert_eq!(MUICACHE.hive, Some(HiveTarget::UsrClass));
        assert_eq!(MUICACHE.scope, DataScope::User);
        assert!(MUICACHE.key_path.contains("MuiCache"));
    }

    // ── AppInit DLLs ─────────────────────────────────────────────────────

    #[test]
    fn appinit_dlls_metadata() {
        assert_eq!(APPINIT_DLLS.id, "appinit_dlls");
        assert_eq!(APPINIT_DLLS.hive, Some(HiveTarget::HklmSoftware));
        assert_eq!(APPINIT_DLLS.scope, DataScope::System);
        assert!(APPINIT_DLLS.mitre_techniques.contains(&"T1546.010"));
        assert!(APPINIT_DLLS.key_path.contains("Windows NT"));
    }

    // ── Winlogon ─────────────────────────────────────────────────────────

    #[test]
    fn winlogon_userinit_metadata() {
        assert_eq!(WINLOGON_USERINIT.id, "winlogon_userinit");
        assert_eq!(WINLOGON_USERINIT.hive, Some(HiveTarget::HklmSoftware));
        assert_eq!(WINLOGON_USERINIT.scope, DataScope::System);
        assert!(WINLOGON_USERINIT.mitre_techniques.contains(&"T1547.004"));
        assert!(WINLOGON_USERINIT.key_path.contains("Winlogon"));
    }

    // ── Screensaver ──────────────────────────────────────────────────────

    #[test]
    fn screensaver_exe_metadata() {
        assert_eq!(SCREENSAVER_EXE.id, "screensaver_exe");
        assert_eq!(SCREENSAVER_EXE.hive, Some(HiveTarget::NtUser));
        assert_eq!(SCREENSAVER_EXE.scope, DataScope::User);
        assert!(SCREENSAVER_EXE.mitre_techniques.contains(&"T1546.002"));
        assert!(SCREENSAVER_EXE.key_path.contains("Desktop"));
    }

    // ── CATALOG completeness ──────────────────────────────────────────────

    #[test]
    fn catalog_contains_all_new_descriptors() {
        let ids: Vec<&str> = CATALOG.list().iter().map(|d| d.id).collect();
        for expected in &[
            "run_key_hkcu",
            "run_key_hkcu_once",
            "run_key_hklm_once",
            "ifeo_debugger",
            "userassist_folder",
            "shellbags_user",
            "amcache_app_file",
            "shimcache",
            "bam_user",
            "dam_user",
            "sam_users",
            "lsa_secrets",
            "dcc2_cache",
            "typed_urls_time",
            "mru_recent_docs",
            "usb_enum",
            "muicache",
            "appinit_dlls",
            "winlogon_userinit",
            "screensaver_exe",
        ] {
            assert!(ids.contains(expected), "CATALOG missing: {expected}");
        }
    }
}

// ── Tests for Batch C (Windows persistence / execution / credential) ──────────

#[cfg(test)]
mod tests_batch_c {
    use super::*;

    // ── Windows persistence ───────────────────────────────────────────────

    #[test]
    fn winlogon_shell_md() {
        assert_eq!(WINLOGON_SHELL.id, "winlogon_shell");
        assert_eq!(WINLOGON_SHELL.hive, Some(HiveTarget::HklmSoftware));
        assert_eq!(WINLOGON_SHELL.scope, DataScope::System);
        assert!(WINLOGON_SHELL.mitre_techniques.contains(&"T1547.004"));
        assert!(WINLOGON_SHELL.key_path.contains("Winlogon"));
    }
    #[test]
    fn services_imagepath_md() {
        assert_eq!(SERVICES_IMAGEPATH.id, "services_imagepath");
        assert_eq!(SERVICES_IMAGEPATH.hive, Some(HiveTarget::HklmSystem));
        assert_eq!(SERVICES_IMAGEPATH.scope, DataScope::System);
        assert!(SERVICES_IMAGEPATH.mitre_techniques.contains(&"T1543.003"));
    }
    #[test]
    fn active_setup_hklm_md() {
        assert_eq!(ACTIVE_SETUP_HKLM.id, "active_setup_hklm");
        assert_eq!(ACTIVE_SETUP_HKLM.hive, Some(HiveTarget::HklmSoftware));
        assert_eq!(ACTIVE_SETUP_HKLM.scope, DataScope::System);
        assert!(ACTIVE_SETUP_HKLM.mitre_techniques.contains(&"T1547.014"));
    }
    #[test]
    fn active_setup_hkcu_md() {
        assert_eq!(ACTIVE_SETUP_HKCU.id, "active_setup_hkcu");
        assert_eq!(ACTIVE_SETUP_HKCU.hive, Some(HiveTarget::NtUser));
        assert_eq!(ACTIVE_SETUP_HKCU.scope, DataScope::User);
    }
    #[test]
    fn com_hijack_clsid_hkcu_md() {
        assert_eq!(COM_HIJACK_CLSID_HKCU.id, "com_hijack_clsid_hkcu");
        assert_eq!(COM_HIJACK_CLSID_HKCU.hive, Some(HiveTarget::UsrClass));
        assert_eq!(COM_HIJACK_CLSID_HKCU.scope, DataScope::User);
        assert!(COM_HIJACK_CLSID_HKCU
            .mitre_techniques
            .contains(&"T1546.015"));
    }
    #[test]
    fn appcert_dlls_md() {
        assert_eq!(APPCERT_DLLS.id, "appcert_dlls");
        assert_eq!(APPCERT_DLLS.hive, Some(HiveTarget::HklmSystem));
        assert_eq!(APPCERT_DLLS.scope, DataScope::System);
        assert!(APPCERT_DLLS.mitre_techniques.contains(&"T1546.009"));
    }
    #[test]
    fn boot_execute_md() {
        assert_eq!(BOOT_EXECUTE.id, "boot_execute");
        assert_eq!(BOOT_EXECUTE.hive, Some(HiveTarget::HklmSystem));
        assert_eq!(BOOT_EXECUTE.scope, DataScope::System);
        assert!(BOOT_EXECUTE.mitre_techniques.contains(&"T1547.001"));
        assert!(BOOT_EXECUTE.key_path.contains("Session Manager"));
    }
    #[test]
    fn lsa_security_pkgs_md() {
        assert_eq!(LSA_SECURITY_PKGS.id, "lsa_security_pkgs");
        assert_eq!(LSA_SECURITY_PKGS.hive, Some(HiveTarget::HklmSystem));
        assert_eq!(LSA_SECURITY_PKGS.scope, DataScope::System);
        assert!(LSA_SECURITY_PKGS.mitre_techniques.contains(&"T1547.005"));
    }
    #[test]
    fn lsa_auth_pkgs_md() {
        assert_eq!(LSA_AUTH_PKGS.id, "lsa_auth_pkgs");
        assert_eq!(LSA_AUTH_PKGS.hive, Some(HiveTarget::HklmSystem));
        assert_eq!(LSA_AUTH_PKGS.scope, DataScope::System);
        assert!(LSA_AUTH_PKGS.mitre_techniques.contains(&"T1547.002"));
    }
    #[test]
    fn print_monitors_md() {
        assert_eq!(PRINT_MONITORS.id, "print_monitors");
        assert_eq!(PRINT_MONITORS.hive, Some(HiveTarget::HklmSystem));
        assert_eq!(PRINT_MONITORS.scope, DataScope::System);
        assert!(PRINT_MONITORS.mitre_techniques.contains(&"T1547.010"));
    }
    #[test]
    fn time_providers_md() {
        assert_eq!(TIME_PROVIDERS.id, "time_providers");
        assert_eq!(TIME_PROVIDERS.hive, Some(HiveTarget::HklmSystem));
        assert_eq!(TIME_PROVIDERS.scope, DataScope::System);
        assert!(TIME_PROVIDERS.mitre_techniques.contains(&"T1547.003"));
    }
    #[test]
    fn netsh_helper_dlls_md() {
        assert_eq!(NETSH_HELPER_DLLS.id, "netsh_helper_dlls");
        assert_eq!(NETSH_HELPER_DLLS.hive, Some(HiveTarget::HklmSoftware));
        assert_eq!(NETSH_HELPER_DLLS.scope, DataScope::System);
        assert!(NETSH_HELPER_DLLS.mitre_techniques.contains(&"T1546.007"));
    }
    #[test]
    fn browser_helper_objects_md() {
        assert_eq!(BROWSER_HELPER_OBJECTS.id, "browser_helper_objects");
        assert_eq!(BROWSER_HELPER_OBJECTS.hive, Some(HiveTarget::HklmSoftware));
        assert_eq!(BROWSER_HELPER_OBJECTS.scope, DataScope::System);
        assert!(BROWSER_HELPER_OBJECTS.mitre_techniques.contains(&"T1176"));
    }
    #[test]
    fn startup_folder_user_md() {
        assert_eq!(STARTUP_FOLDER_USER.id, "startup_folder_user");
        assert_eq!(STARTUP_FOLDER_USER.artifact_type, ArtifactType::Directory);
        assert_eq!(STARTUP_FOLDER_USER.scope, DataScope::User);
        assert!(STARTUP_FOLDER_USER.mitre_techniques.contains(&"T1547.001"));
    }
    #[test]
    fn startup_folder_system_md() {
        assert_eq!(STARTUP_FOLDER_SYSTEM.id, "startup_folder_system");
        assert_eq!(STARTUP_FOLDER_SYSTEM.artifact_type, ArtifactType::Directory);
        assert_eq!(STARTUP_FOLDER_SYSTEM.scope, DataScope::System);
        assert!(STARTUP_FOLDER_SYSTEM
            .mitre_techniques
            .contains(&"T1547.001"));
    }
    #[test]
    fn scheduled_tasks_dir_md() {
        assert_eq!(SCHEDULED_TASKS_DIR.id, "scheduled_tasks_dir");
        assert_eq!(SCHEDULED_TASKS_DIR.artifact_type, ArtifactType::Directory);
        assert_eq!(SCHEDULED_TASKS_DIR.scope, DataScope::System);
        assert!(SCHEDULED_TASKS_DIR.mitre_techniques.contains(&"T1053.005"));
    }
    #[test]
    fn wdigest_caching_md() {
        assert_eq!(WDIGEST_CACHING.id, "wdigest_caching");
        assert_eq!(WDIGEST_CACHING.hive, Some(HiveTarget::HklmSystem));
        assert_eq!(WDIGEST_CACHING.scope, DataScope::System);
        assert!(WDIGEST_CACHING.mitre_techniques.contains(&"T1003.001"));
    }

    // ── Windows execution evidence ────────────────────────────────────────

    #[test]
    fn wordwheel_query_md() {
        assert_eq!(WORDWHEEL_QUERY.id, "wordwheel_query");
        assert_eq!(WORDWHEEL_QUERY.hive, Some(HiveTarget::NtUser));
        assert_eq!(WORDWHEEL_QUERY.scope, DataScope::User);
        assert!(WORDWHEEL_QUERY.key_path.contains("WordWheelQuery"));
    }
    #[test]
    fn opensave_mru_md() {
        assert_eq!(OPENSAVE_MRU.id, "opensave_mru");
        assert_eq!(OPENSAVE_MRU.hive, Some(HiveTarget::NtUser));
        assert_eq!(OPENSAVE_MRU.scope, DataScope::User);
        assert!(OPENSAVE_MRU.key_path.contains("OpenSaveMRU"));
    }
    #[test]
    fn lastvisited_mru_md() {
        assert_eq!(LASTVISITED_MRU.id, "lastvisited_mru");
        assert_eq!(LASTVISITED_MRU.hive, Some(HiveTarget::NtUser));
        assert_eq!(LASTVISITED_MRU.scope, DataScope::User);
        assert!(LASTVISITED_MRU.key_path.contains("LastVisitedMRU"));
    }
    #[test]
    fn prefetch_dir_md() {
        assert_eq!(PREFETCH_DIR.id, "prefetch_dir");
        assert_eq!(PREFETCH_DIR.artifact_type, ArtifactType::Directory);
        assert_eq!(PREFETCH_DIR.scope, DataScope::System);
        assert!(PREFETCH_DIR.mitre_techniques.contains(&"T1204.002"));
    }
    #[test]
    fn srum_db_md() {
        assert_eq!(SRUM_DB.id, "srum_db");
        assert_eq!(SRUM_DB.artifact_type, ArtifactType::File);
        assert_eq!(SRUM_DB.scope, DataScope::System);
        assert!(SRUM_DB.os_scope == OsScope::Win8Plus);
    }
    #[test]
    fn windows_timeline_md() {
        assert_eq!(WINDOWS_TIMELINE.id, "windows_timeline");
        assert_eq!(WINDOWS_TIMELINE.artifact_type, ArtifactType::File);
        assert_eq!(WINDOWS_TIMELINE.scope, DataScope::User);
        assert_eq!(WINDOWS_TIMELINE.os_scope, OsScope::Win10Plus);
    }
    #[test]
    fn powershell_history_md() {
        assert_eq!(POWERSHELL_HISTORY.id, "powershell_history");
        assert_eq!(POWERSHELL_HISTORY.artifact_type, ArtifactType::File);
        assert_eq!(POWERSHELL_HISTORY.scope, DataScope::User);
        assert!(POWERSHELL_HISTORY.mitre_techniques.contains(&"T1059.001"));
    }
    #[test]
    fn recycle_bin_md() {
        assert_eq!(RECYCLE_BIN.id, "recycle_bin");
        assert_eq!(RECYCLE_BIN.artifact_type, ArtifactType::Directory);
        assert_eq!(RECYCLE_BIN.scope, DataScope::User);
        assert!(RECYCLE_BIN.mitre_techniques.contains(&"T1070.004"));
    }
    #[test]
    fn thumbcache_md() {
        assert_eq!(THUMBCACHE.id, "thumbcache");
        assert_eq!(THUMBCACHE.artifact_type, ArtifactType::Directory);
        assert_eq!(THUMBCACHE.scope, DataScope::User);
    }
    #[test]
    fn search_db_user_md() {
        assert_eq!(SEARCH_DB_USER.id, "search_db_user");
        assert_eq!(SEARCH_DB_USER.artifact_type, ArtifactType::File);
        assert_eq!(SEARCH_DB_USER.scope, DataScope::System);
    }

    // ── Windows credentials ───────────────────────────────────────────────

    #[test]
    fn dpapi_masterkey_user_md() {
        assert_eq!(DPAPI_MASTERKEY_USER.id, "dpapi_masterkey_user");
        assert_eq!(DPAPI_MASTERKEY_USER.artifact_type, ArtifactType::Directory);
        assert_eq!(DPAPI_MASTERKEY_USER.scope, DataScope::User);
        assert!(DPAPI_MASTERKEY_USER.mitre_techniques.contains(&"T1555.004"));
    }
    #[test]
    fn dpapi_cred_user_md() {
        assert_eq!(DPAPI_CRED_USER.id, "dpapi_cred_user");
        assert_eq!(DPAPI_CRED_USER.artifact_type, ArtifactType::Directory);
        assert_eq!(DPAPI_CRED_USER.scope, DataScope::User);
    }
    #[test]
    fn dpapi_cred_roaming_md() {
        assert_eq!(DPAPI_CRED_ROAMING.id, "dpapi_cred_roaming");
        assert_eq!(DPAPI_CRED_ROAMING.artifact_type, ArtifactType::Directory);
        assert_eq!(DPAPI_CRED_ROAMING.scope, DataScope::User);
    }
    #[test]
    fn windows_vault_user_md() {
        assert_eq!(WINDOWS_VAULT_USER.id, "windows_vault_user");
        assert_eq!(WINDOWS_VAULT_USER.artifact_type, ArtifactType::Directory);
        assert_eq!(WINDOWS_VAULT_USER.scope, DataScope::User);
        assert!(WINDOWS_VAULT_USER.mitre_techniques.contains(&"T1555.004"));
    }
    #[test]
    fn windows_vault_system_md() {
        assert_eq!(WINDOWS_VAULT_SYSTEM.id, "windows_vault_system");
        assert_eq!(WINDOWS_VAULT_SYSTEM.artifact_type, ArtifactType::Directory);
        assert_eq!(WINDOWS_VAULT_SYSTEM.scope, DataScope::System);
    }
    #[test]
    fn rdp_client_servers_md() {
        assert_eq!(RDP_CLIENT_SERVERS.id, "rdp_client_servers");
        assert_eq!(RDP_CLIENT_SERVERS.hive, Some(HiveTarget::NtUser));
        assert_eq!(RDP_CLIENT_SERVERS.scope, DataScope::User);
        assert!(RDP_CLIENT_SERVERS.mitre_techniques.contains(&"T1021.001"));
    }
    #[test]
    fn rdp_client_default_md() {
        assert_eq!(RDP_CLIENT_DEFAULT.id, "rdp_client_default");
        assert_eq!(RDP_CLIENT_DEFAULT.hive, Some(HiveTarget::NtUser));
        assert_eq!(RDP_CLIENT_DEFAULT.scope, DataScope::User);
        assert!(RDP_CLIENT_DEFAULT.mitre_techniques.contains(&"T1021.001"));
    }
    #[test]
    fn ntds_dit_md() {
        assert_eq!(NTDS_DIT.id, "ntds_dit");
        assert_eq!(NTDS_DIT.artifact_type, ArtifactType::File);
        assert_eq!(NTDS_DIT.scope, DataScope::System);
        assert!(NTDS_DIT.mitre_techniques.contains(&"T1003.003"));
    }
    #[test]
    fn chrome_login_data_md() {
        assert_eq!(CHROME_LOGIN_DATA.id, "chrome_login_data");
        assert_eq!(CHROME_LOGIN_DATA.artifact_type, ArtifactType::File);
        assert_eq!(CHROME_LOGIN_DATA.scope, DataScope::User);
        assert!(CHROME_LOGIN_DATA.mitre_techniques.contains(&"T1555.003"));
    }
    #[test]
    fn firefox_logins_md() {
        assert_eq!(FIREFOX_LOGINS.id, "firefox_logins");
        assert_eq!(FIREFOX_LOGINS.artifact_type, ArtifactType::File);
        assert_eq!(FIREFOX_LOGINS.scope, DataScope::User);
        assert!(FIREFOX_LOGINS.mitre_techniques.contains(&"T1555.003"));
    }
    #[test]
    fn wifi_profiles_md() {
        assert_eq!(WIFI_PROFILES.id, "wifi_profiles");
        assert_eq!(WIFI_PROFILES.artifact_type, ArtifactType::Directory);
        assert_eq!(WIFI_PROFILES.scope, DataScope::System);
        assert!(WIFI_PROFILES.mitre_techniques.contains(&"T1552.001"));
    }

    // ── CATALOG completeness (batch C) ────────────────────────────────────

    #[test]
    fn catalog_contains_batch_c() {
        let ids: Vec<&str> = CATALOG.list().iter().map(|d| d.id).collect();
        for expected in &[
            "winlogon_shell",
            "services_imagepath",
            "active_setup_hklm",
            "active_setup_hkcu",
            "com_hijack_clsid_hkcu",
            "appcert_dlls",
            "boot_execute",
            "lsa_security_pkgs",
            "lsa_auth_pkgs",
            "print_monitors",
            "time_providers",
            "netsh_helper_dlls",
            "browser_helper_objects",
            "startup_folder_user",
            "startup_folder_system",
            "scheduled_tasks_dir",
            "wdigest_caching",
            "wordwheel_query",
            "opensave_mru",
            "lastvisited_mru",
            "prefetch_dir",
            "srum_db",
            "windows_timeline",
            "powershell_history",
            "recycle_bin",
            "thumbcache",
            "search_db_user",
            "dpapi_masterkey_user",
            "dpapi_cred_user",
            "dpapi_cred_roaming",
            "windows_vault_user",
            "windows_vault_system",
            "rdp_client_servers",
            "rdp_client_default",
            "ntds_dit",
            "chrome_login_data",
            "firefox_logins",
            "wifi_profiles",
        ] {
            assert!(ids.contains(expected), "CATALOG missing: {expected}");
        }
    }
}

// ── Tests for Batch D (Linux persistence / execution / credential) ────────────

#[cfg(test)]
mod tests_batch_d {
    use super::*;

    // ── Linux persistence: cron ───────────────────────────────────────────

    #[test]
    fn linux_crontab_system_md() {
        assert_eq!(LINUX_CRONTAB_SYSTEM.id, "linux_crontab_system");
        assert_eq!(LINUX_CRONTAB_SYSTEM.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_CRONTAB_SYSTEM.scope, DataScope::System);
        assert_eq!(LINUX_CRONTAB_SYSTEM.os_scope, OsScope::Linux);
        assert!(LINUX_CRONTAB_SYSTEM.mitre_techniques.contains(&"T1053.003"));
    }
    #[test]
    fn linux_cron_d_md() {
        assert_eq!(LINUX_CRON_D.id, "linux_cron_d");
        assert_eq!(LINUX_CRON_D.artifact_type, ArtifactType::Directory);
        assert_eq!(LINUX_CRON_D.scope, DataScope::System);
        assert_eq!(LINUX_CRON_D.os_scope, OsScope::Linux);
    }
    #[test]
    fn linux_cron_periodic_md() {
        assert_eq!(LINUX_CRON_PERIODIC.id, "linux_cron_periodic");
        assert_eq!(LINUX_CRON_PERIODIC.artifact_type, ArtifactType::Directory);
        assert_eq!(LINUX_CRON_PERIODIC.scope, DataScope::System);
    }
    #[test]
    fn linux_user_crontab_md() {
        assert_eq!(LINUX_USER_CRONTAB.id, "linux_user_crontab");
        assert_eq!(LINUX_USER_CRONTAB.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_USER_CRONTAB.scope, DataScope::User);
        assert!(LINUX_USER_CRONTAB.mitre_techniques.contains(&"T1053.003"));
    }
    #[test]
    fn linux_anacrontab_md() {
        assert_eq!(LINUX_ANACRONTAB.id, "linux_anacrontab");
        assert_eq!(LINUX_ANACRONTAB.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_ANACRONTAB.scope, DataScope::System);
    }

    // ── Linux persistence: systemd ────────────────────────────────────────

    #[test]
    fn linux_systemd_system_unit_md() {
        assert_eq!(LINUX_SYSTEMD_SYSTEM_UNIT.id, "linux_systemd_system_unit");
        assert_eq!(
            LINUX_SYSTEMD_SYSTEM_UNIT.artifact_type,
            ArtifactType::Directory
        );
        assert_eq!(LINUX_SYSTEMD_SYSTEM_UNIT.scope, DataScope::System);
        assert_eq!(LINUX_SYSTEMD_SYSTEM_UNIT.os_scope, OsScope::LinuxSystemd);
        assert!(LINUX_SYSTEMD_SYSTEM_UNIT
            .mitre_techniques
            .contains(&"T1543.002"));
    }
    #[test]
    fn linux_systemd_user_unit_md() {
        assert_eq!(LINUX_SYSTEMD_USER_UNIT.id, "linux_systemd_user_unit");
        assert_eq!(
            LINUX_SYSTEMD_USER_UNIT.artifact_type,
            ArtifactType::Directory
        );
        assert_eq!(LINUX_SYSTEMD_USER_UNIT.scope, DataScope::User);
        assert_eq!(LINUX_SYSTEMD_USER_UNIT.os_scope, OsScope::LinuxSystemd);
    }
    #[test]
    fn linux_systemd_timer_md() {
        assert_eq!(LINUX_SYSTEMD_TIMER.id, "linux_systemd_timer");
        assert_eq!(LINUX_SYSTEMD_TIMER.artifact_type, ArtifactType::Directory);
        assert_eq!(LINUX_SYSTEMD_TIMER.os_scope, OsScope::LinuxSystemd);
        assert!(LINUX_SYSTEMD_TIMER.mitre_techniques.contains(&"T1053.006"));
    }

    // ── Linux persistence: init / rc.local ───────────────────────────────

    #[test]
    fn linux_rc_local_md() {
        assert_eq!(LINUX_RC_LOCAL.id, "linux_rc_local");
        assert_eq!(LINUX_RC_LOCAL.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_RC_LOCAL.scope, DataScope::System);
        assert!(LINUX_RC_LOCAL.mitre_techniques.contains(&"T1037.004"));
    }
    #[test]
    fn linux_init_d_md() {
        assert_eq!(LINUX_INIT_D.id, "linux_init_d");
        assert_eq!(LINUX_INIT_D.artifact_type, ArtifactType::Directory);
        assert_eq!(LINUX_INIT_D.scope, DataScope::System);
    }

    // ── Linux persistence: shell startup ─────────────────────────────────

    #[test]
    fn linux_bashrc_user_md() {
        assert_eq!(LINUX_BASHRC_USER.id, "linux_bashrc_user");
        assert_eq!(LINUX_BASHRC_USER.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_BASHRC_USER.scope, DataScope::User);
        assert!(LINUX_BASHRC_USER.mitre_techniques.contains(&"T1546.004"));
    }
    #[test]
    fn linux_bash_profile_user_md() {
        assert_eq!(LINUX_BASH_PROFILE_USER.id, "linux_bash_profile_user");
        assert_eq!(LINUX_BASH_PROFILE_USER.scope, DataScope::User);
        assert!(LINUX_BASH_PROFILE_USER
            .mitre_techniques
            .contains(&"T1546.004"));
    }
    #[test]
    fn linux_profile_user_md() {
        assert_eq!(LINUX_PROFILE_USER.id, "linux_profile_user");
        assert_eq!(LINUX_PROFILE_USER.scope, DataScope::User);
    }
    #[test]
    fn linux_zshrc_user_md() {
        assert_eq!(LINUX_ZSHRC_USER.id, "linux_zshrc_user");
        assert_eq!(LINUX_ZSHRC_USER.scope, DataScope::User);
        assert!(LINUX_ZSHRC_USER.mitre_techniques.contains(&"T1546.004"));
    }
    #[test]
    fn linux_profile_system_md() {
        assert_eq!(LINUX_PROFILE_SYSTEM.id, "linux_profile_system");
        assert_eq!(LINUX_PROFILE_SYSTEM.scope, DataScope::System);
    }
    #[test]
    fn linux_profile_d_md() {
        assert_eq!(LINUX_PROFILE_D.id, "linux_profile_d");
        assert_eq!(LINUX_PROFILE_D.artifact_type, ArtifactType::Directory);
        assert_eq!(LINUX_PROFILE_D.scope, DataScope::System);
    }

    // ── Linux persistence: LD_PRELOAD / linker ────────────────────────────

    #[test]
    fn linux_ld_so_preload_md() {
        assert_eq!(LINUX_LD_SO_PRELOAD.id, "linux_ld_so_preload");
        assert_eq!(LINUX_LD_SO_PRELOAD.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_LD_SO_PRELOAD.scope, DataScope::System);
        assert!(LINUX_LD_SO_PRELOAD.mitre_techniques.contains(&"T1574.006"));
    }
    #[test]
    fn linux_ld_so_conf_d_md() {
        assert_eq!(LINUX_LD_SO_CONF_D.id, "linux_ld_so_conf_d");
        assert_eq!(LINUX_LD_SO_CONF_D.artifact_type, ArtifactType::Directory);
        assert_eq!(LINUX_LD_SO_CONF_D.scope, DataScope::System);
    }

    // ── Linux persistence: SSH ────────────────────────────────────────────

    #[test]
    fn linux_ssh_authorized_keys_md() {
        assert_eq!(LINUX_SSH_AUTHORIZED_KEYS.id, "linux_ssh_authorized_keys");
        assert_eq!(LINUX_SSH_AUTHORIZED_KEYS.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_SSH_AUTHORIZED_KEYS.scope, DataScope::User);
        assert!(LINUX_SSH_AUTHORIZED_KEYS
            .mitre_techniques
            .contains(&"T1098.004"));
    }

    // ── Linux persistence: PAM / sudo / kernel ────────────────────────────

    #[test]
    fn linux_pam_d_md() {
        assert_eq!(LINUX_PAM_D.id, "linux_pam_d");
        assert_eq!(LINUX_PAM_D.artifact_type, ArtifactType::Directory);
        assert_eq!(LINUX_PAM_D.scope, DataScope::System);
        assert!(LINUX_PAM_D.mitre_techniques.contains(&"T1556.003"));
    }
    #[test]
    fn linux_sudoers_d_md() {
        assert_eq!(LINUX_SUDOERS_D.id, "linux_sudoers_d");
        assert_eq!(LINUX_SUDOERS_D.artifact_type, ArtifactType::Directory);
        assert_eq!(LINUX_SUDOERS_D.scope, DataScope::System);
        assert!(LINUX_SUDOERS_D.mitre_techniques.contains(&"T1548.003"));
    }
    #[test]
    fn linux_modules_load_d_md() {
        assert_eq!(LINUX_MODULES_LOAD_D.id, "linux_modules_load_d");
        assert_eq!(LINUX_MODULES_LOAD_D.artifact_type, ArtifactType::Directory);
        assert_eq!(LINUX_MODULES_LOAD_D.scope, DataScope::System);
        assert!(LINUX_MODULES_LOAD_D.mitre_techniques.contains(&"T1547.006"));
    }
    #[test]
    fn linux_motd_d_md() {
        assert_eq!(LINUX_MOTD_D.id, "linux_motd_d");
        assert_eq!(LINUX_MOTD_D.artifact_type, ArtifactType::Directory);
        assert_eq!(LINUX_MOTD_D.scope, DataScope::System);
    }
    #[test]
    fn linux_udev_rules_d_md() {
        assert_eq!(LINUX_UDEV_RULES_D.id, "linux_udev_rules_d");
        assert_eq!(LINUX_UDEV_RULES_D.artifact_type, ArtifactType::Directory);
        assert_eq!(LINUX_UDEV_RULES_D.scope, DataScope::System);
        assert!(LINUX_UDEV_RULES_D.mitre_techniques.contains(&"T1546"));
    }

    // ── Linux execution evidence ──────────────────────────────────────────

    #[test]
    fn linux_bash_history_md() {
        assert_eq!(LINUX_BASH_HISTORY.id, "linux_bash_history");
        assert_eq!(LINUX_BASH_HISTORY.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_BASH_HISTORY.scope, DataScope::User);
        assert!(LINUX_BASH_HISTORY.mitre_techniques.contains(&"T1059.004"));
    }
    #[test]
    fn linux_zsh_history_md() {
        assert_eq!(LINUX_ZSH_HISTORY.id, "linux_zsh_history");
        assert_eq!(LINUX_ZSH_HISTORY.scope, DataScope::User);
    }
    #[test]
    fn linux_wtmp_md() {
        assert_eq!(LINUX_WTMP.id, "linux_wtmp");
        assert_eq!(LINUX_WTMP.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_WTMP.scope, DataScope::System);
        assert!(LINUX_WTMP.mitre_techniques.contains(&"T1078"));
    }
    #[test]
    fn linux_btmp_md() {
        assert_eq!(LINUX_BTMP.id, "linux_btmp");
        assert_eq!(LINUX_BTMP.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_BTMP.scope, DataScope::System);
    }
    #[test]
    fn linux_lastlog_md() {
        assert_eq!(LINUX_LASTLOG.id, "linux_lastlog");
        assert_eq!(LINUX_LASTLOG.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_LASTLOG.scope, DataScope::System);
    }
    #[test]
    fn linux_auth_log_md() {
        assert_eq!(LINUX_AUTH_LOG.id, "linux_auth_log");
        assert_eq!(LINUX_AUTH_LOG.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_AUTH_LOG.scope, DataScope::System);
        assert!(LINUX_AUTH_LOG.mitre_techniques.contains(&"T1078"));
    }
    #[test]
    fn linux_journal_dir_md() {
        assert_eq!(LINUX_JOURNAL_DIR.id, "linux_journal_dir");
        assert_eq!(LINUX_JOURNAL_DIR.artifact_type, ArtifactType::Directory);
        assert_eq!(LINUX_JOURNAL_DIR.os_scope, OsScope::LinuxSystemd);
    }

    // ── Linux credentials ─────────────────────────────────────────────────

    #[test]
    fn linux_passwd_md() {
        assert_eq!(LINUX_PASSWD.id, "linux_passwd");
        assert_eq!(LINUX_PASSWD.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_PASSWD.scope, DataScope::System);
        assert!(LINUX_PASSWD.mitre_techniques.contains(&"T1087.001"));
    }
    #[test]
    fn linux_shadow_md() {
        assert_eq!(LINUX_SHADOW.id, "linux_shadow");
        assert_eq!(LINUX_SHADOW.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_SHADOW.scope, DataScope::System);
        assert!(LINUX_SHADOW.mitre_techniques.contains(&"T1003.008"));
    }
    #[test]
    fn linux_ssh_private_key_md() {
        assert_eq!(LINUX_SSH_PRIVATE_KEY.id, "linux_ssh_private_key");
        assert_eq!(LINUX_SSH_PRIVATE_KEY.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_SSH_PRIVATE_KEY.scope, DataScope::User);
        assert!(LINUX_SSH_PRIVATE_KEY
            .mitre_techniques
            .contains(&"T1552.004"));
    }
    #[test]
    fn linux_ssh_known_hosts_md() {
        assert_eq!(LINUX_SSH_KNOWN_HOSTS.id, "linux_ssh_known_hosts");
        assert_eq!(LINUX_SSH_KNOWN_HOSTS.scope, DataScope::User);
        assert!(LINUX_SSH_KNOWN_HOSTS
            .mitre_techniques
            .contains(&"T1021.004"));
    }
    #[test]
    fn linux_gnupg_private_md() {
        assert_eq!(LINUX_GNUPG_PRIVATE.id, "linux_gnupg_private");
        assert_eq!(LINUX_GNUPG_PRIVATE.artifact_type, ArtifactType::Directory);
        assert_eq!(LINUX_GNUPG_PRIVATE.scope, DataScope::User);
        assert!(LINUX_GNUPG_PRIVATE.mitre_techniques.contains(&"T1552.004"));
    }
    #[test]
    fn linux_aws_credentials_md() {
        assert_eq!(LINUX_AWS_CREDENTIALS.id, "linux_aws_credentials");
        assert_eq!(LINUX_AWS_CREDENTIALS.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_AWS_CREDENTIALS.scope, DataScope::User);
        assert!(LINUX_AWS_CREDENTIALS
            .mitre_techniques
            .contains(&"T1552.001"));
    }
    #[test]
    fn linux_docker_config_md() {
        assert_eq!(LINUX_DOCKER_CONFIG.id, "linux_docker_config");
        assert_eq!(LINUX_DOCKER_CONFIG.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_DOCKER_CONFIG.scope, DataScope::User);
        assert!(LINUX_DOCKER_CONFIG.mitre_techniques.contains(&"T1552.001"));
    }

    // ── CATALOG completeness (batch D) ────────────────────────────────────

    #[test]
    fn catalog_contains_batch_d() {
        let ids: Vec<&str> = CATALOG.list().iter().map(|d| d.id).collect();
        for expected in &[
            "linux_crontab_system",
            "linux_cron_d",
            "linux_cron_periodic",
            "linux_user_crontab",
            "linux_anacrontab",
            "linux_systemd_system_unit",
            "linux_systemd_user_unit",
            "linux_systemd_timer",
            "linux_rc_local",
            "linux_init_d",
            "linux_bashrc_user",
            "linux_bash_profile_user",
            "linux_profile_user",
            "linux_zshrc_user",
            "linux_profile_system",
            "linux_profile_d",
            "linux_ld_so_preload",
            "linux_ld_so_conf_d",
            "linux_ssh_authorized_keys",
            "linux_pam_d",
            "linux_sudoers_d",
            "linux_modules_load_d",
            "linux_motd_d",
            "linux_udev_rules_d",
            "linux_bash_history",
            "linux_zsh_history",
            "linux_wtmp",
            "linux_btmp",
            "linux_lastlog",
            "linux_auth_log",
            "linux_journal_dir",
            "linux_passwd",
            "linux_shadow",
            "linux_ssh_private_key",
            "linux_ssh_known_hosts",
            "linux_gnupg_private",
            "linux_aws_credentials",
            "linux_docker_config",
        ] {
            assert!(ids.contains(expected), "CATALOG missing: {expected}");
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Batch E — Windows execution / persistence / credential (RED)
    // ═══════════════════════════════════════════════════════════════════════

    // ── Windows execution evidence ────────────────────────────────────────

    #[test]
    fn lnk_files_md() {
        assert_eq!(LNK_FILES.id, "lnk_files");
        assert_eq!(LNK_FILES.artifact_type, ArtifactType::Directory);
        assert_eq!(LNK_FILES.scope, DataScope::User);
        assert!(LNK_FILES.mitre_techniques.contains(&"T1547.009"));
    }
    #[test]
    fn jump_list_auto_md() {
        assert_eq!(JUMP_LIST_AUTO.id, "jump_list_auto");
        assert_eq!(JUMP_LIST_AUTO.artifact_type, ArtifactType::Directory);
        assert_eq!(JUMP_LIST_AUTO.scope, DataScope::User);
        assert!(JUMP_LIST_AUTO.mitre_techniques.contains(&"T1547.009"));
    }
    #[test]
    fn jump_list_custom_md() {
        assert_eq!(JUMP_LIST_CUSTOM.id, "jump_list_custom");
        assert_eq!(JUMP_LIST_CUSTOM.artifact_type, ArtifactType::Directory);
        assert_eq!(JUMP_LIST_CUSTOM.scope, DataScope::User);
        assert!(JUMP_LIST_CUSTOM.mitre_techniques.contains(&"T1547.009"));
    }
    #[test]
    fn evtx_dir_md() {
        assert_eq!(EVTX_DIR.id, "evtx_dir");
        assert_eq!(EVTX_DIR.artifact_type, ArtifactType::Directory);
        assert_eq!(EVTX_DIR.scope, DataScope::System);
        assert!(EVTX_DIR.mitre_techniques.contains(&"T1070.001"));
    }
    #[test]
    fn usn_journal_md() {
        assert_eq!(USN_JOURNAL.id, "usn_journal");
        assert_eq!(USN_JOURNAL.artifact_type, ArtifactType::File);
        assert_eq!(USN_JOURNAL.scope, DataScope::System);
        assert_eq!(USN_JOURNAL.os_scope, OsScope::Win7Plus);
    }

    // ── Windows persistence ───────────────────────────────────────────────

    #[test]
    fn wmi_mof_dir_md() {
        assert_eq!(WMI_MOF_DIR.id, "wmi_mof_dir");
        assert_eq!(WMI_MOF_DIR.artifact_type, ArtifactType::Directory);
        assert_eq!(WMI_MOF_DIR.scope, DataScope::System);
        assert!(WMI_MOF_DIR.mitre_techniques.contains(&"T1546.003"));
    }
    #[test]
    fn bits_db_md() {
        assert_eq!(BITS_DB.id, "bits_db");
        assert_eq!(BITS_DB.artifact_type, ArtifactType::Directory);
        assert_eq!(BITS_DB.scope, DataScope::System);
        assert!(BITS_DB.mitre_techniques.contains(&"T1197"));
    }
    #[test]
    fn wmi_subscriptions_md() {
        assert_eq!(WMI_SUBSCRIPTIONS.id, "wmi_subscriptions");
        assert_eq!(WMI_SUBSCRIPTIONS.artifact_type, ArtifactType::RegistryKey);
        assert_eq!(WMI_SUBSCRIPTIONS.scope, DataScope::System);
        assert!(WMI_SUBSCRIPTIONS.mitre_techniques.contains(&"T1546.003"));
    }
    #[test]
    fn logon_scripts_md() {
        assert_eq!(LOGON_SCRIPTS.id, "logon_scripts");
        assert_eq!(LOGON_SCRIPTS.artifact_type, ArtifactType::RegistryValue);
        assert_eq!(LOGON_SCRIPTS.scope, DataScope::User);
        assert!(LOGON_SCRIPTS.mitre_techniques.contains(&"T1037.001"));
    }
    #[test]
    fn winsock_lsp_md() {
        assert_eq!(WINSOCK_LSP.id, "winsock_lsp");
        assert_eq!(WINSOCK_LSP.artifact_type, ArtifactType::RegistryKey);
        assert_eq!(WINSOCK_LSP.scope, DataScope::System);
        assert!(WINSOCK_LSP.mitre_techniques.contains(&"T1547.010"));
    }
    #[test]
    fn appshim_db_md() {
        assert_eq!(APPSHIM_DB.id, "appshim_db");
        assert_eq!(APPSHIM_DB.artifact_type, ArtifactType::Directory);
        assert_eq!(APPSHIM_DB.scope, DataScope::System);
        assert!(APPSHIM_DB.mitre_techniques.contains(&"T1546.011"));
    }
    #[test]
    fn password_filter_dll_md() {
        assert_eq!(PASSWORD_FILTER_DLL.id, "password_filter_dll");
        assert_eq!(
            PASSWORD_FILTER_DLL.artifact_type,
            ArtifactType::RegistryValue
        );
        assert_eq!(PASSWORD_FILTER_DLL.scope, DataScope::System);
        assert!(PASSWORD_FILTER_DLL.mitre_techniques.contains(&"T1556.002"));
    }
    #[test]
    fn office_normal_dotm_md() {
        assert_eq!(OFFICE_NORMAL_DOTM.id, "office_normal_dotm");
        assert_eq!(OFFICE_NORMAL_DOTM.artifact_type, ArtifactType::File);
        assert_eq!(OFFICE_NORMAL_DOTM.scope, DataScope::User);
        assert!(OFFICE_NORMAL_DOTM.mitre_techniques.contains(&"T1137.001"));
    }
    #[test]
    fn powershell_profile_all_md() {
        assert_eq!(POWERSHELL_PROFILE_ALL.id, "powershell_profile_all");
        assert_eq!(POWERSHELL_PROFILE_ALL.artifact_type, ArtifactType::File);
        assert_eq!(POWERSHELL_PROFILE_ALL.scope, DataScope::System);
        assert!(POWERSHELL_PROFILE_ALL
            .mitre_techniques
            .contains(&"T1546.013"));
    }

    // ── Windows credentials ───────────────────────────────────────────────

    #[test]
    fn dpapi_system_masterkey_md() {
        assert_eq!(DPAPI_SYSTEM_MASTERKEY.id, "dpapi_system_masterkey");
        assert_eq!(
            DPAPI_SYSTEM_MASTERKEY.artifact_type,
            ArtifactType::Directory
        );
        assert_eq!(DPAPI_SYSTEM_MASTERKEY.scope, DataScope::System);
        assert!(DPAPI_SYSTEM_MASTERKEY
            .mitre_techniques
            .contains(&"T1555.004"));
    }
    #[test]
    fn dpapi_credhist_md() {
        assert_eq!(DPAPI_CREDHIST.id, "dpapi_credhist");
        assert_eq!(DPAPI_CREDHIST.artifact_type, ArtifactType::File);
        assert_eq!(DPAPI_CREDHIST.scope, DataScope::User);
        assert!(DPAPI_CREDHIST.mitre_techniques.contains(&"T1555.004"));
    }
    #[test]
    fn chrome_cookies_md() {
        assert_eq!(CHROME_COOKIES.id, "chrome_cookies");
        assert_eq!(CHROME_COOKIES.artifact_type, ArtifactType::File);
        assert_eq!(CHROME_COOKIES.scope, DataScope::User);
        assert!(CHROME_COOKIES.mitre_techniques.contains(&"T1539"));
    }
    #[test]
    fn edge_webcache_md() {
        assert_eq!(EDGE_WEBCACHE.id, "edge_webcache");
        assert_eq!(EDGE_WEBCACHE.artifact_type, ArtifactType::Directory);
        assert_eq!(EDGE_WEBCACHE.scope, DataScope::User);
        assert!(EDGE_WEBCACHE.mitre_techniques.contains(&"T1539"));
    }
    #[test]
    fn vpn_ras_phonebook_md() {
        assert_eq!(VPN_RAS_PHONEBOOK.id, "vpn_ras_phonebook");
        assert_eq!(VPN_RAS_PHONEBOOK.artifact_type, ArtifactType::File);
        assert_eq!(VPN_RAS_PHONEBOOK.scope, DataScope::User);
        assert!(VPN_RAS_PHONEBOOK.mitre_techniques.contains(&"T1552.001"));
    }
    #[test]
    fn windows_hello_ngc_md() {
        assert_eq!(WINDOWS_HELLO_NGC.id, "windows_hello_ngc");
        assert_eq!(WINDOWS_HELLO_NGC.artifact_type, ArtifactType::Directory);
        assert_eq!(WINDOWS_HELLO_NGC.scope, DataScope::System);
        assert!(WINDOWS_HELLO_NGC.mitre_techniques.contains(&"T1555"));
    }
    #[test]
    fn user_cert_private_key_md() {
        assert_eq!(USER_CERT_PRIVATE_KEY.id, "user_cert_private_key");
        assert_eq!(USER_CERT_PRIVATE_KEY.artifact_type, ArtifactType::Directory);
        assert_eq!(USER_CERT_PRIVATE_KEY.scope, DataScope::User);
        assert!(USER_CERT_PRIVATE_KEY
            .mitre_techniques
            .contains(&"T1552.004"));
    }
    #[test]
    fn machine_cert_store_md() {
        assert_eq!(MACHINE_CERT_STORE.id, "machine_cert_store");
        assert_eq!(MACHINE_CERT_STORE.artifact_type, ArtifactType::Directory);
        assert_eq!(MACHINE_CERT_STORE.scope, DataScope::System);
        assert!(MACHINE_CERT_STORE.mitre_techniques.contains(&"T1552.004"));
    }

    // ── CATALOG completeness (batch E) ────────────────────────────────────

    #[test]
    fn catalog_contains_batch_e() {
        let ids: Vec<&str> = CATALOG.list().iter().map(|d| d.id).collect();
        for expected in &[
            "lnk_files",
            "jump_list_auto",
            "jump_list_custom",
            "evtx_dir",
            "mft_file",
            "usn_journal",
            "wmi_mof_dir",
            "bits_db",
            "wmi_subscriptions",
            "logon_scripts",
            "winsock_lsp",
            "appshim_db",
            "password_filter_dll",
            "office_normal_dotm",
            "powershell_profile_all",
            "dpapi_system_masterkey",
            "dpapi_credhist",
            "chrome_cookies",
            "edge_webcache",
            "vpn_ras_phonebook",
            "windows_hello_ngc",
            "user_cert_private_key",
            "machine_cert_store",
        ] {
            assert!(ids.contains(expected), "CATALOG missing: {expected}");
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Batch F — Linux extended credential / execution artifacts (RED)
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn linux_at_queue_md() {
        assert_eq!(LINUX_AT_QUEUE.id, "linux_at_queue");
        assert_eq!(LINUX_AT_QUEUE.artifact_type, ArtifactType::Directory);
        assert_eq!(LINUX_AT_QUEUE.scope, DataScope::System);
        assert!(LINUX_AT_QUEUE.mitre_techniques.contains(&"T1053.001"));
    }
    #[test]
    fn linux_sshd_config_md() {
        assert_eq!(LINUX_SSHD_CONFIG.id, "linux_sshd_config");
        assert_eq!(LINUX_SSHD_CONFIG.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_SSHD_CONFIG.scope, DataScope::System);
        assert!(LINUX_SSHD_CONFIG.mitre_techniques.contains(&"T1098.004"));
    }
    #[test]
    fn linux_etc_group_md() {
        assert_eq!(LINUX_ETC_GROUP.id, "linux_etc_group");
        assert_eq!(LINUX_ETC_GROUP.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_ETC_GROUP.scope, DataScope::System);
        assert!(LINUX_ETC_GROUP.mitre_techniques.contains(&"T1087.001"));
    }
    #[test]
    fn linux_gnome_keyring_md() {
        assert_eq!(LINUX_GNOME_KEYRING.id, "linux_gnome_keyring");
        assert_eq!(LINUX_GNOME_KEYRING.artifact_type, ArtifactType::Directory);
        assert_eq!(LINUX_GNOME_KEYRING.scope, DataScope::User);
        assert!(LINUX_GNOME_KEYRING.mitre_techniques.contains(&"T1555.003"));
    }
    #[test]
    fn linux_kde_kwallet_md() {
        assert_eq!(LINUX_KDE_KWALLET.id, "linux_kde_kwallet");
        assert_eq!(LINUX_KDE_KWALLET.artifact_type, ArtifactType::Directory);
        assert_eq!(LINUX_KDE_KWALLET.scope, DataScope::User);
        assert!(LINUX_KDE_KWALLET.mitre_techniques.contains(&"T1555.003"));
    }
    #[test]
    fn linux_chrome_login_linux_md() {
        assert_eq!(LINUX_CHROME_LOGIN_LINUX.id, "linux_chrome_login_linux");
        assert_eq!(LINUX_CHROME_LOGIN_LINUX.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_CHROME_LOGIN_LINUX.scope, DataScope::User);
        assert!(LINUX_CHROME_LOGIN_LINUX
            .mitre_techniques
            .contains(&"T1555.003"));
    }
    #[test]
    fn linux_firefox_logins_linux_md() {
        assert_eq!(LINUX_FIREFOX_LOGINS_LINUX.id, "linux_firefox_logins_linux");
        assert_eq!(LINUX_FIREFOX_LOGINS_LINUX.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_FIREFOX_LOGINS_LINUX.scope, DataScope::User);
        assert!(LINUX_FIREFOX_LOGINS_LINUX
            .mitre_techniques
            .contains(&"T1555.003"));
    }
    #[test]
    fn linux_utmp_md() {
        assert_eq!(LINUX_UTMP.id, "linux_utmp");
        assert_eq!(LINUX_UTMP.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_UTMP.scope, DataScope::System);
        assert!(LINUX_UTMP.mitre_techniques.contains(&"T1078"));
    }
    #[test]
    fn linux_gcp_credentials_md() {
        assert_eq!(LINUX_GCP_CREDENTIALS.id, "linux_gcp_credentials");
        assert_eq!(LINUX_GCP_CREDENTIALS.artifact_type, ArtifactType::Directory);
        assert_eq!(LINUX_GCP_CREDENTIALS.scope, DataScope::User);
        assert!(LINUX_GCP_CREDENTIALS
            .mitre_techniques
            .contains(&"T1552.001"));
    }
    #[test]
    fn linux_azure_credentials_md() {
        assert_eq!(LINUX_AZURE_CREDENTIALS.id, "linux_azure_credentials");
        assert_eq!(
            LINUX_AZURE_CREDENTIALS.artifact_type,
            ArtifactType::Directory
        );
        assert_eq!(LINUX_AZURE_CREDENTIALS.scope, DataScope::User);
        assert!(LINUX_AZURE_CREDENTIALS
            .mitre_techniques
            .contains(&"T1552.001"));
    }
    #[test]
    fn linux_kube_config_md() {
        assert_eq!(LINUX_KUBE_CONFIG.id, "linux_kube_config");
        assert_eq!(LINUX_KUBE_CONFIG.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_KUBE_CONFIG.scope, DataScope::User);
        assert!(LINUX_KUBE_CONFIG.mitre_techniques.contains(&"T1552.001"));
    }
    #[test]
    fn linux_git_credentials_md() {
        assert_eq!(LINUX_GIT_CREDENTIALS.id, "linux_git_credentials");
        assert_eq!(LINUX_GIT_CREDENTIALS.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_GIT_CREDENTIALS.scope, DataScope::User);
        assert!(LINUX_GIT_CREDENTIALS
            .mitre_techniques
            .contains(&"T1552.001"));
    }
    #[test]
    fn linux_netrc_md() {
        assert_eq!(LINUX_NETRC.id, "linux_netrc");
        assert_eq!(LINUX_NETRC.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_NETRC.scope, DataScope::User);
        assert!(LINUX_NETRC.mitre_techniques.contains(&"T1552.001"));
    }

    // ── CATALOG completeness (batch F) ────────────────────────────────────

    #[test]
    fn catalog_contains_batch_f() {
        let ids: Vec<&str> = CATALOG.list().iter().map(|d| d.id).collect();
        for expected in &[
            "linux_at_queue",
            "linux_sshd_config",
            "linux_etc_group",
            "linux_gnome_keyring",
            "linux_kde_kwallet",
            "linux_chrome_login_linux",
            "linux_firefox_logins_linux",
            "linux_utmp",
            "linux_gcp_credentials",
            "linux_azure_credentials",
            "linux_kube_config",
            "linux_git_credentials",
            "linux_netrc",
        ] {
            assert!(ids.contains(expected), "CATALOG missing: {expected}");
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Batch G — LinuxPersist-sourced artifacts (RED)
    // Source: https://github.com/GuyEldad/LinuxPersist
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn linux_etc_environment_md() {
        assert_eq!(LINUX_ETC_ENVIRONMENT.id, "linux_etc_environment");
        assert_eq!(LINUX_ETC_ENVIRONMENT.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_ETC_ENVIRONMENT.scope, DataScope::System);
        assert!(LINUX_ETC_ENVIRONMENT
            .mitre_techniques
            .contains(&"T1546.004"));
    }
    #[test]
    fn linux_xdg_autostart_user_md() {
        assert_eq!(LINUX_XDG_AUTOSTART_USER.id, "linux_xdg_autostart_user");
        assert_eq!(
            LINUX_XDG_AUTOSTART_USER.artifact_type,
            ArtifactType::Directory
        );
        assert_eq!(LINUX_XDG_AUTOSTART_USER.scope, DataScope::User);
        assert!(LINUX_XDG_AUTOSTART_USER
            .mitre_techniques
            .contains(&"T1547.014"));
    }
    #[test]
    fn linux_xdg_autostart_system_md() {
        assert_eq!(LINUX_XDG_AUTOSTART_SYSTEM.id, "linux_xdg_autostart_system");
        assert_eq!(
            LINUX_XDG_AUTOSTART_SYSTEM.artifact_type,
            ArtifactType::Directory
        );
        assert_eq!(LINUX_XDG_AUTOSTART_SYSTEM.scope, DataScope::System);
        assert!(LINUX_XDG_AUTOSTART_SYSTEM
            .mitre_techniques
            .contains(&"T1547.014"));
    }
    #[test]
    fn linux_networkmanager_dispatcher_md() {
        assert_eq!(
            LINUX_NETWORKMANAGER_DISPATCHER.id,
            "linux_networkmanager_dispatcher"
        );
        assert_eq!(
            LINUX_NETWORKMANAGER_DISPATCHER.artifact_type,
            ArtifactType::Directory
        );
        assert_eq!(LINUX_NETWORKMANAGER_DISPATCHER.scope, DataScope::System);
        assert!(LINUX_NETWORKMANAGER_DISPATCHER
            .mitre_techniques
            .contains(&"T1547.013"));
    }
    #[test]
    fn linux_apt_hooks_md() {
        assert_eq!(LINUX_APT_HOOKS.id, "linux_apt_hooks");
        assert_eq!(LINUX_APT_HOOKS.artifact_type, ArtifactType::Directory);
        assert_eq!(LINUX_APT_HOOKS.scope, DataScope::System);
        assert_eq!(LINUX_APT_HOOKS.os_scope, OsScope::LinuxDebian);
        assert!(LINUX_APT_HOOKS.mitre_techniques.contains(&"T1546.004"));
    }

    // ── CATALOG completeness (batch G) ────────────────────────────────────

    #[test]
    fn catalog_contains_batch_g() {
        let ids: Vec<&str> = CATALOG.list().iter().map(|d| d.id).collect();
        for expected in &[
            "linux_etc_environment",
            "linux_xdg_autostart_user",
            "linux_xdg_autostart_system",
            "linux_networkmanager_dispatcher",
            "linux_apt_hooks",
        ] {
            assert!(ids.contains(expected), "CATALOG missing: {expected}");
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Batch H — Jump List / LNK / Prefetch / SRUM tables / EVTX channels
    // ═══════════════════════════════════════════════════════════════════════

    // ── Jump Lists ────────────────────────────────────────────────────────

    #[test]
    fn jump_list_system_md() {
        assert_eq!(JUMP_LIST_SYSTEM.id, "jump_list_system");
        assert_eq!(JUMP_LIST_SYSTEM.artifact_type, ArtifactType::Directory);
        assert_eq!(JUMP_LIST_SYSTEM.scope, DataScope::System);
        assert!(JUMP_LIST_SYSTEM.mitre_techniques.contains(&"T1547.009"));
    }

    // ── LNK Files ─────────────────────────────────────────────────────────

    #[test]
    fn lnk_files_office_md() {
        assert_eq!(LNK_FILES_OFFICE.id, "lnk_files_office");
        assert_eq!(LNK_FILES_OFFICE.artifact_type, ArtifactType::Directory);
        assert_eq!(LNK_FILES_OFFICE.scope, DataScope::User);
        assert!(LNK_FILES_OFFICE.mitre_techniques.contains(&"T1547.009"));
    }

    // ── Prefetch ──────────────────────────────────────────────────────────

    #[test]
    fn prefetch_file_md() {
        assert_eq!(PREFETCH_FILE.id, "prefetch_file");
        assert_eq!(PREFETCH_FILE.artifact_type, ArtifactType::File);
        assert_eq!(PREFETCH_FILE.scope, DataScope::System);
        assert_eq!(PREFETCH_FILE.os_scope, OsScope::Win7Plus);
        assert!(PREFETCH_FILE.mitre_techniques.contains(&"T1059"));
    }

    // ── SRUM tables ───────────────────────────────────────────────────────

    #[test]
    fn srum_network_usage_md() {
        assert_eq!(SRUM_NETWORK_USAGE.id, "srum_network_usage");
        assert_eq!(SRUM_NETWORK_USAGE.artifact_type, ArtifactType::File);
        assert_eq!(SRUM_NETWORK_USAGE.scope, DataScope::System);
        assert_eq!(SRUM_NETWORK_USAGE.os_scope, OsScope::Win8Plus);
        assert!(SRUM_NETWORK_USAGE.mitre_techniques.contains(&"T1049"));
    }
    #[test]
    fn srum_app_resource_md() {
        assert_eq!(SRUM_APP_RESOURCE.id, "srum_app_resource");
        assert_eq!(SRUM_APP_RESOURCE.artifact_type, ArtifactType::File);
        assert_eq!(SRUM_APP_RESOURCE.scope, DataScope::System);
        assert_eq!(SRUM_APP_RESOURCE.os_scope, OsScope::Win8Plus);
        assert!(SRUM_APP_RESOURCE.mitre_techniques.contains(&"T1059"));
    }
    #[test]
    fn srum_energy_usage_md() {
        assert_eq!(SRUM_ENERGY_USAGE.id, "srum_energy_usage");
        assert_eq!(SRUM_ENERGY_USAGE.artifact_type, ArtifactType::File);
        assert_eq!(SRUM_ENERGY_USAGE.scope, DataScope::System);
        assert_eq!(SRUM_ENERGY_USAGE.os_scope, OsScope::Win8Plus);
        assert!(SRUM_ENERGY_USAGE.mitre_techniques.contains(&"T1059"));
    }
    #[test]
    fn srum_push_notification_md() {
        assert_eq!(SRUM_PUSH_NOTIFICATION.id, "srum_push_notification");
        assert_eq!(SRUM_PUSH_NOTIFICATION.artifact_type, ArtifactType::File);
        assert_eq!(SRUM_PUSH_NOTIFICATION.scope, DataScope::System);
        assert_eq!(SRUM_PUSH_NOTIFICATION.os_scope, OsScope::Win10Plus);
        assert!(SRUM_PUSH_NOTIFICATION.mitre_techniques.contains(&"T1059"));
    }

    // ── SRUM DRY: no MITRE URLs in sources[] ─────────────────────────────
    //
    // mitre_techniques[] already carries the ATT&CK IDs.
    // sources[] is for researcher docs, specs, and tool repos — not MITRE pages.
    // See CLAUDE.md accuracy standard #7.

    #[test]
    fn srum_db_sources_no_mitre_urls() {
        for url in SRUM_DB.sources {
            assert!(
                !url.contains("attack.mitre.org"),
                "srum_db.sources[] must not contain MITRE URLs (DRY — use mitre_techniques[]): {url}"
            );
        }
    }

    #[test]
    fn srum_network_usage_sources_no_mitre_urls() {
        for url in SRUM_NETWORK_USAGE.sources {
            assert!(
                !url.contains("attack.mitre.org"),
                "srum_network_usage.sources[] must not contain MITRE URLs: {url}"
            );
        }
    }

    #[test]
    fn srum_app_resource_sources_no_mitre_urls() {
        for url in SRUM_APP_RESOURCE.sources {
            assert!(
                !url.contains("attack.mitre.org"),
                "srum_app_resource.sources[] must not contain MITRE URLs: {url}"
            );
        }
    }

    #[test]
    fn srum_energy_usage_sources_no_mitre_urls() {
        for url in SRUM_ENERGY_USAGE.sources {
            assert!(
                !url.contains("attack.mitre.org"),
                "srum_energy_usage.sources[] must not contain MITRE URLs: {url}"
            );
        }
    }

    #[test]
    fn srum_push_notification_sources_no_mitre_urls() {
        for url in SRUM_PUSH_NOTIFICATION.sources {
            assert!(
                !url.contains("attack.mitre.org"),
                "srum_push_notification.sources[] must not contain MITRE URLs: {url}"
            );
        }
    }

    // ── SRUM enrichment: ssid + network_connections ───────────────────────

    #[test]
    fn srum_network_usage_has_ssid_field() {
        // Network Usage records the wireless SSID (L2ProfileId ESE column)
        // when the interface is wireless. Essential for correlating exfil
        // with specific WiFi networks (e.g. airport, hotel, home).
        // Source: https://github.com/MarkBaggett/srum-dump
        assert!(
            SRUM_NETWORK_USAGE
                .fields
                .iter()
                .any(|f| f.name == "l2_profile_id"),
            "srum_network_usage must have 'l2_profile_id' field (wireless SSID)"
        );
    }

    #[test]
    fn srum_network_connections_exists() {
        // Separate SRUM table {DD6636C4-8929-4683-974E-22C046A43763}.
        // Tracks connection-level metadata: start time, interface type,
        // connected duration. Distinct from Network Data Usage (bytes).
        // Source: https://github.com/MarkBaggett/srum-dump
        assert!(
            CATALOG.by_id("srum_network_connections").is_some(),
            "srum_network_connections artifact must exist in catalog"
        );
    }

    #[test]
    fn srum_network_connections_has_correct_guid() {
        let d = CATALOG.by_id("srum_network_connections").unwrap();
        assert!(
            d.file_path
                .unwrap_or("")
                .contains("DD6636C4-8929-4683-974E-22C046A43763"),
            "srum_network_connections file_path must embed ESE table GUID"
        );
    }

    #[test]
    fn srum_network_connections_has_interface_type_field() {
        let d = CATALOG.by_id("srum_network_connections").unwrap();
        assert!(
            d.fields.iter().any(|f| f.name == "interface_type"),
            "srum_network_connections must have 'interface_type' field (6=ethernet, 71=wireless)"
        );
    }

    #[test]
    fn srum_network_connections_has_connected_time_field() {
        let d = CATALOG.by_id("srum_network_connections").unwrap();
        assert!(
            d.fields.iter().any(|f| f.name == "connected_time"),
            "srum_network_connections must have 'connected_time' field (duration in seconds)"
        );
    }

    #[test]
    fn srum_network_connections_cites_srum_dump() {
        let d = CATALOG.by_id("srum_network_connections").unwrap();
        assert!(
            d.sources
                .iter()
                .any(|s| s.contains("github.com/MarkBaggett/srum-dump")),
            "srum_network_connections must cite srum-dump as authoritative schema source"
        );
    }

    #[test]
    fn catalog_count_after_srum_network_connections() {
        // +1 from srum_network_connections
        assert_eq!(CATALOG.list().len(), 6624);
    }

    // ── EVTX channels ─────────────────────────────────────────────────────

    #[test]
    fn evtx_security_md() {
        assert_eq!(EVTX_SECURITY.id, "evtx_security");
        assert_eq!(EVTX_SECURITY.artifact_type, ArtifactType::File);
        assert_eq!(EVTX_SECURITY.scope, DataScope::System);
        assert!(EVTX_SECURITY.mitre_techniques.contains(&"T1070.001"));
    }
    #[test]
    fn evtx_system_md() {
        assert_eq!(EVTX_SYSTEM.id, "evtx_system");
        assert_eq!(EVTX_SYSTEM.artifact_type, ArtifactType::File);
        assert_eq!(EVTX_SYSTEM.scope, DataScope::System);
        assert!(EVTX_SYSTEM.mitre_techniques.contains(&"T1543.003"));
    }
    #[test]
    fn evtx_powershell_md() {
        assert_eq!(EVTX_POWERSHELL.id, "evtx_powershell");
        assert_eq!(EVTX_POWERSHELL.artifact_type, ArtifactType::File);
        assert_eq!(EVTX_POWERSHELL.scope, DataScope::System);
        assert!(EVTX_POWERSHELL.mitre_techniques.contains(&"T1059.001"));
    }
    #[test]
    fn evtx_sysmon_md() {
        assert_eq!(EVTX_SYSMON.id, "evtx_sysmon");
        assert_eq!(EVTX_SYSMON.artifact_type, ArtifactType::File);
        assert_eq!(EVTX_SYSMON.scope, DataScope::System);
        assert!(EVTX_SYSMON.mitre_techniques.contains(&"T1059"));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Enhancement I — retention / triage_priority / related_artifacts (RED)
    // ═══════════════════════════════════════════════════════════════════════

    // ── TriagePriority enum exists and is ordered ─────────────────────────

    #[test]
    fn triage_priority_ordering() {
        assert!(TriagePriority::Critical > TriagePriority::High);
        assert!(TriagePriority::High > TriagePriority::Medium);
        assert!(TriagePriority::Medium > TriagePriority::Low);
    }

    // ── ArtifactDescriptor has new fields ─────────────────────────────────

    #[test]
    fn descriptor_has_retention_field() {
        // retention is Option<&str>; registry persistence keys are indefinite
        assert_eq!(RUN_KEY_HKLM_RUN.retention, None);
    }

    #[test]
    fn descriptor_has_triage_priority_field() {
        assert_eq!(RUN_KEY_HKLM_RUN.triage_priority, TriagePriority::High);
    }

    #[test]
    fn descriptor_has_related_artifacts_field() {
        let _ = RUN_KEY_HKLM_RUN.related_artifacts;
    }

    // ── Specific retention values ─────────────────────────────────────────

    #[test]
    fn srum_retention_is_30_days() {
        assert_eq!(SRUM_DB.retention, Some("~30 days"));
    }

    #[test]
    fn shimcache_retention_mentions_shutdown() {
        assert!(SHIMCACHE.retention.unwrap_or("").contains("shutdown"));
    }

    #[test]
    fn powershell_history_retention_mentions_limit() {
        assert!(POWERSHELL_HISTORY.retention.unwrap_or("").contains("4096"));
    }

    #[test]
    fn bam_user_retention_is_7_days() {
        assert!(BAM_USER.retention.unwrap_or("").contains("7 day"));
    }

    #[test]
    fn evtx_security_retention_mentions_rolling() {
        assert!(EVTX_SECURITY.retention.unwrap_or("").contains("rolling"));
    }

    // ── Specific triage_priority values ──────────────────────────────────

    #[test]
    fn evtx_security_triage_is_critical() {
        assert_eq!(EVTX_SECURITY.triage_priority, TriagePriority::Critical);
    }

    #[test]
    fn sam_users_triage_is_critical() {
        assert_eq!(SAM_USERS.triage_priority, TriagePriority::Critical);
    }

    #[test]
    fn lsa_secrets_triage_is_critical() {
        assert_eq!(LSA_SECRETS.triage_priority, TriagePriority::Critical);
    }

    #[test]
    fn linux_shadow_triage_is_critical() {
        assert_eq!(LINUX_SHADOW.triage_priority, TriagePriority::Critical);
    }

    #[test]
    fn shimcache_triage_is_critical() {
        assert_eq!(SHIMCACHE.triage_priority, TriagePriority::Critical);
    }

    #[test]
    fn userassist_exe_triage_is_high() {
        assert_eq!(USERASSIST_EXE.triage_priority, TriagePriority::High);
    }

    #[test]
    fn thumbcache_triage_is_medium() {
        assert_eq!(THUMBCACHE.triage_priority, TriagePriority::Medium);
    }

    #[test]
    fn vpn_ras_phonebook_triage_is_low() {
        assert_eq!(VPN_RAS_PHONEBOOK.triage_priority, TriagePriority::Low);
    }

    // ── related_artifacts ────────────────────────────────────────────────

    #[test]
    fn srum_network_related_includes_evtx_security() {
        assert!(SRUM_NETWORK_USAGE
            .related_artifacts
            .contains(&"evtx_security"));
    }

    #[test]
    fn evtx_security_related_includes_srum() {
        assert!(EVTX_SECURITY
            .related_artifacts
            .contains(&"srum_network_usage"));
    }

    #[test]
    fn prefetch_file_related_includes_shimcache() {
        assert!(PREFETCH_FILE.related_artifacts.contains(&"shimcache"));
    }

    #[test]
    fn dpapi_masterkey_related_includes_dpapi_cred() {
        assert!(DPAPI_MASTERKEY_USER
            .related_artifacts
            .contains(&"dpapi_cred_user"));
    }

    // ── New catalog API ──────────────────────────────────────────────────

    #[test]
    fn catalog_by_mitre_finds_srum_network_usage() {
        let hits = CATALOG.by_mitre("T1049");
        assert!(hits.iter().any(|d| d.id == "srum_network_usage"));
    }

    #[test]
    fn catalog_by_mitre_finds_no_results_for_unknown() {
        assert!(CATALOG.by_mitre("T9999.999").is_empty());
    }

    #[test]
    fn catalog_for_triage_nonempty_and_critical_first() {
        let hits = CATALOG.for_triage();
        assert!(!hits.is_empty());
        assert_eq!(hits[0].triage_priority, TriagePriority::Critical);
        // Last entry must not be higher priority than Medium
        assert!(hits.last().unwrap().triage_priority <= TriagePriority::Medium);
    }

    #[test]
    fn catalog_for_triage_stable_within_priority() {
        // All Criticals before any High; all Highs before any Medium
        let hits = CATALOG.for_triage();
        let mut max_seen = TriagePriority::Critical;
        for d in &hits {
            assert!(d.triage_priority <= max_seen, "priority not monotone");
            max_seen = d.triage_priority;
        }
    }

    #[test]
    fn catalog_filter_by_keyword_finds_dpapi() {
        let hits = CATALOG.filter_by_keyword("DPAPI");
        assert!(!hits.is_empty());
        assert!(hits.iter().any(|d| d.id.contains("dpapi")));
    }

    #[test]
    fn catalog_filter_by_keyword_case_insensitive() {
        let lower = CATALOG.filter_by_keyword("dpapi");
        let upper = CATALOG.filter_by_keyword("DPAPI");
        assert_eq!(lower.len(), upper.len());
    }

    #[test]
    fn parsing_profile_lookup_is_case_insensitive() {
        let lower = parsing_profile("hiberfil_sys").unwrap();
        let upper = parsing_profile("HIBERFIL_SYS").unwrap();
        assert_eq!(lower.artifact_id, upper.artifact_id);
    }

    #[test]
    fn container_profile_lookup_is_case_insensitive() {
        let lower = container_profile("windows_registry_hive").unwrap();
        let upper = container_profile("WINDOWS_REGISTRY_HIVE").unwrap();
        assert_eq!(lower.id, upper.id);
    }

    #[test]
    fn userassist_resolves_to_registry_container_profile() {
        let profile = CATALOG.container_profile("userassist_exe").unwrap();
        assert_eq!(profile.id, "windows_registry_hive");
        assert!(profile
            .parser_hints
            .iter()
            .any(|hint| hint.contains("value name")));
    }

    #[test]
    fn windows_timeline_resolves_to_sqlite_container_profile() {
        let profile = CATALOG.container_profile("windows_timeline").unwrap();
        assert_eq!(profile.id, "sqlite_database");
    }

    #[test]
    fn registry_container_signature_has_regf_magic() {
        let sig = CATALOG.container_signature("userassist_exe").unwrap();
        assert_eq!(sig.container_id, "windows_registry_hive");
        assert_eq!(sig.header_magic, b"regf");
    }

    #[test]
    fn userassist_record_signature_prefers_payload_specific_signature() {
        let sigs = CATALOG.record_signatures("userassist_exe");
        assert!(sigs.iter().any(|sig| sig.id == "userassist_count_payload"));
        assert!(sigs
            .iter()
            .all(|sig| sig.artifact_id == Some("userassist_exe")));
    }

    #[test]
    fn registry_artifact_without_direct_record_signature_falls_back_to_container_records() {
        let sigs = CATALOG.record_signatures("run_key_hkcu");
        assert!(sigs.iter().any(|sig| sig.id == "registry_nk_cell"));
        assert!(sigs.iter().any(|sig| sig.id == "registry_vk_cell"));
    }

    #[test]
    fn userassist_parsing_profile_captures_rot13_knowledge() {
        let profile = CATALOG.parsing_profile("userassist_exe").unwrap();
        assert!(profile
            .parser_hints
            .iter()
            .any(|hint| hint.contains("ROT13")));
        assert!(profile.extracted_fields.contains(&"last_run"));
    }

    #[test]
    fn hiberfil_parsing_profile_describes_memory_reconstruction() {
        let profile = CATALOG.parsing_profile("hiberfil_sys").unwrap();
        assert!(profile.summary.contains("memory"));
        assert!(profile
            .parser_hints
            .iter()
            .any(|hint| hint.contains("reconstruct")));
    }

    #[test]
    fn bits_parsing_profile_mentions_notify_command() {
        let profile = CATALOG.parsing_profile("bits_db").unwrap();
        assert!(profile.extracted_fields.contains(&"notify_command"));
        assert!(profile
            .parser_hints
            .iter()
            .any(|hint| hint.contains("notify")));
    }

    #[test]
    fn wmi_parsing_profiles_cover_repository_and_registry_views() {
        let repo = CATALOG.parsing_profile("wmi_mof_dir").unwrap();
        let reg = CATALOG.parsing_profile("wmi_subscriptions").unwrap();
        assert!(repo.extracted_fields.contains(&"binding_filter"));
        assert!(reg.summary.contains("pivot"));
    }

    // ── CATALOG completeness (batch H) ────────────────────────────────────

    // ── sources field — every high-value descriptor must cite at least one
    //    authoritative external reference (SANS, Harlan Carvey, Brian Carrier,
    //    Red Canary, Microsoft docs, MITRE ATT&CK, etc.)  ────────────────────

    #[test]
    fn userassist_has_authoritative_sources() {
        assert!(
            !USERASSIST_EXE.sources.is_empty(),
            "USERASSIST_EXE must cite at least one authoritative source"
        );
    }

    #[test]
    fn run_key_hklm_has_authoritative_sources() {
        assert!(
            !RUN_KEY_HKLM_RUN.sources.is_empty(),
            "RUN_KEY_HKLM_RUN must cite at least one authoritative source"
        );
    }

    #[test]
    fn shimcache_has_authoritative_sources() {
        assert!(
            !SHIMCACHE.sources.is_empty(),
            "SHIMCACHE must cite at least one authoritative source"
        );
    }

    #[test]
    fn prefetch_dir_has_authoritative_sources() {
        assert!(
            !PREFETCH_DIR.sources.is_empty(),
            "PREFETCH_DIR must cite at least one authoritative source"
        );
    }

    #[test]
    fn amcache_has_authoritative_sources() {
        assert!(
            !AMCACHE_APP_FILE.sources.is_empty(),
            "AMCACHE_APP_FILE must cite at least one authoritative source"
        );
    }

    #[test]
    fn evtx_security_has_authoritative_sources() {
        assert!(
            !EVTX_SECURITY.sources.is_empty(),
            "EVTX_SECURITY must cite at least one authoritative source"
        );
    }

    #[test]
    fn srum_app_resource_has_authoritative_sources() {
        assert!(
            !SRUM_APP_RESOURCE.sources.is_empty(),
            "SRUM_APP_RESOURCE must cite at least one authoritative source"
        );
    }

    #[test]
    fn sam_users_has_authoritative_sources() {
        assert!(
            !SAM_USERS.sources.is_empty(),
            "SAM_USERS must cite at least one authoritative source"
        );
    }

    #[test]
    fn shellbags_has_authoritative_sources() {
        assert!(
            !SHELLBAGS_USER.sources.is_empty(),
            "SHELLBAGS_USER must cite at least one authoritative source"
        );
    }

    #[test]
    fn no_descriptor_in_catalog_has_empty_sources() {
        let empty: Vec<&str> = CATALOG
            .list()
            .iter()
            .filter(|d| d.sources.is_empty())
            .map(|d| d.id)
            .collect();
        assert!(
            empty.is_empty(),
            "These catalog entries have no authoritative sources: {empty:?}"
        );
    }

    #[test]
    fn catalog_contains_batch_h() {
        let ids: Vec<&str> = CATALOG.list().iter().map(|d| d.id).collect();
        for expected in &[
            "jump_list_system",
            "lnk_files_office",
            "prefetch_file",
            "srum_network_usage",
            "srum_app_resource",
            "srum_energy_usage",
            "srum_push_notification",
            "evtx_security",
            "evtx_system",
            "evtx_powershell",
            "evtx_sysmon",
        ] {
            assert!(ids.contains(expected), "CATALOG missing: {expected}");
        }
    }

    #[test]
    fn regipy_batch_has_authoritative_sources() {
        for desc in [
            &TYPED_PATHS,
            &RUN_MRU,
            &NETWORK_DRIVES,
            &APP_PATHS,
            &MOUNTED_DEVICES,
            &NETWORKLIST_PROFILES,
            &PUTTY_SESSIONS,
            &WINSCP_SAVED_SESSIONS,
            &WINRAR_HISTORY,
        ] {
            assert!(
                !desc.sources.is_empty(),
                "{} must cite at least one authoritative source",
                desc.id
            );
        }
    }

    #[test]
    fn catalog_contains_regipy_batch() {
        let ids: Vec<&str> = CATALOG.list().iter().map(|d| d.id).collect();
        for expected in &[
            "typed_paths",
            "run_mru",
            "network_drives",
            "app_paths",
            "mounted_devices",
            "networklist_profiles",
            "putty_sessions",
            "winscp_saved_sessions",
            "winrar_history",
        ] {
            assert!(ids.contains(expected), "CATALOG missing: {expected}");
        }
    }

    #[test]
    fn catalog_contains_blue_team_batch() {
        let ids: Vec<&str> = CATALOG.list().iter().map(|d| d.id).collect();
        for expected in &[
            "network_interfaces",
            "pagefile_sys",
            "hiberfil_sys",
            "mountpoints2",
            "portable_devices",
            "rdp_bitmap_cache",
        ] {
            assert!(ids.contains(expected), "CATALOG missing: {expected}");
        }
    }

    // ── NTFS metadata files (Tier 1 IR artifacts) ─────────────────────────

    #[test]
    fn mft_exists_in_catalog() {
        // The generated fa_file_environ_systemdrive_mft stub is triage Low with no
        // MITRE or fields. We need a hand-curated Critical entry: id="mft".
        let ids: Vec<&str> = CATALOG.list().iter().map(|d| d.id).collect();
        assert!(
            ids.contains(&"mft"),
            "CATALOG missing 'mft' — $MFT is Tier 1 IR"
        );
    }

    #[test]
    fn mft_is_critical_triage() {
        assert_eq!(
            MFT.triage_priority,
            TriagePriority::Critical,
            "$MFT is a Tier 1 triage artifact — must be Critical"
        );
    }

    #[test]
    fn mft_file_path_is_ntfs_root() {
        let path = MFT.file_path.expect("$MFT must have a file_path");
        assert!(
            path.contains("$MFT"),
            "$MFT file_path must reference the NTFS $MFT file, got: {path}"
        );
    }

    #[test]
    fn mft_has_si_vs_fn_timestamp_fields() {
        // The key forensic value of $MFT is detecting timestomping via
        // discrepancy between $STANDARD_INFORMATION and $FILE_NAME timestamps.
        let field_names: Vec<&str> = MFT.fields.iter().map(|f| f.name).collect();
        assert!(
            field_names.contains(&"si_created") || field_names.contains(&"mft_record_number"),
            "$MFT fields must include SI timestamps or mft_record_number for timestomping analysis; got: {field_names:?}"
        );
    }

    #[test]
    fn mft_covers_timestomping_technique() {
        assert!(
            MFT.mitre_techniques.contains(&"T1070.006"),
            "$MFT must map to T1070.006 (Timestomping); got: {:?}",
            MFT.mitre_techniques
        );
    }

    #[test]
    fn mft_has_authoritative_sources() {
        assert!(
            !MFT.sources.is_empty(),
            "MFT must cite at least one authoritative source"
        );
        for src in MFT.sources {
            assert!(
                src.starts_with("https://"),
                "MFT source must be a URL, not a name stub: {src}"
            );
        }
    }

    #[test]
    fn usnjrnl_exists_in_catalog() {
        // The generated fa_file_extend_usnjrnl stub is triage Low with no MITRE or fields.
        // We need a hand-curated Critical entry: id="usnjrnl".
        let ids: Vec<&str> = CATALOG.list().iter().map(|d| d.id).collect();
        assert!(
            ids.contains(&"usnjrnl"),
            "CATALOG missing 'usnjrnl' — $UsnJrnl is Tier 1 IR"
        );
    }

    #[test]
    fn usnjrnl_is_critical_triage() {
        assert_eq!(
            USNJRNL.triage_priority,
            TriagePriority::Critical,
            "$UsnJrnl is a Tier 1 triage artifact — must be Critical"
        );
    }

    #[test]
    fn usnjrnl_file_path_references_j_stream() {
        let path = USNJRNL.file_path.expect("$UsnJrnl must have a file_path");
        assert!(
            path.contains("$UsnJrnl") || path.contains("UsnJrnl"),
            "$UsnJrnl file_path must reference $Extend\\$UsnJrnl, got: {path}"
        );
    }

    #[test]
    fn usnjrnl_has_reason_field_with_bitmask() {
        // USN V2 records have a `reason` bitfield (FILE_CREATE, FILE_DELETE,
        // RENAME_OLD_NAME, RENAME_NEW_NAME, CLOSE, etc.) — the primary
        // forensic value of the journal.
        let field_names: Vec<&str> = USNJRNL.fields.iter().map(|f| f.name).collect();
        assert!(
            field_names.contains(&"reason") || field_names.contains(&"usn_reason"),
            "$UsnJrnl fields must include the USN reason bitmask field; got: {field_names:?}"
        );
    }

    #[test]
    fn usnjrnl_covers_file_deletion_technique() {
        assert!(
            USNJRNL.mitre_techniques.contains(&"T1070.004"),
            "$UsnJrnl must map to T1070.004 (File Deletion — indicator removal); got: {:?}",
            USNJRNL.mitre_techniques
        );
    }

    #[test]
    fn usnjrnl_has_authoritative_sources() {
        assert!(
            !USNJRNL.sources.is_empty(),
            "USNJRNL must cite at least one authoritative source"
        );
        for src in USNJRNL.sources {
            assert!(
                src.starts_with("https://"),
                "USNJRNL source must be a URL, not a name stub: {src}"
            );
        }
    }
}

#[cfg(test)]
#[cfg(feature = "serde")]
mod serde_tests {
    use super::*;

    #[test]
    fn artifact_type_roundtrips_json() {
        let json = serde_json::to_string(&ArtifactType::File).unwrap();
        assert_eq!(json, "\"File\"");
        let decoded: ArtifactType = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, ArtifactType::File);
    }

    #[test]
    fn triage_priority_roundtrips_json() {
        let json = serde_json::to_string(&TriagePriority::Critical).unwrap();
        assert_eq!(json, "\"Critical\"");
        let decoded: TriagePriority = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, TriagePriority::Critical);
    }

    #[test]
    fn data_scope_roundtrips_json() {
        let json = serde_json::to_string(&DataScope::User).unwrap();
        assert_eq!(json, "\"User\"");
        let decoded: DataScope = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, DataScope::User);
    }

    #[test]
    fn artifact_value_text_roundtrips_json() {
        let val = ArtifactValue::Text("hello".to_string());
        let json = serde_json::to_string(&val).unwrap();
        let decoded: ArtifactValue = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn artifact_value_list_roundtrips_json() {
        let val = ArtifactValue::List(vec![ArtifactValue::Integer(1), ArtifactValue::Bool(true)]);
        let json = serde_json::to_string(&val).unwrap();
        let decoded: ArtifactValue = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn artifact_descriptor_serializes_to_json() {
        let d = CATALOG.by_id("userassist_exe").unwrap();
        let json = serde_json::to_string(d).unwrap();
        assert!(json.contains("userassist_exe"), "id missing from JSON");
        assert!(json.contains("UserAssist"), "name missing from JSON");
        assert!(json.contains("T1059"), "mitre_techniques missing from JSON");
    }

    #[test]
    fn decode_error_serializes_to_json() {
        let err = DecodeError::InvalidUtf8;
        let json = serde_json::to_string(&err).unwrap();
        assert_eq!(json, "\"InvalidUtf8\"");
    }

    #[test]
    fn decode_error_buffer_too_short_serializes_to_json() {
        let err = DecodeError::BufferTooShort {
            expected: 8,
            actual: 3,
        };
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("BufferTooShort"), "variant name missing");
        assert!(json.contains("8"), "expected value missing");
        assert!(json.contains("3"), "actual value missing");
    }

    #[test]
    fn os_scope_roundtrips_json() {
        let json = serde_json::to_string(&OsScope::Win10Plus).unwrap();
        let decoded: OsScope = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, OsScope::Win10Plus);
    }
}

#[cfg(test)]
mod macos_tests {
    use crate::catalog::{OsScope, CATALOG};

    #[test]
    fn macos_artifacts_exist_in_catalog() {
        let macos_artifacts: Vec<_> = CATALOG
            .for_triage()
            .into_iter()
            .filter(|d| {
                matches!(
                    d.os_scope,
                    OsScope::MacOS
                        | OsScope::MacOS12Plus
                        | OsScope::MacOS13Plus
                        | OsScope::MacOS14Plus
                )
            })
            .collect();
        assert!(
            macos_artifacts.len() >= 10,
            "Expected at least 10 macOS artifacts, got {}",
            macos_artifacts.len()
        );
    }

    #[test]
    fn macos_launch_agents_user_exists() {
        assert!(
            CATALOG.by_id("macos_launch_agents_user").is_some(),
            "macos_launch_agents_user should be in catalog"
        );
    }

    #[test]
    fn macos_tcc_db_has_mitre_mapping() {
        let d = CATALOG
            .by_id("macos_tcc_db")
            .expect("macos_tcc_db should be in catalog");
        assert!(
            !d.mitre_techniques.is_empty(),
            "macos_tcc_db should have MITRE techniques"
        );
    }

    #[test]
    fn macos_unified_log_exists() {
        assert!(
            CATALOG.by_id("macos_unified_log").is_some(),
            "macos_unified_log should be in catalog"
        );
    }

    #[test]
    fn macos_artifacts_have_sources() {
        for d in CATALOG.for_triage() {
            if matches!(
                d.os_scope,
                OsScope::MacOS | OsScope::MacOS12Plus | OsScope::MacOS13Plus | OsScope::MacOS14Plus
            ) {
                assert!(
                    !d.sources.is_empty(),
                    "macOS artifact '{}' has no sources",
                    d.id
                );
            }
        }
    }
}

#[cfg(test)]
mod memory_tests {
    use super::*;

    #[test]
    fn memory_region_artifacts_exist() {
        let mem: Vec<_> = CATALOG
            .list()
            .iter()
            .filter(|d| matches!(d.artifact_type, ArtifactType::MemoryRegion))
            .collect();
        assert!(
            mem.len() >= 3,
            "Should have at least 3 MemoryRegion artifacts"
        );
    }

    #[test]
    fn mem_running_processes_exists() {
        assert!(CATALOG.by_id("mem_running_processes").is_some());
    }

    #[test]
    fn mem_user_credentials_is_critical() {
        let d = CATALOG
            .by_id("mem_user_credentials")
            .expect("mem_user_credentials missing");
        assert_eq!(d.triage_priority, TriagePriority::Critical);
    }

    #[test]
    fn memory_artifacts_have_mitre_mappings() {
        let mem: Vec<_> = CATALOG
            .list()
            .iter()
            .filter(|d| matches!(d.artifact_type, ArtifactType::MemoryRegion))
            .collect();
        for d in &mem {
            assert!(
                !d.mitre_techniques.is_empty(),
                "{} has no MITRE mappings",
                d.id
            );
        }
    }
}

// ── Extension artifact tests (windows_registry_ext, windows_evtx_ext, macos_ext, linux_ext) ──

#[cfg(test)]
mod extension_tests {
    use super::*;

    #[test]
    fn catalog_grows_to_at_least_284() {
        assert!(
            CATALOG.list().len() >= 284,
            "expected ≥ 284 artifacts, got {}",
            CATALOG.list().len()
        );
    }

    // Windows registry extension spot-checks
    #[test]
    fn credential_providers_exists() {
        assert!(CATALOG.by_id("credential_providers").is_some());
    }

    #[test]
    fn known_dlls_exists() {
        assert!(CATALOG.by_id("known_dlls").is_some());
    }

    #[test]
    fn usb_stor_enum_exists() {
        assert!(CATALOG.by_id("usb_stor_enum").is_some());
    }

    #[test]
    fn ifeo_global_flag_exists() {
        assert!(CATALOG.by_id("ifeo_global_flag").is_some());
    }

    // Windows EVTX extension spot-checks
    #[test]
    fn evtx_task_scheduler_exists() {
        assert!(CATALOG.by_id("evtx_task_scheduler").is_some());
    }

    #[test]
    fn evtx_rdp_inbound_exists() {
        assert!(CATALOG.by_id("evtx_rdp_inbound").is_some());
    }

    #[test]
    fn evtx_defender_exists() {
        assert!(CATALOG.by_id("evtx_defender").is_some());
    }

    #[test]
    fn evtx_wmi_activity_exists() {
        assert!(CATALOG.by_id("evtx_wmi_activity").is_some());
    }

    // macOS extension spot-checks
    #[test]
    fn macos_fsevents_exists() {
        assert!(CATALOG.by_id("macos_fsevents").is_some());
    }

    #[test]
    fn macos_tcc_system_db_exists() {
        assert!(CATALOG.by_id("macos_tcc_system_db").is_some());
    }

    #[test]
    fn macos_wifi_plist_exists() {
        assert!(CATALOG.by_id("macos_wifi_plist").is_some());
    }

    #[test]
    fn macos_mdm_enrollment_exists() {
        assert!(CATALOG.by_id("macos_mdm_enrollment").is_some());
    }

    // Linux extension spot-checks
    #[test]
    fn linux_auditd_log_exists() {
        assert!(CATALOG.by_id("linux_auditd_log").is_some());
    }

    #[test]
    fn linux_apparmor_profiles_exists() {
        assert!(CATALOG.by_id("linux_apparmor_profiles").is_some());
    }

    #[test]
    fn linux_docker_container_logs_exists() {
        assert!(CATALOG.by_id("linux_docker_container_logs").is_some());
    }

    #[test]
    fn linux_selinux_config_exists() {
        assert!(CATALOG.by_id("linux_selinux_config").is_some());
    }
}

#[cfg(test)]
mod phase2_registry_tests {
    use super::*;

    #[test]
    fn catalog_count_includes_phase2() {
        // Updated to 354 after phase-2b file artifact additions
        assert_eq!(CATALOG.list().len(), 6624);
    }

    #[test]
    fn winlogon_autoadmin_logon_exists() {
        let d = CATALOG.by_id("winlogon_autoadmin_logon").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Critical);
        assert!(d.mitre_techniques.contains(&"T1547.001"));
    }

    #[test]
    fn winlogon_default_password_exists() {
        let d = CATALOG.by_id("winlogon_default_password").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Critical);
        assert!(d.mitre_techniques.contains(&"T1552.002"));
    }

    #[test]
    fn portproxy_config_exists() {
        let d = CATALOG.by_id("portproxy_config").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Critical);
        assert!(d.mitre_techniques.contains(&"T1572"));
    }

    #[test]
    fn windows_defender_exclusions_local_exists() {
        let d = CATALOG.by_id("windows_defender_exclusions_local").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Critical);
        assert!(d.mitre_techniques.contains(&"T1562.001"));
    }

    #[test]
    fn vss_files_not_to_snapshot_exists() {
        let d = CATALOG.by_id("vss_files_not_to_snapshot").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Critical);
        assert!(d.mitre_techniques.contains(&"T1490"));
    }

    #[test]
    fn ifeo_silent_exit_exists() {
        let d = CATALOG.by_id("ifeo_silent_exit").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Critical);
        assert!(d.mitre_techniques.contains(&"T1546.012"));
    }

    #[test]
    fn rdp_shadow_sessions_exists() {
        let d = CATALOG.by_id("rdp_shadow_sessions").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Critical);
        assert!(d.mitre_techniques.contains(&"T1021.001"));
    }

    #[test]
    fn taskcache_tasks_path_exists() {
        let d = CATALOG.by_id("taskcache_tasks_path").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Critical);
        assert!(d.mitre_techniques.contains(&"T1053.005"));
    }

    #[test]
    fn event_log_channel_status_exists() {
        let d = CATALOG.by_id("event_log_channel_status").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Critical);
        assert!(d.mitre_techniques.contains(&"T1562.002"));
    }

    #[test]
    fn sysinternals_eula_exists() {
        let d = CATALOG.by_id("sysinternals_eula").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::High);
        assert!(d.mitre_techniques.contains(&"T1012"));
    }

    #[test]
    fn startup_approved_run_system_exists() {
        let d = CATALOG.by_id("startup_approved_run_system").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::High);
        assert!(d.mitre_techniques.contains(&"T1547.001"));
    }

    #[test]
    fn profile_list_users_exists() {
        let d = CATALOG.by_id("profile_list_users").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::High);
        assert!(!d.sources.is_empty());
    }

    #[test]
    fn firewall_rules_exists() {
        let d = CATALOG.by_id("firewall_rules").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::High);
        assert!(d.mitre_techniques.contains(&"T1562.004"));
    }

    #[test]
    fn all_phase2_ids_present() {
        let ids = [
            "winlogon_autoadmin_logon",
            "winlogon_default_password",
            "winlogon_default_username",
            "logonui_last_loggedon_user",
            "portproxy_config",
            "windows_defender_exclusions_local",
            "windows_defender_disabled_av",
            "windows_defender_realtime",
            "ms_office_trusted_docs",
            "vss_files_not_to_snapshot",
            "vss_files_not_to_backup",
            "ifeo_silent_exit",
            "exefile_shell_open_software",
            "exefile_shell_open_usrclass",
            "rdp_shadow_sessions",
            "restricted_admin_rdp",
            "network_shares_server",
            "sysinternals_eula",
            "ms_office_server_cache",
            "powershell_cobalt_info",
            "startup_approved_run_system",
            "startup_approved_run_user",
            "taskcache_tasks_path",
            "profile_list_users",
            "registrar_favorites",
            "dhcp_ipv4_interface",
            "ntfs_last_access_status",
            "prefetch_status",
            "firewall_rules",
            "event_log_channel_status",
        ];
        for id in &ids {
            assert!(
                CATALOG.by_id(id).is_some(),
                "missing phase-2 artifact: {id}"
            );
        }
    }
}

#[cfg(test)]
mod phase2b_files_tests {
    use super::*;

    #[test]
    fn catalog_count_includes_phase2b() {
        // phase2a adds 30 registry artifacts (284→314), phase2b adds 40 file artifacts (314→354)
        // Note: chrome_login_data was already present from Phase 1; not duplicated here.
        assert_eq!(CATALOG.list().len(), 6624);
    }

    #[test]
    fn chrome_history_exists() {
        let d = CATALOG.by_id("chrome_history").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Critical);
        assert!(d.mitre_techniques.contains(&"T1217"));
    }

    #[test]
    fn chrome_web_data_exists() {
        assert!(CATALOG.by_id("chrome_web_data").is_some());
    }

    #[test]
    fn edge_chromium_history_exists() {
        let d = CATALOG.by_id("edge_chromium_history").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Critical);
    }

    #[test]
    fn edge_chromium_login_data_exists() {
        let d = CATALOG.by_id("edge_chromium_login_data").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Critical);
        assert!(d.mitre_techniques.contains(&"T1555.003"));
    }

    #[test]
    fn firefox_places_exists() {
        let d = CATALOG.by_id("firefox_places").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Critical);
        assert!(d.mitre_techniques.contains(&"T1217"));
    }

    #[test]
    fn firefox_form_history_exists() {
        assert!(CATALOG.by_id("firefox_form_history").is_some());
    }

    #[test]
    fn firefox_session_restore_exists() {
        assert!(CATALOG.by_id("firefox_session_restore").is_some());
    }

    #[test]
    fn psreadline_history_exists() {
        let d = CATALOG.by_id("psreadline_history").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Critical);
        assert!(d.mitre_techniques.contains(&"T1059.001"));
    }

    #[test]
    fn psreadline_history_system_exists() {
        let d = CATALOG.by_id("psreadline_history_system").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Critical);
    }

    #[test]
    fn powershell_transcripts_exists() {
        let d = CATALOG.by_id("powershell_transcripts").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Critical);
    }

    #[test]
    fn teamviewer_connection_log_exists() {
        let d = CATALOG.by_id("teamviewer_connection_log").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Critical);
        assert!(d.mitre_techniques.contains(&"T1219"));
    }

    #[test]
    fn anydesk_trace_user_exists() {
        let d = CATALOG.by_id("anydesk_trace_user").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Critical);
    }

    #[test]
    fn anydesk_trace_system_exists() {
        let d = CATALOG.by_id("anydesk_trace_system").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Critical);
    }

    #[test]
    fn anydesk_connection_trace_exists() {
        assert!(CATALOG.by_id("anydesk_connection_trace").is_some());
    }

    #[test]
    fn anydesk_file_transfer_log_exists() {
        let d = CATALOG.by_id("anydesk_file_transfer_log").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Critical);
    }

    #[test]
    fn screenconnect_session_db_exists() {
        let d = CATALOG.by_id("screenconnect_session_db").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Critical);
    }

    #[test]
    fn rustdesk_logs_exists() {
        assert!(CATALOG.by_id("rustdesk_logs").is_some());
    }

    #[test]
    fn dropbox_instance_db_exists() {
        let d = CATALOG.by_id("dropbox_instance_db").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Critical);
        assert!(d.mitre_techniques.contains(&"T1567.002"));
    }

    #[test]
    fn onedrive_metadata_exists() {
        let d = CATALOG.by_id("onedrive_metadata").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Critical);
    }

    #[test]
    fn google_drive_fs_metadata_exists() {
        let d = CATALOG.by_id("google_drive_fs_metadata").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Critical);
    }

    #[test]
    fn megasync_data_exists() {
        assert!(CATALOG.by_id("megasync_data").is_some());
    }

    #[test]
    fn teams_indexed_db_exists() {
        let d = CATALOG.by_id("teams_indexed_db").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Critical);
    }

    #[test]
    fn slack_indexed_db_exists() {
        let d = CATALOG.by_id("slack_indexed_db").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Critical);
    }

    #[test]
    fn discord_local_storage_exists() {
        let d = CATALOG.by_id("discord_local_storage").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Critical);
        assert!(d.mitre_techniques.contains(&"T1539"));
    }

    #[test]
    fn signal_database_exists() {
        let d = CATALOG.by_id("signal_database").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Critical);
    }

    #[test]
    fn signal_config_json_exists() {
        let d = CATALOG.by_id("signal_config_json").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Critical);
        assert!(d.mitre_techniques.contains(&"T1552.001"));
    }

    #[test]
    fn windows_search_edb_exists() {
        assert!(CATALOG.by_id("windows_search_edb").is_some());
    }

    #[test]
    fn event_transcript_db_exists() {
        assert!(CATALOG.by_id("event_transcript_db").is_some());
    }

    #[test]
    fn certutil_cache_exists() {
        let d = CATALOG.by_id("certutil_cache").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Critical);
        assert!(d.mitre_techniques.contains(&"T1105"));
    }

    #[test]
    fn sdb_custom_files_exists() {
        let d = CATALOG.by_id("sdb_custom_files").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Critical);
        assert!(d.mitre_techniques.contains(&"T1546.011"));
    }

    #[test]
    fn wer_reports_exists() {
        assert!(CATALOG.by_id("wer_reports").is_some());
    }

    #[test]
    fn iis_w3svc_logs_exists() {
        let d = CATALOG.by_id("iis_w3svc_logs").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Critical);
        assert!(d.mitre_techniques.contains(&"T1190"));
    }

    #[test]
    fn iis_config_applicationhost_exists() {
        let d = CATALOG.by_id("iis_config_applicationhost").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Critical);
    }

    #[test]
    fn dns_debug_log_exists() {
        let d = CATALOG.by_id("dns_debug_log").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Critical);
        assert!(d.mitre_techniques.contains(&"T1071.004"));
    }

    #[test]
    fn dhcp_server_log_exists() {
        assert!(CATALOG.by_id("dhcp_server_log").is_some());
    }

    #[test]
    fn sum_db_exists() {
        let d = CATALOG.by_id("sum_db").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Critical);
    }

    #[test]
    fn copilot_recall_ukg_exists() {
        let d = CATALOG.by_id("copilot_recall_ukg").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Critical);
        assert!(d.mitre_techniques.contains(&"T1113"));
    }

    #[test]
    fn ntuser_dat_file_exists() {
        let d = CATALOG.by_id("ntuser_dat_file").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Critical);
        assert!(d.mitre_techniques.contains(&"T1012"));
    }

    #[test]
    fn usrclass_dat_file_exists() {
        assert!(CATALOG.by_id("usrclass_dat_file").is_some());
    }

    #[test]
    fn all_phase2b_ids_present() {
        let ids = [
            "chrome_history",
            "chrome_web_data",
            "edge_chromium_history",
            "edge_chromium_login_data",
            "firefox_places",
            "firefox_form_history",
            "firefox_session_restore",
            "psreadline_history",
            "psreadline_history_system",
            "powershell_transcripts",
            "teamviewer_connection_log",
            "teamviewer_app_log",
            "anydesk_trace_user",
            "anydesk_trace_system",
            "anydesk_connection_trace",
            "anydesk_file_transfer_log",
            "screenconnect_session_db",
            "rustdesk_logs",
            "dropbox_instance_db",
            "onedrive_metadata",
            "google_drive_fs_metadata",
            "megasync_data",
            "teams_indexed_db",
            "slack_indexed_db",
            "discord_local_storage",
            "signal_database",
            "signal_config_json",
            "windows_search_edb",
            "event_transcript_db",
            "certutil_cache",
            "sdb_custom_files",
            "wer_reports",
            "iis_w3svc_logs",
            "iis_config_applicationhost",
            "dns_debug_log",
            "dhcp_server_log",
            "sum_db",
            "copilot_recall_ukg",
            "ntuser_dat_file",
            "usrclass_dat_file",
            "teamviewer_app_log",
        ];
        for id in &ids {
            assert!(
                CATALOG.by_id(id).is_some(),
                "missing phase-2b artifact: {id}"
            );
        }
    }
}

#[cfg(test)]
mod phase3_persistence_tests {
    use super::*;

    #[test]
    fn catalog_count_includes_phase3() {
        // phase3 adds 7 net-new artifacts not already in catalog (354 → 361)
        // Note: winlogon_shell, winlogon_userinit, appinit_dlls, boot_execute,
        //       ifeo_debugger, netsh_helper_dlls, mountpoints2 were already present.
        assert_eq!(CATALOG.list().len(), 6624);
    }

    // ── Pre-existing artifacts verified present ───────────────────────────────

    #[test]
    fn winlogon_shell_already_exists() {
        let d = CATALOG.by_id("winlogon_shell").unwrap();
        assert!(d.mitre_techniques.contains(&"T1547.004") || d.mitre_techniques.contains(&"T1547"));
    }

    #[test]
    fn winlogon_userinit_already_exists() {
        let d = CATALOG.by_id("winlogon_userinit").unwrap();
        assert!(d.mitre_techniques.contains(&"T1547.004") || d.mitre_techniques.contains(&"T1547"));
    }

    #[test]
    fn appinit_dlls_already_exists() {
        let d = CATALOG.by_id("appinit_dlls").unwrap();
        assert!(d.mitre_techniques.contains(&"T1546.010") || d.mitre_techniques.contains(&"T1546"));
    }

    #[test]
    fn boot_execute_already_exists() {
        let d = CATALOG.by_id("boot_execute").unwrap();
        assert!(d.mitre_techniques.contains(&"T1547.001") || d.mitre_techniques.contains(&"T1542"));
    }

    #[test]
    fn ifeo_debugger_already_exists() {
        let d = CATALOG.by_id("ifeo_debugger").unwrap();
        assert!(d.mitre_techniques.contains(&"T1546.012") || d.mitre_techniques.contains(&"T1546"));
    }

    #[test]
    fn netsh_helper_dlls_already_exists() {
        let d = CATALOG.by_id("netsh_helper_dlls").unwrap();
        assert!(d.mitre_techniques.contains(&"T1546.007") || d.mitre_techniques.contains(&"T1546"));
    }

    #[test]
    fn mountpoints2_already_exists() {
        let d = CATALOG.by_id("mountpoints2").unwrap();
        assert!(
            d.mitre_techniques.contains(&"T1091")
                || d.mitre_techniques.contains(&"T1135")
                || d.mitre_techniques.contains(&"T1025")
        );
    }

    // ── Net-new phase-3 artifacts (ext3) ─────────────────────────────────────

    #[test]
    fn active_setup_exists() {
        let d = CATALOG.by_id("active_setup").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Critical);
        assert!(d.mitre_techniques.contains(&"T1547.014"));
    }

    #[test]
    fn lsa_auth_packages_exists() {
        let d = CATALOG.by_id("lsa_auth_packages").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Critical);
        assert!(d.mitre_techniques.contains(&"T1547.002"));
    }

    #[test]
    fn lsa_security_packages_exists() {
        let d = CATALOG.by_id("lsa_security_packages").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Critical);
        assert!(d.mitre_techniques.contains(&"T1547.005"));
    }

    #[test]
    fn lsa_notification_packages_exists() {
        let d = CATALOG.by_id("lsa_notification_packages").unwrap();
        assert!(d.mitre_techniques.contains(&"T1547.008"));
    }

    #[test]
    fn screensaver_persistence_exists() {
        let d = CATALOG.by_id("screensaver_persistence").unwrap();
        assert!(d.mitre_techniques.contains(&"T1546.002"));
    }

    #[test]
    fn print_monitor_dlls_exists() {
        let d = CATALOG.by_id("print_monitor_dlls").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Critical);
        assert!(d.mitre_techniques.contains(&"T1547.010"));
    }

    #[test]
    fn services_hklm_exists() {
        let d = CATALOG.by_id("services_hklm").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Critical);
        assert!(d.mitre_techniques.contains(&"T1543.003"));
    }

    #[test]
    fn all_phase3_ids_present() {
        let ids = [
            // pre-existing (verified above)
            "winlogon_shell",
            "winlogon_userinit",
            "appinit_dlls",
            "boot_execute",
            "ifeo_debugger",
            "netsh_helper_dlls",
            "mountpoints2",
            // net-new from ext3
            "active_setup",
            "lsa_auth_packages",
            "lsa_security_packages",
            "lsa_notification_packages",
            "screensaver_persistence",
            "print_monitor_dlls",
            "services_hklm",
        ];
        for id in &ids {
            assert!(
                CATALOG.by_id(id).is_some(),
                "missing phase-3 artifact: {id}"
            );
        }
    }
}

#[cfg(test)]
mod batch_i_tests {
    use crate::catalog::{TriagePriority, CATALOG};

    #[test]
    fn batch_i_artifacts_all_present() {
        let ids = [
            "linux_dmesg_log",
            "linux_kern_log",
            "linux_proc_kallsyms",
            "linux_proc_net_tcp",
            "linux_proc_net_tcp6",
            "linux_proc_net_udp",
            "linux_proc_net_unix",
            "linux_lsof_output",
            "linux_ss_output",
            "linux_chkrootkit_output",
            "linux_rkhunter_log",
            "linux_sysctl_conf",
            "windows_crash_dump",
            "windows_minidump",
            "amcache_driver",
            "wer_report_queue",
            "windows_notification_db",
            "amcache_shortcut",
            "linux_fail2ban_log",
        ];
        for id in &ids {
            assert!(
                CATALOG.by_id(id).is_some(),
                "missing batch-I artifact: {id}"
            );
        }
    }

    #[test]
    fn linux_dmesg_log_is_critical_for_rootkit_detection() {
        let d = CATALOG.by_id("linux_dmesg_log").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Critical);
        assert!(d.mitre_techniques.contains(&"T1014"));
    }

    #[test]
    fn linux_proc_net_tcp_enables_rootkit_comparison() {
        let d = CATALOG.by_id("linux_proc_net_tcp").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Critical);
        assert!(d.mitre_techniques.contains(&"T1014"));
    }

    #[test]
    fn amcache_driver_is_critical_for_byovd() {
        let d = CATALOG.by_id("amcache_driver").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Critical);
        assert!(d.mitre_techniques.contains(&"T1068"));
    }
}

// ── JumpList / LNK enrichment from kacos2000/Jumplist-Browser ────────────────
// Source: https://github.com/kacos2000/Jumplist-Browser
// Key forensic additions: BEEF0004 extension (48-bit MFT record, 64-bit file
// size, OS type hint), DestList MRU rank, per-entry Arguments field,
// AppID hash registry index (JumplistData), TaskBand pinned items.
mod tests_jump_list_enrichment {
    use super::*;

    // ── JUMP_LIST_AUTO field enrichment ───────────────────────────────────────

    #[test]
    fn jump_list_auto_has_mft_record_field() {
        // BEEF0004 extension provides 48-bit MFT record number split across
        // two sub-fields (low 32 bits + high 16 bits). Needed to pivot from
        // jump list entry to $MFT for timestomping analysis.
        let field_names: Vec<&str> = JUMP_LIST_AUTO.fields.iter().map(|f| f.name).collect();
        assert!(
            field_names.contains(&"mft_record_number"),
            "jump_list_auto fields must include mft_record_number (48-bit from BEEF0004); \
             got: {field_names:?}"
        );
    }

    #[test]
    fn jump_list_auto_has_file_size_64bit_field() {
        // LNK header has 32-bit FileSize (truncates for files >4 GB).
        // BEEF0004 adds high 32 bits to reconstruct the full 64-bit size.
        // Critical for large file identification in data-exfiltration cases.
        let field_names: Vec<&str> = JUMP_LIST_AUTO.fields.iter().map(|f| f.name).collect();
        assert!(
            field_names.contains(&"file_size_64bit"),
            "jump_list_auto fields must include file_size_64bit (BEEF0004 reconstruction); \
             got: {field_names:?}"
        );
    }

    #[test]
    fn jump_list_auto_has_mru_rank_field() {
        // DestList entry order = MRU ranking. The most recently accessed file
        // is rank 0. Analysts need this to reconstruct access chronology.
        let field_names: Vec<&str> = JUMP_LIST_AUTO.fields.iter().map(|f| f.name).collect();
        assert!(
            field_names.contains(&"mru_rank"),
            "jump_list_auto fields must include mru_rank (DestList entry order); \
             got: {field_names:?}"
        );
    }

    #[test]
    fn jump_list_auto_cites_kacos2000() {
        // kacos2000/Jumplist-Browser is the most detailed public reference for
        // DestList entry structure and BEEF0004 field-level documentation.
        assert!(
            JUMP_LIST_AUTO
                .sources
                .iter()
                .any(|s| s.contains("kacos2000")),
            "jump_list_auto must cite github.com/kacos2000/Jumplist-Browser; \
             got: {:?}",
            JUMP_LIST_AUTO.sources
        );
    }

    // ── JUMP_LIST_CUSTOM field enrichment ─────────────────────────────────────

    #[test]
    fn jump_list_custom_has_group_name_field() {
        // CustomDestinations files organise entries into named groups
        // (e.g. "Tasks", "Recent", "Pinned"). Group name is essential context.
        let field_names: Vec<&str> = JUMP_LIST_CUSTOM.fields.iter().map(|f| f.name).collect();
        assert!(
            field_names.contains(&"group_name"),
            "jump_list_custom fields must include group_name (jump list category); \
             got: {field_names:?}"
        );
    }

    #[test]
    fn jump_list_custom_has_arguments_field() {
        // The embedded LNK StringData section carries command-line Arguments.
        // Attackers weaponise LNKs by adding malicious arguments; this field
        // is the primary indicator of a weaponised jump list entry.
        let field_names: Vec<&str> = JUMP_LIST_CUSTOM.fields.iter().map(|f| f.name).collect();
        assert!(
            field_names.contains(&"arguments"),
            "jump_list_custom fields must include arguments (LNK StringData — weaponisation \
             indicator); got: {field_names:?}"
        );
    }

    // ── LNK_FILES field enrichment ────────────────────────────────────────────

    #[test]
    fn lnk_files_has_arguments_field() {
        // LNK StringData.Arguments is the primary indicator of weaponisation.
        // A normal LNK has empty arguments; a malicious one may carry
        // PowerShell commands, encoded payloads, or stager URLs.
        let field_names: Vec<&str> = LNK_FILES.fields.iter().map(|f| f.name).collect();
        assert!(
            field_names.contains(&"arguments"),
            "lnk_files fields must include arguments (StringData — primary weaponisation \
             indicator); got: {field_names:?}"
        );
    }

    #[test]
    fn lnk_files_has_drive_type_field() {
        // LinkInfo.DriveType distinguishes FIXED/REMOVABLE/REMOTE source media.
        // Combined with VolumeSerialNumber, links LNK to USB artifacts and
        // MountPoints2 to reconstruct source device.
        let field_names: Vec<&str> = LNK_FILES.fields.iter().map(|f| f.name).collect();
        assert!(
            field_names.contains(&"drive_type"),
            "lnk_files fields must include drive_type (source media type); \
             got: {field_names:?}"
        );
    }

    #[test]
    fn lnk_files_has_mft_record_field() {
        // BEEF0004 extension provides 48-bit MFT record number. Allows
        // independent verification of target file identity even after path
        // changes or deletion (pivot to $MFT/$UsnJrnl).
        let field_names: Vec<&str> = LNK_FILES.fields.iter().map(|f| f.name).collect();
        assert!(
            field_names.contains(&"mft_record_number"),
            "lnk_files fields must include mft_record_number (48-bit from BEEF0004); \
             got: {field_names:?}"
        );
    }

    #[test]
    fn lnk_files_cites_kacos2000() {
        assert!(
            LNK_FILES.sources.iter().any(|s| s.contains("kacos2000")),
            "lnk_files must cite github.com/kacos2000/Jumplist-Browser for BEEF0004 field docs; \
             got: {:?}",
            LNK_FILES.sources
        );
    }

    // ── New artifacts ─────────────────────────────────────────────────────────

    #[test]
    fn jump_list_appid_registry_exists() {
        // HKCU\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData
        // maps 8-byte CRC64 AppID hashes to application display names.
        // Required to resolve AppID filenames back to human-readable app names
        // without consulting an external AppID lookup database.
        assert!(
            CATALOG.by_id("jump_list_appid_registry").is_some(),
            "jump_list_appid_registry artifact must exist in catalog"
        );
    }

    #[test]
    fn taskband_favorites_exists() {
        // HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband\Favorites
        // stores taskbar-pinned application order as a binary blob.
        // Reveals which applications were pinned and their taskbar position —
        // attackers may pin malicious tools to ensure they survive reboots.
        assert!(
            CATALOG.by_id("taskband_favorites").is_some(),
            "taskband_favorites artifact must exist in catalog"
        );
    }
}

// ── Windows Timeline + Windows Search enrichment ──────────────────────────────

#[cfg(test)]
mod tests_timeline_search_enrichment {
    use super::*;

    // ── Windows Timeline (ActivitiesCache.db) ─────────────────────────────────

    #[test]
    fn windows_timeline_does_not_use_srum_fields() {
        // SRUM_FIELDS is the wrong schema for ActivitiesCache.db.
        // SRUM is an ESE database (SRUDB.dat) tracking network/CPU/energy by app;
        // Windows Timeline is a SQLite database tracking app focus and clipboard.
        // They share nothing in their schema.
        let srum_field_names: Vec<&str> = SRUM_DB.fields.iter().map(|f| f.name).collect();
        let timeline_field_names: Vec<&str> =
            WINDOWS_TIMELINE.fields.iter().map(|f| f.name).collect();
        assert!(
            timeline_field_names != srum_field_names,
            "windows_timeline must not reuse SRUM_FIELDS — different database, different schema; \
             both currently have: {timeline_field_names:?}"
        );
    }

    #[test]
    fn windows_timeline_has_activity_type_field() {
        // Activities.Activity_Type (int): 5=AppInFocus, 6=AppLifecycle, 11=UserActivity,
        // 12=Notification, 16=CopyPaste. The type determines how to decode payload_json.
        // Source: https://kacos2000.github.io/WindowsTimeline/WindowsTimeline.pdf
        let field_names: Vec<&str> = WINDOWS_TIMELINE.fields.iter().map(|f| f.name).collect();
        assert!(
            field_names.contains(&"activity_type"),
            "windows_timeline fields must include activity_type (int, distinguishes focus/clipboard/notification); \
             got: {field_names:?}"
        );
    }

    #[test]
    fn windows_timeline_has_start_time_field() {
        // Activities.StartTime and EndTime are Unix epoch integers.
        // Duration = EndTime - StartTime gives app focus duration — critical for
        // establishing what the user was doing during an incident window.
        // Source: https://kacos2000.github.io/WindowsTimeline/WindowsTimeline.pdf
        let field_names: Vec<&str> = WINDOWS_TIMELINE.fields.iter().map(|f| f.name).collect();
        assert!(
            field_names.contains(&"start_time"),
            "windows_timeline fields must include start_time (Unix epoch); \
             got: {field_names:?}"
        );
    }

    #[test]
    fn windows_timeline_has_payload_json_field() {
        // Activities.Payload is a JSON blob whose schema depends on activity_type.
        // For type 16 (CopyPaste), it contains clipboard text — forensically critical
        // for credential exfiltration and data staging detection.
        // Source: https://kacos2000.github.io/WindowsTimeline/WindowsTimeline.pdf
        let field_names: Vec<&str> = WINDOWS_TIMELINE.fields.iter().map(|f| f.name).collect();
        assert!(
            field_names.contains(&"payload_json"),
            "windows_timeline fields must include payload_json (type-specific JSON blob); \
             got: {field_names:?}"
        );
    }

    #[test]
    fn windows_timeline_has_platform_device_id_field() {
        // Activities.PlatformDeviceId is a GUID identifying the device that created
        // the activity. Cross-references DeviceCache registry for human-readable name.
        // Key for multi-device investigations — was this activity local or synced?
        // Cloud sync disabled July 2021 for MSA accounts (local db persists).
        // Source: https://kacos2000.github.io/WindowsTimeline/WindowsTimeline.pdf
        let field_names: Vec<&str> = WINDOWS_TIMELINE.fields.iter().map(|f| f.name).collect();
        assert!(
            field_names.contains(&"platform_device_id"),
            "windows_timeline fields must include platform_device_id (device GUID); \
             got: {field_names:?}"
        );
    }

    #[test]
    fn windows_timeline_cites_kacos2000() {
        // kacos2000/WindowsTimeline is the authoritative source for ActivitiesCache.db
        // schema (table names, column types, activity_type enum values).
        assert!(
            WINDOWS_TIMELINE
                .sources
                .iter()
                .any(|s| s.contains("kacos2000")),
            "windows_timeline must cite github.com/kacos2000/WindowsTimeline; \
             got: {:?}",
            WINDOWS_TIMELINE.sources
        );
    }

    #[test]
    fn windows_timeline_devicecache_registry_exists() {
        // HKCU\Software\Microsoft\Windows\CurrentVersion\CloudStore\
        //   Store\Cache\DefaultAccount\*\Current\Data
        // DeviceCache resolves PlatformDeviceId GUIDs to human-readable device names.
        // Without this lookup, platform_device_id is an opaque GUID.
        // Source: https://kacos2000.github.io/WindowsTimeline/WindowsTimeline.pdf
        assert!(
            CATALOG.by_id("windows_timeline_devicecache").is_some(),
            "windows_timeline_devicecache registry artifact must exist in catalog \
             (resolves PlatformDeviceId GUID to device name)"
        );
    }

    // ── Windows Search Index ───────────────────────────────────────────────────

    #[test]
    fn windows_search_edb_exists() {
        // Windows.edb: ESE database at
        //   %PROGRAMDATA%\Microsoft\Windows Search\Data\Applications\Windows\Windows.edb
        // Contains SystemIndex_0A table: every file/folder indexed by Windows Search.
        // System_Search_GatherTime = last time Windows indexed the file — forensically
        // useful because it is independent of $MFT timestamps and can reveal when a
        // file existed even after deletion.
        // Source: https://github.com/kacos2000/WinEDB
        assert!(
            CATALOG.by_id("windows_search_edb").is_some(),
            "windows_search_edb artifact must exist in catalog \
             (Windows Search ESE index, Win7–Win10 21H2)"
        );
    }

    #[test]
    fn windows_search_db_win11_exists() {
        // Win11 22H2+ migrated Windows Search from ESE to SQLite3:
        //   C:\ProgramData\Microsoft\Search\Data\Applications\Windows\windows.db
        // The migration is silently automatic — analysts must check for both files.
        // Source: https://github.com/kacos2000/WinEDB
        assert!(
            CATALOG.by_id("windows_search_db_win11").is_some(),
            "windows_search_db_win11 artifact must exist in catalog \
             (Windows Search SQLite, Win11 22H2+)"
        );
    }

    #[test]
    fn windows_search_edb_has_gather_time_field() {
        // System_Search_GatherTime is the key forensic field in Windows.edb:
        // it records when Windows Search last indexed the file, independent of
        // NTFS timestamps — survives timestamp manipulation and file deletion.
        // Source: https://github.com/kacos2000/WinEDB
        let desc = CATALOG.by_id("windows_search_edb").unwrap();
        let field_names: Vec<&str> = desc.fields.iter().map(|f| f.name).collect();
        assert!(
            field_names.contains(&"gather_time"),
            "windows_search_edb fields must include gather_time \
             (System_Search_GatherTime — timestamp-independent index time); \
             got: {field_names:?}"
        );
    }
}

mod tests_prefetch_mft_enrichment {
    use super::*;

    // ── Prefetch-Browser enrichment ─────────────────────────────────────────

    #[test]
    fn prefetch_has_volume_creation_time_field() {
        // Volumes information block stores VolumeCreationTime (FILETIME UTC) per
        // volume accessed during execution. Pivot: matches $MFT volume birth time.
        // Source: https://github.com/kacos2000/Prefetch-Browser
        let desc = CATALOG.by_id("prefetch_file").unwrap();
        let names: Vec<&str> = desc.fields.iter().map(|f| f.name).collect();
        assert!(
            names.contains(&"volume_creation_time"),
            "prefetch_file fields must include volume_creation_time \
             (FILETIME per volume in the Volumes Information block); got: {names:?}"
        );
    }

    #[test]
    fn prefetch_has_volume_serial_number_field() {
        // Volume serial number from the Volumes Information block.
        // Correlates with $VOLUME_INFORMATION in $MFT for origin-volume identification.
        // Source: https://github.com/kacos2000/Prefetch-Browser
        let desc = CATALOG.by_id("prefetch_file").unwrap();
        let names: Vec<&str> = desc.fields.iter().map(|f| f.name).collect();
        assert!(
            names.contains(&"volume_serial_number"),
            "prefetch_file fields must include volume_serial_number \
             (u32 from Volumes Information; pivot to $MFT $VOLUME_INFORMATION); got: {names:?}"
        );
    }

    #[test]
    fn prefetch_has_mft_record_number_field() {
        // File metrics entries with flag bit 0x100 set include the 48-bit MFT
        // record number of each referenced file. Pivot to $MFT for timestomping.
        // Source: https://github.com/kacos2000/Prefetch-Browser
        let desc = CATALOG.by_id("prefetch_file").unwrap();
        let names: Vec<&str> = desc.fields.iter().map(|f| f.name).collect();
        assert!(
            names.contains(&"mft_record_number"),
            "prefetch_file fields must include mft_record_number \
             (48-bit MFT ref from File Metrics entry flag 0x100); got: {names:?}"
        );
    }

    #[test]
    fn prefetch_has_format_version_field() {
        // SCCA header offset 0x0000: u32 version. Used to select correct
        // timestamp-array and run-count offsets:
        //   17 (XP), 23 (Vista/7), 26 (Win8), 30/31 (Win10/11)
        // Source: https://github.com/kacos2000/Prefetch-Browser
        let desc = CATALOG.by_id("prefetch_file").unwrap();
        let names: Vec<&str> = desc.fields.iter().map(|f| f.name).collect();
        assert!(
            names.contains(&"format_version"),
            "prefetch_file fields must include format_version \
             (SCCA u32 at offset 0: 17=XP, 23=Vista/7, 26=Win8, 30/31=Win10/11); got: {names:?}"
        );
    }

    #[test]
    fn prefetch_cites_kacos2000() {
        // kacos2000/Prefetch-Browser documents the MAM compressed wrapper,
        // Volumes Information block, and File Metrics MFT reference flag 0x100.
        let desc = CATALOG.by_id("prefetch_file").unwrap();
        let cites_kacos = desc
            .sources
            .iter()
            .any(|s| s.contains("kacos2000") && s.contains("Prefetch"));
        assert!(
            cites_kacos,
            "prefetch_file sources must cite kacos2000/Prefetch-Browser; got: {:?}",
            desc.sources
        );
    }

    #[test]
    fn prefetch_cites_libscca() {
        // libscca is the authoritative format spec for all SCCA versions.
        // Source: https://github.com/libyal/libscca
        let desc = CATALOG.by_id("prefetch_file").unwrap();
        let cites_libscca = desc
            .sources
            .iter()
            .any(|s| s.contains("libscca") || s.contains("libyal"));
        assert!(
            cites_libscca,
            "prefetch_file sources must cite libscca (authoritative SCCA format spec); got: {:?}",
            desc.sources
        );
    }

    // ── MFT-Browser enrichment ───────────────────────────────────────────────

    #[test]
    fn mft_has_lsn_field() {
        // $LogFile Sequence Number at MFT record header offset 0x08 (uint64).
        // Increments on every modification — chronological ordering without
        // relying on timestamps. Key for detecting out-of-order $LogFile entries.
        // Source: https://github.com/kacos2000/MFT_Browser
        let desc = CATALOG.by_id("mft_file").unwrap();
        let names: Vec<&str> = desc.fields.iter().map(|f| f.name).collect();
        assert!(
            names.contains(&"lsn"),
            "mft_file fields must include lsn \
             ($LogFile Sequence Number at header 0x08, uint64; chronological anchor); got: {names:?}"
        );
    }

    #[test]
    fn mft_has_fn_changed_and_accessed_fields() {
        // MFT_Browser exposes all 8 MACE timestamps: 4 from $STANDARD_INFORMATION
        // and 4 from $FILE_NAME. fn_changed and fn_accessed complete the FN set —
        // these are kernel-maintained and harder to forge than SI equivalents.
        // Source: https://github.com/kacos2000/MFT_Browser
        let desc = CATALOG.by_id("mft_file").unwrap();
        let names: Vec<&str> = desc.fields.iter().map(|f| f.name).collect();
        assert!(
            names.contains(&"fn_changed"),
            "mft_file fields must include fn_changed \
             ($FILE_NAME MFT-record-changed time, kernel-maintained); got: {names:?}"
        );
        assert!(
            names.contains(&"fn_accessed"),
            "mft_file fields must include fn_accessed \
             ($FILE_NAME last-accessed time, kernel-maintained); got: {names:?}"
        );
    }

    #[test]
    fn mft_has_hard_link_count_field() {
        // Hard link count at MFT record header offset 0x12 (uint16).
        // Count > 1 = multiple directory entries point to this record.
        // Anti-forensic use: hard links to executables in innocuous locations.
        // Source: https://github.com/kacos2000/MFT_Browser
        let desc = CATALOG.by_id("mft_file").unwrap();
        let names: Vec<&str> = desc.fields.iter().map(|f| f.name).collect();
        assert!(
            names.contains(&"hard_link_count"),
            "mft_file fields must include hard_link_count \
             (uint16 at header 0x12; > 1 indicates multiple directory entries); got: {names:?}"
        );
    }

    #[test]
    fn mft_has_record_slack_field() {
        // Record slack = PhysicalSize - LogicalSize.
        // Carved from residual bytes at end of a 1024- or 4096-byte record.
        // May contain prior attribute remnants after file metadata shrinks.
        // Source: https://github.com/kacos2000/MFT_Browser
        let desc = CATALOG.by_id("mft_file").unwrap();
        let names: Vec<&str> = desc.fields.iter().map(|f| f.name).collect();
        assert!(
            names.contains(&"record_slack"),
            "mft_file fields must include record_slack \
             (PhysicalSize - LogicalSize; may contain prior attribute remnants); got: {names:?}"
        );
    }

    #[test]
    fn mft_has_usn_field() {
        // USN value from $STANDARD_INFORMATION at SI offset +64 (8 bytes).
        // Links this MFT record to its entry in $UsnJrnl:$J.
        // Source: https://github.com/kacos2000/MFT_Browser
        let desc = CATALOG.by_id("mft_file").unwrap();
        let names: Vec<&str> = desc.fields.iter().map(|f| f.name).collect();
        assert!(
            names.contains(&"usn"),
            "mft_file fields must include usn \
             ($SI offset +64, links record to $UsnJrnl:$J entry); got: {names:?}"
        );
    }

    #[test]
    fn mft_cites_kacos2000() {
        // kacos2000/MFT_Browser is the authoritative source for:
        // all NTFS attribute offsets, record slack, LSN, 8-timestamp dual set,
        // hard link count, USN in $SI, and $Object_ID UUID creation time.
        let desc = CATALOG.by_id("mft_file").unwrap();
        let cites_kacos = desc
            .sources
            .iter()
            .any(|s| s.contains("kacos2000") && s.contains("MFT"));
        assert!(
            cites_kacos,
            "mft_file sources must cite kacos2000/MFT_Browser; got: {:?}",
            desc.sources
        );
    }
}

// ── Recycle Bin $I schema enrichment ─────────────────────────────────────────
//
// Source: https://github.com/akhil-dara/RecycleBin-Forensic-Explorer
// $I binary format: version(u64@0) | size(u64@8) | deletion_time(FILETIME@16)
//                   | original_path(UTF-16LE@24 v1, @28 v2)
//
#[cfg(test)]
mod tests_recycle_bin_enrichment {
    use crate::catalog::CATALOG;

    fn desc() -> &'static crate::catalog::ArtifactDescriptor {
        CATALOG
            .by_id("recycle_bin")
            .expect("recycle_bin must exist")
    }

    #[test]
    fn recycle_bin_has_version_field() {
        // uint64 at offset 0: 1=Vista/7/8/8.1, 2=Win10/11 (different path offset)
        let d = desc();
        let has_version = d
            .fields
            .iter()
            .any(|f| f.name == "version" || f.name == "i_version");
        assert!(
            has_version,
            "recycle_bin fields must include version (uint64 @0); got: {:?}",
            d.fields.iter().map(|f| f.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn recycle_bin_has_original_size_field() {
        // uint64 at offset 8: deleted file size in bytes
        let d = desc();
        let has_field = d
            .fields
            .iter()
            .any(|f| f.name.contains("size") || f.name == "original_size");
        assert!(
            has_field,
            "recycle_bin fields must include original_size (uint64 @8); got: {:?}",
            d.fields.iter().map(|f| f.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn recycle_bin_has_deletion_time_field() {
        // FILETIME at offset 16: moment the file was sent to Recycle.Bin
        let d = desc();
        let has_field = d
            .fields
            .iter()
            .any(|f| f.name.contains("deletion") || f.name.contains("deleted_time"));
        assert!(
            has_field,
            "recycle_bin fields must include deletion_time (FILETIME @16); got: {:?}",
            d.fields.iter().map(|f| f.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn recycle_bin_has_original_path_field() {
        // UTF-16LE string at offset 24 (v1) or 28 (v2): full pre-deletion Windows path
        let d = desc();
        let has_field = d
            .fields
            .iter()
            .any(|f| f.name.contains("path") || f.name == "original_path");
        assert!(
            has_field,
            "recycle_bin fields must include original_path (UTF-16LE); got: {:?}",
            d.fields.iter().map(|f| f.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn recycle_bin_has_sid_field() {
        // SID from directory name: S-1-5-21-{Authority}-{Sub1}-{Sub2}-{RID}
        // pivot to SAM hive for username resolution
        let d = desc();
        let has_field = d.fields.iter().any(|f| f.name.contains("sid"));
        assert!(
            has_field,
            "recycle_bin fields must include sid (directory attribution); got: {:?}",
            d.fields.iter().map(|f| f.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn recycle_bin_has_r_file_exists_field() {
        // bool: $R file presence (content recoverable vs metadata-only)
        let d = desc();
        let has_field = d
            .fields
            .iter()
            .any(|f| f.name.contains("r_file") || f.name.contains("content_recoverable"));
        assert!(
            has_field,
            "recycle_bin fields must include r_file_exists (content recovery indicator); got: {:?}",
            d.fields.iter().map(|f| f.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn recycle_bin_cites_rbcmd() {
        // EricZimmerman/RBCmd is the standard tool for $I parsing
        let d = desc();
        let cites = d.sources.iter().any(|s| s.contains("RBCmd"));
        assert!(
            cites,
            "recycle_bin sources must cite RBCmd; got: {:?}",
            d.sources
        );
    }

    #[test]
    fn recycle_bin_cites_akhil_dara() {
        // Binary format reference: $I offset schema and version semantics
        let d = desc();
        let cites = d
            .sources
            .iter()
            .any(|s| s.contains("akhil-dara") || s.contains("RecycleBin-Forensic"));
        assert!(
            cites,
            "recycle_bin sources must cite akhil-dara/RecycleBin-Forensic-Explorer; got: {:?}",
            d.sources
        );
    }

    #[test]
    fn recycle_bin_triage_is_high_or_critical() {
        use crate::catalog::TriagePriority;
        let d = desc();
        let is_high_value = matches!(
            d.triage_priority,
            TriagePriority::High | TriagePriority::Critical
        );
        assert!(
            is_high_value,
            "recycle_bin triage should be High or Critical — $I files reveal deletion time \
             and original path even after Recycle Bin emptied; got: {:?}",
            d.triage_priority
        );
    }

    #[test]
    fn recycle_bin_has_t1078_003_for_user_attribution() {
        // T1078.003 Valid Accounts: Local Accounts — SID → username pivoting
        let d = desc();
        let has_t = d.mitre_techniques.iter().any(|t| t.starts_with("T1078"));
        assert!(
            has_t,
            "recycle_bin should include T1078 (user attribution via SID); got: {:?}",
            d.mitre_techniques
        );
    }

    #[test]
    fn recycle_bin_related_includes_sam_users() {
        // SID in $I directory requires SAM hive for username resolution
        let d = desc();
        let has_sam = d
            .related_artifacts
            .iter()
            .any(|r| r.contains("sam") || r.contains("user"));
        assert!(
            has_sam,
            "recycle_bin related must include sam_users (SID attribution); got: {:?}",
            d.related_artifacts
        );
    }
}

#[cfg(test)]
mod tests_batch_i_presence {
    use super::*;

    #[test]
    fn catalog_has_cbs_log() {
        assert!(
            CATALOG.by_id("cbs_log").is_some(),
            "CBS_LOG missing from catalog"
        );
    }

    #[test]
    fn catalog_has_pfro_log() {
        assert!(
            CATALOG.by_id("pfro_log").is_some(),
            "PFRO_LOG missing from catalog"
        );
    }

    #[test]
    fn catalog_has_setuperr_log() {
        assert!(
            CATALOG.by_id("setuperr_log").is_some(),
            "SETUPERR_LOG missing from catalog"
        );
    }

    #[test]
    fn catalog_has_setupapi_upgrade_log() {
        assert!(
            CATALOG.by_id("setupapi_upgrade_log").is_some(),
            "SETUPAPI_UPGRADE_LOG missing from catalog"
        );
    }

    #[test]
    fn catalog_has_wer_reports_user() {
        assert!(
            CATALOG.by_id("wer_reports_user").is_some(),
            "WER_REPORTS_USER missing from catalog"
        );
    }

    #[test]
    fn catalog_has_wer_reports_system() {
        assert!(
            CATALOG.by_id("wer_reports_system").is_some(),
            "WER_REPORTS_SYSTEM missing from catalog"
        );
    }

    #[test]
    fn catalog_has_evtx_application() {
        assert!(
            CATALOG.by_id("evtx_application").is_some(),
            "EVTX_APPLICATION missing from catalog"
        );
    }

    #[test]
    fn catalog_has_evtx_dns_client() {
        assert!(
            CATALOG.by_id("evtx_dns_client").is_some(),
            "EVTX_DNS_CLIENT missing from catalog"
        );
    }

    #[test]
    fn catalog_has_evtx_terminal_services() {
        assert!(
            CATALOG.by_id("evtx_terminal_services").is_some(),
            "EVTX_TERMINAL_SERVICES missing from catalog"
        );
    }

    #[test]
    fn catalog_has_linux_kern_log() {
        assert!(
            CATALOG.by_id("linux_kern_log").is_some(),
            "LINUX_KERN_LOG missing from catalog"
        );
    }

    #[test]
    fn catalog_has_linux_dmesg() {
        assert!(
            CATALOG.by_id("linux_dmesg").is_some(),
            "LINUX_DMESG missing from catalog"
        );
    }

    #[test]
    fn catalog_has_linux_proc_net_tcp() {
        assert!(
            CATALOG.by_id("linux_proc_net_tcp").is_some(),
            "LINUX_PROC_NET_TCP missing from catalog"
        );
    }

    #[test]
    fn catalog_has_linux_proc_net_unix() {
        assert!(
            CATALOG.by_id("linux_proc_net_unix").is_some(),
            "LINUX_PROC_NET_UNIX missing from catalog"
        );
    }

    #[test]
    fn catalog_has_linux_boot_log() {
        assert!(
            CATALOG.by_id("linux_boot_log").is_some(),
            "LINUX_BOOT_LOG missing from catalog"
        );
    }

    #[test]
    fn catalog_has_linux_faillog() {
        assert!(
            CATALOG.by_id("linux_faillog").is_some(),
            "LINUX_FAILLOG missing from catalog"
        );
    }

    #[test]
    fn catalog_has_appx_packages_user() {
        assert!(
            CATALOG.by_id("appx_packages_user").is_some(),
            "APPX_PACKAGES_USER missing from catalog"
        );
    }

    #[test]
    fn catalog_has_appx_install_log() {
        assert!(
            CATALOG.by_id("appx_install_log").is_some(),
            "APPX_INSTALL_LOG missing from catalog"
        );
    }

    #[test]
    fn catalog_has_diagnostic_data_dir() {
        assert!(
            CATALOG.by_id("diagnostic_data_dir").is_some(),
            "DIAGNOSTIC_DATA_DIR missing from catalog"
        );
    }

    #[test]
    fn catalog_has_windows_update_session() {
        assert!(
            CATALOG.by_id("windows_update_session").is_some(),
            "WINDOWS_UPDATE_SESSION missing from catalog"
        );
    }

    #[test]
    fn catalog_count_includes_batch_i() {
        assert_eq!(
            CATALOG.list().len(),
            6624,
            "catalog count after batch I + quicklook + install_date + winscp + wifi + clipboard + unified_log + apfs + samsung + honda + ios14_maps + garmin"
        );
    }
}

// ── QuickLook / windows_install_date enrichment ───────────────────────────────

#[cfg(test)]
mod tests_quicklook_install_date {
    use super::*;

    // ── quicklook_thumbnails ──────────────────────────────────────────────────

    #[test]
    fn quicklook_thumbnails_exists() {
        assert!(
            CATALOG.by_id("quicklook_thumbnails").is_some(),
            "catalog must contain 'quicklook_thumbnails'"
        );
    }

    #[test]
    fn quicklook_thumbnails_is_macos() {
        let d = CATALOG.by_id("quicklook_thumbnails").unwrap();
        assert_eq!(
            d.os_scope,
            OsScope::MacOS,
            "quicklook_thumbnails must be MacOS scope"
        );
    }

    #[test]
    fn quicklook_thumbnails_path_contains_thumbnailcache() {
        let d = CATALOG.by_id("quicklook_thumbnails").unwrap();
        let fp = d.file_path.unwrap_or("");
        assert!(
            fp.contains("QuickLook.thumbnailcache") || fp.contains("thumbnailcache"),
            "file_path must reference thumbnailcache; got: {fp}"
        );
    }

    #[test]
    fn quicklook_thumbnails_has_file_path_field() {
        let d = CATALOG.by_id("quicklook_thumbnails").unwrap();
        assert!(
            d.fields.iter().any(|f| f.name == "file_path"),
            "quicklook_thumbnails fields must include 'file_path' (previewed file path from index.sqlite)"
        );
    }

    #[test]
    fn quicklook_thumbnails_has_last_hit_date_field() {
        let d = CATALOG.by_id("quicklook_thumbnails").unwrap();
        assert!(
            d.fields.iter().any(|f| f.name == "last_hit_date"),
            "quicklook_thumbnails fields must include 'last_hit_date' (timestamp from index.sqlite)"
        );
    }

    #[test]
    fn quicklook_thumbnails_has_hit_count_field() {
        let d = CATALOG.by_id("quicklook_thumbnails").unwrap();
        assert!(
            d.fields.iter().any(|f| f.name == "hit_count"),
            "quicklook_thumbnails fields must include 'hit_count' (times thumbnail was requested)"
        );
    }

    #[test]
    fn quicklook_thumbnails_triage_is_medium_or_higher() {
        let d = CATALOG.by_id("quicklook_thumbnails").unwrap();
        assert!(
            matches!(
                d.triage_priority,
                TriagePriority::Medium | TriagePriority::High | TriagePriority::Critical
            ),
            "quicklook_thumbnails triage must be Medium or higher; got {:?}",
            d.triage_priority
        );
    }

    #[test]
    fn quicklook_thumbnails_cites_az4n6() {
        let d = CATALOG.by_id("quicklook_thumbnails").unwrap();
        assert!(
            d.sources
                .iter()
                .any(|s| s.contains("az4n6") && s.contains("quicklook")),
            "quicklook_thumbnails must cite az4n6 quicklook post; sources: {:?}",
            d.sources
        );
    }

    #[test]
    fn quicklook_thumbnails_has_original_file_size_field() {
        let d = CATALOG.by_id("quicklook_thumbnails").unwrap();
        assert!(
            d.fields.iter().any(|f| f.name == "original_file_size"),
            "quicklook_thumbnails fields must include 'original_file_size' (from version BLOB plist)"
        );
    }

    #[test]
    fn quicklook_thumbnails_has_original_last_modified_field() {
        let d = CATALOG.by_id("quicklook_thumbnails").unwrap();
        assert!(
            d.fields.iter().any(|f| f.name == "original_last_modified"),
            "quicklook_thumbnails fields must include 'original_last_modified' (from version BLOB plist)"
        );
    }

    #[test]
    fn quicklook_thumbnails_cites_iacis_newcomer() {
        let d = CATALOG.by_id("quicklook_thumbnails").unwrap();
        assert!(
            d.sources.iter().any(|s| s.contains("iacis.org")),
            "quicklook_thumbnails must cite Sara Newcomer's IACIS white paper; sources: {:?}",
            d.sources
        );
    }

    #[test]
    fn quicklook_thumbnails_index_sqlite_source_resolves() {
        let d = CATALOG.by_id("quicklook_thumbnails").unwrap();
        // The correct URL for the index.sqlite blog post is the May 2016 post
        assert!(
            d.sources
                .iter()
                .any(|s| s.contains("az4n6") && s.contains("2016/05")),
            "quicklook_thumbnails must cite the May 2016 az4n6 post (2016/05/quicklook-python-parser); \
             the 2016/01 URL is a dead link; sources: {:?}",
            d.sources
        );
    }

    #[test]
    fn quicklook_thumbnails_meaning_mentions_removable_media() {
        let d = CATALOG.by_id("quicklook_thumbnails").unwrap();
        let meaning = d.meaning.to_lowercase();
        assert!(
            meaning.contains("removable")
                || meaning.contains("external")
                || meaning.contains("thumb drive"),
            "meaning must note that QuickLook records files from removable/external media; got: {}",
            d.meaning
        );
    }

    // ── windows_install_date ──────────────────────────────────────────────────

    #[test]
    fn windows_install_date_exists() {
        assert!(
            CATALOG.by_id("windows_install_date").is_some(),
            "catalog must contain 'windows_install_date'"
        );
    }

    #[test]
    fn windows_install_date_key_path_is_current_version() {
        let d = CATALOG.by_id("windows_install_date").unwrap();
        assert!(
            d.key_path.contains("CurrentVersion"),
            "key_path must reference CurrentVersion; got: {}",
            d.key_path
        );
    }

    #[test]
    fn windows_install_date_has_install_date_field() {
        let d = CATALOG.by_id("windows_install_date").unwrap();
        assert!(
            d.fields.iter().any(|f| f.name == "install_date"),
            "windows_install_date fields must include 'install_date' (REG_DWORD Unix epoch)"
        );
    }

    #[test]
    fn windows_install_date_meaning_mentions_feature_update() {
        let d = CATALOG.by_id("windows_install_date").unwrap();
        let meaning = d.meaning.to_lowercase();
        assert!(
            meaning.contains("feature update") || meaning.contains("1607"),
            "meaning must warn about Feature Update reset; got: {}",
            d.meaning
        );
    }

    #[test]
    fn windows_install_date_triage_is_low() {
        let d = CATALOG.by_id("windows_install_date").unwrap();
        assert_eq!(
            d.triage_priority,
            TriagePriority::Low,
            "windows_install_date triage must be Low (unreliable without corroboration)"
        );
    }

    #[test]
    fn windows_install_date_cites_az4n6() {
        let d = CATALOG.by_id("windows_install_date").unwrap();
        assert!(
            d.sources
                .iter()
                .any(|s| s.contains("az4n6") && s.contains("windows-lies")),
            "windows_install_date must cite az4n6 'when-windows-lies' post; sources: {:?}",
            d.sources
        );
    }

    #[test]
    fn windows_install_date_meaning_mentions_systeminfo() {
        let d = CATALOG.by_id("windows_install_date").unwrap();
        let meaning = d.meaning.to_lowercase();
        assert!(
            meaning.contains("systeminfo"),
            "meaning must warn that `systeminfo` command also shows the incorrect date; got: {}",
            d.meaning
        );
    }

    #[test]
    fn windows_install_date_meaning_mentions_spoliation_risk() {
        let d = CATALOG.by_id("windows_install_date").unwrap();
        let meaning = d.meaning.to_lowercase();
        assert!(
            meaning.contains("spoliation"),
            "meaning must warn about false spoliation conclusions; got: {}",
            d.meaning
        );
    }

    #[test]
    fn windows_install_date_has_install_time_field() {
        let d = CATALOG.by_id("windows_install_date").unwrap();
        assert!(
            d.fields.iter().any(|f| f.name == "install_time"),
            "windows_install_date fields must include 'install_time' (REG_QWORD FILETIME companion)"
        );
    }

    #[test]
    fn windows_install_date_meaning_mentions_clone_image_caveat() {
        let d = CATALOG.by_id("windows_install_date").unwrap();
        let meaning = d.meaning.to_lowercase();
        assert!(
            meaning.contains("clone") || meaning.contains("image"),
            "meaning must note that corporate clones/images also produce misleading install dates; got: {}",
            d.meaning
        );
    }

    // ── count ─────────────────────────────────────────────────────────────────

    #[test]
    fn catalog_count_includes_quicklook_and_install_date() {
        assert_eq!(
            CATALOG.list().len(),
            6624,
            "catalog count after quicklook + install_date + winscp + wifi + clipboard + unified_log + apfs + samsung + honda + ios14_maps + garmin"
        );
    }
}

// ── winscp_ini lateral-movement descriptor ────────────────────────────────────

#[cfg(test)]
mod tests_winscp_ini {
    use super::*;

    #[test]
    fn winscp_ini_exists() {
        assert!(
            CATALOG.by_id("winscp_ini").is_some(),
            "catalog must contain 'winscp_ini'"
        );
    }

    #[test]
    fn winscp_ini_is_file_artifact() {
        let d = CATALOG.by_id("winscp_ini").unwrap();
        assert_eq!(
            d.artifact_type,
            ArtifactType::File,
            "winscp_ini must be a File artifact"
        );
    }

    #[test]
    fn winscp_ini_file_path_contains_winscp_ini() {
        let d = CATALOG.by_id("winscp_ini").unwrap();
        let fp = d.file_path.unwrap_or("");
        assert!(
            fp.contains("WinSCP.ini") || fp.contains("winscp.ini"),
            "file_path must reference WinSCP.ini; got: {fp}"
        );
    }

    #[test]
    fn winscp_ini_triage_is_high() {
        let d = CATALOG.by_id("winscp_ini").unwrap();
        assert_eq!(
            d.triage_priority,
            TriagePriority::High,
            "winscp_ini triage must be High (lateral movement evidence)"
        );
    }

    #[test]
    fn winscp_ini_has_connected_hosts_field() {
        let d = CATALOG.by_id("winscp_ini").unwrap();
        assert!(
            d.fields.iter().any(|f| f.name == "connected_hosts"),
            "winscp_ini fields must include 'connected_hosts' \
            ([Configuration\\CDCache] — all hosts connected to, even without saving session)"
        );
    }

    #[test]
    fn winscp_ini_has_local_target_dirs_field() {
        let d = CATALOG.by_id("winscp_ini").unwrap();
        assert!(
            d.fields.iter().any(|f| f.name == "local_target_dirs"),
            "winscp_ini fields must include 'local_target_dirs' \
            ([Configuration\\History\\LocalTarget] — exfil staging directories)"
        );
    }

    #[test]
    fn winscp_ini_has_last_local_path_field() {
        let d = CATALOG.by_id("winscp_ini").unwrap();
        assert!(
            d.fields.iter().any(|f| f.name == "last_local_path"),
            "winscp_ini fields must include 'last_local_path' \
            ([Configuration\\Interface\\Commander\\LocalPanel] LastPath)"
        );
    }

    #[test]
    fn winscp_ini_has_session_hostname_field() {
        let d = CATALOG.by_id("winscp_ini").unwrap();
        assert!(
            d.fields.iter().any(|f| f.name == "session_hostname"),
            "winscp_ini fields must include 'session_hostname' \
            ([Sessions\\*] HostName — only present if session was saved)"
        );
    }

    #[test]
    fn winscp_ini_has_session_password_field() {
        let d = CATALOG.by_id("winscp_ini").unwrap();
        assert!(
            d.fields.iter().any(|f| f.name == "session_password"),
            "winscp_ini fields must include 'session_password' \
            (obfuscated, reversible — XOR-based, see winscp/winscp Security.cpp)"
        );
    }

    #[test]
    fn winscp_ini_has_exfil_mitre() {
        let d = CATALOG.by_id("winscp_ini").unwrap();
        assert!(
            d.mitre_techniques.contains(&"T1048"),
            "winscp_ini mitre_techniques must include T1048 \
            (Exfiltration Over Alternative Protocol); got: {:?}",
            d.mitre_techniques
        );
    }

    #[test]
    fn winscp_ini_has_lateral_movement_mitre() {
        let d = CATALOG.by_id("winscp_ini").unwrap();
        assert!(
            d.mitre_techniques.contains(&"T1021.004"),
            "winscp_ini mitre_techniques must include T1021.004 (SSH lateral movement); \
            got: {:?}",
            d.mitre_techniques
        );
    }

    #[test]
    fn winscp_ini_cites_az4n6_lateral_movement() {
        let d = CATALOG.by_id("winscp_ini").unwrap();
        assert!(
            d.sources
                .iter()
                .any(|s| s.contains("az4n6") && s.contains("winscp")),
            "winscp_ini must cite az4n6 WinSCP lateral movement post; sources: {:?}",
            d.sources
        );
    }

    #[test]
    fn winscp_ini_related_includes_winscp_saved_sessions() {
        let d = CATALOG.by_id("winscp_ini").unwrap();
        assert!(
            d.related_artifacts.contains(&"winscp_saved_sessions"),
            "winscp_ini related_artifacts must include 'winscp_saved_sessions'"
        );
    }

    #[test]
    fn winscp_ini_related_includes_srum() {
        let d = CATALOG.by_id("winscp_ini").unwrap();
        assert!(
            d.related_artifacts.iter().any(|r| r.contains("srum")),
            "winscp_ini related_artifacts must include a srum artifact \
            (SRUM confirms bytes transferred via WinSCP); got: {:?}",
            d.related_artifacts
        );
    }

    #[test]
    fn catalog_count_includes_winscp_ini() {
        assert_eq!(
            CATALOG.list().len(),
            6624,
            "catalog count after winscp + wifi + clipboard + apfs + samsung + honda + ios14_maps + garmin"
        );
    }
}

// ── Apple Intelligence WiFi database ──────────────────────────────────────────

#[cfg(test)]
mod tests_macos_wifi_intelligence {
    use super::*;

    #[test]
    fn macos_wifi_intelligence_exists() {
        assert!(
            CATALOG.by_id("macos_wifi_intelligence").is_some(),
            "catalog must contain 'macos_wifi_intelligence'"
        );
    }

    #[test]
    fn macos_wifi_intelligence_is_macos() {
        let d = CATALOG.by_id("macos_wifi_intelligence").unwrap();
        assert_eq!(
            d.os_scope,
            OsScope::MacOS,
            "macos_wifi_intelligence must be MacOS scope"
        );
    }

    #[test]
    fn macos_wifi_intelligence_is_database_entry() {
        let d = CATALOG.by_id("macos_wifi_intelligence").unwrap();
        assert_eq!(
            d.artifact_type,
            ArtifactType::DatabaseEntry,
            "macos_wifi_intelligence must be DatabaseEntry (SQLite)"
        );
    }

    #[test]
    fn macos_wifi_intelligence_path_contains_intelligenceplatform() {
        let d = CATALOG.by_id("macos_wifi_intelligence").unwrap();
        let fp = d.file_path.unwrap_or("");
        assert!(
            fp.contains("IntelligencePlatform"),
            "file_path must reference IntelligencePlatform; got: {fp}"
        );
    }

    #[test]
    fn macos_wifi_intelligence_path_contains_views_db() {
        let d = CATALOG.by_id("macos_wifi_intelligence").unwrap();
        let fp = d.file_path.unwrap_or("");
        assert!(
            fp.contains("views.db"),
            "file_path must reference views.db; got: {fp}"
        );
    }

    #[test]
    fn macos_wifi_intelligence_has_ssid_field() {
        let d = CATALOG.by_id("macos_wifi_intelligence").unwrap();
        assert!(
            d.fields.iter().any(|f| f.name == "ssid"),
            "macos_wifi_intelligence must have 'ssid' field"
        );
    }

    #[test]
    fn macos_wifi_intelligence_has_event_type_field() {
        let d = CATALOG.by_id("macos_wifi_intelligence").unwrap();
        assert!(
            d.fields.iter().any(|f| f.name == "event_type"),
            "macos_wifi_intelligence must have 'event_type' field (connect/disconnect)"
        );
    }

    #[test]
    fn macos_wifi_intelligence_has_timestamp_field() {
        let d = CATALOG.by_id("macos_wifi_intelligence").unwrap();
        assert!(
            d.fields
                .iter()
                .any(|f| f.name == "timestamp" && f.value_type == ValueType::Timestamp),
            "macos_wifi_intelligence must have a Timestamp-typed 'timestamp' field"
        );
    }

    #[test]
    fn macos_wifi_intelligence_mitre_t1016() {
        let d = CATALOG.by_id("macos_wifi_intelligence").unwrap();
        assert!(
            d.mitre_techniques.contains(&"T1016"),
            "macos_wifi_intelligence must map to T1016 (System Network Configuration Discovery)"
        );
    }

    #[test]
    fn macos_wifi_intelligence_triage_medium() {
        let d = CATALOG.by_id("macos_wifi_intelligence").unwrap();
        assert_eq!(
            d.triage_priority,
            TriagePriority::Medium,
            "macos_wifi_intelligence triage should be Medium"
        );
    }

    #[test]
    fn macos_wifi_intelligence_related_includes_wifi_plist() {
        let d = CATALOG.by_id("macos_wifi_intelligence").unwrap();
        assert!(
            d.related_artifacts.contains(&"macos_wifi_plist"),
            "macos_wifi_intelligence should relate to macos_wifi_plist"
        );
    }

    #[test]
    fn macos_wifi_intelligence_cites_swiftforensics() {
        let d = CATALOG.by_id("macos_wifi_intelligence").unwrap();
        assert!(
            d.sources.iter().any(|s| s.contains("swiftforensics.com")),
            "macos_wifi_intelligence must cite swiftforensics.com as source"
        );
    }

    #[test]
    fn macos_wifi_intelligence_user_scope() {
        let d = CATALOG.by_id("macos_wifi_intelligence").unwrap();
        assert_eq!(
            d.scope,
            DataScope::User,
            "macos_wifi_intelligence is per-user (under ~/Library)"
        );
    }
}

// ── Windows Clipboard History ─────────────────────────────────────────────────

#[cfg(test)]
mod tests_windows_clipboard_history {
    use super::*;

    #[test]
    fn windows_clipboard_history_exists() {
        assert!(
            CATALOG.by_id("windows_clipboard_history").is_some(),
            "catalog must contain 'windows_clipboard_history'"
        );
    }

    #[test]
    fn windows_clipboard_history_is_windows() {
        let d = CATALOG.by_id("windows_clipboard_history").unwrap();
        assert_eq!(
            d.os_scope,
            OsScope::Win10Plus,
            "windows_clipboard_history must be Win10Plus scope"
        );
    }

    #[test]
    fn windows_clipboard_history_is_registry() {
        let d = CATALOG.by_id("windows_clipboard_history").unwrap();
        assert_eq!(
            d.artifact_type,
            ArtifactType::RegistryKey,
            "windows_clipboard_history must be RegistryKey type"
        );
    }

    #[test]
    fn windows_clipboard_history_key_path_contains_clipboard() {
        let d = CATALOG.by_id("windows_clipboard_history").unwrap();
        assert!(
            d.key_path.contains("Clipboard"),
            "key_path must reference Clipboard; got: {}",
            d.key_path
        );
    }

    #[test]
    fn windows_clipboard_history_has_enable_field() {
        let d = CATALOG.by_id("windows_clipboard_history").unwrap();
        assert!(
            d.fields
                .iter()
                .any(|f| f.name == "enable_clipboard_history"),
            "windows_clipboard_history must have 'enable_clipboard_history' field"
        );
    }

    #[test]
    fn windows_clipboard_history_has_sync_field() {
        let d = CATALOG.by_id("windows_clipboard_history").unwrap();
        assert!(
            d.fields
                .iter()
                .any(|f| f.name == "allow_cross_device_clipboard"),
            "windows_clipboard_history must have 'allow_cross_device_clipboard' field"
        );
    }

    #[test]
    fn windows_clipboard_history_mitre_t1115() {
        let d = CATALOG.by_id("windows_clipboard_history").unwrap();
        assert!(
            d.mitre_techniques.contains(&"T1115"),
            "windows_clipboard_history must map to T1115 (Clipboard Data)"
        );
    }

    #[test]
    fn windows_clipboard_history_triage_medium() {
        let d = CATALOG.by_id("windows_clipboard_history").unwrap();
        assert_eq!(
            d.triage_priority,
            TriagePriority::Medium,
            "windows_clipboard_history triage should be Medium"
        );
    }

    #[test]
    fn windows_clipboard_history_related_includes_timeline() {
        let d = CATALOG.by_id("windows_clipboard_history").unwrap();
        assert!(
            d.related_artifacts.contains(&"windows_timeline"),
            "windows_clipboard_history should relate to windows_timeline"
        );
    }

    #[test]
    fn windows_clipboard_history_cites_windowsir() {
        let d = CATALOG.by_id("windows_clipboard_history").unwrap();
        assert!(
            d.sources
                .iter()
                .any(|s| s.contains("windowsir.blogspot.com")),
            "windows_clipboard_history must cite windowsir.blogspot.com as source"
        );
    }

    #[test]
    fn windows_clipboard_history_user_scope() {
        let d = CATALOG.by_id("windows_clipboard_history").unwrap();
        assert_eq!(
            d.scope,
            DataScope::User,
            "windows_clipboard_history is per-user (HKCU)"
        );
    }

    #[test]
    fn catalog_count_includes_clipboard_history() {
        assert_eq!(
            CATALOG.list().len(),
            6624,
            "catalog count after valley_rat + ntuser_man + apfs + samsung + honda + ios14_maps + garmin"
        );
    }
}

// ── Valley RAT Registry (from WinIR Grab Bag 2026-01) ──────────────────────

#[cfg(test)]
mod tests_valley_rat_registry {
    use super::*;

    #[test]
    fn valley_rat_registry_exists() {
        assert!(CATALOG.by_id("valley_rat_registry").is_some());
    }

    #[test]
    fn valley_rat_registry_os_scope() {
        let d = CATALOG.by_id("valley_rat_registry").unwrap();
        assert_eq!(d.os_scope, OsScope::Win7Plus);
    }

    #[test]
    fn valley_rat_registry_triage_priority() {
        let d = CATALOG.by_id("valley_rat_registry").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::High);
    }

    #[test]
    fn valley_rat_registry_hive_ntuser() {
        let d = CATALOG.by_id("valley_rat_registry").unwrap();
        assert_eq!(d.hive, Some(HiveTarget::NtUser));
    }

    #[test]
    fn valley_rat_registry_key_path() {
        let d = CATALOG.by_id("valley_rat_registry").unwrap();
        assert!(
            d.key_path.contains("HKCU\\Console"),
            "key_path must reference HKCU\\Console"
        );
    }

    #[test]
    fn valley_rat_registry_user_scope() {
        let d = CATALOG.by_id("valley_rat_registry").unwrap();
        assert_eq!(d.scope, DataScope::User);
    }

    #[test]
    fn valley_rat_registry_has_config_field() {
        let d = CATALOG.by_id("valley_rat_registry").unwrap();
        assert!(
            d.fields.iter().any(|f| f.name == "config_data"),
            "valley_rat_registry must have 'config_data' field"
        );
    }

    #[test]
    fn valley_rat_registry_has_plugin_path_field() {
        let d = CATALOG.by_id("valley_rat_registry").unwrap();
        assert!(
            d.fields.iter().any(|f| f.name == "plugin_subkey"),
            "valley_rat_registry must have 'plugin_subkey' field"
        );
    }

    #[test]
    fn valley_rat_registry_mitre_t1547_001() {
        let d = CATALOG.by_id("valley_rat_registry").unwrap();
        assert!(
            d.mitre_techniques.contains(&"T1547.001"),
            "valley_rat_registry must map to T1547.001 (Registry Run Keys)"
        );
    }

    #[test]
    fn valley_rat_registry_mitre_t1005() {
        let d = CATALOG.by_id("valley_rat_registry").unwrap();
        assert!(
            d.mitre_techniques.contains(&"T1005"),
            "valley_rat_registry must map to T1005 (Data from Local System)"
        );
    }

    #[test]
    fn valley_rat_registry_cites_cloudsek() {
        let d = CATALOG.by_id("valley_rat_registry").unwrap();
        assert!(
            d.sources.iter().any(|s| s.contains("cloudsek.com")),
            "valley_rat_registry must cite cloudsek.com as source"
        );
    }

    #[test]
    fn valley_rat_registry_cites_windowsir() {
        let d = CATALOG.by_id("valley_rat_registry").unwrap();
        assert!(
            d.sources
                .iter()
                .any(|s| s.contains("windowsir.blogspot.com")),
            "valley_rat_registry must cite windowsir.blogspot.com as source"
        );
    }

    #[test]
    fn valley_rat_registry_is_registry_key() {
        let d = CATALOG.by_id("valley_rat_registry").unwrap();
        assert_eq!(d.artifact_type, ArtifactType::RegistryKey);
    }
}

// ── NTUSER.MAN Persistence (from WinIR Grab Bag 2026-01 + DeceptIQ) ────────

#[cfg(test)]
mod tests_ntuser_man_persistence {
    use super::*;

    #[test]
    fn ntuser_man_persistence_exists() {
        assert!(CATALOG.by_id("ntuser_man_persistence").is_some());
    }

    #[test]
    fn ntuser_man_persistence_os_scope() {
        let d = CATALOG.by_id("ntuser_man_persistence").unwrap();
        assert_eq!(d.os_scope, OsScope::Win7Plus);
    }

    #[test]
    fn ntuser_man_persistence_triage_priority() {
        let d = CATALOG.by_id("ntuser_man_persistence").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Critical);
    }

    #[test]
    fn ntuser_man_persistence_is_file() {
        let d = CATALOG.by_id("ntuser_man_persistence").unwrap();
        assert_eq!(d.artifact_type, ArtifactType::File);
    }

    #[test]
    fn ntuser_man_persistence_file_path() {
        let d = CATALOG.by_id("ntuser_man_persistence").unwrap();
        assert!(
            d.file_path.unwrap_or("").contains("NTUSER.MAN"),
            "file_path must reference NTUSER.MAN"
        );
    }

    #[test]
    fn ntuser_man_persistence_user_scope() {
        let d = CATALOG.by_id("ntuser_man_persistence").unwrap();
        assert_eq!(d.scope, DataScope::User);
    }

    #[test]
    fn ntuser_man_persistence_mitre_t1547_001() {
        let d = CATALOG.by_id("ntuser_man_persistence").unwrap();
        assert!(
            d.mitre_techniques.contains(&"T1547.001"),
            "ntuser_man_persistence must map to T1547.001 (Registry Run Keys)"
        );
    }

    #[test]
    fn ntuser_man_persistence_mitre_t1112() {
        let d = CATALOG.by_id("ntuser_man_persistence").unwrap();
        assert!(
            d.mitre_techniques.contains(&"T1112"),
            "ntuser_man_persistence must map to T1112 (Modify Registry)"
        );
    }

    #[test]
    fn ntuser_man_persistence_cites_deceptiq() {
        let d = CATALOG.by_id("ntuser_man_persistence").unwrap();
        assert!(
            d.sources.iter().any(|s| s.contains("deceptiq.com")),
            "ntuser_man_persistence must cite deceptiq.com as source"
        );
    }

    #[test]
    fn ntuser_man_persistence_cites_windowsir() {
        let d = CATALOG.by_id("ntuser_man_persistence").unwrap();
        assert!(
            d.sources
                .iter()
                .any(|s| s.contains("windowsir.blogspot.com")),
            "ntuser_man_persistence must cite windowsir.blogspot.com as source"
        );
    }

    #[test]
    fn ntuser_man_persistence_related_run_keys() {
        let d = CATALOG.by_id("ntuser_man_persistence").unwrap();
        assert!(
            d.related_artifacts.contains(&"run_key_hkcu"),
            "ntuser_man_persistence should relate to run_key_hkcu"
        );
    }

    #[test]
    fn ntuser_man_persistence_has_mandatory_profile_field() {
        let d = CATALOG.by_id("ntuser_man_persistence").unwrap();
        assert!(
            d.fields.iter().any(|f| f.name == "is_mandatory_profile"),
            "ntuser_man_persistence must have 'is_mandatory_profile' field"
        );
    }

    #[test]
    fn ntuser_man_persistence_has_file_timestamp_field() {
        let d = CATALOG.by_id("ntuser_man_persistence").unwrap();
        assert!(
            d.fields.iter().any(|f| f.name == "file_modified_time"),
            "ntuser_man_persistence must have 'file_modified_time' field"
        );
    }
}

// ── iOS Unified Log descriptor ──────────────────────────────────────────────

#[cfg(test)]
mod tests_ios_unified_log {
    use super::*;

    #[test]
    fn ios_unified_log_exists() {
        assert!(
            CATALOG.by_id("ios_unified_log").is_some(),
            "catalog must contain 'ios_unified_log'"
        );
    }

    #[test]
    fn ios_unified_log_is_ios_scope() {
        let d = CATALOG.by_id("ios_unified_log").unwrap();
        assert_eq!(
            d.os_scope,
            OsScope::IOS,
            "ios_unified_log must be IOS scope"
        );
    }

    #[test]
    fn ios_unified_log_triage_is_critical() {
        let d = CATALOG.by_id("ios_unified_log").unwrap();
        assert_eq!(
            d.triage_priority,
            TriagePriority::Critical,
            "ios_unified_log must be Critical triage priority"
        );
    }

    #[test]
    fn ios_unified_log_is_directory_type() {
        let d = CATALOG.by_id("ios_unified_log").unwrap();
        assert_eq!(
            d.artifact_type,
            ArtifactType::Directory,
            "ios_unified_log must be Directory artifact type"
        );
    }

    #[test]
    fn ios_unified_log_has_diagnostics_path() {
        let d = CATALOG.by_id("ios_unified_log").unwrap();
        let path = d.file_path.unwrap();
        assert!(
            path.contains("/private/var/db/diagnostics"),
            "ios_unified_log file_path must reference /private/var/db/diagnostics; got: {path}"
        );
    }

    #[test]
    fn ios_unified_log_has_timestamp_field() {
        let d = CATALOG.by_id("ios_unified_log").unwrap();
        assert!(
            d.fields.iter().any(|f| f.name == "timestamp"),
            "ios_unified_log must have 'timestamp' field"
        );
    }

    #[test]
    fn ios_unified_log_has_process_id_field() {
        let d = CATALOG.by_id("ios_unified_log").unwrap();
        assert!(
            d.fields.iter().any(|f| f.name == "process_id"),
            "ios_unified_log must have 'process_id' field"
        );
    }

    #[test]
    fn ios_unified_log_has_subsystem_field() {
        let d = CATALOG.by_id("ios_unified_log").unwrap();
        assert!(
            d.fields.iter().any(|f| f.name == "subsystem"),
            "ios_unified_log must have 'subsystem' field"
        );
    }

    #[test]
    fn ios_unified_log_has_category_field() {
        let d = CATALOG.by_id("ios_unified_log").unwrap();
        assert!(
            d.fields.iter().any(|f| f.name == "category"),
            "ios_unified_log must have 'category' field"
        );
    }

    #[test]
    fn ios_unified_log_has_event_message_field() {
        let d = CATALOG.by_id("ios_unified_log").unwrap();
        assert!(
            d.fields.iter().any(|f| f.name == "event_message"),
            "ios_unified_log must have 'event_message' field"
        );
    }

    #[test]
    fn ios_unified_log_has_trace_id_field() {
        let d = CATALOG.by_id("ios_unified_log").unwrap();
        assert!(
            d.fields.iter().any(|f| f.name == "trace_id"),
            "ios_unified_log must have 'trace_id' field"
        );
    }

    #[test]
    fn ios_unified_log_cites_abrignoni() {
        let d = CATALOG.by_id("ios_unified_log").unwrap();
        assert!(
            d.sources
                .iter()
                .any(|s| s.contains("abrignoni.blogspot.com")),
            "ios_unified_log must cite abrignoni blog post; sources: {:?}",
            d.sources
        );
    }

    #[test]
    fn ios_unified_log_cites_ios_unifiedlogs() {
        let d = CATALOG.by_id("ios_unified_log").unwrap();
        assert!(
            d.sources.iter().any(|s| s.contains("ios-unifiedlogs.com")),
            "ios_unified_log must cite ios-unifiedlogs.com; sources: {:?}",
            d.sources
        );
    }

    #[test]
    fn ios_unified_log_has_mitre_techniques() {
        let d = CATALOG.by_id("ios_unified_log").unwrap();
        assert!(
            d.mitre_techniques.contains(&"T1070.001"),
            "ios_unified_log must include T1070.001 (Indicator Removal: Clear Logs)"
        );
    }

    #[test]
    fn ios_unified_log_relates_to_macos_unified_log() {
        let d = CATALOG.by_id("ios_unified_log").unwrap();
        assert!(
            d.related_artifacts.contains(&"macos_unified_log"),
            "ios_unified_log must relate to macos_unified_log"
        );
    }
}

#[cfg(test)]
mod tests_apfs_container {
    use super::*;

    #[test]
    fn apfs_container_exists() {
        assert!(CATALOG.by_id("apfs_container").is_some());
    }

    #[test]
    fn apfs_container_os_scope() {
        let d = CATALOG.by_id("apfs_container").unwrap();
        assert_eq!(d.os_scope, OsScope::MacOS);
    }

    #[test]
    fn apfs_container_artifact_type() {
        let d = CATALOG.by_id("apfs_container").unwrap();
        assert_eq!(d.artifact_type, ArtifactType::File);
    }

    #[test]
    fn apfs_container_scope() {
        let d = CATALOG.by_id("apfs_container").unwrap();
        assert_eq!(d.scope, DataScope::System);
    }

    #[test]
    fn apfs_container_triage_priority() {
        let d = CATALOG.by_id("apfs_container").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::High);
    }

    #[test]
    fn apfs_container_has_fields() {
        let d = CATALOG.by_id("apfs_container").unwrap();
        let names: Vec<&str> = d.fields.iter().map(|f| f.name).collect();
        assert!(
            names.contains(&"container_uuid"),
            "must have container_uuid field"
        );
        assert!(
            names.contains(&"volume_name"),
            "must have volume_name field"
        );
        assert!(
            names.contains(&"encryption_state"),
            "must have encryption_state field"
        );
    }

    #[test]
    fn apfs_container_has_mitre() {
        let d = CATALOG.by_id("apfs_container").unwrap();
        assert!(
            d.mitre_techniques.contains(&"T1005"),
            "apfs_container must map to T1005 (Data from Local System)"
        );
    }

    #[test]
    fn apfs_container_cites_az4n6() {
        let d = CATALOG.by_id("apfs_container").unwrap();
        assert!(
            d.sources.iter().any(|s| s.contains("az4n6.blogspot.com")),
            "apfs_container must cite az4n6 blog; sources: {:?}",
            d.sources
        );
    }

    #[test]
    fn apfs_container_cites_apfs_fuse() {
        let d = CATALOG.by_id("apfs_container").unwrap();
        assert!(
            d.sources.iter().any(|s| s.contains("github.com/sgan81")),
            "apfs_container must cite apfs-fuse repo; sources: {:?}",
            d.sources
        );
    }

    #[test]
    fn apfs_container_relates_to_macos_fsevents() {
        let d = CATALOG.by_id("apfs_container").unwrap();
        assert!(
            d.related_artifacts.contains(&"macos_fsevents"),
            "apfs_container must relate to macos_fsevents"
        );
    }

    #[test]
    fn apfs_container_cites_az4n6_windows_post() {
        let d = CATALOG.by_id("apfs_container").unwrap();
        assert!(
            d.sources
                .iter()
                .any(|s| s.contains("how-to-mount-mac-apfs-images-in-windows")),
            "apfs_container must cite az4n6 Windows APFS mounting post; sources: {:?}",
            d.sources
        );
    }

    #[test]
    fn apfs_container_meaning_mentions_windows_mounting() {
        let d = CATALOG.by_id("apfs_container").unwrap();
        assert!(
            d.meaning.contains("Windows")
                || d.meaning.contains("Paragon")
                || d.meaning.contains("Arsenal"),
            "apfs_container meaning should mention Windows mounting workflow"
        );
    }
}

// ── az4n6 "Finding and Decoding Malicious PowerShell Scripts" enrichments ───
// Source: https://az4n6.blogspot.com/2017/10/finding-and-decoding-malicious.html
#[cfg(test)]
mod tests_evtx_system_ps_service_enrichment {
    use super::*;

    #[test]
    fn evtx_system_cites_az4n6_ps_services_post() {
        let d = CATALOG.by_id("evtx_system").unwrap();
        assert!(
            d.sources
                .iter()
                .any(|s| s.contains("az4n6.blogspot.com") && s.contains("finding-and-decoding")),
            "evtx_system must cite az4n6 'Finding and Decoding Malicious PowerShell Scripts' post; sources: {:?}",
            d.sources
        );
    }

    #[test]
    fn evtx_system_meaning_mentions_comspec_ps_abuse() {
        let d = CATALOG.by_id("evtx_system").unwrap();
        assert!(
            d.meaning.contains("COMSPEC") || d.meaning.contains("%COMSPEC%"),
            "evtx_system meaning should mention %%COMSPEC%% PowerShell service abuse pattern"
        );
    }

    #[test]
    fn evtx_system_meaning_mentions_misleading_7000_7009() {
        let d = CATALOG.by_id("evtx_system").unwrap();
        assert!(
            d.meaning.contains("7000") && d.meaning.contains("7009"),
            "evtx_system meaning should warn about misleading 7000/7009 errors after PS service creation"
        );
    }

    #[test]
    fn evtx_system_has_t1059_001() {
        let d = CATALOG.by_id("evtx_system").unwrap();
        assert!(
            d.mitre_techniques.contains(&"T1059.001"),
            "evtx_system must have T1059.001 (PowerShell) for PS-as-service abuse"
        );
    }
}

#[cfg(test)]
mod tests_services_imagepath_ps_enrichment {
    use super::*;

    #[test]
    fn services_imagepath_cites_az4n6_ps_services_post() {
        let d = CATALOG.by_id("services_imagepath").unwrap();
        assert!(
            d.sources
                .iter()
                .any(|s| s.contains("az4n6.blogspot.com") && s.contains("finding-and-decoding")),
            "services_imagepath must cite az4n6 PS services post; sources: {:?}",
            d.sources
        );
    }

    #[test]
    fn services_imagepath_meaning_mentions_encodedcommand() {
        let d = CATALOG.by_id("services_imagepath").unwrap();
        assert!(
            d.meaning.contains("encodedcommand")
                || d.meaning.contains("-EncodedCommand")
                || d.meaning.contains("base64"),
            "services_imagepath meaning should mention encoded PowerShell abuse in binPath"
        );
    }

    #[test]
    fn services_imagepath_has_t1059_001() {
        let d = CATALOG.by_id("services_imagepath").unwrap();
        assert!(
            d.mitre_techniques.contains(&"T1059.001"),
            "services_imagepath must have T1059.001 (PowerShell) for PS-encoded service abuse"
        );
    }

    #[test]
    fn services_imagepath_has_t1027() {
        let d = CATALOG.by_id("services_imagepath").unwrap();
        assert!(
            d.mitre_techniques.contains(&"T1027"),
            "services_imagepath must have T1027 (Obfuscated Files) for base64/gzip obfuscation"
        );
    }

    #[test]
    fn services_imagepath_relates_to_evtx_system() {
        let d = CATALOG.by_id("services_imagepath").unwrap();
        assert!(
            d.related_artifacts.contains(&"evtx_system"),
            "services_imagepath must relate to evtx_system (7045 records service installs)"
        );
    }
}

// ── az4n6 Mac Live Imaging enrichment ───────────────────────────────────────
#[cfg(test)]
mod az4n6_mac_live_imaging_tests {
    use super::*;

    /// The blog post documents that on a running FileVault2-encrypted Mac the
    /// logical volume appears as "Unlocked Encrypted" in diskutil output and can
    /// be imaged via /dev/rdisk (raw, unbuffered device) using dd.  The
    /// apfs_container descriptor should reference this source and mention live
    /// acquisition of unlocked encrypted volumes and the rdisk performance note.
    #[test]
    fn apfs_container_cites_az4n6_live_imaging_post() {
        let d = CATALOG.by_id("apfs_container").unwrap();
        assert!(
            d.sources
                .iter()
                .any(|s| s.contains("mac-live-imaging-functionality-versus")),
            "apfs_container must cite az4n6 Mac Live Imaging post as a source"
        );
    }

    #[test]
    fn apfs_container_meaning_mentions_live_acquisition() {
        let d = CATALOG.by_id("apfs_container").unwrap();
        assert!(
            d.meaning.contains("live") || d.meaning.contains("Live"),
            "apfs_container meaning must mention live acquisition of unlocked encrypted volumes"
        );
    }

    #[test]
    fn apfs_container_meaning_mentions_rdisk() {
        let d = CATALOG.by_id("apfs_container").unwrap();
        assert!(
            d.meaning.contains("rdisk"),
            "apfs_container meaning must mention /dev/rdisk for faster raw device imaging"
        );
    }

    // ── Google Takeout Location Records ─────────────────────────────────

    #[test]
    fn google_takeout_location_records_exists() {
        let d = CATALOG.by_id("google_takeout_location_records").unwrap();
        assert_eq!(d.name, "Google Takeout Location Records");
        assert_eq!(d.artifact_type, ArtifactType::File);
        assert_eq!(d.os_scope, OsScope::All);
        assert_eq!(d.scope, DataScope::User);
    }

    #[test]
    fn google_takeout_location_records_file_path() {
        let d = CATALOG.by_id("google_takeout_location_records").unwrap();
        let fp = d.file_path.unwrap();
        assert!(
            fp.contains("Records.json"),
            "file_path must reference Records.json: {fp}"
        );
        assert!(
            fp.contains("Location History"),
            "file_path must reference Location History folder: {fp}"
        );
    }

    #[test]
    fn google_takeout_location_records_fields() {
        let d = CATALOG.by_id("google_takeout_location_records").unwrap();
        let names: Vec<&str> = d.fields.iter().map(|f| f.name).collect();
        assert!(names.contains(&"latitudeE7"), "must have latitudeE7 field");
        assert!(
            names.contains(&"longitudeE7"),
            "must have longitudeE7 field"
        );
        assert!(names.contains(&"timestamp"), "must have timestamp field");
        assert!(names.contains(&"activity"), "must have activity field");
        assert!(names.contains(&"source"), "must have source field");
        assert!(names.contains(&"deviceTag"), "must have deviceTag field");
        assert!(names.contains(&"accuracy"), "must have accuracy field");
    }

    #[test]
    fn google_takeout_location_records_meaning_mentions_detected_activity() {
        let d = CATALOG.by_id("google_takeout_location_records").unwrap();
        assert!(
            d.meaning.contains("DetectedActivity"),
            "meaning must mention DetectedActivity classification: {}",
            d.meaning
        );
    }

    #[test]
    fn google_takeout_location_records_meaning_mentions_activity_types() {
        let d = CATALOG.by_id("google_takeout_location_records").unwrap();
        assert!(
            d.meaning.contains("STILL")
                && d.meaning.contains("IN_VEHICLE")
                && d.meaning.contains("ON_FOOT"),
            "meaning must enumerate key DetectedActivity types: {}",
            d.meaning
        );
    }

    #[test]
    fn google_takeout_location_records_triage() {
        let d = CATALOG.by_id("google_takeout_location_records").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::High);
    }

    #[test]
    fn google_takeout_location_records_sources() {
        let d = CATALOG.by_id("google_takeout_location_records").unwrap();
        assert!(
            d.sources.iter().any(|s| s.contains("cheeky4n6monkey")),
            "sources must cite the cheeky4n6monkey blog post"
        );
    }

    // ── Google Takeout Semantic Location History ─────────────────────────

    #[test]
    fn google_takeout_semantic_location_history_exists() {
        let d = CATALOG
            .by_id("google_takeout_semantic_location_history")
            .unwrap();
        assert_eq!(d.name, "Google Takeout Semantic Location History");
        assert_eq!(d.artifact_type, ArtifactType::File);
        assert_eq!(d.os_scope, OsScope::All);
        assert_eq!(d.scope, DataScope::User);
    }

    #[test]
    fn google_takeout_semantic_location_history_file_path() {
        let d = CATALOG
            .by_id("google_takeout_semantic_location_history")
            .unwrap();
        let fp = d.file_path.unwrap();
        assert!(
            fp.contains("Semantic Location History"),
            "file_path must reference Semantic Location History folder: {fp}"
        );
    }

    #[test]
    fn google_takeout_semantic_location_history_fields() {
        let d = CATALOG
            .by_id("google_takeout_semantic_location_history")
            .unwrap();
        let names: Vec<&str> = d.fields.iter().map(|f| f.name).collect();
        assert!(names.contains(&"placeVisit"), "must have placeVisit field");
        assert!(
            names.contains(&"activitySegment"),
            "must have activitySegment field"
        );
    }

    #[test]
    fn google_takeout_semantic_location_history_meaning_mentions_place_visits() {
        let d = CATALOG
            .by_id("google_takeout_semantic_location_history")
            .unwrap();
        assert!(
            d.meaning.contains("place visit") || d.meaning.contains("placeVisit"),
            "meaning must mention place visits: {}",
            d.meaning
        );
    }

    #[test]
    fn google_takeout_semantic_location_history_triage() {
        let d = CATALOG
            .by_id("google_takeout_semantic_location_history")
            .unwrap();
        assert_eq!(d.triage_priority, TriagePriority::High);
    }

    #[test]
    fn google_takeout_semantic_location_history_sources() {
        let d = CATALOG
            .by_id("google_takeout_semantic_location_history")
            .unwrap();
        assert!(
            d.sources.iter().any(|s| s.contains("cheeky4n6monkey")),
            "sources must cite the cheeky4n6monkey blog post"
        );
    }

    #[test]
    fn google_takeout_semantic_location_history_related() {
        let d = CATALOG
            .by_id("google_takeout_semantic_location_history")
            .unwrap();
        assert!(
            d.related_artifacts
                .contains(&"google_takeout_location_records"),
            "must cross-reference location_records"
        );
    }

    #[test]
    fn google_takeout_location_records_related() {
        let d = CATALOG.by_id("google_takeout_location_records").unwrap();
        assert!(
            d.related_artifacts
                .contains(&"google_takeout_semantic_location_history"),
            "must cross-reference semantic_location_history"
        );
    }
}

// ── Samsung Gallery3d Trash ─────────────────────────────────────────────────

#[cfg(test)]
mod tests_samsung_gallery3d_trash {
    use super::*;

    #[test]
    fn exists_in_catalog() {
        assert!(
            CATALOG.by_id("samsung_gallery3d_trash").is_some(),
            "catalog must contain 'samsung_gallery3d_trash'"
        );
    }

    #[test]
    fn is_android_scope() {
        let d = CATALOG.by_id("samsung_gallery3d_trash").unwrap();
        assert_eq!(
            d.os_scope,
            OsScope::Android,
            "samsung_gallery3d_trash must be Android scope"
        );
    }

    #[test]
    fn is_database_entry_type() {
        let d = CATALOG.by_id("samsung_gallery3d_trash").unwrap();
        assert_eq!(
            d.artifact_type,
            ArtifactType::DatabaseEntry,
            "samsung_gallery3d_trash must be DatabaseEntry type"
        );
    }

    #[test]
    fn triage_is_high() {
        let d = CATALOG.by_id("samsung_gallery3d_trash").unwrap();
        assert_eq!(
            d.triage_priority,
            TriagePriority::High,
            "samsung_gallery3d_trash must be High triage priority"
        );
    }

    #[test]
    fn file_path_contains_local_db() {
        let d = CATALOG.by_id("samsung_gallery3d_trash").unwrap();
        let path = d.file_path.expect("must have file_path");
        assert!(
            path.contains("local.db"),
            "file_path must reference local.db; got: {path}"
        );
    }

    #[test]
    fn file_path_contains_gallery3d_package() {
        let d = CATALOG.by_id("samsung_gallery3d_trash").unwrap();
        let path = d.file_path.unwrap();
        assert!(
            path.contains("com.sec.android.gallery3d"),
            "file_path must contain com.sec.android.gallery3d; got: {path}"
        );
    }

    #[test]
    fn has_origin_path_field() {
        let d = CATALOG.by_id("samsung_gallery3d_trash").unwrap();
        assert!(
            d.fields.iter().any(|f| f.name == "__originPath"),
            "samsung_gallery3d_trash must have '__originPath' field"
        );
    }

    #[test]
    fn has_delete_time_field() {
        let d = CATALOG.by_id("samsung_gallery3d_trash").unwrap();
        assert!(
            d.fields.iter().any(|f| f.name == "__deleteTime"),
            "samsung_gallery3d_trash must have '__deleteTime' field"
        );
    }

    #[test]
    fn delete_time_is_timestamp_type() {
        let d = CATALOG.by_id("samsung_gallery3d_trash").unwrap();
        let f = d.fields.iter().find(|f| f.name == "__deleteTime").unwrap();
        assert_eq!(
            f.value_type,
            ValueType::Timestamp,
            "__deleteTime must be Timestamp type"
        );
    }

    #[test]
    fn has_abs_path_field() {
        let d = CATALOG.by_id("samsung_gallery3d_trash").unwrap();
        assert!(
            d.fields.iter().any(|f| f.name == "__absPath"),
            "samsung_gallery3d_trash must have '__absPath' field"
        );
    }

    #[test]
    fn has_restore_extra_field() {
        let d = CATALOG.by_id("samsung_gallery3d_trash").unwrap();
        assert!(
            d.fields.iter().any(|f| f.name == "__restoreExtra"),
            "samsung_gallery3d_trash must have '__restoreExtra' field"
        );
    }

    #[test]
    fn restore_extra_is_json_type() {
        let d = CATALOG.by_id("samsung_gallery3d_trash").unwrap();
        let f = d
            .fields
            .iter()
            .find(|f| f.name == "__restoreExtra")
            .unwrap();
        assert_eq!(
            f.value_type,
            ValueType::Json,
            "__restoreExtra must be Json type"
        );
    }

    #[test]
    fn has_media_type_field() {
        let d = CATALOG.by_id("samsung_gallery3d_trash").unwrap();
        assert!(
            d.fields.iter().any(|f| f.name == "__mediaType"),
            "samsung_gallery3d_trash must have '__mediaType' field"
        );
    }

    #[test]
    fn meaning_mentions_trash() {
        let d = CATALOG.by_id("samsung_gallery3d_trash").unwrap();
        let lc = d.meaning.to_ascii_lowercase();
        assert!(
            lc.contains("trash"),
            "meaning must mention trash; got: {}",
            d.meaning
        );
    }

    #[test]
    fn cites_cheeky4n6monkey() {
        let d = CATALOG.by_id("samsung_gallery3d_trash").unwrap();
        assert!(
            d.sources.iter().any(|s| s.contains("cheeky4n6monkey")),
            "samsung_gallery3d_trash must cite cheeky4n6monkey blog; sources: {:?}",
            d.sources
        );
    }

    #[test]
    fn relates_to_log() {
        let d = CATALOG.by_id("samsung_gallery3d_trash").unwrap();
        assert!(
            d.related_artifacts.contains(&"samsung_gallery3d_log"),
            "samsung_gallery3d_trash must relate to samsung_gallery3d_log"
        );
    }

    #[test]
    fn scope_is_user() {
        let d = CATALOG.by_id("samsung_gallery3d_trash").unwrap();
        assert_eq!(d.scope, DataScope::User, "must be User scope");
    }
}

// ── Samsung Gallery3d Log ───────────────────────────────────────────────────

#[cfg(test)]
mod tests_samsung_gallery3d_log {
    use super::*;

    #[test]
    fn exists_in_catalog() {
        assert!(
            CATALOG.by_id("samsung_gallery3d_log").is_some(),
            "catalog must contain 'samsung_gallery3d_log'"
        );
    }

    #[test]
    fn is_android_scope() {
        let d = CATALOG.by_id("samsung_gallery3d_log").unwrap();
        assert_eq!(
            d.os_scope,
            OsScope::Android,
            "samsung_gallery3d_log must be Android scope"
        );
    }

    #[test]
    fn is_database_entry_type() {
        let d = CATALOG.by_id("samsung_gallery3d_log").unwrap();
        assert_eq!(
            d.artifact_type,
            ArtifactType::DatabaseEntry,
            "samsung_gallery3d_log must be DatabaseEntry type"
        );
    }

    #[test]
    fn triage_is_high() {
        let d = CATALOG.by_id("samsung_gallery3d_log").unwrap();
        assert_eq!(
            d.triage_priority,
            TriagePriority::High,
            "samsung_gallery3d_log must be High triage priority"
        );
    }

    #[test]
    fn file_path_contains_local_db() {
        let d = CATALOG.by_id("samsung_gallery3d_log").unwrap();
        let path = d.file_path.expect("must have file_path");
        assert!(
            path.contains("local.db"),
            "file_path must reference local.db; got: {path}"
        );
    }

    #[test]
    fn has_timestamp_field() {
        let d = CATALOG.by_id("samsung_gallery3d_log").unwrap();
        assert!(
            d.fields.iter().any(|f| f.name == "__timestamp"),
            "samsung_gallery3d_log must have '__timestamp' field"
        );
    }

    #[test]
    fn has_log_field() {
        let d = CATALOG.by_id("samsung_gallery3d_log").unwrap();
        assert!(
            d.fields.iter().any(|f| f.name == "__log"),
            "samsung_gallery3d_log must have '__log' field"
        );
    }

    #[test]
    fn has_category_field() {
        let d = CATALOG.by_id("samsung_gallery3d_log").unwrap();
        assert!(
            d.fields.iter().any(|f| f.name == "__category"),
            "samsung_gallery3d_log must have '__category' field"
        );
    }

    #[test]
    fn meaning_mentions_base64() {
        let d = CATALOG.by_id("samsung_gallery3d_log").unwrap();
        let lc = d.meaning.to_ascii_lowercase();
        assert!(
            lc.contains("base64"),
            "meaning must mention base64-encoded paths; got: {}",
            d.meaning
        );
    }

    #[test]
    fn meaning_mentions_move_to_trash() {
        let d = CATALOG.by_id("samsung_gallery3d_log").unwrap();
        assert!(
            d.meaning.contains("MOVE_TO_TRASH"),
            "meaning must mention MOVE_TO_TRASH action; got: {}",
            d.meaning
        );
    }

    #[test]
    fn cites_cheeky4n6monkey() {
        let d = CATALOG.by_id("samsung_gallery3d_log").unwrap();
        assert!(
            d.sources.iter().any(|s| s.contains("cheeky4n6monkey")),
            "samsung_gallery3d_log must cite cheeky4n6monkey blog; sources: {:?}",
            d.sources
        );
    }

    #[test]
    fn relates_to_trash() {
        let d = CATALOG.by_id("samsung_gallery3d_log").unwrap();
        assert!(
            d.related_artifacts.contains(&"samsung_gallery3d_trash"),
            "samsung_gallery3d_log must relate to samsung_gallery3d_trash"
        );
    }

    #[test]
    fn scope_is_user() {
        let d = CATALOG.by_id("samsung_gallery3d_log").unwrap();
        assert_eq!(d.scope, DataScope::User, "must be User scope");
    }
}

// ── Honda Accord Infotainment — RecentStops ────────────────────────────────

#[cfg(test)]
mod tests_honda_accord_recentstops {
    use super::*;

    #[test]
    fn exists_in_catalog() {
        assert!(
            CATALOG.by_id("honda_accord_recentstops").is_some(),
            "catalog must contain 'honda_accord_recentstops'"
        );
    }

    #[test]
    fn is_database_entry_type() {
        let d = CATALOG.by_id("honda_accord_recentstops").unwrap();
        assert_eq!(d.artifact_type, ArtifactType::DatabaseEntry);
    }

    #[test]
    fn is_android_scope() {
        let d = CATALOG.by_id("honda_accord_recentstops").unwrap();
        assert_eq!(d.os_scope, OsScope::Android);
    }

    #[test]
    fn triage_is_high() {
        let d = CATALOG.by_id("honda_accord_recentstops").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::High);
    }

    #[test]
    fn has_fields() {
        let d = CATALOG.by_id("honda_accord_recentstops").unwrap();
        let names: Vec<&str> = d.fields.iter().map(|f| f.name).collect();
        assert!(names.contains(&"time"));
        assert!(names.contains(&"lat"));
        assert!(names.contains(&"lon"));
        assert!(names.contains(&"name"));
    }

    #[test]
    fn file_path_set() {
        let d = CATALOG.by_id("honda_accord_recentstops").unwrap();
        assert_eq!(
            d.file_path,
            Some("/data/com.honda.displayaudio.navi/Garmin/sqlite/RecentStops.db")
        );
    }

    #[test]
    fn has_source() {
        let d = CATALOG.by_id("honda_accord_recentstops").unwrap();
        assert!(!d.sources.is_empty());
    }
}

// ── Honda Accord Infotainment — CRM Eco Logs ──────────────────────────────

#[cfg(test)]
mod tests_honda_accord_crm_eco_logs {
    use super::*;

    #[test]
    fn exists_in_catalog() {
        assert!(
            CATALOG.by_id("honda_accord_crm_eco_logs").is_some(),
            "catalog must contain 'honda_accord_crm_eco_logs'"
        );
    }

    #[test]
    fn is_database_entry_type() {
        let d = CATALOG.by_id("honda_accord_crm_eco_logs").unwrap();
        assert_eq!(d.artifact_type, ArtifactType::DatabaseEntry);
    }

    #[test]
    fn has_trip_fields() {
        let d = CATALOG.by_id("honda_accord_crm_eco_logs").unwrap();
        let names: Vec<&str> = d.fields.iter().map(|f| f.name).collect();
        assert!(names.contains(&"trip_id"));
        assert!(names.contains(&"start_pos_time"));
        assert!(names.contains(&"finish_pos_time"));
        assert!(names.contains(&"mileage"));
    }

    #[test]
    fn file_path_set() {
        let d = CATALOG.by_id("honda_accord_crm_eco_logs").unwrap();
        assert_eq!(
            d.file_path,
            Some("/data/com.honda.telematics.core/databases/crm.db")
        );
    }

    #[test]
    fn triage_is_medium() {
        let d = CATALOG.by_id("honda_accord_crm_eco_logs").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Medium);
    }
}

// ── Honda Accord Infotainment — Phone DB ───────────────────────────────────

#[cfg(test)]
mod tests_honda_accord_phonedb {
    use super::*;

    #[test]
    fn exists_in_catalog() {
        assert!(
            CATALOG.by_id("honda_accord_phonedb").is_some(),
            "catalog must contain 'honda_accord_phonedb'"
        );
    }

    #[test]
    fn is_database_entry_type() {
        let d = CATALOG.by_id("honda_accord_phonedb").unwrap();
        assert_eq!(d.artifact_type, ArtifactType::DatabaseEntry);
    }

    #[test]
    fn has_call_fields() {
        let d = CATALOG.by_id("honda_accord_phonedb").unwrap();
        let names: Vec<&str> = d.fields.iter().map(|f| f.name).collect();
        assert!(names.contains(&"phonenum"));
        assert!(names.contains(&"calldate"));
        assert!(names.contains(&"calltype"));
    }

    #[test]
    fn file_path_set() {
        let d = CATALOG.by_id("honda_accord_phonedb").unwrap();
        assert_eq!(
            d.file_path,
            Some("/data/com.clarion.bluetooth/databases/phonedb.db")
        );
    }

    #[test]
    fn triage_is_high() {
        let d = CATALOG.by_id("honda_accord_phonedb").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::High);
    }

    #[test]
    fn relates_to_bluetooth() {
        let d = CATALOG.by_id("honda_accord_phonedb").unwrap();
        assert!(d.related_artifacts.contains(&"honda_accord_bluetooth"));
    }
}

// ── Honda Accord Infotainment — Bluetooth Settings ─────────────────────────

#[cfg(test)]
mod tests_honda_accord_bluetooth {
    use super::*;

    #[test]
    fn exists_in_catalog() {
        assert!(
            CATALOG.by_id("honda_accord_bluetooth").is_some(),
            "catalog must contain 'honda_accord_bluetooth'"
        );
    }

    #[test]
    fn is_database_entry_type() {
        let d = CATALOG.by_id("honda_accord_bluetooth").unwrap();
        assert_eq!(d.artifact_type, ArtifactType::DatabaseEntry);
    }

    #[test]
    fn has_device_fields() {
        let d = CATALOG.by_id("honda_accord_bluetooth").unwrap();
        let names: Vec<&str> = d.fields.iter().map(|f| f.name).collect();
        assert!(names.contains(&"device_bank"));
        assert!(names.contains(&"device_addr"));
        assert!(names.contains(&"device_name"));
    }

    #[test]
    fn file_path_set() {
        let d = CATALOG.by_id("honda_accord_bluetooth").unwrap();
        assert_eq!(
            d.file_path,
            Some("/data/com.clarion.bluetooth/databases/bluetoothsettings.db")
        );
    }

    #[test]
    fn triage_is_medium() {
        let d = CATALOG.by_id("honda_accord_bluetooth").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Medium);
    }

    #[test]
    fn relates_to_phonedb() {
        let d = CATALOG.by_id("honda_accord_bluetooth").unwrap();
        assert!(d.related_artifacts.contains(&"honda_accord_phonedb"));
    }
}

// ── iOS14 Apple Maps History ───────────────────────────────────────────────

#[cfg(test)]
mod tests_ios14_maps_history {
    use super::*;

    #[test]
    fn exists_in_catalog() {
        assert!(
            CATALOG.by_id("ios14_maps_history").is_some(),
            "catalog must contain 'ios14_maps_history'"
        );
    }

    #[test]
    fn is_database_entry_type() {
        let d = CATALOG.by_id("ios14_maps_history").unwrap();
        assert_eq!(d.artifact_type, ArtifactType::DatabaseEntry);
    }

    #[test]
    fn is_ios_scope() {
        let d = CATALOG.by_id("ios14_maps_history").unwrap();
        assert_eq!(d.os_scope, OsScope::IOS);
    }

    #[test]
    fn triage_is_high() {
        let d = CATALOG.by_id("ios14_maps_history").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::High);
    }

    #[test]
    fn has_key_fields() {
        let d = CATALOG.by_id("ios14_maps_history").unwrap();
        let names: Vec<&str> = d.fields.iter().map(|f| f.name).collect();
        assert!(names.contains(&"z_pk"));
        assert!(names.contains(&"z_ent"));
        assert!(names.contains(&"ZCREATETIME"));
        assert!(names.contains(&"ZLATITUDE"));
        assert!(names.contains(&"ZLONGITUDE"));
        assert!(names.contains(&"ZQUERY"));
    }

    #[test]
    fn has_sources() {
        let d = CATALOG.by_id("ios14_maps_history").unwrap();
        assert!(!d.sources.is_empty());
    }

    #[test]
    fn scope_is_user() {
        let d = CATALOG.by_id("ios14_maps_history").unwrap();
        assert_eq!(d.scope, DataScope::User);
    }
}

// ── Garmin nuvi Voice Log ──────────────────────────────────────────────────

#[cfg(test)]
mod tests_garmin_nuvi_voice_log {
    use super::*;

    #[test]
    fn exists_in_catalog() {
        assert!(
            CATALOG.by_id("garmin_nuvi_voice_log").is_some(),
            "catalog must contain 'garmin_nuvi_voice_log'"
        );
    }

    #[test]
    fn is_file_type() {
        let d = CATALOG.by_id("garmin_nuvi_voice_log").unwrap();
        assert_eq!(d.artifact_type, ArtifactType::File);
    }

    #[test]
    fn is_all_scope() {
        let d = CATALOG.by_id("garmin_nuvi_voice_log").unwrap();
        assert_eq!(d.os_scope, OsScope::All);
    }

    #[test]
    fn triage_is_high() {
        let d = CATALOG.by_id("garmin_nuvi_voice_log").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::High);
    }

    #[test]
    fn has_fields() {
        let d = CATALOG.by_id("garmin_nuvi_voice_log").unwrap();
        let names: Vec<&str> = d.fields.iter().map(|f| f.name).collect();
        assert!(names.contains(&"timestamp"));
        assert!(names.contains(&"voice_string"));
    }

    #[test]
    fn file_path_set() {
        let d = CATALOG.by_id("garmin_nuvi_voice_log").unwrap();
        assert!(d.file_path.unwrap().contains("vpm_log_all"));
    }

    #[test]
    fn has_sources() {
        let d = CATALOG.by_id("garmin_nuvi_voice_log").unwrap();
        assert!(!d.sources.is_empty());
    }
}

// ── HEIC Image File ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests_heic_image_file {
    use super::*;

    #[test]
    fn exists_in_catalog() {
        assert!(
            CATALOG.by_id("heic_image_file").is_some(),
            "catalog must contain 'heic_image_file'"
        );
    }

    #[test]
    fn is_file_type() {
        let d = CATALOG.by_id("heic_image_file").unwrap();
        assert_eq!(d.artifact_type, ArtifactType::File);
    }

    #[test]
    fn os_scope_is_ios() {
        let d = CATALOG.by_id("heic_image_file").unwrap();
        assert_eq!(d.os_scope, OsScope::IOS);
    }

    #[test]
    fn triage_is_medium() {
        let d = CATALOG.by_id("heic_image_file").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Medium);
    }

    #[test]
    fn has_fields() {
        let d = CATALOG.by_id("heic_image_file").unwrap();
        let names: Vec<&str> = d.fields.iter().map(|f| f.name).collect();
        assert!(names.contains(&"major_brand"));
        assert!(names.contains(&"compatible_brands"));
        assert!(names.contains(&"handler_type"));
        assert!(names.contains(&"item_count"));
        assert!(names.contains(&"exif_gps_latitude"));
        assert!(names.contains(&"exif_gps_longitude"));
        assert!(names.contains(&"exif_datetime_original"));
        assert!(names.contains(&"exif_camera_model"));
    }

    #[test]
    fn file_path_set() {
        let d = CATALOG.by_id("heic_image_file").unwrap();
        assert!(d.file_path.unwrap().contains(".heic"));
    }

    #[test]
    fn has_sources() {
        let d = CATALOG.by_id("heic_image_file").unwrap();
        assert!(!d.sources.is_empty());
        // Must cite the cheeky4n6monkey post
        assert!(
            d.sources.iter().any(|s| s.contains("cheeky4n6monkey")),
            "sources must include cheeky4n6monkey HEIC blog post"
        );
    }

    #[test]
    fn meaning_mentions_heif() {
        let d = CATALOG.by_id("heic_image_file").unwrap();
        assert!(
            d.meaning.to_ascii_lowercase().contains("heif")
                || d.meaning.to_ascii_lowercase().contains("high efficiency"),
            "meaning should reference HEIF/High Efficiency Image"
        );
    }
}

// ── LAN Turtle Loot ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests_lan_turtle_loot {
    use super::*;

    #[test]
    fn exists_in_catalog() {
        assert!(
            CATALOG.by_id("lan_turtle_loot").is_some(),
            "catalog must contain 'lan_turtle_loot'"
        );
    }

    #[test]
    fn is_directory_type() {
        let d = CATALOG.by_id("lan_turtle_loot").unwrap();
        assert_eq!(d.artifact_type, ArtifactType::Directory);
    }

    #[test]
    fn os_scope_is_linux() {
        let d = CATALOG.by_id("lan_turtle_loot").unwrap();
        assert_eq!(d.os_scope, OsScope::Linux);
    }

    #[test]
    fn triage_is_critical() {
        let d = CATALOG.by_id("lan_turtle_loot").unwrap();
        assert_eq!(d.triage_priority, TriagePriority::Critical);
    }

    #[test]
    fn has_fields() {
        let d = CATALOG.by_id("lan_turtle_loot").unwrap();
        let names: Vec<&str> = d.fields.iter().map(|f| f.name).collect();
        assert!(names.contains(&"credential_type"));
        assert!(names.contains(&"victim_hostname"));
        assert!(names.contains(&"hash_value"));
    }

    #[test]
    fn file_path_set() {
        let d = CATALOG.by_id("lan_turtle_loot").unwrap();
        assert!(d.file_path.unwrap().contains("/root/loot"));
    }

    #[test]
    fn has_sources() {
        let d = CATALOG.by_id("lan_turtle_loot").unwrap();
        assert!(!d.sources.is_empty());
        assert!(
            d.sources.iter().any(|s| s.contains("cheeky4n6monkey")),
            "sources must include cheeky4n6monkey LAN Turtle blog post"
        );
    }

    #[test]
    fn has_mitre_techniques() {
        let d = CATALOG.by_id("lan_turtle_loot").unwrap();
        assert!(
            d.mitre_techniques.contains(&"T1557.001"),
            "should map to LLMNR/NBT-NS Poisoning"
        );
    }
}
