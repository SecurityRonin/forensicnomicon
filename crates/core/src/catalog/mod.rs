//! Forensic artifact catalog — engine and types.
//!
//! This is the stable engine half of the catalog: the descriptor [`types`], the
//! [`ForensicCatalog`] lookup engine and its query methods, the container/record
//! parsing-profile tables, and the in-core [`Decoder`] logic. It carries **no**
//! artifact data — the assembled descriptor dataset lives in the umbrella
//! `forensicnomicon` crate, which wires it into a global `CATALOG` via
//! [`ForensicCatalog::new`].
//!
//! Parser knowledge is layered:
//!
//! - [`ContainerProfile`] models how to open and enumerate the outer container
//!   such as an offline Registry hive, SQLite database, EVTX log, or memory image.
//! - [`ContainerSignature`] models how to recognize or carve that container
//!   from raw bytes in unallocated space or memory.
//! - [`ArtifactDescriptor`] identifies where the artifact lives inside that
//!   container or on disk.
//! - [`ArtifactParsingProfile`] captures artifact-specific interpretation rules
//!   such as "UserAssist names are ROT13".
//! - [`RecordSignature`] models how to recognize or validate individual records
//!   or payloads inside a container when carving or validating fragments.
//! - [`Decoder`] is reserved for compact, stable transforms we can implement
//!   safely in-core.

mod containers_parsing;
mod decode;
pub mod types;

pub use types::{
    ArtifactDescriptor, ArtifactLocation, ArtifactParsingProfile, ArtifactQuery, ArtifactRecord,
    ArtifactValue, BinaryField, BinaryFieldType, ContainerProfile, ContainerSignature, DataScope,
    DecodeError, Decoder, FieldSchema, ForensicCatalog, HiveTarget, OsScope, Platform,
    PlatformMask, RecordSignature, TriagePriority, ValueType,
};

pub use containers_parsing::{
    all_container_profiles, all_container_signatures, all_parsing_profiles, all_record_signatures,
    container_profile, container_signature, parsing_profile, record_signatures_for_container,
};

// In-core decode helpers, exposed (doc-hidden) so cross-crate catalog tests in the
// umbrella crate can exercise ROT13 / FILETIME directly. Not part of the stable API.
#[doc(hidden)]
pub use decode::{filetime_to_iso8601, rot13};

// ── ForensicCatalog extension methods ─────────────────────────────────────────
// These delegate to sibling parsing/decode modules. They look an artifact up in
// `self` (the catalog instance) rather than any global, so the engine carries no
// dependency on a particular dataset.

impl ForensicCatalog {
    /// Look up parsing guidance for an artifact id.
    pub fn parsing_profile(&self, id: &str) -> Option<&'static ArtifactParsingProfile> {
        containers_parsing::parsing_profile(id)
    }

    /// Look up the container parsing layer for an artifact id.
    pub fn container_profile(&self, id: &str) -> Option<&'static ContainerProfile> {
        if let Some(binding) = containers_parsing::artifact_container_bindings()
            .iter()
            .find(|b| b.artifact_id.eq_ignore_ascii_case(id))
        {
            return containers_parsing::container_profile(binding.container_id);
        }
        let desc = self.by_id(id)?;
        containers_parsing::infer_container_profile_pub(desc)
    }

    /// Look up carving/recognition guidance for an artifact's outer container.
    pub fn container_signature(&self, id: &str) -> Option<&'static ContainerSignature> {
        let profile = self.container_profile(id)?;
        containers_parsing::container_signature(profile.id)
    }

    /// Look up carving/recognition guidance for records associated with an artifact.
    pub fn record_signatures(&self, id: &str) -> Vec<&'static RecordSignature> {
        let direct: Vec<&'static RecordSignature> = containers_parsing::all_record_signatures()
            .iter()
            .filter(|sig| {
                sig.artifact_id
                    .is_some_and(|artifact_id| artifact_id.eq_ignore_ascii_case(id))
            })
            .collect();
        if !direct.is_empty() {
            return direct;
        }
        if let Some(profile) = self.container_profile(id) {
            return containers_parsing::record_signatures_for_container(profile.id);
        }
        Vec::new()
    }

    /// Decode raw data using the descriptor's embedded decoder.
    ///
    /// # Parameters
    /// - `descriptor` -- the catalog entry describing the artifact
    /// - `name` -- the registry value name (or filename), used by ROT13 and
    ///   PipeDelimited decoders
    /// - `raw` -- the raw byte payload of the registry value or file content
    pub fn decode(
        &self,
        descriptor: &ArtifactDescriptor,
        name: &str,
        raw: &[u8],
    ) -> Result<ArtifactRecord, DecodeError> {
        decode::decode_artifact(descriptor, name, raw)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use types::{DataScope, OsScope, TriagePriority};

    fn desc(
        id: &'static str,
        artifact_type: ArtifactLocation,
        hive: Option<HiveTarget>,
    ) -> ArtifactDescriptor {
        ArtifactDescriptor {
            id,
            name: "n",
            artifact_type,
            hive,
            key_path: "",
            value_name: None,
            file_path: None,
            scope: DataScope::System,
            os_scope: OsScope::All,
            decoder: Decoder::Identity,
            meaning: "m",
            mitre_techniques: &[],
            fields: &[],
            retention: None,
            triage_priority: TriagePriority::Medium,
            related_artifacts: &[],
            sources: &[],
            evidence_strength: None,
            evidence_caveats: &[],
            volatility: None,
            volatility_rationale: "",
        }
    }

    static ENTRIES: &[ArtifactDescriptor] = &[
        ArtifactDescriptor {
            id: "userassist_exe",
            name: "UserAssist",
            artifact_type: ArtifactLocation::RegistryValue,
            hive: Some(HiveTarget::NtUser),
            key_path: "",
            value_name: None,
            file_path: None,
            scope: DataScope::User,
            os_scope: OsScope::Win7Plus,
            decoder: Decoder::Identity,
            meaning: "m",
            mitre_techniques: &[],
            fields: &[],
            retention: None,
            triage_priority: TriagePriority::High,
            related_artifacts: &[],
            sources: &[],
            evidence_strength: None,
            evidence_caveats: &[],
            volatility: None,
            volatility_rationale: "",
        },
        ArtifactDescriptor {
            id: "reg_only",
            name: "RegOnly",
            artifact_type: ArtifactLocation::RegistryValue,
            hive: Some(HiveTarget::HklmSystem),
            key_path: "",
            value_name: None,
            file_path: None,
            scope: DataScope::System,
            os_scope: OsScope::All,
            decoder: Decoder::Identity,
            meaning: "m",
            mitre_techniques: &[],
            fields: &[],
            retention: None,
            triage_priority: TriagePriority::Low,
            related_artifacts: &[],
            sources: &[],
            evidence_strength: None,
            evidence_caveats: &[],
            volatility: None,
            volatility_rationale: "",
        },
    ];

    fn cat() -> ForensicCatalog {
        ForensicCatalog::new(ENTRIES)
    }

    #[test]
    fn parsing_profile_delegates() {
        let cat = cat();
        assert_eq!(
            cat.parsing_profile("userassist_exe").unwrap().artifact_id,
            "userassist_exe"
        );
        assert!(cat.parsing_profile("nope").is_none());
    }

    #[test]
    fn container_profile_binding_infer_and_none() {
        let cat = cat();
        // Binding path: windows_timeline -> sqlite_database (no descriptor needed).
        assert_eq!(
            cat.container_profile("windows_timeline").unwrap().id,
            "sqlite_database"
        );
        // Infer path: registry descriptor with a hive -> windows_registry_hive.
        assert_eq!(
            cat.container_profile("reg_only").unwrap().id,
            "windows_registry_hive"
        );
        // Unknown id, no binding, not in catalog -> None.
        assert!(cat.container_profile("ghost").is_none());
    }

    #[test]
    fn container_signature_resolves_via_profile() {
        let cat = cat();
        assert_eq!(
            cat.container_signature("windows_timeline")
                .unwrap()
                .container_id,
            "sqlite_database"
        );
        assert!(cat.container_signature("ghost").is_none());
    }

    #[test]
    fn record_signatures_direct_container_and_empty() {
        let cat = cat();
        // Direct: userassist_exe is the artifact_id of a record signature.
        let direct = cat.record_signatures("userassist_exe");
        assert_eq!(direct.len(), 1);
        assert_eq!(direct[0].id, "userassist_count_payload");

        // Container fallback: windows_timeline -> sqlite_database container sigs.
        let via_container = cat.record_signatures("windows_timeline");
        assert!(via_container.iter().any(|s| s.id == "sqlite_btree_page"));

        // No direct match and no resolvable container -> empty.
        assert!(cat.record_signatures("ghost").is_empty());
    }

    #[test]
    fn decode_delegates_to_decoder() {
        let cat = cat();
        let d = desc(
            "x",
            ArtifactLocation::RegistryValue,
            Some(HiveTarget::NtUser),
        );
        let rec = cat.decode(&d, "val", b"hi").unwrap();
        assert_eq!(rec.fields[0], ("value", ArtifactValue::Text("hi".into())));
    }
}
