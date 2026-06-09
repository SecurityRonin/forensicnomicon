//! Artifact identity facets and cohort-grouping disciplines for the `[H]` layer.

use std::path::PathBuf;

/// Opaque volume identifier (e.g. drive letter "C:", APFS UUID, ext4 UUID string).
pub type VolumeId = String;

/// Schema reference string (e.g. "sqlite:msgstore#messages").
pub type SchemaRef = String;

/// Application identifier string (e.g. "com.whatsapp", "chrome").
pub type AppId = String;

/// Digest algorithm used in a `IdentityClaim::ContentHash`.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HashAlgo {
    Md5,
    Sha1,
    Sha256,
    Sha512,
    Blake3,
    /// Any other algorithm, identified by name.
    Other(String),
}

/// One facet of artifact identity. Multiple claims can coexist in an `ArtifactRef`.
///
/// Identity disagreement between facets is itself a forensic finding. For example,
/// a `PathStable` cohort whose `ContentStable` subcohorts split indicates the file at
/// that path was swapped while preserving its name.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityClaim {
    /// Filesystem canonical path.
    CanonicalPath { volume: VolumeId, path: PathBuf },
    /// POSIX inode number + optional generation counter.
    InodeIdentity {
        volume: VolumeId,
        inode: u64,
        generation: Option<u32>,
    },
    /// Windows NTFS MFT record + sequence number.
    NtfsFileRef {
        volume: VolumeId,
        mft_record: u64,
        sequence: u16,
    },
    /// APFS file identifier (volume UUID as 16 bytes + file_id).
    ApfsFileId { volume_uuid: [u8; 16], file_id: u64 },
    /// Cryptographic content hash. Stable across copies; equates duplicates.
    ContentHash { algo: HashAlgo, digest: Vec<u8> },
    /// Application-level record identity (e.g. SQLite rowid, email Message-ID).
    RecordIdentity {
        schema: SchemaRef,
        primary_key: Vec<u8>,
    },
    /// Application GUID (e.g. WhatsApp message GUID).
    ApplicationGuid { app: AppId, guid: [u8; 16] },
    /// Code-signing subject (issuer DN + subject DN, e.g. from Authenticode).
    SigningSubject { issuer: String, subject: String },
}

/// How to match artifact identity across temporal states when building a cohort.
///
/// Callers select a discipline at query time. Different disciplines for the same
/// artifact can yield different (all valid) cohort groupings.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdentityDiscipline {
    /// Same canonical path across snapshots. Grouping: by `CanonicalPath` claim.
    PathStable,
    /// Same content hash. Groups copies/duplicates together.
    ContentStable,
    /// Same filesystem object (inode+generation, MFT record+sequence). Detects swaps.
    ObjectStable,
    /// Same application-level record (rowid, message_id). Detects app reinstalls.
    RecordStable,
    /// Same logical artifact across reinstalls (rarely provable without external evidence).
    LogicalStable,
}

/// Opaque key used to group temporal states into a cohort under a given `IdentityDiscipline`.
///
/// Computed from the selected discipline + the relevant claim fields. Two `ArtifactRef`
/// values that produce the same `CohortKey` for a given discipline belong to the same cohort.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CohortKey([u8; 32]);

impl CohortKey {
    /// Construct from a pre-computed 32-byte key (e.g. SHA-256 of the identity claims).
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Set of identity claims describing a single artifact across all its temporal states.
///
/// Multiple claims can coexist; each facet can independently agree or disagree across
/// snapshot boundaries. Disagreement between facets is surfaced as an
/// `IdentityDiscontinuity` forensic finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactRef {
    pub claims: Vec<IdentityClaim>,
}

impl ArtifactRef {
    /// Check whether `other` refers to the same artifact under `discipline`.
    #[must_use]
    pub fn matches(&self, other: &Self, discipline: IdentityDiscipline) -> bool {
        for a in &self.claims {
            for b in &other.claims {
                if claims_match_under(a, b, discipline) {
                    return true;
                }
            }
        }
        false
    }

    /// Derive a cohort grouping key for this artifact under `discipline`.
    ///
    /// Uses a simple FNV-like fold; callers that need collision-resistance should
    /// supply their own hashing layer above this crate.
    #[must_use]
    pub fn cohort_key(&self, discipline: IdentityDiscipline) -> CohortKey {
        let mut key = [0u8; 32];
        // Mix discipline into first byte.
        key[0] = discipline as u8;
        // Mix relevant claim bytes in a deterministic (but not crypto-secure) way.
        for (i, claim) in self.claims.iter().enumerate() {
            if claim_matches_discipline(claim, discipline) {
                let bytes = claim_fingerprint(claim);
                for (j, b) in bytes.iter().enumerate() {
                    key[(i + j + 1) % 32] ^= b;
                }
            }
        }
        CohortKey(key)
    }
}

fn claims_match_under(a: &IdentityClaim, b: &IdentityClaim, d: IdentityDiscipline) -> bool {
    match d {
        IdentityDiscipline::PathStable => match (a, b) {
            (
                IdentityClaim::CanonicalPath {
                    volume: va,
                    path: pa,
                },
                IdentityClaim::CanonicalPath {
                    volume: vb,
                    path: pb,
                },
            ) => va == vb && pa == pb,
            _ => false,
        },
        IdentityDiscipline::ContentStable => match (a, b) {
            (
                IdentityClaim::ContentHash {
                    algo: aa,
                    digest: da,
                },
                IdentityClaim::ContentHash {
                    algo: ab,
                    digest: db,
                },
            ) => aa == ab && da == db,
            _ => false,
        },
        IdentityDiscipline::ObjectStable => match (a, b) {
            (
                IdentityClaim::InodeIdentity {
                    volume: va,
                    inode: ia,
                    generation: ga,
                },
                IdentityClaim::InodeIdentity {
                    volume: vb,
                    inode: ib,
                    generation: gb,
                },
            ) => va == vb && ia == ib && ga == gb,
            (
                IdentityClaim::NtfsFileRef {
                    volume: va,
                    mft_record: ma,
                    sequence: sa,
                },
                IdentityClaim::NtfsFileRef {
                    volume: vb,
                    mft_record: mb,
                    sequence: sb,
                },
            ) => va == vb && ma == mb && sa == sb,
            _ => false,
        },
        IdentityDiscipline::RecordStable => match (a, b) {
            (
                IdentityClaim::RecordIdentity {
                    schema: sa,
                    primary_key: ka,
                },
                IdentityClaim::RecordIdentity {
                    schema: sb,
                    primary_key: kb,
                },
            ) => sa == sb && ka == kb,
            _ => false,
        },
        IdentityDiscipline::LogicalStable => {
            // Logical stability requires out-of-band evidence; default to path+record.
            claims_match_under(a, b, IdentityDiscipline::PathStable)
                || claims_match_under(a, b, IdentityDiscipline::RecordStable)
        }
    }
}

fn claim_matches_discipline(claim: &IdentityClaim, d: IdentityDiscipline) -> bool {
    matches!(
        (claim, d),
        (
            IdentityClaim::CanonicalPath { .. },
            IdentityDiscipline::PathStable
        ) | (
            IdentityClaim::ContentHash { .. },
            IdentityDiscipline::ContentStable
        ) | (
            IdentityClaim::InodeIdentity { .. } | IdentityClaim::NtfsFileRef { .. },
            IdentityDiscipline::ObjectStable
        ) | (
            IdentityClaim::RecordIdentity { .. },
            IdentityDiscipline::RecordStable
        )
    )
}

fn claim_fingerprint(claim: &IdentityClaim) -> Vec<u8> {
    match claim {
        IdentityClaim::CanonicalPath { volume, path } => {
            let mut v = volume.as_bytes().to_vec();
            v.extend_from_slice(path.to_string_lossy().as_bytes());
            v
        }
        IdentityClaim::InodeIdentity {
            volume,
            inode,
            generation,
        } => {
            let mut v = volume.as_bytes().to_vec();
            v.extend_from_slice(&inode.to_le_bytes());
            if let Some(g) = generation {
                v.extend_from_slice(&g.to_le_bytes());
            }
            v
        }
        IdentityClaim::NtfsFileRef {
            volume,
            mft_record,
            sequence,
        } => {
            let mut v = volume.as_bytes().to_vec();
            v.extend_from_slice(&mft_record.to_le_bytes());
            v.extend_from_slice(&sequence.to_le_bytes());
            v
        }
        IdentityClaim::ApfsFileId {
            volume_uuid,
            file_id,
        } => {
            let mut v = volume_uuid.to_vec();
            v.extend_from_slice(&file_id.to_le_bytes());
            v
        }
        IdentityClaim::ContentHash { digest, .. } => digest.clone(),
        IdentityClaim::RecordIdentity {
            schema,
            primary_key,
        } => {
            let mut v = schema.as_bytes().to_vec();
            v.extend_from_slice(primary_key);
            v
        }
        IdentityClaim::ApplicationGuid { guid, .. } => guid.to_vec(),
        IdentityClaim::SigningSubject { issuer, subject } => {
            let mut v = issuer.as_bytes().to_vec();
            v.extend_from_slice(subject.as_bytes());
            v
        }
    }
}
