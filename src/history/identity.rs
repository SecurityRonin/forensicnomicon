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

#[cfg(test)]
mod tests {
    use super::*;

    fn path_claim(vol: &str, p: &str) -> IdentityClaim {
        IdentityClaim::CanonicalPath {
            volume: vol.to_string(),
            path: PathBuf::from(p),
        }
    }

    fn content_claim(digest: &[u8]) -> IdentityClaim {
        IdentityClaim::ContentHash {
            algo: HashAlgo::Sha256,
            digest: digest.to_vec(),
        }
    }

    #[test]
    fn cohort_key_new_roundtrips_bytes() {
        let raw = [7u8; 32];
        let k = CohortKey::new(raw);
        assert_eq!(k.as_bytes(), &raw);
    }

    #[test]
    fn cohort_key_mixes_discipline_into_first_byte_when_no_claim_matches() {
        // An ApfsFileId matches no discipline, so cohort_key is just the discipline seed.
        let art = ArtifactRef {
            claims: vec![IdentityClaim::ApfsFileId {
                volume_uuid: [1u8; 16],
                file_id: 9,
            }],
        };
        let k = art.cohort_key(IdentityDiscipline::ContentStable);
        let mut expected = [0u8; 32];
        expected[0] = IdentityDiscipline::ContentStable as u8;
        assert_eq!(k.as_bytes(), &expected);
    }

    #[test]
    fn cohort_key_folds_single_matching_claim_by_documented_construction() {
        // Single claim at index 0: key[0]=discipline seed, key[(0+j+1)%32]^=digest[j].
        let art = ArtifactRef {
            claims: vec![content_claim(&[0xAB, 0xCD])],
        };
        let k = art.cohort_key(IdentityDiscipline::ContentStable);
        let b = k.as_bytes();
        assert_eq!(b[0], IdentityDiscipline::ContentStable as u8);
        assert_eq!(b[1], 0xAB);
        assert_eq!(b[2], 0xCD);
        assert!(b[3..].iter().all(|&x| x == 0));
    }

    #[test]
    fn cohort_key_is_deterministic_and_content_sensitive() {
        let a = ArtifactRef {
            claims: vec![content_claim(&[1, 2, 3])],
        };
        let a_again = ArtifactRef {
            claims: vec![content_claim(&[1, 2, 3])],
        };
        let b = ArtifactRef {
            claims: vec![content_claim(&[1, 2, 4])],
        };
        assert_eq!(
            a.cohort_key(IdentityDiscipline::ContentStable),
            a_again.cohort_key(IdentityDiscipline::ContentStable)
        );
        assert_ne!(
            a.cohort_key(IdentityDiscipline::ContentStable),
            b.cohort_key(IdentityDiscipline::ContentStable)
        );
    }

    #[test]
    fn matches_true_under_path_stable_and_false_on_divergent_path() {
        let a = ArtifactRef {
            claims: vec![path_claim("C:", "/x")],
        };
        let b = ArtifactRef {
            claims: vec![path_claim("C:", "/x")],
        };
        let c = ArtifactRef {
            claims: vec![path_claim("C:", "/y")],
        };
        assert!(a.matches(&b, IdentityDiscipline::PathStable));
        assert!(!a.matches(&c, IdentityDiscipline::PathStable));
    }

    #[test]
    fn matches_false_when_no_claim_pair_agrees() {
        let a = ArtifactRef {
            claims: vec![content_claim(&[1])],
        };
        let b = ArtifactRef {
            claims: vec![path_claim("C:", "/x")],
        };
        assert!(!a.matches(&b, IdentityDiscipline::ContentStable));
    }

    #[test]
    fn claims_match_path_stable_arms() {
        let a = path_claim("C:", "/x");
        let b = path_claim("C:", "/x");
        let d = path_claim("D:", "/x");
        assert!(claims_match_under(&a, &b, IdentityDiscipline::PathStable));
        assert!(!claims_match_under(&a, &d, IdentityDiscipline::PathStable));
        // Mismatched variant hits the `_ => false` arm.
        assert!(!claims_match_under(
            &a,
            &content_claim(&[1]),
            IdentityDiscipline::PathStable
        ));
    }

    #[test]
    fn claims_match_content_stable_arms() {
        let a = content_claim(&[1, 2]);
        let b = content_claim(&[1, 2]);
        assert!(claims_match_under(
            &a,
            &b,
            IdentityDiscipline::ContentStable
        ));
        assert!(!claims_match_under(
            &a,
            &path_claim("C:", "/x"),
            IdentityDiscipline::ContentStable
        ));
    }

    #[test]
    fn claims_match_object_stable_inode_and_ntfs_arms() {
        let inode = |gen| IdentityClaim::InodeIdentity {
            volume: "v".to_string(),
            inode: 42,
            generation: gen,
        };
        assert!(claims_match_under(
            &inode(Some(1)),
            &inode(Some(1)),
            IdentityDiscipline::ObjectStable
        ));
        let ntfs = |seq| IdentityClaim::NtfsFileRef {
            volume: "v".to_string(),
            mft_record: 7,
            sequence: seq,
        };
        assert!(claims_match_under(
            &ntfs(3),
            &ntfs(3),
            IdentityDiscipline::ObjectStable
        ));
        assert!(!claims_match_under(
            &ntfs(3),
            &ntfs(4),
            IdentityDiscipline::ObjectStable
        ));
        // Cross-variant hits the `_ => false` arm.
        assert!(!claims_match_under(
            &inode(Some(1)),
            &ntfs(3),
            IdentityDiscipline::ObjectStable
        ));
    }

    #[test]
    fn claims_match_record_stable_arms() {
        let rec = |k: &[u8]| IdentityClaim::RecordIdentity {
            schema: "sqlite:msgstore#messages".to_string(),
            primary_key: k.to_vec(),
        };
        assert!(claims_match_under(
            &rec(&[9]),
            &rec(&[9]),
            IdentityDiscipline::RecordStable
        ));
        assert!(!claims_match_under(
            &rec(&[9]),
            &path_claim("C:", "/x"),
            IdentityDiscipline::RecordStable
        ));
    }

    #[test]
    fn logical_stable_delegates_to_path_and_record() {
        let path = path_claim("C:", "/x");
        let rec = IdentityClaim::RecordIdentity {
            schema: "s".to_string(),
            primary_key: vec![1],
        };
        // Path branch of the delegation.
        assert!(claims_match_under(
            &path,
            &path.clone(),
            IdentityDiscipline::LogicalStable
        ));
        // Record branch of the delegation.
        assert!(claims_match_under(
            &rec,
            &rec.clone(),
            IdentityDiscipline::LogicalStable
        ));
        // Neither branch agrees.
        assert!(!claims_match_under(
            &path,
            &content_claim(&[1]),
            IdentityDiscipline::LogicalStable
        ));
    }

    #[test]
    fn claim_matches_discipline_true_and_false() {
        assert!(claim_matches_discipline(
            &path_claim("C:", "/x"),
            IdentityDiscipline::PathStable
        ));
        assert!(claim_matches_discipline(
            &content_claim(&[1]),
            IdentityDiscipline::ContentStable
        ));
        assert!(claim_matches_discipline(
            &IdentityClaim::InodeIdentity {
                volume: "v".to_string(),
                inode: 1,
                generation: None,
            },
            IdentityDiscipline::ObjectStable
        ));
        // A claim that matches no discipline.
        assert!(!claim_matches_discipline(
            &IdentityClaim::ApfsFileId {
                volume_uuid: [0u8; 16],
                file_id: 1,
            },
            IdentityDiscipline::ObjectStable
        ));
    }

    #[test]
    fn fingerprint_canonical_path() {
        let fp = claim_fingerprint(&path_claim("C:", "/a"));
        assert_eq!(fp, b"C:/a".to_vec());
    }

    #[test]
    fn fingerprint_inode_with_and_without_generation() {
        let with = claim_fingerprint(&IdentityClaim::InodeIdentity {
            volume: "v".to_string(),
            inode: 1,
            generation: Some(2),
        });
        let mut expected = b"v".to_vec();
        expected.extend_from_slice(&1u64.to_le_bytes());
        expected.extend_from_slice(&2u32.to_le_bytes());
        assert_eq!(with, expected);

        let without = claim_fingerprint(&IdentityClaim::InodeIdentity {
            volume: "v".to_string(),
            inode: 1,
            generation: None,
        });
        let mut expected_none = b"v".to_vec();
        expected_none.extend_from_slice(&1u64.to_le_bytes());
        assert_eq!(without, expected_none);
    }

    #[test]
    fn fingerprint_ntfs_ref() {
        let fp = claim_fingerprint(&IdentityClaim::NtfsFileRef {
            volume: "n".to_string(),
            mft_record: 5,
            sequence: 3,
        });
        let mut expected = b"n".to_vec();
        expected.extend_from_slice(&5u64.to_le_bytes());
        expected.extend_from_slice(&3u16.to_le_bytes());
        assert_eq!(fp, expected);
    }

    #[test]
    fn fingerprint_apfs_file_id() {
        let fp = claim_fingerprint(&IdentityClaim::ApfsFileId {
            volume_uuid: [0u8; 16],
            file_id: 7,
        });
        let mut expected = vec![0u8; 16];
        expected.extend_from_slice(&7u64.to_le_bytes());
        assert_eq!(fp, expected);
    }

    #[test]
    fn fingerprint_content_hash_is_the_digest() {
        let fp = claim_fingerprint(&content_claim(&[1, 2, 3]));
        assert_eq!(fp, vec![1, 2, 3]);
    }

    #[test]
    fn fingerprint_record_identity() {
        let fp = claim_fingerprint(&IdentityClaim::RecordIdentity {
            schema: "s".to_string(),
            primary_key: vec![9],
        });
        assert_eq!(fp, b"s\x09".to_vec());
    }

    #[test]
    fn fingerprint_application_guid_is_the_guid() {
        let guid = [4u8; 16];
        let fp = claim_fingerprint(&IdentityClaim::ApplicationGuid {
            app: "com.whatsapp".to_string(),
            guid,
        });
        assert_eq!(fp, guid.to_vec());
    }

    #[test]
    fn fingerprint_signing_subject_concatenates_issuer_subject() {
        let fp = claim_fingerprint(&IdentityClaim::SigningSubject {
            issuer: "i".to_string(),
            subject: "s".to_string(),
        });
        assert_eq!(fp, b"is".to_vec());
    }
}
