//! Decoder logic: ROT13, FILETIME conversion, binary field parsing, and the
//! core `decode_artifact` dispatch function.

use super::types::{
    ArtifactDescriptor, ArtifactLocation, ArtifactRecord, ArtifactValue, BinaryField,
    BinaryFieldType, DecodeError, Decoder, HiveTarget,
};

/// ROT13-decode an ASCII string: rotate A-Z and a-z by 13, leave other chars.
#[doc(hidden)]
pub fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' => (b'A' + (c as u8 - b'A' + 13) % 26) as char,
            'a'..='z' => (b'a' + (c as u8 - b'a' + 13) % 26) as char,
            other => other,
        })
        .collect()
}

/// Convert a Windows FILETIME (100ns ticks since 1601-01-01) to ISO 8601 UTC.
///
/// Returns `None` for zero or negative Unix epoch values.
#[doc(hidden)]
pub fn filetime_to_iso8601(ft: u64) -> Option<String> {
    // FILETIME epoch is 1601-01-01. Unix epoch offset in 100ns ticks:
    const EPOCH_DIFF: u64 = 116_444_736_000_000_000;
    if ft == 0 {
        return None;
    }
    if ft < EPOCH_DIFF {
        return None;
    }
    let unix_secs = (ft - EPOCH_DIFF) / 10_000_000;

    // Convert unix_secs to calendar date/time via pure arithmetic.
    // Algorithm: days since epoch -> year/month/day; remainder -> H:M:S.
    let secs_per_day: u64 = 86400;
    let mut days = unix_secs / secs_per_day;
    let day_secs = unix_secs % secs_per_day;
    let hours = day_secs / 3600;
    let minutes = (day_secs % 3600) / 60;
    let seconds = day_secs % 60;

    // Civil date from days since 1970-01-01 (Euclidean affine algorithm).
    // Shift epoch to 0000-03-01 to make leap-year logic simpler.
    days += 719_468; // days from 0000-03-01 to 1970-01-01
    let era = days / 146_097;
    let doe = days - era * 146_097; // day of era [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    Some(format!(
        "{y:04}-{m:02}-{d:02}T{hours:02}:{minutes:02}:{seconds:02}Z"
    ))
}

/// Read a u16 LE at `offset`, returning 0 if out of bounds.
fn read_u16_le(data: &[u8], offset: usize) -> u16 {
    if offset + 2 > data.len() {
        return 0;
    }
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

/// Read a u32 LE at `offset`, returning 0 if out of bounds.
fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    if offset + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

/// Read a u64 LE at `offset`, returning 0 if out of bounds.
fn read_u64_le(data: &[u8], offset: usize) -> u64 {
    if offset + 8 > data.len() {
        return 0;
    }
    u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}

/// Read an i32 LE at `offset`, returning 0 if out of bounds.
fn read_i32_le(data: &[u8], offset: usize) -> i32 {
    if offset + 4 > data.len() {
        return 0;
    }
    i32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

/// Read an i64 LE at `offset`, returning 0 if out of bounds.
fn read_i64_le(data: &[u8], offset: usize) -> i64 {
    if offset + 8 > data.len() {
        return 0;
    }
    i64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}

/// Decode a single [`BinaryField`] from a raw buffer into an [`ArtifactValue`].
fn decode_binary_field(field: &BinaryField, raw: &[u8]) -> Result<ArtifactValue, DecodeError> {
    let size = match field.field_type {
        BinaryFieldType::U16Le => 2,
        BinaryFieldType::U32Le | BinaryFieldType::I32Le => 4,
        BinaryFieldType::U64Le | BinaryFieldType::I64Le | BinaryFieldType::FiletimeLe => 8,
        BinaryFieldType::Bytes { len } => len,
    };
    if field.offset + size > raw.len() {
        return Err(DecodeError::FieldOutOfBounds {
            field: field.name,
            offset: field.offset,
            size,
            buf_len: raw.len(),
        });
    }
    Ok(match field.field_type {
        BinaryFieldType::U16Le => {
            ArtifactValue::UnsignedInt(u64::from(read_u16_le(raw, field.offset)))
        }
        BinaryFieldType::U32Le => {
            ArtifactValue::UnsignedInt(u64::from(read_u32_le(raw, field.offset)))
        }
        BinaryFieldType::U64Le => ArtifactValue::UnsignedInt(read_u64_le(raw, field.offset)),
        BinaryFieldType::I32Le => ArtifactValue::Integer(i64::from(read_i32_le(raw, field.offset))),
        BinaryFieldType::I64Le => ArtifactValue::Integer(read_i64_le(raw, field.offset)),
        BinaryFieldType::FiletimeLe => {
            let ft = read_u64_le(raw, field.offset);
            match filetime_to_iso8601(ft) {
                Some(ts) => ArtifactValue::Timestamp(ts),
                None => ArtifactValue::Null,
            }
        }
        BinaryFieldType::Bytes { len } => {
            ArtifactValue::Bytes(raw[field.offset..field.offset + len].to_vec())
        }
    })
}

/// Build the default UID for a registry artifact.
fn build_registry_uid(descriptor: &ArtifactDescriptor, name: &str) -> String {
    let hive_prefix = match descriptor.hive {
        Some(HiveTarget::NtUser) => "HKCU",
        Some(HiveTarget::UsrClass) => "HKCU_Classes",
        Some(HiveTarget::HklmSoftware) => "HKLM\\SOFTWARE",
        Some(HiveTarget::HklmSystem) => "HKLM\\SYSTEM",
        Some(HiveTarget::HklmSam) => "HKLM\\SAM",
        Some(HiveTarget::HklmSecurity) => "HKLM\\SECURITY",
        Some(HiveTarget::Amcache) => "Amcache",
        Some(HiveTarget::Bcd) => "BCD",
        Some(HiveTarget::None) | None => "unknown",
    };
    if name.is_empty() {
        format!("winreg://{}/{}", hive_prefix, descriptor.key_path)
    } else {
        format!("winreg://{}/{}/{}", hive_prefix, descriptor.key_path, name)
    }
}

/// Build the default UID for a file artifact.
fn build_file_uid(descriptor: &ArtifactDescriptor, name: &str) -> String {
    let path = descriptor.file_path.unwrap_or("");
    if name.is_empty() {
        format!("file://{path}")
    } else {
        format!("file://{path}#{name}")
    }
}

/// Decode a slice of [`BinaryField`]s from raw bytes, returning field values
/// and the first FILETIME timestamp encountered (if any).
#[allow(clippy::type_complexity)]
fn decode_binary_fields(
    binary_fields: &[BinaryField],
    raw: &[u8],
) -> Result<(Vec<(&'static str, ArtifactValue)>, Option<String>), DecodeError> {
    let mut decoded = Vec::new();
    let mut ts = None;
    for bf in binary_fields {
        let val = decode_binary_field(bf, raw)?;
        if bf.field_type == BinaryFieldType::FiletimeLe {
            if let ArtifactValue::Timestamp(ref s) = val {
                if ts.is_none() {
                    ts = Some(s.clone());
                }
            }
        }
        decoded.push((bf.name, val));
    }
    Ok((decoded, ts))
}

/// Core decode function: routes to the appropriate decoder variant.
#[allow(clippy::too_many_lines)]
pub(super) fn decode_artifact(
    descriptor: &ArtifactDescriptor,
    name: &str,
    raw: &[u8],
) -> Result<ArtifactRecord, DecodeError> {
    let (fields, timestamp) = match descriptor.decoder {
        Decoder::Identity => {
            let text = std::str::from_utf8(raw)
                .map_err(|_| DecodeError::InvalidUtf8)?
                .to_string();
            (vec![("value", ArtifactValue::Text(text))], None)
        }

        Decoder::Rot13Name => {
            let decoded = rot13(name);
            (vec![("program", ArtifactValue::Text(decoded))], None)
        }

        Decoder::FiletimeAt { offset } => {
            if offset + 8 > raw.len() {
                return Err(DecodeError::BufferTooShort {
                    expected: offset + 8,
                    actual: raw.len(),
                });
            }
            let ft = read_u64_le(raw, offset);
            let ts = filetime_to_iso8601(ft);
            (
                vec![(
                    "timestamp",
                    match ts {
                        Some(ref s) => ArtifactValue::Timestamp(s.clone()),
                        None => ArtifactValue::Null,
                    },
                )],
                ts,
            )
        }

        Decoder::Utf16Le => {
            if raw.len() % 2 != 0 {
                return Err(DecodeError::InvalidUtf16);
            }
            let u16s: Vec<u16> = raw
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            // Trim trailing NUL(s).
            let trimmed: &[u16] = match u16s.iter().position(|&c| c == 0) {
                Some(pos) => &u16s[..pos],
                None => &u16s,
            };
            let text = String::from_utf16(trimmed).map_err(|_| DecodeError::InvalidUtf16)?;
            (vec![("value", ArtifactValue::Text(text))], None)
        }

        Decoder::PipeDelimited {
            fields: field_names,
        } => {
            // Try name first; fall back to raw as UTF-8.
            let source = if name.is_empty() {
                std::str::from_utf8(raw)
                    .map_err(|_| DecodeError::InvalidUtf8)?
                    .to_string()
            } else {
                name.to_string()
            };
            let parts: Vec<&str> = source.split('|').collect();
            let decoded_fields: Vec<(&'static str, ArtifactValue)> = field_names
                .iter()
                .enumerate()
                .map(|(i, &fname)| {
                    let val = match parts.get(i) {
                        Some(s) => ArtifactValue::Text((*s).to_string()),
                        None => ArtifactValue::Null,
                    };
                    (fname, val)
                })
                .collect();
            (decoded_fields, None)
        }

        Decoder::DwordLe => {
            if raw.len() < 4 {
                return Err(DecodeError::BufferTooShort {
                    expected: 4,
                    actual: raw.len(),
                });
            }
            let val = read_u32_le(raw, 0);
            (
                vec![("value", ArtifactValue::UnsignedInt(u64::from(val)))],
                None,
            )
        }

        Decoder::MultiSz => {
            // REG_MULTI_SZ: UTF-16LE, NUL-separated, double NUL terminated.
            if raw.len() < 2 {
                return Ok(make_record(
                    descriptor,
                    name,
                    vec![("values", ArtifactValue::List(vec![]))],
                    None,
                ));
            }
            if raw.len() % 2 != 0 {
                return Err(DecodeError::InvalidUtf16);
            }
            let u16s: Vec<u16> = raw
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            // Split on NUL, dropping the final empty string(s) from the double NUL.
            let strings: Vec<ArtifactValue> = u16s
                .split(|&c| c == 0)
                .filter(|s| !s.is_empty())
                .map(|s| ArtifactValue::Text(String::from_utf16_lossy(s)))
                .collect();
            (vec![("values", ArtifactValue::List(strings))], None)
        }

        Decoder::MruListEx => {
            // u32 LE index list terminated by 0xFFFFFFFF.
            let mut indices = Vec::new();
            let mut offset = 0;
            while offset + 4 <= raw.len() {
                let idx = read_u32_le(raw, offset);
                if idx == 0xFFFF_FFFF {
                    break;
                }
                indices.push(ArtifactValue::UnsignedInt(u64::from(idx)));
                offset += 4;
            }
            (vec![("indices", ArtifactValue::List(indices))], None)
        }

        Decoder::BinaryRecord(binary_fields) => decode_binary_fields(binary_fields, raw)?,

        Decoder::Rot13NameWithBinaryValue(binary_fields) => {
            let (mut fields, ts) = decode_binary_fields(binary_fields, raw)?;
            fields.insert(0, ("program", ArtifactValue::Text(rot13(name))));
            (fields, ts)
        }

        Decoder::EseDatabase => {
            use core::fmt::Write as _;
            // ESE/JET database files are binary; surface raw bytes as hex for now.
            let hex = raw.iter().fold(String::new(), |mut acc, b| {
                let _ = write!(acc, "{b:02x}");
                acc
            });
            (vec![("value", ArtifactValue::Text(hex))], None)
        }
    };

    Ok(make_record(descriptor, name, fields, timestamp))
}

/// Construct an [`ArtifactRecord`] from decoded fields.
fn make_record(
    descriptor: &ArtifactDescriptor,
    name: &str,
    fields: Vec<(&'static str, ArtifactValue)>,
    timestamp: Option<String>,
) -> ArtifactRecord {
    let uid = match descriptor.artifact_type {
        ArtifactLocation::File | ArtifactLocation::Directory => build_file_uid(descriptor, name),
        _ => build_registry_uid(descriptor, name),
    };
    ArtifactRecord {
        uid,
        artifact_id: descriptor.id,
        artifact_name: descriptor.name,
        scope: descriptor.scope,
        os_scope: descriptor.os_scope,
        timestamp,
        fields,
        meaning: descriptor.meaning.to_string(),
        mitre_techniques: descriptor.mitre_techniques.to_vec(),
        confidence: 1.0,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::catalog::types::{DataScope, OsScope, TriagePriority};

    /// Minimal registry descriptor with the given decoder; other fields defaulted.
    fn base(decoder: Decoder) -> ArtifactDescriptor {
        ArtifactDescriptor {
            id: "test_id",
            name: "Test Artifact",
            artifact_type: ArtifactLocation::RegistryValue,
            hive: Some(HiveTarget::NtUser),
            key_path: "Software\\Foo",
            value_name: None,
            file_path: None,
            scope: DataScope::User,
            os_scope: OsScope::All,
            decoder,
            meaning: "meaning",
            mitre_techniques: &["T1000"],
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

    // ── rot13 ─────────────────────────────────────────────────────────────
    #[test]
    fn rot13_rotates_letters_leaves_others() {
        assert_eq!(rot13("Abc123 XYZ"), "Nop123 KLM");
        assert_eq!(rot13("Hello, World!"), "Uryyb, Jbeyq!");
        // ROT13 is self-inverse.
        assert_eq!(rot13(&rot13("Mixed Case 42")), "Mixed Case 42");
    }

    // ── filetime_to_iso8601 (oracle: Python datetime) ─────────────────────
    #[test]
    fn filetime_zero_and_pre_epoch_are_none() {
        assert_eq!(filetime_to_iso8601(0), None);
        assert_eq!(filetime_to_iso8601(1), None); // below EPOCH_DIFF
        assert_eq!(filetime_to_iso8601(116_444_736_000_000_000 - 1), None);
    }

    #[test]
    fn filetime_valid_conversions() {
        // EPOCH_DIFF exactly -> Unix epoch (Jan branch: m <= 2 => y + 1).
        assert_eq!(
            filetime_to_iso8601(116_444_736_000_000_000).as_deref(),
            Some("1970-01-01T00:00:00Z")
        );
        // July 2021 (m > 2 branch, mp >= 10).
        assert_eq!(
            filetime_to_iso8601(132_695_712_000_000_000).as_deref(),
            Some("2021-07-01T00:00:00Z")
        );
        // Mid-month with time-of-day (hours/minutes/seconds all non-zero).
        assert_eq!(
            filetime_to_iso8601(131_655_974_250_000_000).as_deref(),
            Some("2018-03-15T14:23:45Z")
        );
    }

    // ── read_* helpers (direct, incl. out-of-bounds guard) ────────────────
    #[test]
    fn read_helpers_in_bounds() {
        assert_eq!(read_u16_le(&[0xCD, 0xAB], 0), 0xABCD);
        assert_eq!(read_u32_le(&[0x78, 0x56, 0x34, 0x12], 0), 0x1234_5678);
        assert_eq!(
            read_u64_le(&[0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11], 0),
            0x1122_3344_5566_7788
        );
        assert_eq!(read_i32_le(&[0xFB, 0xFF, 0xFF, 0xFF], 0), -5);
        assert_eq!(
            read_i64_le(&[0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], 0),
            -2
        );
    }

    #[test]
    fn read_helpers_out_of_bounds_return_zero() {
        assert_eq!(read_u16_le(&[0x01], 0), 0);
        assert_eq!(read_u32_le(&[0x01, 0x02], 0), 0);
        assert_eq!(read_u64_le(&[0x01, 0x02, 0x03, 0x04], 0), 0);
        assert_eq!(read_i32_le(&[0x01], 0), 0);
        assert_eq!(read_i64_le(&[0x01], 0), 0);
    }

    /// An `offset` close to `usize::MAX` must be rejected, not wrapped: a
    /// `offset + N > len` guard overflows (debug) or wraps to a small value and
    /// lets the index through (release).
    #[test]
    fn read_helpers_offset_near_usize_max_return_zero() {
        let data = [0u8; 8];
        assert_eq!(read_u16_le(&data, usize::MAX - 1), 0);
        assert_eq!(read_u32_le(&data, usize::MAX - 3), 0);
        assert_eq!(read_u64_le(&data, usize::MAX - 7), 0);
        assert_eq!(read_i32_le(&data, usize::MAX - 3), 0);
        assert_eq!(read_i64_le(&data, usize::MAX - 7), 0);
        // usize::MAX itself: every size wraps.
        assert_eq!(read_u16_le(&data, usize::MAX), 0);
        assert_eq!(read_u64_le(&data, usize::MAX), 0);
    }

    /// `Decoder::FiletimeAt` guards with `offset + 8 > raw.len()`, which wraps
    /// for a near-`usize::MAX` offset. It must report the buffer as too short.
    #[test]
    fn filetime_at_offset_near_usize_max_is_buffer_too_short() {
        let desc = base(Decoder::FiletimeAt {
            offset: usize::MAX - 3,
        });
        assert!(matches!(
            decode_artifact(&desc, "", &[0u8; 8]).unwrap_err(),
            DecodeError::BufferTooShort { actual: 8, .. }
        ));
    }

    /// `decode_binary_field` guards with `field.offset + size > raw.len()`,
    /// which wraps the same way — for every field type, including `Bytes`.
    #[test]
    fn binary_field_offset_near_usize_max_is_field_out_of_bounds() {
        for field_type in [
            BinaryFieldType::U16Le,
            BinaryFieldType::U32Le,
            BinaryFieldType::U64Le,
            BinaryFieldType::I32Le,
            BinaryFieldType::I64Le,
            BinaryFieldType::FiletimeLe,
            BinaryFieldType::Bytes { len: 4 },
        ] {
            let field = BinaryField {
                name: "wrap",
                offset: usize::MAX - 3,
                field_type,
                description: "",
            };
            assert!(
                matches!(
                    decode_binary_field(&field, &[0u8; 8]).unwrap_err(),
                    DecodeError::FieldOutOfBounds { field: "wrap", .. }
                ),
                "{field_type:?} must be rejected, not wrapped"
            );
        }
    }

    // ── decode_binary_field / BinaryRecord (all primitive types) ──────────
    const ALL_TYPES_FIELDS: &[BinaryField] = &[
        BinaryField {
            name: "u16",
            offset: 0,
            field_type: BinaryFieldType::U16Le,
            description: "",
        },
        BinaryField {
            name: "u32",
            offset: 2,
            field_type: BinaryFieldType::U32Le,
            description: "",
        },
        BinaryField {
            name: "i32",
            offset: 6,
            field_type: BinaryFieldType::I32Le,
            description: "",
        },
        BinaryField {
            name: "u64",
            offset: 10,
            field_type: BinaryFieldType::U64Le,
            description: "",
        },
        BinaryField {
            name: "i64",
            offset: 18,
            field_type: BinaryFieldType::I64Le,
            description: "",
        },
        BinaryField {
            name: "raw",
            offset: 26,
            field_type: BinaryFieldType::Bytes { len: 3 },
            description: "",
        },
    ];

    #[test]
    fn binary_record_decodes_every_primitive_type() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&[0xCD, 0xAB]); // u16 = 0xABCD
        raw.extend_from_slice(&[0x78, 0x56, 0x34, 0x12]); // u32 = 0x12345678
        raw.extend_from_slice(&[0xFB, 0xFF, 0xFF, 0xFF]); // i32 = -5
        raw.extend_from_slice(&[0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]); // u64
        raw.extend_from_slice(&[0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]); // i64 = -2
        raw.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // bytes

        let desc = base(Decoder::BinaryRecord(ALL_TYPES_FIELDS));
        let rec = decode_artifact(&desc, "", &raw).unwrap();
        assert_eq!(rec.fields[0], ("u16", ArtifactValue::UnsignedInt(0xABCD)));
        assert_eq!(
            rec.fields[1],
            ("u32", ArtifactValue::UnsignedInt(0x1234_5678))
        );
        assert_eq!(rec.fields[2], ("i32", ArtifactValue::Integer(-5)));
        assert_eq!(
            rec.fields[3],
            ("u64", ArtifactValue::UnsignedInt(0x1122_3344_5566_7788))
        );
        assert_eq!(rec.fields[4], ("i64", ArtifactValue::Integer(-2)));
        assert_eq!(
            rec.fields[5],
            ("raw", ArtifactValue::Bytes(vec![0xAA, 0xBB, 0xCC]))
        );
    }

    const FT_FIELD: &[BinaryField] = &[BinaryField {
        name: "last_run",
        offset: 0,
        field_type: BinaryFieldType::FiletimeLe,
        description: "",
    }];

    #[test]
    fn binary_record_filetime_sets_record_timestamp() {
        let ft: u64 = 132_695_712_000_000_000;
        let desc = base(Decoder::BinaryRecord(FT_FIELD));
        let rec = decode_artifact(&desc, "", &ft.to_le_bytes()).unwrap();
        assert_eq!(rec.timestamp.as_deref(), Some("2021-07-01T00:00:00Z"));
        assert_eq!(
            rec.fields[0],
            (
                "last_run",
                ArtifactValue::Timestamp("2021-07-01T00:00:00Z".to_string())
            )
        );
    }

    #[test]
    fn binary_record_zero_filetime_yields_null_and_no_timestamp() {
        let desc = base(Decoder::BinaryRecord(FT_FIELD));
        let rec = decode_artifact(&desc, "", &0u64.to_le_bytes()).unwrap();
        assert_eq!(rec.timestamp, None);
        assert_eq!(rec.fields[0], ("last_run", ArtifactValue::Null));
    }

    #[test]
    fn binary_record_field_out_of_bounds_errors() {
        let desc = base(Decoder::BinaryRecord(ALL_TYPES_FIELDS));
        let err = decode_artifact(&desc, "", &[0u8; 4]).unwrap_err();
        assert_eq!(
            err,
            DecodeError::FieldOutOfBounds {
                field: "u32",
                offset: 2,
                size: 4,
                buf_len: 4,
            }
        );
    }

    #[test]
    fn rot13_name_with_binary_value_prepends_program() {
        let ft: u64 = 132_695_712_000_000_000;
        let desc = base(Decoder::Rot13NameWithBinaryValue(FT_FIELD));
        let rec = decode_artifact(&desc, "Cebtenz", &ft.to_le_bytes()).unwrap();
        assert_eq!(
            rec.fields[0],
            ("program", ArtifactValue::Text("Program".to_string()))
        );
        assert_eq!(rec.timestamp.as_deref(), Some("2021-07-01T00:00:00Z"));
    }

    // ── decode_artifact: string decoders ──────────────────────────────────
    #[test]
    fn identity_decodes_utf8_and_rejects_invalid() {
        let desc = base(Decoder::Identity);
        let rec = decode_artifact(&desc, "", b"hello").unwrap();
        assert_eq!(
            rec.fields[0],
            ("value", ArtifactValue::Text("hello".into()))
        );
        assert_eq!(
            decode_artifact(&desc, "", &[0xFF, 0xFE]).unwrap_err(),
            DecodeError::InvalidUtf8
        );
    }

    #[test]
    fn rot13_name_decoder() {
        let desc = base(Decoder::Rot13Name);
        let rec = decode_artifact(&desc, "Cebtenz", b"").unwrap();
        assert_eq!(
            rec.fields[0],
            ("program", ArtifactValue::Text("Program".into()))
        );
    }

    #[test]
    fn filetime_at_decoder_all_paths() {
        let ft: u64 = 132_695_712_000_000_000;
        let desc = base(Decoder::FiletimeAt { offset: 2 });
        let mut raw = vec![0u8, 0u8];
        raw.extend_from_slice(&ft.to_le_bytes());
        let rec = decode_artifact(&desc, "", &raw).unwrap();
        assert_eq!(rec.timestamp.as_deref(), Some("2021-07-01T00:00:00Z"));

        // Zero FILETIME -> Null field, no timestamp.
        let mut zraw = vec![0u8, 0u8];
        zraw.extend_from_slice(&0u64.to_le_bytes());
        let zrec = decode_artifact(&desc, "", &zraw).unwrap();
        assert_eq!(zrec.fields[0], ("timestamp", ArtifactValue::Null));
        assert_eq!(zrec.timestamp, None);

        // Too short.
        assert_eq!(
            decode_artifact(&desc, "", &[0u8; 4]).unwrap_err(),
            DecodeError::BufferTooShort {
                expected: 10,
                actual: 4
            }
        );
    }

    #[test]
    fn utf16le_decoder_all_paths() {
        let desc = base(Decoder::Utf16Le);
        // "Hi" with trailing NUL terminator (Some(pos) trim path).
        let raw = [b'H', 0, b'i', 0, 0, 0];
        let rec = decode_artifact(&desc, "", &raw).unwrap();
        assert_eq!(rec.fields[0], ("value", ArtifactValue::Text("Hi".into())));

        // No NUL (None trim path).
        let raw2 = [b'O', 0, b'k', 0];
        let rec2 = decode_artifact(&desc, "", &raw2).unwrap();
        assert_eq!(rec2.fields[0], ("value", ArtifactValue::Text("Ok".into())));

        // Odd length -> error.
        assert_eq!(
            decode_artifact(&desc, "", &[b'H', 0, b'i']).unwrap_err(),
            DecodeError::InvalidUtf16
        );

        // Lone high surrogate -> invalid UTF-16.
        assert_eq!(
            decode_artifact(&desc, "", &[0x00, 0xD8]).unwrap_err(),
            DecodeError::InvalidUtf16
        );
    }

    #[test]
    fn pipe_delimited_decoder_name_and_raw() {
        let desc = base(Decoder::PipeDelimited {
            fields: &["a", "b", "c"],
        });
        // From name (more fields than parts -> trailing Null).
        let rec = decode_artifact(&desc, "one|two", b"").unwrap();
        assert_eq!(rec.fields[0], ("a", ArtifactValue::Text("one".into())));
        assert_eq!(rec.fields[1], ("b", ArtifactValue::Text("two".into())));
        assert_eq!(rec.fields[2], ("c", ArtifactValue::Null));

        // From raw (name empty).
        let rec2 = decode_artifact(&desc, "", b"x|y|z").unwrap();
        assert_eq!(rec2.fields[2], ("c", ArtifactValue::Text("z".into())));

        // Raw not UTF-8 with empty name -> error.
        assert_eq!(
            decode_artifact(&desc, "", &[0xFF]).unwrap_err(),
            DecodeError::InvalidUtf8
        );
    }

    #[test]
    fn dword_le_decoder() {
        let desc = base(Decoder::DwordLe);
        let rec = decode_artifact(&desc, "", &[0x78, 0x56, 0x34, 0x12]).unwrap();
        assert_eq!(
            rec.fields[0],
            ("value", ArtifactValue::UnsignedInt(0x1234_5678))
        );
        assert_eq!(
            decode_artifact(&desc, "", &[0x01]).unwrap_err(),
            DecodeError::BufferTooShort {
                expected: 4,
                actual: 1
            }
        );
    }

    #[test]
    fn multi_sz_decoder_all_paths() {
        let desc = base(Decoder::MultiSz);
        // Empty (len < 2) -> empty list.
        let rec = decode_artifact(&desc, "", &[]).unwrap();
        assert_eq!(rec.fields[0], ("values", ArtifactValue::List(vec![])));

        // "ab\0cd\0\0" as UTF-16LE.
        let raw = [b'a', 0, b'b', 0, 0, 0, b'c', 0, b'd', 0, 0, 0];
        let rec2 = decode_artifact(&desc, "", &raw).unwrap();
        assert_eq!(
            rec2.fields[0],
            (
                "values",
                ArtifactValue::List(vec![
                    ArtifactValue::Text("ab".into()),
                    ArtifactValue::Text("cd".into()),
                ])
            )
        );

        // Odd length -> error.
        assert_eq!(
            decode_artifact(&desc, "", &[0x41, 0x00, 0x42]).unwrap_err(),
            DecodeError::InvalidUtf16
        );
    }

    #[test]
    fn mru_list_ex_decoder() {
        let desc = base(Decoder::MruListEx);
        let mut raw = Vec::new();
        raw.extend_from_slice(&2u32.to_le_bytes());
        raw.extend_from_slice(&0u32.to_le_bytes());
        raw.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // terminator
        raw.extend_from_slice(&9u32.to_le_bytes()); // ignored
        let rec = decode_artifact(&desc, "", &raw).unwrap();
        assert_eq!(
            rec.fields[0],
            (
                "indices",
                ArtifactValue::List(vec![
                    ArtifactValue::UnsignedInt(2),
                    ArtifactValue::UnsignedInt(0),
                ])
            )
        );
    }

    #[test]
    fn ese_database_decoder_emits_hex() {
        let desc = base(Decoder::EseDatabase);
        let rec = decode_artifact(&desc, "", &[0x00, 0x0F, 0xAB]).unwrap();
        assert_eq!(
            rec.fields[0],
            ("value", ArtifactValue::Text("000fab".into()))
        );
    }

    // ── UID construction ──────────────────────────────────────────────────
    #[test]
    fn registry_uid_covers_every_hive_prefix() {
        let cases = [
            (Some(HiveTarget::NtUser), "winreg://HKCU/Software\\Foo/v"),
            (
                Some(HiveTarget::UsrClass),
                "winreg://HKCU_Classes/Software\\Foo/v",
            ),
            (
                Some(HiveTarget::HklmSoftware),
                "winreg://HKLM\\SOFTWARE/Software\\Foo/v",
            ),
            (
                Some(HiveTarget::HklmSystem),
                "winreg://HKLM\\SYSTEM/Software\\Foo/v",
            ),
            (
                Some(HiveTarget::HklmSam),
                "winreg://HKLM\\SAM/Software\\Foo/v",
            ),
            (
                Some(HiveTarget::HklmSecurity),
                "winreg://HKLM\\SECURITY/Software\\Foo/v",
            ),
            (
                Some(HiveTarget::Amcache),
                "winreg://Amcache/Software\\Foo/v",
            ),
            (Some(HiveTarget::Bcd), "winreg://BCD/Software\\Foo/v"),
            (Some(HiveTarget::None), "winreg://unknown/Software\\Foo/v"),
            (None, "winreg://unknown/Software\\Foo/v"),
        ];
        for (hive, expected) in cases {
            let desc = ArtifactDescriptor {
                hive,
                ..base(Decoder::Identity)
            };
            let rec = decode_artifact(&desc, "v", b"x").unwrap();
            assert_eq!(rec.uid, expected, "hive {hive:?}");
        }
    }

    #[test]
    fn registry_uid_without_name_omits_value() {
        let desc = base(Decoder::Identity);
        let rec = decode_artifact(&desc, "", b"x").unwrap();
        assert_eq!(rec.uid, "winreg://HKCU/Software\\Foo");
    }

    #[test]
    fn file_uid_with_and_without_name() {
        let desc = ArtifactDescriptor {
            artifact_type: ArtifactLocation::File,
            hive: None,
            file_path: Some("/etc/passwd"),
            ..base(Decoder::Identity)
        };
        let named = decode_artifact(&desc, "line1", b"x").unwrap();
        assert_eq!(named.uid, "file:///etc/passwd#line1");
        let unnamed = decode_artifact(&desc, "", b"x").unwrap();
        assert_eq!(unnamed.uid, "file:///etc/passwd");

        // Missing file_path -> empty path.
        let desc2 = ArtifactDescriptor {
            file_path: None,
            ..desc
        };
        let rec = decode_artifact(&desc2, "", b"x").unwrap();
        assert_eq!(rec.uid, "file://");
    }
}
