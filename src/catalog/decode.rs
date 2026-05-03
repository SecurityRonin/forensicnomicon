//! Decoder logic: ROT13, FILETIME conversion, binary field parsing, and the
//! core `decode_artifact` dispatch function.

use super::types::{
    ArtifactDescriptor, ArtifactRecord, ArtifactType, ArtifactValue, BinaryField, BinaryFieldType,
    DecodeError, Decoder, HiveTarget,
};

/// ROT13-decode an ASCII string: rotate A-Z and a-z by 13, leave other chars.
pub(crate) fn rot13(s: &str) -> String {
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
pub(crate) fn filetime_to_iso8601(ft: u64) -> Option<String> {
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
            // ESE/JET database files are binary; surface raw bytes as hex for now.
            let hex = raw.iter().map(|b| format!("{b:02x}")).collect::<String>();
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
        ArtifactType::File | ArtifactType::Directory => build_file_uid(descriptor, name),
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
