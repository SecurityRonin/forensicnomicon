//! Windows descriptors for attributing activity to accounts: the SAM per-user
//! F record and RID semantics, WeChat for Windows account folders, the
//! Partition/Diagnostic 1006 disk-arrival event, and FAT/exFAT directory
//! entries on removable volumes.
//!
//! Every artefact here identifies an account, a SID, a device or a volume.
//! None identifies the person at the keyboard: several people sharing one
//! account produce one SID, and a removable volume records no owner at all.
//! The caveats say so on each descriptor rather than leaving it implicit in
//! `DataScope`.

use super::super::types::{
    ArtifactDescriptor, ArtifactLocation, DataScope, Decoder, FieldSchema, HiveTarget, OsScope,
    TriagePriority, ValueType,
};

// ── SAM per-user F record ────────────────────────────────────────────────────

/// Field layout of the SAM `Users\<RID hex>\F` value.
///
/// Source: https://github.com/libyal/winreg-kb/blob/main/docs/sources/security-accounts-manager-keys/Domains.md
/// ("Users RID sub key", "F value data": offsets 8, 24, 32, 40, 48, 56, 64, 66).
pub(crate) static SAM_USER_F_RECORD_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "last_logon",
        value_type: ValueType::Timestamp,
        description: "Offset 8, FILETIME: last logon (lastLogon)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "password_last_set",
        value_type: ValueType::Timestamp,
        description: "Offset 24, FILETIME: password last set (pwdLastSet)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "account_expires",
        value_type: ValueType::Timestamp,
        description: "Offset 32, FILETIME: account expiry; 0x7fffffffffffffff means never",
        is_uid_component: false,
    },
    FieldSchema {
        name: "last_failed_logon",
        value_type: ValueType::Timestamp,
        description: "Offset 40, FILETIME: last password failure (badPasswordTime)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "rid",
        value_type: ValueType::UnsignedInt,
        description: "Offset 48, 4 bytes: relative identifier, the last sub-authority of the account SID; also the hex name of the Users sub-key",
        is_uid_component: true,
    },
    FieldSchema {
        name: "account_control_flags",
        value_type: ValueType::UnsignedInt,
        description: "Offset 56, 4 bytes: user account control flags (0x00000001 account disabled, 0x00000010 normal account, 0x00000200 password does not expire)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "failed_logon_count",
        value_type: ValueType::UnsignedInt,
        description: "Offset 64, 2 bytes: number of password failures (badPwdCount)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "logon_count",
        value_type: ValueType::UnsignedInt,
        description: "Offset 66, 2 bytes: number of logons (logonCount)",
        is_uid_component: false,
    },
];

/// SAM per-user `F` value: logon and password times, RID, flags and counts.
///
/// # Sources
/// - <https://github.com/libyal/winreg-kb/blob/main/docs/sources/security-accounts-manager-keys/Domains.md> —
///   F value layout.
/// - <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers> —
///   RID 500 Administrator, 501 Guest, 502 KRBTGT (domain controllers only);
///   "The SAM on a standalone computer can track the RID values that it has
///   used and make sure that it never uses them again."
/// - <https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts> —
///   DefaultAccount (DSMA) RID 503; WDAGUtilityAccount RID 504.
///
/// The OEM-setup explanation for a first owner at RID 1002 (the OOBE
/// placeholder `defaultuser0` at 1000, an OEM or re-run-OOBE account at
/// 1001) is inferred from practitioner reports, not vendor-documented; the
/// caveat says so.
pub(crate) static SAM_USER_F_RECORD: ArtifactDescriptor = ArtifactDescriptor {
    id: "sam_user_f_record",
    name: "SAM User F Record (logon times, RID, flags, logon count)",
    artifact_type: ArtifactLocation::RegistryValue,
    hive: Some(HiveTarget::HklmSam),
    key_path: r"SAM\Domains\Account\Users\<RID hex>",
    value_name: Some("F"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Binary F value under each local account's SAM\\Domains\\Account\\Users\\<RID hex> \
        key: FILETIMEs for last logon, password last set, account expiry and last failed \
        logon, the account's RID, its user-account-control flags (disabled, normal, password \
        never expires), and counts of failed and successful logons. Joined to the Names \
        sub-key (username) and the V value (full name, comment), it is the account table a \
        registry viewer shows: which local accounts exist, which are disabled, and when each \
        was last used.",
    mitre_techniques: &["T1087.001"],
    fields: SAM_USER_F_RECORD_FIELDS,
    retention: Some("Until the account is deleted; a deleted account's key is removed"),
    triage_priority: TriagePriority::High,
    related_artifacts: &[
        "sam_users",
        "profile_list_users",
        "user_account_sid",
        "evtx_security_account_management",
    ],
    sources: &[
        "https://github.com/libyal/winreg-kb/blob/main/docs/sources/security-accounts-manager-keys/Domains.md",
        "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers",
        "https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: Some(crate::evidence::EvidenceTier::SourceOrMultiImpl),
    evidence_caveats: &[
        "Every value attributes to the account, not a person: several people sharing one account produce one RID, one last-logon time and one logon count",
        "logon_count counts logons of the account, not distinct people or sessions of one person; a high count on a shared account says nothing about how many users there were",
        "Timestamps are UTC FILETIMEs; convert with the system's time zone before comparing with local-time records",
        "Built-in RIDs are fixed: 500 Administrator and 501 Guest (Microsoft, Security identifiers), 503 DefaultAccount and 504 WDAGUtilityAccount (Microsoft, Local accounts); 502 KRBTGT exists only on domain controllers. A claim found online that WDAGUtilityAccount burns RID 1001 is false: it is 504, not 1001",
        "An RID is never reused on a standalone machine, because the SAM tracks the RIDs it has issued (Microsoft), so a deleted and re-created account gets a new RID; a gap in the observed RIDs points to something that was issued one and no longer holds it, which may be a setup placeholder rather than a person",
        "A sole owner at RID 1002 is ordinary on an OEM-installed Windows machine and is not, by itself, evidence of deleted human accounts: setup commonly issues 1000 to the OOBE placeholder defaultuser0 and deletes it, and an OEM or re-run-OOBE account can take 1001. This pattern is inferred from practitioner reports, not documented by Microsoft",
        "To find out what held a missing RID, compare ProfileList orphans, residual C:\\Users folders, $MFT and $UsnJrnl times on profile folders, Security events 4720/4726, and Volume Shadow Copies",
        "Needs the SAM hive itself; a logical export of user documents does not contain it, so figures quoted from it cannot be reproduced from such an export",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Registry value in the SAM hive; updated at each logon, removed with the account",
};

// ── WeChat for Windows ───────────────────────────────────────────────────────

/// WeChat for Windows per-account data folders.
///
/// # Sources
/// - <https://nisos.com/blog/decrypting-wechat-messages/> —
///   `%USERPROFILE%\Documents\WeChat Files\<wxid_…>\Msg`, and that the
///   message databases are encrypted with a key held in WeChat.exe memory.
/// - <https://github.com/RTBRuhan/UsChat> — `WeChat Files\<wxid>\` with `Msg\`
///   (MSG0.db, MicroMsg.db), `FileStorage\` (media) and `BackupFiles\`.
/// - <https://wener.me/notes/platform/wechat/inside> — WeChat 4.x moves core
///   data to `%USERPROFILE%\xwechat_files\<account>\` with a shared
///   `all_users\` folder.
/// - <https://help.wechat.com/cgi-bin/micromsg-bin/oshelpcenter?opcode=2&id=150924byr2am15092432m73y> —
///   WeChat for Windows/Mac login: scan the QR code with WeChat on the phone
///   and confirm the login.
pub(crate) static WECHAT_WINDOWS_FILES: ArtifactDescriptor = ArtifactDescriptor {
    id: "wechat_windows_files",
    name: "WeChat for Windows Account Folders",
    artifact_type: ArtifactLocation::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"%USERPROFILE%\Documents\WeChat Files\<wxid_*>\"),
    scope: DataScope::User,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "WeChat for Windows (3.x) creates one folder per WeChat account that has logged in \
        on this Windows profile, named after the account's wxid: Documents\\WeChat Files\\<wxid>\\ \
        holding Msg\\ (encrypted message and contact databases such as Multi\\MSG0.db and \
        MicroMsg.db), FileStorage\\ (received and sent files and media) and BackupFiles\\, \
        beside a shared WeChat Files\\All Users\\ folder. WeChat 4.x moves account data to \
        %USERPROFILE%\\xwechat_files\\<account>\\ with a shared all_users\\ folder, and the data \
        location can be changed in the client's settings. Several account folders on one \
        profile mean several WeChat accounts were used there.",
    mitre_techniques: &[],
    fields: &[FieldSchema {
        name: "account_folder",
        value_type: ValueType::Text,
        description: "Folder name: the WeChat account ID (wxid_…) of an account that logged in on this profile",
        is_uid_component: true,
    }],
    retention: Some("Until removed by the user or the client; survives logout"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["profile_list_users", "windows_notification_db"],
    sources: &[
        "https://nisos.com/blog/decrypting-wechat-messages/",
        "https://github.com/RTBRuhan/UsChat",
        "https://wener.me/notes/platform/wechat/inside",
        "https://help.wechat.com/cgi-bin/micromsg-bin/oshelpcenter?opcode=2&id=150924byr2am15092432m73y",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: Some(crate::evidence::EvidenceTier::SourceOrMultiImpl),
    evidence_caveats: &[
        "An account folder shows that the WeChat account logged in on this Windows profile, not who operated it: WeChat documents that a PC login is authorised by scanning a QR code with the logged-in phone, which proves the phone approved the login, not who later used the session",
        "Several wxid folders on one profile are consistent with one person holding several accounts or with several people; the folders alone do not distinguish the two",
        "The message databases are encrypted per account with a key held in client memory; folder presence and FileStorage content are readable without it, message content is not",
        "Read wxid values from the on-disk folder names; OCR of screenshots or printed reports garbles them",
        "In a logical export selected by file type (an extension whitelist), a wxid folder appears only if it held a selected file, so absence from the export is not absence from the machine",
        "Check the configured data location and the 4.x xwechat_files layout before concluding WeChat data is absent",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Per-account folders persist on disk after logout",
};

// ── Partition/Diagnostic 1006 ────────────────────────────────────────────────

/// Microsoft-Windows-Partition/Diagnostic event 1006: per-arrival disk record.
///
/// # Sources
/// - <http://windowsir.blogspot.com/2017/10/stuff.html> is the origin write-up
///   (Carvey, 2017, relaying Graeber) but is plain HTTP; the HTTPS sources
///   below state the same fields.
/// - <https://forensics.wiki/usb_history_viewing/> — 1006 "may contain
///   Manufacturer, Model, Serial, and raw Partition Table, MFT, and VBR data".
/// - <https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/> —
///   the Vbr0 boot-record snapshot and the per-file-system VSN offsets
///   (NTFS 0x48, FAT32 0x43, exFAT 0x64); major updates may clear the log.
pub(crate) static EVTX_PARTITION_DIAGNOSTIC_1006: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_partition_diagnostic_1006",
    name: "Partition/Diagnostic Event 1006 (disk arrival: model, serial, capacity, boot records)",
    artifact_type: ArtifactLocation::EventLog,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(
        "%SystemRoot%\\System32\\winevt\\Logs\\Microsoft-Windows-Partition%4Diagnostic.evtx",
    ),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Event 1006 in the Microsoft-Windows-Partition/Diagnostic channel (Windows 10 and \
        later) is written when a disk arrives, with fields including Manufacturer, Model, \
        SerialNumber and Capacity, plus raw copies of the partition table and boot records \
        (Vbr0 and following). The volume serial number can be read from the Vbr0 snapshot at \
        the file system's offset (NTFS 0x48, FAT32 0x43, exFAT 0x64). Unlike USBSTOR, which \
        keeps first and last arrival, each connection leaves its own timestamped record, so \
        the channel gives a per-connection history of a device and joins a seized device to \
        this host by hardware serial and by volume serial.",
    mitre_techniques: &["T1052.001"],
    fields: &[
        FieldSchema { name: "serial_number", value_type: ValueType::Text, description: "SerialNumber: device serial as reported to Windows", is_uid_component: true },
        FieldSchema { name: "model", value_type: ValueType::Text, description: "Manufacturer and Model strings", is_uid_component: false },
        FieldSchema { name: "capacity", value_type: ValueType::UnsignedInt, description: "Capacity in bytes", is_uid_component: false },
        FieldSchema { name: "vbr0", value_type: ValueType::Bytes, description: "Vbr0: raw boot record of the first volume; volume serial at NTFS 0x48, FAT32 0x43, exFAT 0x64", is_uid_component: false },
    ],
    retention: Some("EVTX channel; size-limited, and major Windows updates may clear it"),
    triage_priority: TriagePriority::High,
    related_artifacts: &[
        "usb_stor_enum",
        "setupapi_dev_log",
        "mounted_devices",
        "emdmgmt_readyboost",
        "evtx_microsoft_windows_partition_diagnostic",
    ],
    sources: &[
        "https://forensics.wiki/usb_history_viewing/",
        "https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/",
        "https://learn.microsoft.com/en-us/windows/win32/fileio/exfat-specification",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: Some(crate::evidence::EvidenceTier::SourceOrMultiImpl),
    evidence_caveats: &[
        "The event records the disk arriving at this computer, not which account or person connected it; join to MountPoints2 for the profile under which it was mounted",
        "Major Windows updates may clear this channel, and it rolls over at its size limit, so absence of a device is weak evidence it was never connected",
        "Read the volume serial from Vbr0 at the offset for the volume's file system; reformatting the volume changes the serial while the hardware serial stays",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "EVTX channel; oldest records purged when the size limit is reached",
};

// ── FAT / exFAT directory entries ────────────────────────────────────────────

/// FAT12/16/32 and exFAT directory entries on removable volumes.
///
/// # Sources
/// - <https://download.microsoft.com/download/1/6/1/161ba512-40e2-4cc9-843a-923143f3456c/fatgen103.doc> —
///   Microsoft FAT32 File System Specification: DIR_Name[0] == 0xE5 marks a
///   free (deleted) entry; DIR_LstAccDate "Note that there is no last access
///   time, only a date"; creation and access fields are optional.
/// - <https://learn.microsoft.com/en-us/windows/win32/fileio/exfat-specification> —
///   exFAT File directory entry: Create/LastModified/LastAccessed timestamps
///   with UtcOffset fields; security descriptors exist only in the TexFAT
///   extension, not the basic specification.
pub(crate) static FAT_EXFAT_DIRECTORY_ENTRY: ArtifactDescriptor = ArtifactDescriptor {
    id: "fat_exfat_directory_entry",
    name: "FAT/exFAT Directory Entry (removable-volume file metadata)",
    artifact_type: ArtifactLocation::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("<directory clusters of a FAT12/16/32 or exFAT volume>"),
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "The metadata a FAT or exFAT volume (the usual format of USB sticks and memory \
        cards) keeps for each file: name (8.3 short name, plus long-name entries on FAT; UTF-16 \
        name entries on exFAT), size, first cluster, attributes, and created, modified and \
        accessed times. A deleted FAT entry has its first name byte overwritten with 0xE5, so \
        the entry and often its data survive until reused, with the original first character \
        lost. That is the whole of the record: it carries no owner, SID or access-control \
        list. What a removable volume can attribute comes from the content of its files \
        (document authorship, EXIF) and from linking the volume to host computers by its \
        serial.",
    mitre_techniques: &["T1052.001"],
    fields: &[
        FieldSchema { name: "name", value_type: ValueType::Text, description: "Short (8.3) and long file names; first byte 0xE5 marks a deleted FAT entry", is_uid_component: true },
        FieldSchema { name: "first_cluster", value_type: ValueType::UnsignedInt, description: "First cluster of the file data", is_uid_component: false },
        FieldSchema { name: "size", value_type: ValueType::UnsignedInt, description: "File size in bytes", is_uid_component: false },
        FieldSchema { name: "created", value_type: ValueType::Timestamp, description: "Creation date and time (optional on FAT)", is_uid_component: false },
        FieldSchema { name: "modified", value_type: ValueType::Timestamp, description: "Last write date and time", is_uid_component: false },
        FieldSchema { name: "accessed", value_type: ValueType::Timestamp, description: "Last access: date only on FAT; date and time on exFAT", is_uid_component: false },
    ],
    retention: Some("Until the entry is reused or the volume is reformatted"),
    triage_priority: TriagePriority::Medium,
    related_artifacts: &["evtx_partition_diagnostic_1006", "usb_stor_enum", "macos_trash"],
    sources: &[
        "https://download.microsoft.com/download/1/6/1/161ba512-40e2-4cc9-843a-923143f3456c/fatgen103.doc",
        "https://learn.microsoft.com/en-us/windows/win32/fileio/exfat-specification",
        // Source: Word owner file (~$ name, same folder, holds the opener's
        // logon name, left behind when Word quits improperly)
        "https://support.microsoft.com/en-us/word/the-document-is-locked-for-editing-by-another-user-error-message-when-you-try-to-open-a-document-in",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Corroborative),
    evidence_tier: Some(crate::evidence::EvidenceTier::VendorDocumented),
    evidence_caveats: &[
        "The entry has no owner, SID or access-control field (the exFAT basic specification leaves security descriptors to the TexFAT extension), so a removable volume cannot show which account or person wrote a file or which computer it was written on",
        "FAT keeps last access as a date only, with no time, and its creation and access fields are optional (fatgen103)",
        "FAT12/16/32 times carry no time-zone field and are written in whatever clock the writing host used; exFAT records a UtcOffset beside each timestamp",
        "A deleted FAT entry's first character is overwritten with 0xE5, so a search for the original file name misses it; search by the rest of the name or by surviving long-name entries",
        "A surviving Word owner file (~$ followed by the rest of the document name) sits in the same folder as the document and, per Microsoft, holds the logon name of the person who opened it; Word deletes it on a clean exit, so one left on the volume shows a document there was opened in Word and names the opening account, not the person",
        "The format is platform-independent; it is catalogued under Windows because the catalogue's OsScope has no cross-platform value",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Residual),
    volatility_rationale: "Directory entries are present on every FAT/exFAT volume and deleted entries persist until reused",
};
