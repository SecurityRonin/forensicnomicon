//! Ransomware IOC constants — ransom note filenames across major families.
//!
//! [`RANSOM_NOTE_FILENAMES`] is the canonical reference list used by every
//! detection layer (EVTX/Sysmon file-creation, PE string scanning, filesystem
//! hunting).  Any layer that needs to ask "is this file a ransom note?" must
//! import from here rather than maintain its own local copy.

// ── Ransom note filenames ──────────────────────────────────────────────────────
//
// Organised by ransomware family, with the most prevalent families first.
// All filenames are matched case-insensitively at runtime.
//
// Sources: MalwareBazaar, ID Ransomware, ANY.RUN, Sophos Rapid Response,
// Recorded Future, Group-IB, Mandiant, Palo Alto Unit42, CrowdStrike, CISA
// advisories, and primary incident-response reporting (2013–2025).
//
// MAINTENANCE: Add new families below the last entry in alphabetical order.
// Do NOT add partial substrings — every entry must be a complete filename
// (basename only, no path prefix).

/// Complete filenames dropped by ransomware as ransom notes.
///
/// Match case-insensitively against a file's basename.  A match indicates a
/// ransom note was created or is present on disk (T1486 — Data Encrypted for
/// Impact; T1491.001 — Defacement: Internal).
pub const RANSOM_NOTE_FILENAMES: &[&str] = &[
    // ── STOP/DJVU — largest consumer victim count (2018–present) ──────────────
    "_readme.txt",
    // ── LockBit 2.0 / 3.0 / Green (2021–present) ─────────────────────────────
    "Restore-My-Files.txt",
    "LockBit_README.txt",
    "LockBit-README.txt",
    "LockBit3.0.hta",
    "LockBit_Green_README.txt",
    "!!!READ_ME_EDWARD.txt",
    // ── BlackCat / ALPHV (2021–present) ──────────────────────────────────────
    "RECOVER-FILES.txt",
    "GET-IT-BACK-FILES.txt",
    "HOW_TO_GET_YOUR_FILES_BACK.txt",
    // ── RansomHub (2024–present; ex-ALPHV affiliates) ────────────────────────
    "README_RANSOMHUB.txt",
    "RANSOMHUB.txt",
    // ── Conti (2020–2022) ────────────────────────────────────────────────────
    "CONTI_README.txt",
    // ── Hive (2021–2023; FBI takedown) ───────────────────────────────────────
    "HOW_TO_DECRYPT.txt",
    "hive.README.txt",
    // ── REvil / Sodinokibi (2019–2022) ───────────────────────────────────────
    "HOW-DECRYPT.txt",
    "Decryption README.txt",
    // ── GandCrab (2018–2019; predecessor to REvil) ───────────────────────────
    "GDCB-DECRYPT.txt",
    "KRAB-DECRYPT.txt",
    "GandCrab.html",
    // ── Cl0p / Clop (2019–present) ────────────────────────────────────────────
    "ClopReadMe.txt",
    "!Cl0pReadMe.txt",
    "C!0p.txt",
    // ── Ryuk (2018–2021) ──────────────────────────────────────────────────────
    "RyukReadMe.txt",
    "RYUK_README.txt",
    // ── DarkSide / BlackMatter (2020–2021) ───────────────────────────────────
    "DarkSide.README.txt",
    // ── Phobos (2019–present) ─────────────────────────────────────────────────
    "info.hta",
    "Phobos.README.txt",
    // ── MedusaLocker (2019–present) ──────────────────────────────────────────
    "HOW_TO_RECOVER_DATA.html",
    "How_To_Recover_Encrypted_Files.html",
    "Recovery_Instructions.html",
    "HOW_TO_RECOVER_ENCRYPTED_DATA.html",
    // ── Maze (2019–2020) ──────────────────────────────────────────────────────
    "DECRYPT-FILES.txt",
    "MAZE-DECRYPT.txt",
    "DECRYPT-FILES.html",
    // ── Egregor (2020–2021; Maze successor) ──────────────────────────────────
    // RECOVER-FILES.txt already listed under BlackCat

    // ── DoppelPaymer (2019–2022) ──────────────────────────────────────────────
    "readme2unlock.txt",
    "DOPPEL-README.txt",
    // ── WannaCry (2017; EternalBlue) ──────────────────────────────────────────
    "@Please_Read_Me@.txt",
    "@WanaDecryptor@.txt",
    "!WannaCry!.txt",
    // ── Matrix (2016–present) ─────────────────────────────────────────────────
    "#README_MATRIX#.rtf",
    "!readme_matrix_decryption.rtf",
    "#Decrypt_files_readme#.rtf",
    // ── Dharma / CrySiS (2016–present) ───────────────────────────────────────
    "FILES ENCRYPTED.txt",
    "RETURN FILES.txt",
    "DECRYPT_NOTE.txt",
    // ── Hermes / Ryuk ancestor (2017–2018) ───────────────────────────────────
    "DECRYPT_INFORMATION.html",
    "HERMES_README.txt",
    // ── SamSam (2015–2018) ────────────────────────────────────────────────────
    "HELP_DECRYPT_YOUR_FILES.html",
    "HELP_TO_DECRYPT.html",
    // ── Locky (2016–2017) ─────────────────────────────────────────────────────
    "_Locky_recover_instructions.txt",
    "HELP_instructions.html",
    // ── CryptoLocker (2013–2014; first major modern ransomware) ──────────────
    "DECRYPT_INSTRUCTION.html",
    "HOW_TO_RESTORE_FILES.txt",
    "CryptoLocker.txt",
    "CryptoLocker.html",
    // ── TeslaCrypt (2015–2016) ────────────────────────────────────────────────
    "HELP_TO_DECRYPT_YOUR_FILES.txt",
    "HOWTO_RESTORE_FILES.txt",
    // ── CTB-Locker (2014–2017) ────────────────────────────────────────────────
    "!Decrypt-All-Files.txt",
    // ── Shade / Troldesh (2014–2019) ──────────────────────────────────────────
    "README1.txt",
    "README_crypted.txt",
    // ── AvosLocker (2021–present) ─────────────────────────────────────────────
    "GET_YOUR_FILES_BACK.txt",
    "AvosLocker.txt",
    // ── BlackBasta (2022–present) ─────────────────────────────────────────────
    "Instructions.txt",
    // ── Lorenz (2021–present) ─────────────────────────────────────────────────
    "HELP_SECURITY_EVENT.html",
    "HELP_SECURITY_EVENT.txt",
    // ── Quantum (2021–present) ────────────────────────────────────────────────
    "README_TO_DECRYPT.html",
    "README-QUANTUM.txt",
    // ── BianLian (2022–present) ───────────────────────────────────────────────
    "Look at this instruction.txt",
    "BianLian.txt",
    // ── Royal (2022–2024) ─────────────────────────────────────────────────────
    "README.TXT",
    "ROYAL_README.txt",
    // ── Play (2022–present) ───────────────────────────────────────────────────
    "ReadMe.txt",
    // ── 8Base (2022–present; Phobos variant) ─────────────────────────────────
    "IMPORTANT NOTICE.txt",
    "How To Restore Your Files.txt",
    // ── Akira (2023–present) ──────────────────────────────────────────────────
    "akira_readme.txt",
    "AKIRA_RECOVERY.txt",
    // ── Rhysida (2023–present) ────────────────────────────────────────────────
    "CriticalBreachDetected.pdf",
    // ── INC Ransom (2023–present) ─────────────────────────────────────────────
    "INC-README.txt",
    "INC_README.txt",
    // ── Hunters International (2023–present) ──────────────────────────────────
    "Contact_for_Unlock.txt",
    // ── Qilin / Agenda (2022–present) ─────────────────────────────────────────
    "README-IMPORTANT.txt",
    "QILIN-README.txt",
    // ── DragonForce (2023–present) ────────────────────────────────────────────
    "DragonForce_README.txt",
    // ── BlackSuit (2023–present; Royal successor) ─────────────────────────────
    "README.BlackSuit.txt",
    "BlackSuit_README.txt",
    // ── Vice Society (2021–2023) ──────────────────────────────────────────────
    "AllYFilesAE.txt",
    // ── Sabbath / Eruption (2021) ─────────────────────────────────────────────
    "RESTORE_FILES.txt",
    // ── Karma (2021) ──────────────────────────────────────────────────────────
    "KARMA-README.txt",
    // ── Babuk (2021; source leaked) — "How To Restore Your Files.txt" (8Base) ─

    // ── Yanluowang (2021–2022) ────────────────────────────────────────────────
    "Yanluowang_readme.txt",
    // ── Diavol (2021; Trickbot group) ────────────────────────────────────────
    "README_FOR_DECRYPT.txt",
    // ── Ragnar Locker (2020–2023; Europol takedown) ───────────────────────────
    "RAGNAR_LOCKER_README.txt",
    // ── FiveHands / HelloKitty (2021) ─────────────────────────────────────────
    "read_me_unlock.txt",
    "FIVEHANDS.README.txt",
    // ── Trigona (2022–2023; law enforcement action) ───────────────────────────
    "_how_to_decrypt.txt",
    "how_to_decrypt.txt",
    // ── Nevada (2022–present) ─────────────────────────────────────────────────
    "NEVADA_README.txt",
    // ── Zeppelin (2019–2022; FBI advisory) ───────────────────────────────────
    "!!! ALL YOUR FILES ARE ENCRYPTED !!!.TXT",
    "Zeppelin.txt",
    // ── PYSA / Mespinoza (2019–2022) ─────────────────────────────────────────
    "Pysa.README.txt",
    // ── Monti (2022–present; Conti derivative) ────────────────────────────────
    "Monti_README.txt",
    // ── NoEscape (2023) ───────────────────────────────────────────────────────
    "HOW-TO-DECRYPT.txt",
    // ── ESXiArgs (2023; ESXi mass exploitation) ───────────────────────────────
    "HOW_TO_RESTORE_YOUR_FILES.txt",
    // ── CrossLock (2023) ──────────────────────────────────────────────────────
    "CrossLock_readme.txt",
    // ── RAGroup (2023–present) ────────────────────────────────────────────────
    "RA_Help.txt",
    // ── MalasLocker (2023) ────────────────────────────────────────────────────
    "instructions.txt",
    // ── Cuba (2019–present; CISA advisory) ────────────────────────────────────
    "!! CUBA !!.txt",
    // ── Nokoyawa (2022–2023) ──────────────────────────────────────────────────
    "NOKOYAWA_readme.txt",
    // ── Rorschach / BabLock (2023) ────────────────────────────────────────────
    "Rorschach_Note.txt",
    // ── Cylance (2019–present) ────────────────────────────────────────────────
    "!HowToDecrypt.txt",
    // ── Avaddon (2020–2021; retired) ─────────────────────────────────────────
    "avaddon_readme.html",
    // ── Prometheus (2021) ────────────────────────────────────────────────────
    "PROMETHEUS_README.txt",
    // ── Grief / PayOrGrief (2021; DoppelPaymer successor) ────────────────────
    "grief_readme.txt",
    // ── MountLocker (2020–2021) ───────────────────────────────────────────────
    "RecoveryManual.html",
    "!-MountLocker-recover_instructions.txt",
    // ── Thanos (2020–2021) ───────────────────────────────────────────────────
    "Restore_My_Files.txt",
    // ── NetWalker / Mailto (2019–2021; law enforcement action) ───────────────
    "!Readme.txt",
    "~readme.txt",
    // ── DearCry (2021; ProxyLogon exploitation) ───────────────────────────────
    "DearCry.txt",
    // ── Cheerscrypt (2022; ESXi) ──────────────────────────────────────────────
    "Read_Me.html",
    // ── AtomSilo (2021) ───────────────────────────────────────────────────────
    "ATOMIKSILO_README.txt",
    // ── Knight / Cyclops (2023–present) ───────────────────────────────────────
    "Knight_README.txt",
    // ── Pandora (2022–present) ────────────────────────────────────────────────
    "Pandora.txt",
    // ── Mindware (2022) ───────────────────────────────────────────────────────
    "MindWare.readme.txt",
    // ── QWCrypt / RedCurl / GOLD BLADE (2024–present) ────────────────────────
    // Group-IB and Palo Alto Unit42 incident reports; note dropped in the same
    // directory as the encrypted VHD/VHDX files.
    "FILES_ENCRYPTED.txt",
    "HOW-TO-DECRYPT-FILES.txt",
    // ── Generic / cross-family names (used by multiple unrelated families) ────
    // Listed last; high false-positive potential — rely on directory context.
    "readme.txt",
    "README.txt",
    "READ_ME.txt",
    "READ-ME.txt",
    "!readme.txt",
    "RESTORE_INSTRUCTIONS.txt",
    "DECRYPT_INSTRUCTION.txt",
    "HELP_DECRYPT.html",
    "HELP_DECRYPT.txt",
    "HELP_YOUR_FILES.txt",
    "IMPORTANT.txt",
    "IMPORTANT_README.txt",
    "YOUR_FILES_ARE_ENCRYPTED.txt",
    "HOW_RECOVER_FILES.txt",
    "DECRYPT_YOUR_FILES.html",
    "HOW_TO_UNLOCK.txt",
];

// ── Ransomware process kill / service stop constants ───────────────────────────
//
// Cross-validated against: LockBit 3.0 CISA AA23-075A (explicit kill list),
// leaked Conti and Babuk source code (kill-list arrays), and vendor IR reports
// (Akira/BlackCat/RansomHub/BlackBasta/BianLian/Medusa/Rhysida/Play).
// All basenames lowercased; compare case-insensitively at runtime.

/// AV/EDR/database/backup process names targeted by ransomware kill scripts.
///
/// Used with `RANSOMWARE_KILL_CLUSTER_THRESHOLD` — a cluster of ≥N kills from
/// this list within `RANSOMWARE_KILL_WINDOW_NS` is near-zero-FP for ransomware
/// staging (T1562.001 / T1489).  Single kills have medium FP risk.
pub const RANSOMWARE_KILL_PROCESSES: &[&str] = &[
    // SQL / database
    "sql.exe",
    "sqlserv.exe",
    "sqlbrowser.exe",
    "sqlwriter.exe",
    "sqlagent.exe",
    "sqlservr.exe",
    "oracle.exe",
    "ocssd.exe",
    "dbsnmp.exe",
    "dbeng50.exe",
    "mysqld.exe",
    "mysqld-nt.exe",
    "mysqld-opt.exe",
    "postgres.exe",
    // Office / productivity (locked open = can't encrypt)
    "excel.exe",
    "infopath.exe",
    "msaccess.exe",
    "mspub.exe",
    "onenote.exe",
    "outlook.exe",
    "powerpnt.exe",
    "winword.exe",
    "wordpad.exe",
    "notepad.exe",
    "thunderbird.exe",
    "thebat.exe",
    "tbirdconfig.exe",
    "steam.exe",
    "firefox.exe",
    // Veeam backup
    "veeam.exe",
    "veeamguestindexer.exe",
    "veeamtransportsvc.exe",
    "veeamdeploymentsvc.exe",
    "veeammountservice.exe",
    // Sophos AV
    "sophos.exe",
    "savadminservice.exe",
    "savservice.exe",
    "sedservice.exe",
    // Malwarebytes
    "mbamtray.exe",
    "mbam.exe",
    // Windows Defender (rarely succeeds but always attempted)
    "msmpeng.exe",
    "nissrv.exe",
    "securityhealthservice.exe",
    // SentinelOne
    "sentinelagent.exe",
    "sentinelhelperservice.exe",
    "sentinelservicehost.exe",
    // CrowdStrike
    "csfalconservice.exe",
    "crowdstrike.exe",
    // Elastic
    "elastic-agent.exe",
    // ESET
    "ekrn.exe",
    "egui.exe",
    // Avira
    "avgnt.exe",
    "avguard.exe",
    // Kaspersky
    "avp.exe",
    "kavfsslp.exe",
    "klnagent.exe",
    // McAfee
    "mfemms.exe",
    "masvc.exe",
    "macmnsvc.exe",
    "mcshield.exe",
    // Trend Micro
    "tmlisten.exe",
    "pccntmon.exe",
    "ntrtscan.exe",
    "tmccsf.exe",
    // Backup tools
    "backup.exe",
    "backupexecagentaccelerator.exe",
    "backupexecagentbrowser.exe",
    "backupexecdevicemediaservice.exe",
    "backupexecjobengine.exe",
    "backupexecmanagementservice.exe",
    "backupexecrpcservice.exe",
    "backupexecvssprovider.exe",
    "bedbg.exe",
    "benetns.exe",
    "beserver.exe",
    "pvlsvr.exe",
    "raw_agent_svc.exe",
    "cagservice.exe",
    // Accounting / ERP
    "sage.exe",
    "qbw32.exe",
    "qbdbmgr.exe",
    "qbdbmgrn.exe",
    "qbcfmonitorservice.exe",
    // Misc services
    "synctime.exe",
    "agntsvc.exe",
    "isqlplussvc.exe",
    "xfssvccon.exe",
    "mydesktopservice.exe",
    "mydesktopqos.exe",
    "ocautoupds.exe",
    "encsvc.exe",
    "ocomm.exe",
    "sqbcoreservice.exe",
    "ds_agent.exe",
    "zoolz.exe",
    // Web / app servers
    "httpd.exe",
    "nginx.exe",
    "node.exe",
    "java.exe",
    // Misc
    "hitmanpro.alert.exe",
    "googleupdate.exe",
];

/// Minimum number of kills from `RANSOMWARE_KILL_PROCESSES` within
/// `RANSOMWARE_KILL_WINDOW_NS` to constitute a high-confidence ransomware
/// process-termination cluster.
pub const RANSOMWARE_KILL_CLUSTER_THRESHOLD: usize = 5;

/// Sliding time window (nanoseconds) for clustering ransomware process kill events.
pub const RANSOMWARE_KILL_WINDOW_NS: i64 = 60_000_000_000; // 60 seconds

/// Canonical service names stopped by ransomware staging scripts.
///
/// Covers Veeam, SQL Server, Exchange, Commvault, BackupExec, Sophos, McAfee,
/// Kaspersky, and Malwarebytes — the services most commonly enumerated in
/// LockBit 3.0 (CISA AA23-075A), Conti, and Babuk kill scripts.
/// All lowercased; compare case-insensitively at runtime.
pub const RANSOMWARE_STOP_SERVICES: &[&str] = &[
    // VSS (all ransomware)
    "vss",
    // SQL Server
    "sqlserveragent",
    "mssqlserver",
    "sqlbrowser",
    "sqlwriter",
    "reportserver",
    "sqlanywhere",
    "sqladhlp",
    "sqltelemetry",
    "mssqlserveradhelper",
    "mssqlserveradhelper100",
    "mssqlserverolapservice",
    // Veeam backup (LockBit 3.0 CISA AA23-075A + Conti leak)
    "veeambackupsvc",
    "veeamcatalogsvc",
    "veeamtransportsvc",
    "veeammountsvc",
    "veeamdeploysvc",
    "veeamnfssvc",
    "veeamrestsvc",
    "veeamcloudsvc",
    "veeamdistributionsvc",
    "veeamenterprisemanagersvc",
    "veeamdeploymentservice",
    "veeambrokerssvc",
    // Commvault (explicitly cited in CISA AA23-075A for LockBit 3.0)
    "gxvss",
    "gxblr",
    "gxfwd",
    "gxcvd",
    "gxcimgr",
    // BackupExec
    "backupexecagentaccelerator",
    "backupexecagentbrowser",
    "backupexecdevicemediaservice",
    "backupexecjobengine",
    "backupexecmanagementservice",
    "backupexecrpcservice",
    "backupexecvssprovider",
    // Acronis
    "acrsch2svc",
    "acronisagent",
    // Sophos
    "sophosagent",
    "sophosautoupdateservice",
    "savadminservice",
    "savservice",
    "sophosclean",
    "sophoshealth",
    "sophosmcsagent",
    "sophosmcsclient",
    "sophosmessagerouter",
    "sophossafestore",
    "sophossystemprotectionservice",
    // Exchange
    "msexchangeis",
    "msexchangetransport",
    "msexchangeadtopology",
    "msexchangedelivery",
    "msexchangefrontendtransport",
    "msexchangerepl",
    "msexchangesa",
    "msexchangeservicehost",
    "msexchangees",
    "msexchangemta",
    "msexchangeantispamupdate",
    "msexchangefastsearch",
    "msexchangehm",
    "msexchangeum",
    "msexchangeumcr",
    // McAfee
    "mfemms",
    "mfefire",
    "mfevtp",
    "mcshield",
    "mctaskmanager",
    // Kaspersky
    "kavfs",
    "kavfsgt",
    "kavfsslp",
    "klnagent",
    // Malwarebytes
    "mbamservice",
    // QuickBooks
    "qbcfmonitorservice",
    "qbidpservice",
    "qbvss",
    // IIS / web
    "w3svc",
    "iisadmin",
    "smtpsvc",
    "imap4svc",
    "pop3svc",
    // Misc backup / recovery
    "wbengine",
    "sdrsvc",
    "pdvfsservice",
    // ESET
    "ehttpsrv",
    "epsecurityservice",
    "epupdateservice",
    "erasrv",
    "esgshkernel",
    // SCOM / MOM
    "healthservice",
    // Trend Micro
    "ntrtscan",
    "tmccsf",
    "tmlisten",
    // Defender
    "msmpsvc",
];

/// Minimum number of stops from `RANSOMWARE_STOP_SERVICES` within
/// `RANSOMWARE_KILL_WINDOW_NS` to constitute a high-confidence cluster.
pub const RANSOMWARE_SERVICE_STOP_CLUSTER_THRESHOLD: usize = 3;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ransom_note_filenames_not_empty() {
        assert!(
            !RANSOM_NOTE_FILENAMES.is_empty(),
            "RANSOM_NOTE_FILENAMES must contain entries"
        );
    }

    #[test]
    fn ransom_note_filenames_covers_stop_djvu() {
        assert!(
            RANSOM_NOTE_FILENAMES.contains(&"_readme.txt"),
            "STOP/DJVU _readme.txt must be covered"
        );
    }

    #[test]
    fn ransom_note_filenames_covers_lockbit() {
        assert!(
            RANSOM_NOTE_FILENAMES.contains(&"LockBit_README.txt"),
            "LockBit note must be covered"
        );
    }

    #[test]
    fn ransom_note_filenames_covers_wannacry() {
        assert!(
            RANSOM_NOTE_FILENAMES.contains(&"@Please_Read_Me@.txt"),
            "WannaCry note must be covered"
        );
    }

    #[test]
    fn ransom_note_filenames_covers_akira() {
        assert!(
            RANSOM_NOTE_FILENAMES.contains(&"akira_readme.txt"),
            "Akira note must be covered"
        );
    }

    #[test]
    fn ransom_note_filenames_covers_qwcrypt() {
        assert!(
            RANSOM_NOTE_FILENAMES.contains(&"FILES_ENCRYPTED.txt"),
            "QWCrypt/RedCurl note must be covered"
        );
    }

    #[test]
    fn ransom_note_filenames_covers_hive() {
        assert!(
            RANSOM_NOTE_FILENAMES.contains(&"HOW_TO_DECRYPT.txt"),
            "Hive note must be covered"
        );
    }

    #[test]
    fn ransom_note_filenames_covers_cryptolocker() {
        assert!(
            RANSOM_NOTE_FILENAMES.contains(&"DECRYPT_INSTRUCTION.html"),
            "CryptoLocker note must be covered"
        );
    }

    #[test]
    fn ransom_note_filenames_no_duplicates() {
        let mut sorted = RANSOM_NOTE_FILENAMES.to_vec();
        sorted.sort_unstable();
        let original_len = sorted.len();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            original_len,
            "RANSOM_NOTE_FILENAMES contains duplicate entries"
        );
    }

    #[test]
    fn ransom_note_filenames_no_path_separators() {
        for name in RANSOM_NOTE_FILENAMES {
            assert!(
                !name.contains('\\') && !name.contains('/'),
                "Entry '{name}' contains a path separator — basenames only"
            );
        }
    }

    #[test]
    fn ransom_note_filenames_has_substantial_coverage() {
        assert!(
            RANSOM_NOTE_FILENAMES.len() >= 50,
            "Expected at least 50 ransom note filenames for meaningful coverage, got {}",
            RANSOM_NOTE_FILENAMES.len()
        );
    }

    // ── Ransomware kill / stop list tests ────────────────────────────────────

    #[test]
    fn kill_processes_includes_sql_server() {
        assert!(
            RANSOMWARE_KILL_PROCESSES.iter().any(|p| p.contains("sql")),
            "must include SQL server process names"
        );
    }

    #[test]
    fn kill_processes_includes_veeam() {
        assert!(
            RANSOMWARE_KILL_PROCESSES
                .iter()
                .any(|p| p.contains("veeam")),
            "must include Veeam process names"
        );
    }

    #[test]
    fn kill_processes_includes_av_product() {
        assert!(
            RANSOMWARE_KILL_PROCESSES
                .iter()
                .any(|p| p.contains("sophos") || p.contains("mcshield") || p.contains("msmpeng")),
            "must include at least one AV process"
        );
    }

    #[test]
    fn kill_processes_all_lowercase() {
        for name in RANSOMWARE_KILL_PROCESSES {
            assert_eq!(
                *name,
                name.to_lowercase(),
                "all kill-list process names must be lowercase, got '{name}'"
            );
        }
    }

    #[test]
    fn kill_processes_no_path_separators() {
        for name in RANSOMWARE_KILL_PROCESSES {
            assert!(
                !name.contains('\\') && !name.contains('/'),
                "'{name}' must be a basename only"
            );
        }
    }

    #[test]
    fn kill_cluster_threshold_is_at_least_3() {
        const {
            assert!(
                RANSOMWARE_KILL_CLUSTER_THRESHOLD >= 3,
                "threshold must be at least 3 to avoid trivial false positives"
            );
        }
    }

    #[test]
    fn kill_window_is_60_seconds() {
        assert_eq!(
            RANSOMWARE_KILL_WINDOW_NS, 60_000_000_000,
            "window must be exactly 60 seconds in nanoseconds"
        );
    }

    #[test]
    fn stop_services_includes_veeam() {
        assert!(
            RANSOMWARE_STOP_SERVICES.iter().any(|s| s.contains("veeam")),
            "must include Veeam backup services"
        );
    }

    #[test]
    fn stop_services_includes_commvault_cluster() {
        let commvault = &["gxvss", "gxblr", "gxfwd", "gxcvd", "gxcimgr"];
        for svc in commvault {
            assert!(
                RANSOMWARE_STOP_SERVICES.contains(svc),
                "Commvault '{svc}' must be in stop-list (cited in CISA AA23-075A)"
            );
        }
    }

    #[test]
    fn stop_services_all_lowercase() {
        for svc in RANSOMWARE_STOP_SERVICES {
            assert_eq!(
                *svc,
                svc.to_lowercase(),
                "all stop-list service names must be lowercase, got '{svc}'"
            );
        }
    }

    #[test]
    fn service_stop_threshold_is_at_least_3() {
        const {
            assert!(
                RANSOMWARE_SERVICE_STOP_CLUSTER_THRESHOLD >= 3,
                "threshold must be at least 3"
            );
        }
    }
}
