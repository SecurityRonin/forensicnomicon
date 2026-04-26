/// TeamViewer registry indicator paths.
///
/// Sources:
/// - LOLRMM project: <https://lolrmm.io/tools/teamviewer>
/// - CISA Advisory AA23-025A (malicious use of RMM software):
///   <https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a>
/// - Red Canary: <https://redcanary.com/blog/threat-intelligence/remote-monitoring-management/>
pub const TEAMVIEWER_PATHS: &[&str] = &[
    r"SOFTWARE\TeamViewer",
    r"SYSTEM\CurrentControlSet\Services\TeamViewer",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\TeamViewer",
];

/// AnyDesk registry indicator paths.
///
/// Sources:
/// - LOLRMM project: <https://lolrmm.io/tools/anydesk>
/// - CISA Advisory AA23-025A (AnyDesk named as abused RMM):
///   <https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a>
/// - Huntress RMM abuse research:
///   <https://www.huntress.com/blog/no-longer-low-hanging-fruit-hunting-for-risky-rmm-tools>
pub const ANYDESK_PATHS: &[&str] = &[
    r"SOFTWARE\Clients\Media\AnyDesk",
    r"SYSTEM\CurrentControlSet\Services\AnyDesk",
    r"SOFTWARE\Classes\.anydesk\shell\open\command",
    r"SOFTWARE\Classes\AnyDesk\shell\open\command",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\AnyDesk",
    r"DRIVERS\DriverDatabase\DeviceIds\USBPRINT\AnyDesk",
    r"DRIVERS\DriverDatabase\DeviceIds\WSDPRINT\AnyDesk",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Printers\AnyDesk Printer",
];

/// Splashtop registry indicator paths.
///
/// Sources:
/// - LOLRMM project: <https://lolrmm.io/tools/splashtop_remote>
/// - Huntress RMM abuse research:
///   <https://www.huntress.com/blog/no-longer-low-hanging-fruit-hunting-for-risky-rmm-tools>
pub const SPLASHTOP_PATHS: &[&str] = &[
    r"SOFTWARE\WOW6432Node\Splashtop Inc.",
    r"SYSTEM\CurrentControlSet\Services\SplashtopRemoteService",
    r"SYSTEM\CurrentControlSet\Control\SafeBoot\Network\SplashtopRemoteService",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Splashtop Software Updater",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Splashtop-Splashtop Streamer-Remote Session/Operational",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Splashtop-Splashtop Streamer-Status/Operational",
    r"Software\Splashtop Inc.",
];

/// Atera RMM registry indicator paths.
///
/// Sources:
/// - LOLRMM project: <https://lolrmm.io/tools/atera>
/// - CISA Advisory AA23-025A (Atera explicitly named):
///   <https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a>
/// - Huntress RMM abuse research:
///   <https://www.huntress.com/blog/no-longer-low-hanging-fruit-hunting-for-risky-rmm-tools>
pub const ATERA_PATHS: &[&str] = &[
    r"SOFTWARE\ATERA Networks\AlphaAgent",
    r"SOFTWARE\ATERA Networks",
    r"SYSTEM\CurrentControlSet\Services\AteraAgent",
    r"SYSTEM\ControlSet\Services\EventLog\Application\AlphaAgent",
    r"SYSTEM\ControlSet\Services\EventLog\Application\AteraAgent",
    r"SOFTWARE\Microsoft\Tracing\AteraAgent_RASAPI32",
    r"SOFTWARE\Microsoft\Tracing\AteraAgent_RASMANCS",
];

/// GoToAssist / GoTo Resolve / GoToMyPC registry indicator paths.
///
/// Sources:
/// - LOLRMM project: <https://lolrmm.io/tools/gotoassist>
/// - Red Canary: <https://redcanary.com/blog/threat-intelligence/remote-monitoring-management/>
pub const GOTOASSIST_PATHS: &[&str] = &[
    r"SOFTWARE\GoTo Resolve Unattended",
    r"SOFTWARE\Citrix\GoToMyPc",
    r"WOW6432Node\Citrix\GoToMyPc",
];

/// Action1 RMM registry indicator paths.
///
/// Sources:
/// - LOLRMM project: <https://lolrmm.io/tools/action1>
/// - Sophos X-Ops (Action1 abuse in ransomware intrusions):
///   <https://news.sophos.com/en-us/2023/08/03/blacksuit-ransomware/>
pub const ACTION1_PATHS: &[&str] = &[
    r"System\CurrentControlSet\Services\A1Agent",
    r"SOFTWARE\WOW6432Node\Action1",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows\Windows Error Reporting\LocalDumps\action1_agent.exe",
];

/// ManageEngine (Zoho) registry indicator paths.
///
/// Sources:
/// - LOLRMM project: <https://lolrmm.io/tools/manageengine>
/// - CISA Advisory AA22-174A (ManageEngine exploitation):
///   <https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-174a>
pub const MANAGEENGINE_PATHS: &[&str] =
    &[r"SOFTWARE\ManageEngine", r"SOFTWARE\AdventNet\ManageEngine"];

/// Returns an iterator over all LOLRMM remote access tool registry paths.
///
/// Prefer this over the legacy `ALL_LOLRMM_PATHS` slice for bulk scanning —
/// zero allocation, no data duplication.
pub fn all_lolrmm_paths() -> impl Iterator<Item = &'static str> {
    TEAMVIEWER_PATHS
        .iter()
        .chain(ANYDESK_PATHS.iter())
        .chain(SPLASHTOP_PATHS.iter())
        .chain(ATERA_PATHS.iter())
        .chain(GOTOASSIST_PATHS.iter())
        .chain(ACTION1_PATHS.iter())
        .chain(MANAGEENGINE_PATHS.iter())
        .copied()
}

/// Returns true if the given registry path matches a known LOLRMM remote access tool
/// indicator (case-insensitive contains match).
pub fn is_remote_access_tool_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    all_lolrmm_paths().any(|entry| lower.contains(&entry.to_ascii_lowercase()))
}

/// Returns the tool name if the path matches a known LOLRMM remote access tool,
/// or None if not recognized.
pub fn identify_remote_access_tool(path: &str) -> Option<&'static str> {
    let lower = path.to_ascii_lowercase();
    let matches = |entries: &[&str]| {
        entries
            .iter()
            .any(|e| lower.contains(&e.to_ascii_lowercase()))
    };
    if matches(TEAMVIEWER_PATHS) {
        Some("TeamViewer")
    } else if matches(ANYDESK_PATHS) {
        Some("AnyDesk")
    } else if matches(SPLASHTOP_PATHS) {
        Some("Splashtop")
    } else if matches(ATERA_PATHS) {
        Some("Atera")
    } else if matches(GOTOASSIST_PATHS) {
        Some("GoToAssist")
    } else if matches(ACTION1_PATHS) {
        Some("Action1")
    } else if matches(MANAGEENGINE_PATHS) {
        Some("ManageEngine")
    } else {
        None
    }
}

/// Names of malicious Remote Access Trojans (RATs) / backdoors.
///
/// Sources:
/// - MITRE ATT&CK T1219 — Remote Access Software (malicious RAT use):
///   <https://attack.mitre.org/techniques/T1219/>
/// - ANY.RUN — "Top RATs" malware tracker:
///   <https://any.run/malware-trends/njrat>
/// - Recorded Future — Annual threat intelligence report (RAT prevalence):
///   <https://www.recordedfuture.com/research/2024-annual-report>
pub const KNOWN_RAT_NAMES: &[&str] = &[
    "njrat",
    "njrat.exe",
    "darkcomet",
    "darkcomet.exe",
    "quasar",
    "quasar.exe",
    "quasarrat",
    "remcos",
    "remcos.exe",
    "remcosrat",
    "asyncrat",
    "asyncrat.exe",
    "nanocore",
    "nanocore.exe",
    "netwire",
    "netwirerc",
    "xtreme",
    "xtremeRAT",
    "adwind",
    "jrat",
    "strrat",
    "dcrat",
    "dcrat.exe",
    "ratx",
    "gh0st",
    "gh0strat",
    "luminosity",
    "luminositylink",
    "warzone",
    "warzonerat",
    "ave maria",
    "avemaria",
    "revenge",
    "revengerat",
    "agent tesla",
    "agentTesla",
];

/// Returns `true` if `name` matches a known malicious RAT / backdoor name (case-insensitive).
pub fn is_known_rat_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    KNOWN_RAT_NAMES
        .iter()
        .any(|t| t.to_ascii_lowercase() == lower)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn teamviewer_paths_contains_hklm_key() {
        assert!(TEAMVIEWER_PATHS.contains(&r"SOFTWARE\TeamViewer"));
    }

    #[test]
    fn anydesk_paths_contains_service_key() {
        assert!(ANYDESK_PATHS.contains(&r"SYSTEM\CurrentControlSet\Services\AnyDesk"));
    }

    #[test]
    fn all_lolrmm_paths_not_empty() {
        assert!(
            all_lolrmm_paths().next().is_some(),
            "all_lolrmm_paths() must yield at least one entry"
        );
    }

    #[test]
    fn all_lolrmm_paths_covers_all_tools() {
        // Each tool's first path must appear in the combined iterator
        let all: Vec<_> = all_lolrmm_paths().collect();
        for path in [
            TEAMVIEWER_PATHS[0],
            ANYDESK_PATHS[0],
            SPLASHTOP_PATHS[0],
            ATERA_PATHS[0],
            GOTOASSIST_PATHS[0],
            ACTION1_PATHS[0],
            MANAGEENGINE_PATHS[0],
        ] {
            assert!(
                all.contains(&path),
                "Missing path in all_lolrmm_paths: {path}"
            );
        }
    }

    #[test]
    fn is_remote_access_tool_path_teamviewer_matches() {
        assert!(
            is_remote_access_tool_path(r"SOFTWARE\TeamViewer\ConnectionHistory"),
            "TeamViewer path must match"
        );
    }

    #[test]
    fn is_remote_access_tool_path_case_insensitive() {
        assert!(
            is_remote_access_tool_path(r"software\teamviewer"),
            "Match must be case-insensitive"
        );
    }

    #[test]
    fn is_remote_access_tool_path_unrelated_returns_false() {
        assert!(
            !is_remote_access_tool_path(r"SOFTWARE\Microsoft\Office"),
            "Unrelated path must not match"
        );
    }

    #[test]
    fn identify_remote_access_tool_teamviewer() {
        assert_eq!(
            identify_remote_access_tool(r"SOFTWARE\TeamViewer\ConnectionHistory"),
            Some("TeamViewer"),
            "Should identify TeamViewer"
        );
    }

    #[test]
    fn identify_remote_access_tool_anydesk() {
        assert_eq!(
            identify_remote_access_tool(r"SYSTEM\CurrentControlSet\Services\AnyDesk"),
            Some("AnyDesk"),
            "Should identify AnyDesk"
        );
    }

    #[test]
    fn identify_remote_access_tool_unknown_returns_none() {
        assert_eq!(
            identify_remote_access_tool(r"SOFTWARE\Microsoft\Windows"),
            None,
            "Unknown path should return None"
        );
    }

    // --- KNOWN_RAT_NAMES / is_known_rat_name ---
    #[test]
    fn rat_names_contains_njrat() {
        assert!(KNOWN_RAT_NAMES.contains(&"njrat"));
    }
    #[test]
    fn rat_names_contains_remcos() {
        assert!(KNOWN_RAT_NAMES.contains(&"remcos"));
    }
    #[test]
    fn rat_names_contains_asyncrat() {
        assert!(KNOWN_RAT_NAMES.contains(&"asyncrat"));
    }
    #[test]
    fn detects_njrat_exact() {
        assert!(is_known_rat_name("njrat"));
    }
    #[test]
    fn detects_njrat_exe() {
        assert!(is_known_rat_name("njrat.exe"));
    }
    #[test]
    fn detects_quasar_uppercase() {
        assert!(is_known_rat_name("QUASAR"));
    }
    #[test]
    fn detects_asyncrat() {
        assert!(is_known_rat_name("asyncrat"));
    }
    #[test]
    fn detects_remcos_rat_variant() {
        assert!(is_known_rat_name("remcosrat"));
    }
    #[test]
    fn does_not_flag_teamviewer_as_rat() {
        assert!(!is_known_rat_name("teamviewer"));
    }
    #[test]
    fn empty_string_not_rat() {
        assert!(!is_known_rat_name(""));
    }
}
