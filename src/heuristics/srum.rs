//! SRUM (System Resource Usage Monitor) resource ratio heuristics.

/// Ratio threshold above which background CPU dominates (miner indicator).
/// background_cycles / foreground_cycles >= this value is suspicious.
pub const BACKGROUND_CPU_DOMINANCE_RATIO: u64 = 10;

/// Minimum bytes-sent to bytes-received ratio indicating potential exfiltration.
pub const EXFIL_BYTES_RATIO: u64 = 10;

/// Single-session outbound volume threshold for exfiltration candidate.
pub const EXFIL_VOLUME_BYTES: u64 = 100 * 1024 * 1024; // 100 MiB

/// Returns `true` if background CPU cycles dominate foreground cycles by the
/// dominance ratio threshold. Zero foreground cycles returns `true` only when
/// background cycles are non-zero (idle processes are not flagged).
#[must_use]
pub fn is_background_cpu_dominant(background_cycles: u64, foreground_cycles: u64) -> bool {
    background_cycles > 0
        && (foreground_cycles == 0
            || background_cycles / foreground_cycles >= BACKGROUND_CPU_DOMINANCE_RATIO)
}

/// Returns `true` if outbound bytes exceed inbound bytes by the exfil ratio threshold.
/// Zero bytes-received returns `true` when bytes-sent is non-zero.
#[must_use]
pub fn is_exfil_ratio(bytes_sent: u64, bytes_received: u64) -> bool {
    bytes_sent > 0 && (bytes_received == 0 || bytes_sent / bytes_received >= EXFIL_BYTES_RATIO)
}

/// Returns `true` if total outbound bytes exceed the exfiltration volume threshold.
#[must_use]
pub fn is_exfil_volume(bytes_sent: u64) -> bool {
    bytes_sent >= EXFIL_VOLUME_BYTES
}

/// Minimum focus duration (ms) before zero user-input is considered anomalous.
///
/// Brief focus (e.g., a window flash) with no input is not suspicious. Only
/// sustained focus-without-input warrants the automated_execution flag.
pub const AUTOMATED_EXECUTION_FOCUS_THRESHOLD_MS: u64 = 60_000; // 1 minute

/// Returns `true` if an app held focus for at least the threshold duration but
/// received no user input — suggesting automated or scripted execution.
///
/// Legitimate interactive apps (browsers, editors) accumulate user input
/// whenever they hold focus. A sustained focus period with zero input may
/// indicate a process that called `SetForegroundWindow` without the user's
/// involvement, or a fully automated tool masquerading as an interactive app.
#[must_use]
pub fn is_automated_execution(focus_time_ms: u64, user_input_time_ms: u64) -> bool {
    focus_time_ms >= AUTOMATED_EXECUTION_FOCUS_THRESHOLD_MS && user_input_time_ms == 0
}

/// Minimum foreground cycles to consider a phantom-foreground anomaly meaningful.
/// Avoids flagging processes with trivially brief (sub-quantization) foreground time.
pub const PHANTOM_FOREGROUND_MIN_CYCLES: u64 = 1_000;

/// Returns `true` if a process had foreground CPU cycles but zero focus time.
///
/// A process charged foreground cycles but with no Application Timeline focus
/// is anomalous: the scheduler considered it "in front" but the user never
/// directed input to it. Possible causes: `SetForegroundWindow` abuse, or
/// a window briefly flashing to the top without user interaction.
///
/// Only meaningful when focus data is present (i.e., Application Timeline was
/// successfully merged into the record). The caller is responsible for ensuring
/// `focus_time_ms` came from a real measurement, not a missing-data default.
#[must_use]
pub fn is_phantom_foreground(foreground_cycles: u64, focus_time_ms: u64) -> bool {
    foreground_cycles >= PHANTOM_FOREGROUND_MIN_CYCLES && focus_time_ms == 0
}

// ── Beaconing constants ───────────────────────────────────────────────────────

/// Minimum interval (seconds) to consider as a beacon interval.
pub const BEACON_MIN_INTERVAL_SECS: i64 = 60;

/// Maximum interval (seconds) to consider as a beacon interval.
pub const BEACON_MAX_INTERVAL_SECS: i64 = 28_800;

/// Minimum number of valid intervals required for beaconing detection.
pub const BEACON_MIN_SAMPLES: usize = 5;

/// Coefficient-of-variation threshold below which traffic is considered beaconing.
pub const BEACON_COV_THRESHOLD: f64 = 0.15;

// ── Known safe path prefixes (not flagged) ────────────────────────────────────

const SAFE_PATH_PREFIXES: &[&str] = &[
    r"c:\windows\system32\",
    r"c:\windows\syswow64\",
    r"c:\windows\winsxs\",
    r"c:\windows\sysnative\",
    r"c:\program files\",
    r"c:\program files (x86)\",
];

// Document extensions that trigger double-extension detection when followed by
// an executable extension.
const DOC_EXTENSIONS: &[&str] = &[
    ".pdf.", ".docx.", ".xlsx.", ".doc.", ".xls.", ".pptx.", ".txt.", ".jpg.", ".png.",
];

const EXEC_EXTENSIONS: &[&str] = &[".exe", ".dll", ".bat", ".ps1", ".vbs", ".js"];

/// Returns `true` if the Windows executable path suggests malware staging.
///
/// Flags paths that:
/// - Are UNC paths (`\\`)
/// - Contain `\temp\` or `\tmp\`
/// - Contain `\downloads\`
/// - Contain `\windows\temp\`
/// - Have a double extension (document ext followed by executable ext)
/// - Are only one directory deep from a drive root (e.g. `C:\payload.exe`)
///
/// Does NOT flag paths under `System32`, `Program Files`, or bare `AppData\Local`
/// (without `\Temp\`).
#[must_use]
pub fn is_suspicious_path(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }

    let lower = path.to_lowercase();

    // Safe prefixes short-circuit — these are never flagged.
    // AppData\Local without Temp is safe; Temp is caught below by \temp\ check.
    for prefix in SAFE_PATH_PREFIXES {
        if lower.starts_with(prefix) {
            return false;
        }
    }

    // UNC path
    if lower.starts_with(r"\\") {
        return true;
    }

    // Suspicious directory components
    if lower.contains(r"\temp\")
        || lower.contains(r"\tmp\")
        || lower.contains(r"\downloads\")
        || lower.contains(r"\windows\temp\")
    {
        return true;
    }

    // Double extension: doc-type extension followed by exec extension at end
    for doc_ext in DOC_EXTENSIONS {
        if lower.contains(doc_ext) {
            for exec_ext in EXEC_EXTENSIONS {
                if lower.ends_with(exec_ext) {
                    return true;
                }
            }
        }
    }

    // Single-depth from drive root: exactly one backslash total
    // e.g. "C:\payload.exe" — only the drive separator backslash
    if lower.chars().filter(|&c| c == '\\').count() == 1 {
        return true;
    }

    false
}

// ── Process masquerade ────────────────────────────────────────────────────────

const SYSTEM_BINARIES: &[&str] = &[
    "svchost.exe",
    "lsass.exe",
    "services.exe",
    "csrss.exe",
    "winlogon.exe",
    "explorer.exe",
    "cmd.exe",
    "powershell.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "msiexec.exe",
    "werfault.exe",
    "conhost.exe",
    "dllhost.exe",
    "taskhost.exe",
    "smss.exe",
    "wininit.exe",
    "spoolsv.exe",
    "taskhostw.exe",
    "sihost.exe",
];

const SYSTEM_DIRS: &[&str] = &[
    r"\\windows\\system32",
    r"\\windows\\syswow64",
    r"\\windows\\winsxs",
    r"\\windows\\sysnative",
];

/// Inline Levenshtein distance (no external crate).
fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let m = a.len();
    let n = b.len();
    let mut dp = vec![vec![0usize; n + 1]; m + 1];
    for i in 0..=m {
        dp[i][0] = i;
    }
    for j in 0..=n {
        dp[0][j] = j;
    }
    for i in 1..=m {
        for j in 1..=n {
            dp[i][j] = if a[i - 1] == b[j - 1] {
                dp[i - 1][j - 1]
            } else {
                1 + dp[i - 1][j - 1].min(dp[i - 1][j]).min(dp[i][j - 1])
            };
        }
    }
    dp[m][n]
}

/// Returns `true` if `binary_name` is within edit-distance 1–2 of a known
/// Windows system binary AND `dir` is not a recognised system directory.
///
/// An exact match (distance 0) in a wrong directory is not flagged here;
/// use `is_suspicious_path` for that pattern.
#[must_use]
pub fn is_process_masquerade(binary_name: &str, dir: &str) -> bool {
    let dir_lower = dir.to_lowercase();
    // Replace single backslash with double for consistent matching against SYSTEM_DIRS
    // which use escaped double-backslash strings. We normalise to lowercase and compare
    // the raw string content.
    let dir_norm = dir_lower.replace('\\', "\\\\");

    // If dir is a system directory, never flag.
    for sys_dir in SYSTEM_DIRS {
        if dir_norm.contains(sys_dir) {
            return false;
        }
    }
    // Also handle the common single-backslash form directly.
    let dir_lower_single = dir.to_lowercase();
    let sys_dirs_single = &[
        r"\windows\system32",
        r"\windows\syswow64",
        r"\windows\winsxs",
        r"\windows\sysnative",
    ];
    for sys_dir in sys_dirs_single {
        if dir_lower_single.contains(sys_dir) {
            return false;
        }
    }

    let bin_lower = binary_name.to_lowercase();

    // If the binary is an exact match for any known system binary, it's not a
    // masquerade (distance 0).  The wrong-directory case is handled elsewhere.
    for &known in SYSTEM_BINARIES {
        if bin_lower == known {
            return false;
        }
    }

    for &known in SYSTEM_BINARIES {
        let dist = levenshtein(&bin_lower, known);
        if dist >= 1 && dist <= 2 {
            return true;
        }
    }
    false
}

/// Returns `true` if `timestamps_secs` exhibits regular-interval beaconing
/// consistent with C2 check-in traffic.
///
/// Algorithm:
/// 1. Require at least 6 timestamps (5 intervals).
/// 2. Compute consecutive intervals.
/// 3. Keep only intervals in `[BEACON_MIN_INTERVAL_SECS, BEACON_MAX_INTERVAL_SECS]`.
/// 4. Require at least `BEACON_MIN_SAMPLES` valid intervals.
/// 5. Compute coefficient of variation (stddev / mean).
/// 6. Return `true` if CoV < `BEACON_COV_THRESHOLD`.
#[must_use]
pub fn is_beaconing(timestamps_secs: &[i64]) -> bool {
    if timestamps_secs.len() < 2 {
        return false;
    }

    let intervals: Vec<f64> = timestamps_secs
        .windows(2)
        .map(|w| (w[1] - w[0]) as f64)
        .filter(|&iv| {
            iv >= BEACON_MIN_INTERVAL_SECS as f64 && iv <= BEACON_MAX_INTERVAL_SECS as f64
        })
        .collect();

    if intervals.len() < BEACON_MIN_SAMPLES {
        return false;
    }

    let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
    if mean == 0.0 {
        return false;
    }

    let variance =
        intervals.iter().map(|&iv| (iv - mean).powi(2)).sum::<f64>() / intervals.len() as f64;
    let stddev = variance.sqrt();
    let cov = stddev / mean;

    cov < BEACON_COV_THRESHOLD
}

// ── Tests ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn background_dominates_foreground_zero() {
        assert!(is_background_cpu_dominant(1000, 0));
    }

    #[test]
    fn background_dominates_ratio_10x() {
        assert!(is_background_cpu_dominant(1000, 100));
    }

    #[test]
    fn background_dominates_ratio_just_over() {
        assert!(is_background_cpu_dominant(1001, 100));
    }

    #[test]
    fn background_not_dominant_equal() {
        assert!(!is_background_cpu_dominant(100, 100));
    }

    #[test]
    fn background_not_dominant_below_ratio() {
        // 999 / 100 = 9, which is < 10
        assert!(!is_background_cpu_dominant(999, 100));
    }

    #[test]
    fn background_not_dominant_both_zero() {
        assert!(!is_background_cpu_dominant(0, 0));
    }

    #[test]
    fn background_not_dominant_background_zero_foreground_nonzero() {
        assert!(!is_background_cpu_dominant(0, 500));
    }

    #[test]
    fn exfil_ratio_ten_to_one() {
        assert!(is_exfil_ratio(1000, 100));
    }

    #[test]
    fn exfil_ratio_recv_zero_sent_nonzero() {
        assert!(is_exfil_ratio(1, 0));
    }

    #[test]
    fn exfil_ratio_not_triggered_equal() {
        assert!(!is_exfil_ratio(100, 100));
    }

    #[test]
    fn exfil_ratio_not_triggered_below() {
        // 500 / 100 = 5, which is < 10
        assert!(!is_exfil_ratio(500, 100));
    }

    #[test]
    fn exfil_ratio_sent_zero_not_triggered() {
        assert!(!is_exfil_ratio(0, 0));
    }

    #[test]
    fn exfil_volume_above_threshold() {
        assert!(is_exfil_volume(EXFIL_VOLUME_BYTES + 1));
    }

    #[test]
    fn exfil_volume_below_threshold() {
        assert!(!is_exfil_volume(EXFIL_VOLUME_BYTES - 1));
    }

    #[test]
    fn exfil_volume_at_threshold() {
        assert!(is_exfil_volume(EXFIL_VOLUME_BYTES));
    }

    // ── is_automated_execution tests ─────────────────────────────────────────

    #[test]
    fn automated_execution_triggered_at_threshold_with_no_input() {
        assert!(is_automated_execution(AUTOMATED_EXECUTION_FOCUS_THRESHOLD_MS, 0));
    }

    #[test]
    fn automated_execution_triggered_above_threshold_with_no_input() {
        assert!(is_automated_execution(AUTOMATED_EXECUTION_FOCUS_THRESHOLD_MS + 1, 0));
    }

    #[test]
    fn automated_execution_not_triggered_below_threshold() {
        assert!(!is_automated_execution(AUTOMATED_EXECUTION_FOCUS_THRESHOLD_MS - 1, 0));
    }

    #[test]
    fn automated_execution_not_triggered_when_input_present() {
        assert!(!is_automated_execution(AUTOMATED_EXECUTION_FOCUS_THRESHOLD_MS, 1));
    }

    #[test]
    fn automated_execution_not_triggered_both_zero() {
        assert!(!is_automated_execution(0, 0));
    }

    // ── is_phantom_foreground tests ───────────────────────────────────────────

    #[test]
    fn phantom_foreground_triggered_when_fg_cycles_and_no_focus() {
        assert!(is_phantom_foreground(1_000, 0));
    }

    #[test]
    fn phantom_foreground_not_triggered_when_focus_present() {
        assert!(!is_phantom_foreground(1_000, 30_000));
    }

    #[test]
    fn phantom_foreground_not_triggered_below_min_cycles() {
        assert!(!is_phantom_foreground(999, 0));
    }

    #[test]
    fn phantom_foreground_not_triggered_both_zero() {
        assert!(!is_phantom_foreground(0, 0));
    }

    // ── is_suspicious_path tests ──────────────────────────────────────────────

    #[test]
    fn suspicious_path_unc() {
        assert!(is_suspicious_path(r"\\server\share\payload.exe"));
    }

    #[test]
    fn suspicious_path_temp_dir() {
        assert!(is_suspicious_path(r"C:\Users\User\AppData\Local\Temp\abc.exe"));
    }

    #[test]
    fn suspicious_path_windows_temp() {
        assert!(is_suspicious_path(r"C:\Windows\Temp\run.exe"));
    }

    #[test]
    fn suspicious_path_downloads() {
        assert!(is_suspicious_path(r"C:\Users\User\Downloads\tool.exe"));
    }

    #[test]
    fn suspicious_path_double_ext_pdf_exe() {
        assert!(is_suspicious_path(r"C:\Users\User\invoice.pdf.exe"));
    }

    #[test]
    fn suspicious_path_root_depth_one() {
        assert!(is_suspicious_path(r"C:\payload.exe"));
    }

    #[test]
    fn suspicious_path_system32_not_flagged() {
        assert!(!is_suspicious_path(r"C:\Windows\System32\svchost.exe"));
    }

    #[test]
    fn suspicious_path_program_files_not_flagged() {
        assert!(!is_suspicious_path(r"C:\Program Files\Vendor\app.exe"));
    }

    #[test]
    fn suspicious_path_appdata_local_not_flagged() {
        assert!(!is_suspicious_path(r"C:\Users\User\AppData\Local\MyApp\app.exe"));
    }

    #[test]
    fn suspicious_path_empty_not_flagged() {
        assert!(!is_suspicious_path(""));
    }

    // ── is_process_masquerade tests ───────────────────────────────────────────

    #[test]
    fn masquerade_svch0st_not_in_system32() {
        assert!(is_process_masquerade("svch0st.exe", r"C:\Users\User\AppData\Local"));
    }

    #[test]
    fn masquerade_lssas_exe() {
        assert!(is_process_masquerade("lssas.exe", r"C:\Windows\Temp"));
    }

    #[test]
    fn masquerade_exploler_exe() {
        assert!(is_process_masquerade("exploler.exe", r"C:\Users\User"));
    }

    #[test]
    fn masquerade_legitimate_svchost_in_system32() {
        assert!(!is_process_masquerade("svchost.exe", r"C:\Windows\System32"));
    }

    #[test]
    fn masquerade_legitimate_explorer_in_windows() {
        assert!(!is_process_masquerade("explorer.exe", r"C:\Windows"));
    }

    #[test]
    fn masquerade_unrelated_binary_not_flagged() {
        assert!(!is_process_masquerade("myapp.exe", r"C:\Program Files\MyApp"));
    }

    #[test]
    fn masquerade_distance_three_not_flagged() {
        assert!(!is_process_masquerade("svchzzz.exe", r"C:\Users\User"));
    }

    #[test]
    fn masquerade_exact_match_in_wrong_dir_not_flagged_by_this_fn() {
        // exact match: distance = 0, our fn only fires on distance 1-2
        assert!(!is_process_masquerade("svchost.exe", r"C:\Users\User"));
    }

    // ── is_beaconing tests ────────────────────────────────────────────────────

    #[test]
    fn beaconing_detected_regular_hourly() {
        let ts: Vec<i64> = (0..10).map(|i| i * 3600).collect();
        assert!(is_beaconing(&ts));
    }

    #[test]
    fn beaconing_detected_five_minute_interval() {
        let ts: Vec<i64> = (0..10).map(|i| i * 300).collect();
        assert!(is_beaconing(&ts));
    }

    #[test]
    fn beaconing_detected_with_small_jitter() {
        // hourly ± 5s — CoV will be ~0.001, well below 0.15
        let ts: Vec<i64> = (0..10).map(|i| i * 3600 + (i % 3) as i64 * 5).collect();
        assert!(is_beaconing(&ts));
    }

    #[test]
    fn beaconing_not_detected_too_few_points() {
        // 5 timestamps = 4 intervals, need 5
        let ts: Vec<i64> = (0..5).map(|i| i * 3600).collect();
        assert!(!is_beaconing(&ts));
    }

    #[test]
    fn beaconing_not_detected_irregular() {
        let ts = vec![0i64, 100, 5000, 50000, 55000, 200000, 205000, 600000, 601000, 900000];
        assert!(!is_beaconing(&ts));
    }

    #[test]
    fn beaconing_not_detected_too_short_interval() {
        // Every 30 seconds — below min
        let ts: Vec<i64> = (0..10).map(|i| i * 30).collect();
        assert!(!is_beaconing(&ts));
    }

    #[test]
    fn beaconing_not_detected_too_long_interval() {
        // Every 10 hours — above max
        let ts: Vec<i64> = (0..10).map(|i| i * 36000).collect();
        assert!(!is_beaconing(&ts));
    }

    #[test]
    fn beaconing_not_detected_empty() {
        assert!(!is_beaconing(&[]));
    }

    #[test]
    fn beaconing_not_detected_single_point() {
        assert!(!is_beaconing(&[3600]));
    }
}
