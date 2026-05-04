//! Integration tests for the `4n6query` CLI.
//!
//! Design: `4n6query <term>` is the universal entry point. The tool detects
//! whether the term is a LOL/LOFL binary, an abusable domain, a MITRE
//! technique ID, or a keyword and returns all matching results.
//!
//! ```text
//! 4n6query <term>                         # universal lookup
//! 4n6query <term> --platform <p>          # restrict LOLBin search to platform
//! 4n6query <term> --format json|yaml      # machine-readable output
//! 4n6query --triage [--format json|yaml]  # critical-first artifact list
//! 4n6query dump [--dataset ...] [--format ...]
//! ```

use assert_cmd::Command;
use predicates::prelude::*;

fn q() -> Command {
    Command::cargo_bin("4n6query").unwrap()
}

/// Lightweight helper for tests that need to inspect exit code + raw stdout/stderr.
struct Output {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run(args: &[&str]) -> Output {
    let out = Command::cargo_bin("4n6query")
        .unwrap()
        .args(args)
        .output()
        .unwrap();
    Output {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

// ---------------------------------------------------------------------------
// Universal lookup — LOL/LOFL binary
// ---------------------------------------------------------------------------

#[test]
fn query_certutil_exits_zero() {
    q().arg("certutil.exe").assert().success();
}

#[test]
fn query_certutil_stdout_contains_name() {
    q().arg("certutil.exe")
        .assert()
        .success()
        .stdout(predicate::str::contains("certutil.exe"));
}

#[test]
fn query_certutil_with_platform_windows() {
    q().args(["certutil.exe", "--platform", "windows"])
        .assert()
        .success()
        .stdout(predicate::str::contains("certutil.exe"));
}

#[test]
fn query_certutil_platform_linux_not_found() {
    q().args(["certutil.exe", "--platform", "linux"])
        .assert()
        .failure();
}

#[test]
fn query_linux_binary_curl_exits_zero() {
    q().arg("curl")
        .assert()
        .success()
        .stdout(predicate::str::contains("curl"));
}

#[test]
fn query_macos_binary_osascript_exits_zero() {
    q().arg("osascript")
        .assert()
        .success()
        .stdout(predicate::str::contains("osascript"));
}

#[test]
fn query_cmdlet_invoke_command_exits_zero() {
    q().arg("Invoke-Command").assert().success().stdout(
        predicate::str::contains("Invoke-Command").or(predicate::str::contains("invoke-command")),
    );
}

#[test]
fn query_mmc_gpedit_exits_zero() {
    q().arg("gpedit.msc")
        .assert()
        .success()
        .stdout(predicate::str::contains("gpedit.msc"));
}

#[test]
fn query_wmi_win32_process_exits_zero() {
    q().arg("Win32_Process")
        .assert()
        .success()
        .stdout(predicate::str::contains("Win32_Process"));
}

#[test]
fn query_unknown_term_exits_nonzero() {
    q().arg("xyzzy_not_a_real_indicator_99999")
        .assert()
        .failure();
}

// ---------------------------------------------------------------------------
// Universal lookup — JSON output
// ---------------------------------------------------------------------------

#[test]
fn query_certutil_json_is_valid() {
    let out = q()
        .args(["certutil.exe", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value =
        serde_json::from_str(std::str::from_utf8(&out).unwrap()).expect("output is not valid JSON");
    // Top-level must be an object with at least one category key
    assert!(v.is_object(), "expected JSON object");
    assert!(
        v.get("lolbas").is_some() || v.get("sites").is_some() || v.get("artifacts").is_some(),
        "expected at least one of: lolbas, sites, artifacts"
    );
}

#[test]
fn query_certutil_json_lolbas_array_has_platform_field() {
    let out = q()
        .args(["certutil.exe", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(std::str::from_utf8(&out).unwrap()).unwrap();
    let lolbas = v["lolbas"].as_array().expect("missing lolbas array");
    assert!(!lolbas.is_empty());
    assert!(lolbas[0]["platform"].is_string());
    assert!(lolbas[0]["name"].is_string());
    assert!(lolbas[0]["mitre_techniques"].is_array());
}

// ---------------------------------------------------------------------------
// Universal lookup — abusable site
// ---------------------------------------------------------------------------

#[test]
fn query_github_raw_site_exits_zero() {
    q().arg("raw.githubusercontent.com")
        .assert()
        .success()
        .stdout(predicate::str::contains("raw.githubusercontent.com"));
}

#[test]
fn query_github_raw_site_shows_critical() {
    q().arg("raw.githubusercontent.com")
        .assert()
        .success()
        .stdout(predicate::str::contains("critical").or(predicate::str::contains("Critical")));
}

#[test]
fn query_github_raw_site_json() {
    let out = q()
        .args(["raw.githubusercontent.com", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(std::str::from_utf8(&out).unwrap()).unwrap();
    let sites = v["sites"].as_array().expect("missing sites array");
    assert!(!sites.is_empty());
    assert_eq!(sites[0]["domain"], "raw.githubusercontent.com");
    assert_eq!(sites[0]["blocking_risk"], "critical");
}

// ---------------------------------------------------------------------------
// Universal lookup — artifact keyword (fuzzy)
// ---------------------------------------------------------------------------

#[test]
fn query_userassist_finds_both_variants() {
    // Both userassist_exe and userassist_folder should appear
    let out = q()
        .arg("userassist")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = std::str::from_utf8(&out).unwrap();
    assert!(
        text.contains("userassist_exe") || text.contains("UserAssist"),
        "expected userassist_exe or UserAssist in output"
    );
    assert!(
        text.contains("userassist_folder") || text.contains("Folder"),
        "expected userassist_folder or Folder in output"
    );
}

#[test]
fn query_artifact_keyword_prefetch_exits_zero() {
    q().arg("prefetch")
        .assert()
        .success()
        .stdout(predicate::str::contains("prefetch").or(predicate::str::contains("Prefetch")));
}

#[test]
fn query_artifact_json_has_artifacts_array() {
    let out = q()
        .args(["userassist", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(std::str::from_utf8(&out).unwrap()).unwrap();
    let artifacts = v["artifacts"].as_array().expect("missing artifacts array");
    assert!(!artifacts.is_empty());
    assert!(artifacts[0]["id"].is_string());
    assert!(artifacts[0]["name"].is_string());
    assert!(artifacts[0]["triage_priority"].is_string());
}

// ---------------------------------------------------------------------------
// Universal lookup — MITRE technique
// ---------------------------------------------------------------------------

#[test]
fn query_mitre_technique_t1547_exits_zero() {
    q().arg("T1547.001").assert().success();
}

#[test]
fn query_mitre_technique_json_has_artifacts() {
    let out = q()
        .args(["T1547.001", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(std::str::from_utf8(&out).unwrap()).unwrap();
    let artifacts = v["artifacts"].as_array().expect("missing artifacts array");
    assert!(!artifacts.is_empty());
}

#[test]
fn query_unknown_mitre_technique_exits_nonzero() {
    q().arg("T9999.999").assert().failure();
}

// ---------------------------------------------------------------------------
// Triage
// ---------------------------------------------------------------------------

#[test]
fn triage_exits_zero() {
    q().arg("--triage").assert().success();
}

#[test]
fn triage_stdout_contains_critical() {
    q().arg("--triage")
        .assert()
        .success()
        .stdout(predicate::str::contains("critical").or(predicate::str::contains("Critical")));
}

#[test]
fn triage_json_first_entry_is_critical() {
    let out = q()
        .args(["--triage", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(std::str::from_utf8(&out).unwrap()).unwrap();
    let artifacts = v["artifacts"].as_array().expect("missing artifacts array");
    assert!(!artifacts.is_empty());
    assert_eq!(artifacts[0]["triage_priority"], "critical");
}

// ---------------------------------------------------------------------------
// dump
// ---------------------------------------------------------------------------

#[test]
fn dump_json_exits_zero() {
    q().args(["dump", "--format", "json"]).assert().success();
}

#[test]
fn dump_json_has_all_expected_keys() {
    let out = q()
        .args(["dump", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(std::str::from_utf8(&out).unwrap()).unwrap();
    for key in &[
        "lolbas_windows",
        "lolbas_linux",
        "lolbas_macos",
        "lolbas_windows_cmdlets",
        "lolbas_windows_mmc",
        "lolbas_windows_wmi",
        "abusable_sites",
        "catalog",
    ] {
        assert!(v[key].is_array(), "missing or non-array key: {key}");
    }
}

#[test]
fn dump_yaml_exits_zero() {
    q().args(["dump", "--format", "yaml"])
        .assert()
        .success()
        .stdout(predicate::str::contains("lolbas_windows:"));
}

#[test]
fn dump_dataset_lolbas_excludes_sites_and_catalog() {
    let out = q()
        .args(["dump", "--format", "json", "--dataset", "lolbas"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(std::str::from_utf8(&out).unwrap()).unwrap();
    assert!(v["lolbas_windows"].is_array());
    assert!(v.get("abusable_sites").is_none());
    assert!(v.get("catalog").is_none());
}

#[test]
fn dump_dataset_sites_excludes_lolbas() {
    let out = q()
        .args(["dump", "--format", "json", "--dataset", "sites"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(std::str::from_utf8(&out).unwrap()).unwrap();
    assert!(v["abusable_sites"].is_array());
    assert!(v.get("lolbas_windows").is_none());
}

#[test]
fn dump_dataset_catalog_excludes_lolbas() {
    let out = q()
        .args(["dump", "--format", "json", "--dataset", "catalog"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(std::str::from_utf8(&out).unwrap()).unwrap();
    assert!(v["catalog"].is_array());
    assert!(v.get("lolbas_windows").is_none());
}

// ---------------------------------------------------------------------------
// help
// ---------------------------------------------------------------------------

#[test]
fn help_exits_zero() {
    q().arg("--help").assert().success();
}

#[test]
fn dump_help_exits_zero() {
    q().args(["dump", "--help"]).assert().success();
}

// ── --triage --scenario ──────────────────────────────────────────────────────

#[test]
fn triage_scenario_ransomware_exits_zero() {
    let out = run(&["--triage", "--scenario", "ransomware"]);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
}

#[test]
fn triage_scenario_ransomware_lists_artifacts() {
    let out = run(&["--triage", "--scenario", "ransomware"]);
    // should include deletion/anti-forensics artifacts
    assert!(
        !out.stdout.is_empty(),
        "ransomware triage must list some artifacts"
    );
}

#[test]
fn triage_scenario_unknown_exits_nonzero() {
    let out = run(&["--triage", "--scenario", "unicorn"]);
    assert_ne!(out.code, 0, "unknown scenario must exit nonzero");
}

#[test]
fn triage_scenario_json_is_valid() {
    let out = run(&["--triage", "--scenario", "ransomware", "--format", "json"]);
    assert_eq!(out.code, 0);
    let _: serde_json::Value = serde_json::from_str(&out.stdout)
        .expect("--triage --scenario --format json must produce valid JSON");
}

// ── --triage --type ──────────────────────────────────────────────────────────

#[test]
fn triage_type_persistence_exits_zero() {
    let out = run(&["--triage", "--type", "persistence"]);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
}

#[test]
fn triage_type_lateral_movement_exits_zero() {
    let out = run(&["--triage", "--type", "lateral-movement"]);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
}

#[test]
fn triage_type_lateral_movement_is_not_a_scenario() {
    // lateral-movement is a tactic (--type), not a scenario (--scenario)
    let out = run(&["--triage", "--scenario", "lateral-movement"]);
    assert_ne!(
        out.code, 0,
        "lateral-movement must not be a valid --scenario value"
    );
}

#[test]
fn triage_type_unknown_exits_nonzero() {
    let out = run(&["--triage", "--type", "hacking"]);
    assert_ne!(out.code, 0, "unknown tactic must exit nonzero");
}

#[test]
fn triage_type_json_is_valid() {
    let out = run(&["--triage", "--type", "execution", "--format", "json"]);
    assert_eq!(out.code, 0);
    let _: serde_json::Value = serde_json::from_str(&out.stdout)
        .expect("--triage --type --format json must produce valid JSON");
}

#[test]
fn triage_scenario_and_type_combined() {
    let out = run(&[
        "--triage",
        "--scenario",
        "ransomware",
        "--type",
        "defense-evasion",
    ]);
    assert_eq!(out.code, 0);
}

// ── --triage --priority ──────────────────────────────────────────────────────

#[test]
fn triage_priority_critical_exits_zero() {
    let out = run(&["--triage", "--priority", "critical"]);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
}

#[test]
fn triage_priority_critical_only_contains_critical_entries() {
    let out = run(&["--triage", "--priority", "critical", "--format", "json"]);
    assert_eq!(out.code, 0);
    let val: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    let arr = val["artifacts"].as_array().unwrap();
    assert!(!arr.is_empty(), "--priority critical must return some artifacts");
    for entry in arr {
        assert_eq!(
            entry["triage_priority"], "critical",
            "--priority critical must not include non-critical entries"
        );
    }
}

#[test]
fn triage_priority_high_only_contains_high_entries() {
    let out = run(&["--triage", "--priority", "high", "--format", "json"]);
    assert_eq!(out.code, 0);
    let val: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    let arr = val["artifacts"].as_array().unwrap();
    assert!(!arr.is_empty(), "--priority high must return some artifacts");
    for entry in arr {
        assert_eq!(
            entry["triage_priority"], "high",
            "--priority high must not include non-high entries"
        );
    }
}

#[test]
fn triage_priority_critical_high_returns_both() {
    let out = run(&["--triage", "--priority", "critical,high", "--format", "json"]);
    assert_eq!(out.code, 0);
    let val: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    let arr = val["artifacts"].as_array().unwrap();
    let has_critical = arr.iter().any(|e| e["triage_priority"] == "critical");
    let has_high = arr.iter().any(|e| e["triage_priority"] == "high");
    assert!(has_critical, "critical,high must include critical entries");
    assert!(has_high, "critical,high must include high entries");
    for entry in arr {
        let p = entry["triage_priority"].as_str().unwrap();
        assert!(
            p == "critical" || p == "high",
            "--priority critical,high must not include medium/low entries, got: {p}"
        );
    }
}

#[test]
fn triage_priority_unknown_value_exits_nonzero() {
    let out = run(&["--triage", "--priority", "extreme"]);
    assert_ne!(out.code, 0, "unknown --priority value must exit nonzero");
}

#[test]
fn triage_priority_composes_with_scenario() {
    // AND logic: critical artifacts that also appear in the ransomware scenario
    let out = run(&[
        "--triage",
        "--priority",
        "critical",
        "--scenario",
        "ransomware",
        "--format",
        "json",
    ]);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let val: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    let arr = val["artifacts"].as_array().unwrap();
    for entry in arr {
        assert_eq!(
            entry["triage_priority"], "critical",
            "--priority critical --scenario must only return critical entries"
        );
    }
}

// ── --playbook ───────────────────────────────────────────────────────────────

#[test]
fn playbook_list_exits_zero() {
    let out = run(&["--playbook"]);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
}

#[test]
fn playbook_list_shows_five_scenarios() {
    let out = run(&["--playbook"]);
    // All 5 scenario IDs must appear
    for id in &[
        "ransomware",
        "data_breach",
        "bec",
        "insider",
        "supply_chain",
    ] {
        assert!(
            out.stdout.contains(id),
            "--playbook must list scenario id '{id}'"
        );
    }
    // All 6 investigation path IDs must also appear (shown in Paths section)
    for id in &[
        "lateral_movement",
        "credential_harvesting",
        "persistence",
        "data_exfiltration",
        "execution_trace",
        "defense_evasion",
    ] {
        assert!(
            out.stdout.contains(id),
            "--playbook must list investigation path id '{id}'"
        );
    }
}

#[test]
fn playbook_id_lateral_movement_exits_zero() {
    let out = run(&["--playbook", "lateral_movement"]);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
}

#[test]
fn playbook_id_shows_steps() {
    let out = run(&["--playbook", "lateral_movement"]);
    assert!(
        out.stdout.contains("rdp_client_servers"),
        "playbook steps must include rdp_client_servers"
    );
    assert!(
        out.stdout.contains("rationale") || out.stdout.contains("Establishes"),
        "playbook must include step rationale"
    );
}

#[test]
fn playbook_id_unknown_exits_nonzero() {
    let out = run(&["--playbook", "not_a_real_playbook"]);
    assert_ne!(out.code, 0, "unknown playbook ID must exit nonzero");
}

#[test]
fn playbook_format_json_is_valid() {
    let out = run(&["--playbook", "execution_trace", "--format", "json"]);
    assert_eq!(out.code, 0);
    let v: serde_json::Value = serde_json::from_str(&out.stdout)
        .expect("--playbook --format json must produce valid JSON");
    assert!(v["steps"].is_array(), "JSON must have steps array");
}

#[test]
fn playbook_list_json_is_valid() {
    let out = run(&["--playbook", "--format", "json"]);
    assert_eq!(out.code, 0);
    let v: serde_json::Value = serde_json::from_str(&out.stdout)
        .expect("--playbook list --format json must produce valid JSON");
    assert!(v.is_array(), "JSON list must be an array");
    assert_eq!(
        v.as_array().unwrap().len(),
        5,
        "JSON list must have exactly 5 scenario playbooks"
    );
}
