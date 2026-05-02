//! Integration tests for the `fnquery` CLI.
//!
//! These tests run the compiled binary via assert_cmd and verify:
//! - `lolbas lookup <platform> <name>` finds known LOL binaries and exits 0
//! - `lolbas lookup <platform> <unknown>` exits non-zero with a clear message
//! - `sites lookup <domain>` finds known abusable sites
//! - `dump --format json` produces a valid JSON object with expected top-level keys
//! - `dump --format yaml` produces valid YAML
//! - `--help` exits 0 on all subcommands

use assert_cmd::Command;
use predicates::prelude::*;

fn fnquery() -> Command {
    Command::cargo_bin("4n6query").unwrap()
}

// ---------------------------------------------------------------------------
// lolbas lookup
// ---------------------------------------------------------------------------

#[test]
fn lolbas_lookup_windows_certutil_exits_zero() {
    fnquery()
        .args(["lolbas", "lookup", "windows", "certutil.exe"])
        .assert()
        .success();
}

#[test]
fn lolbas_lookup_windows_certutil_prints_name() {
    fnquery()
        .args(["lolbas", "lookup", "windows", "certutil.exe"])
        .assert()
        .success()
        .stdout(predicate::str::contains("certutil.exe"));
}

#[test]
fn lolbas_lookup_linux_curl_exits_zero() {
    fnquery()
        .args(["lolbas", "lookup", "linux", "curl"])
        .assert()
        .success()
        .stdout(predicate::str::contains("curl"));
}

#[test]
fn lolbas_lookup_macos_osascript_exits_zero() {
    fnquery()
        .args(["lolbas", "lookup", "macos", "osascript"])
        .assert()
        .success()
        .stdout(predicate::str::contains("osascript"));
}

#[test]
fn lolbas_lookup_windows_cmdlet_invoke_webrequest() {
    fnquery()
        .args(["lolbas", "lookup", "windows-cmdlet", "Invoke-WebRequest"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Invoke-WebRequest"));
}

#[test]
fn lolbas_lookup_windows_mmc_gpedit() {
    fnquery()
        .args(["lolbas", "lookup", "windows-mmc", "gpedit.msc"])
        .assert()
        .success()
        .stdout(predicate::str::contains("gpedit.msc"));
}

#[test]
fn lolbas_lookup_windows_wmi_win32_process() {
    fnquery()
        .args(["lolbas", "lookup", "windows-wmi", "Win32_Process"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Win32_Process"));
}

#[test]
fn lolbas_lookup_unknown_binary_exits_nonzero() {
    fnquery()
        .args(["lolbas", "lookup", "windows", "definitly_not_a_lolbin_xyz"])
        .assert()
        .failure();
}

#[test]
fn lolbas_lookup_unknown_binary_prints_not_found() {
    fnquery()
        .args(["lolbas", "lookup", "windows", "definitly_not_a_lolbin_xyz"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found").or(predicate::str::contains("Not found")));
}

// ---------------------------------------------------------------------------
// lolbas lookup --format json
// ---------------------------------------------------------------------------

#[test]
fn lolbas_lookup_json_output_is_valid_json() {
    let output = fnquery()
        .args(["lolbas", "lookup", "windows", "certutil.exe", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = std::str::from_utf8(&output).unwrap();
    let v: serde_json::Value = serde_json::from_str(text).expect("output is not valid JSON");
    assert_eq!(v["name"], "certutil.exe");
    assert_eq!(v["platform"], "windows");
}

// ---------------------------------------------------------------------------
// sites lookup
// ---------------------------------------------------------------------------

#[test]
fn sites_lookup_github_raw_exits_zero() {
    fnquery()
        .args(["sites", "lookup", "raw.githubusercontent.com"])
        .assert()
        .success()
        .stdout(predicate::str::contains("raw.githubusercontent.com"));
}

#[test]
fn sites_lookup_github_raw_shows_blocking_risk() {
    fnquery()
        .args(["sites", "lookup", "raw.githubusercontent.com"])
        .assert()
        .success()
        .stdout(predicate::str::contains("critical").or(predicate::str::contains("Critical")));
}

#[test]
fn sites_lookup_unknown_domain_exits_nonzero() {
    fnquery()
        .args(["sites", "lookup", "this-domain-is-not-abusable.example.com"])
        .assert()
        .failure();
}

#[test]
fn sites_lookup_json_output_is_valid_json() {
    let output = fnquery()
        .args(["sites", "lookup", "raw.githubusercontent.com", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = std::str::from_utf8(&output).unwrap();
    let v: serde_json::Value = serde_json::from_str(text).expect("output is not valid JSON");
    assert_eq!(v["domain"], "raw.githubusercontent.com");
    assert_eq!(v["blocking_risk"], "critical");
}

// ---------------------------------------------------------------------------
// dump
// ---------------------------------------------------------------------------

#[test]
fn dump_json_exits_zero() {
    fnquery()
        .args(["dump", "--format", "json"])
        .assert()
        .success();
}

#[test]
fn dump_json_output_is_valid_json_object() {
    let output = fnquery()
        .args(["dump", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = std::str::from_utf8(&output).unwrap();
    let v: serde_json::Value = serde_json::from_str(text).expect("dump output is not valid JSON");
    assert!(v.is_object(), "expected top-level JSON object");
}

#[test]
fn dump_json_has_all_six_lolbas_keys() {
    let output = fnquery()
        .args(["dump", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = std::str::from_utf8(&output).unwrap();
    let v: serde_json::Value = serde_json::from_str(text).unwrap();
    for key in &[
        "lolbas_windows",
        "lolbas_linux",
        "lolbas_macos",
        "lofl_windows_cmdlets",
        "lofl_windows_mmc",
        "lofl_windows_wmi",
    ] {
        assert!(v[key].is_array(), "missing key: {key}");
        assert!(
            !v[key].as_array().unwrap().is_empty(),
            "empty array for key: {key}"
        );
    }
}

#[test]
fn dump_json_has_abusable_sites_key() {
    let output = fnquery()
        .args(["dump", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = std::str::from_utf8(&output).unwrap();
    let v: serde_json::Value = serde_json::from_str(text).unwrap();
    assert!(v["abusable_sites"].is_array());
    assert!(!v["abusable_sites"].as_array().unwrap().is_empty());
}

#[test]
fn dump_json_lolbas_windows_contains_certutil() {
    let output = fnquery()
        .args(["dump", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = std::str::from_utf8(&output).unwrap();
    let v: serde_json::Value = serde_json::from_str(text).unwrap();
    let windows = v["lolbas_windows"].as_array().unwrap();
    assert!(windows.iter().any(|e| e.as_str() == Some("certutil.exe")));
}

#[test]
fn dump_yaml_exits_zero() {
    fnquery()
        .args(["dump", "--format", "yaml"])
        .assert()
        .success();
}

#[test]
fn dump_yaml_contains_lolbas_windows_key() {
    fnquery()
        .args(["dump", "--format", "yaml"])
        .assert()
        .success()
        .stdout(predicate::str::contains("lolbas_windows:"));
}

#[test]
fn dump_yaml_contains_abusable_sites_key() {
    fnquery()
        .args(["dump", "--format", "yaml"])
        .assert()
        .success()
        .stdout(predicate::str::contains("abusable_sites:"));
}

// ---------------------------------------------------------------------------
// dump --dataset filtering
// ---------------------------------------------------------------------------

#[test]
fn dump_json_dataset_lolbas_only_has_lolbas_keys() {
    let output = fnquery()
        .args(["dump", "--format", "json", "--dataset", "lolbas"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = std::str::from_utf8(&output).unwrap();
    let v: serde_json::Value = serde_json::from_str(text).unwrap();
    assert!(v["lolbas_windows"].is_array());
    // abusable_sites should NOT be present
    assert!(v.get("abusable_sites").is_none());
}

#[test]
fn dump_json_dataset_sites_only_has_sites_key() {
    let output = fnquery()
        .args(["dump", "--format", "json", "--dataset", "sites"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = std::str::from_utf8(&output).unwrap();
    let v: serde_json::Value = serde_json::from_str(text).unwrap();
    assert!(v["abusable_sites"].is_array());
    // lolbas_windows should NOT be present
    assert!(v.get("lolbas_windows").is_none());
}

// ---------------------------------------------------------------------------
// help
// ---------------------------------------------------------------------------

#[test]
fn top_level_help_exits_zero() {
    fnquery().arg("--help").assert().success();
}

#[test]
fn lolbas_help_exits_zero() {
    fnquery().args(["lolbas", "--help"]).assert().success();
}

#[test]
fn sites_help_exits_zero() {
    fnquery().args(["sites", "--help"]).assert().success();
}

#[test]
fn dump_help_exits_zero() {
    fnquery().args(["dump", "--help"]).assert().success();
}
