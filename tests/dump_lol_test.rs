/// Integration tests for the `dump_lol` example.
///
/// These tests run `cargo run --example dump_lol --features serde` and then
/// verify the generated JSON snapshot files in `data/`.
use std::process::Command;

/// Builds the manifest dir path for this crate (workspace root).
fn workspace_root() -> std::path::PathBuf {
    // CARGO_MANIFEST_DIR is set by cargo test to the package root.
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Run `cargo run --example dump_lol --features serde` from the workspace root.
///
/// Returns the exit status plus stdout/stderr for diagnostics.
fn run_dump_lol() -> std::process::Output {
    Command::new("cargo")
        .args(["run", "--example", "dump_lol", "--features", "serde"])
        .current_dir(workspace_root())
        .output()
        .expect("failed to spawn cargo")
}

#[test]
fn dump_lol_exits_zero() {
    let out = run_dump_lol();
    assert!(
        out.status.success(),
        "dump_lol exited non-zero.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

#[test]
fn dump_lol_all_json_exists_and_is_valid_object() {
    let _ = run_dump_lol();
    let path = workspace_root().join("data/all.json");
    assert!(path.exists(), "data/all.json does not exist");

    let content = std::fs::read_to_string(&path).expect("cannot read data/all.json");
    let value: serde_json::Value =
        serde_json::from_str(&content).expect("data/all.json is not valid JSON");
    assert!(value.is_object(), "data/all.json must be a JSON object");
}

#[test]
fn dump_lol_all_json_has_required_keys() {
    let _ = run_dump_lol();
    let path = workspace_root().join("data/all.json");
    let content = std::fs::read_to_string(&path).expect("cannot read data/all.json");
    let value: serde_json::Value = serde_json::from_str(&content).unwrap();
    let obj = value.as_object().unwrap();

    let required_keys = [
        "lolbas_windows",
        "lolbas_linux",
        "lolbas_macos",
        "lolbas_windows_cmdlets",
        "lolbas_windows_mmc",
        "lolbas_windows_wmi",
        "abusable_sites",
    ];
    for key in required_keys {
        assert!(
            obj.contains_key(key),
            "data/all.json is missing key: {key}"
        );
    }
}

#[test]
fn dump_lol_lolbas_windows_json_is_nonempty_array() {
    let _ = run_dump_lol();
    let path = workspace_root().join("data/lolbas_windows.json");
    assert!(path.exists(), "data/lolbas_windows.json does not exist");

    let content =
        std::fs::read_to_string(&path).expect("cannot read data/lolbas_windows.json");
    let value: serde_json::Value = serde_json::from_str(&content).unwrap();
    let arr = value.as_array().expect("lolbas_windows.json must be a JSON array");
    assert!(!arr.is_empty(), "lolbas_windows.json array must not be empty");
}

#[test]
fn dump_lol_lolbas_windows_entries_have_required_fields() {
    let _ = run_dump_lol();
    let path = workspace_root().join("data/lolbas_windows.json");
    let content = std::fs::read_to_string(&path).unwrap();
    let value: serde_json::Value = serde_json::from_str(&content).unwrap();
    let arr = value.as_array().unwrap();

    for (i, entry) in arr.iter().enumerate() {
        let obj = entry
            .as_object()
            .unwrap_or_else(|| panic!("entry {i} is not an object"));
        for field in ["name", "mitre_techniques", "use_cases", "description"] {
            assert!(
                obj.contains_key(field),
                "lolbas_windows entry {i} missing field: {field}"
            );
        }
    }
}
