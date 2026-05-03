"""Integration tests for bindings/python/4n6query.py.

These tests exercise the Python CLI as a subprocess, verifying that it
delegates correctly to the underlying `4n6query` Rust binary.

Prerequisite: run `cargo build -p forensicnomicon-cli` so the binary is
available. The fixture resolves the binary from CARGO_TARGET_DIR →
target/debug/4n6query relative to the repo root, then passes it via the
FORENSICNOMICON_BIN environment variable.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
CLI_PY = REPO_ROOT / "bindings" / "python" / "4n6query.py"

_target = os.environ.get("CARGO_TARGET_DIR", str(REPO_ROOT / "target"))
RUST_BIN = Path(_target) / "debug" / "4n6query"


def run(*args, **kwargs):
    env = {**os.environ, "FORENSICNOMICON_BIN": str(RUST_BIN)}
    return subprocess.run(
        [sys.executable, str(CLI_PY), *args],
        capture_output=True,
        text=True,
        env=env,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Universal lookup — LOL/LOFL binary
# ---------------------------------------------------------------------------


def test_certutil_found():
    r = run("certutil.exe")
    assert r.returncode == 0
    assert "certutil.exe" in r.stdout


def test_certutil_platform_windows_found():
    r = run("certutil.exe", "--platform", "windows")
    assert r.returncode == 0
    assert "certutil.exe" in r.stdout


def test_certutil_platform_linux_not_found():
    r = run("certutil.exe", "--platform", "linux")
    assert r.returncode != 0


def test_curl_found():
    r = run("curl")
    assert r.returncode == 0
    assert "curl" in r.stdout


def test_osascript_found():
    r = run("osascript")
    assert r.returncode == 0


def test_invoke_command_found():
    r = run("Invoke-Command")
    assert r.returncode == 0


def test_unknown_term_exits_nonzero():
    r = run("xyzzy_not_a_real_indicator_99999")
    assert r.returncode != 0


# ---------------------------------------------------------------------------
# JSON output — LOLBin
# ---------------------------------------------------------------------------


def test_certutil_json_is_valid():
    r = run("certutil.exe", "--format", "json")
    assert r.returncode == 0
    v = json.loads(r.stdout)
    assert isinstance(v, dict)
    lolbas = v.get("lolbas", [])
    assert len(lolbas) > 0
    assert lolbas[0]["name"] == "certutil.exe"
    assert lolbas[0]["platform"] == "windows"
    assert isinstance(lolbas[0]["mitre_techniques"], list)


# ---------------------------------------------------------------------------
# Abusable site lookup
# ---------------------------------------------------------------------------


def test_github_raw_site_found():
    r = run("raw.githubusercontent.com")
    assert r.returncode == 0
    assert "raw.githubusercontent.com" in r.stdout


def test_github_raw_site_json():
    r = run("raw.githubusercontent.com", "--format", "json")
    assert r.returncode == 0
    v = json.loads(r.stdout)
    sites = v.get("sites", [])
    assert len(sites) > 0
    assert sites[0]["domain"] == "raw.githubusercontent.com"
    assert sites[0]["blocking_risk"] == "critical"


# ---------------------------------------------------------------------------
# Artifact keyword search
# ---------------------------------------------------------------------------


def test_userassist_finds_both_variants():
    r = run("userassist")
    assert r.returncode == 0
    assert "userassist" in r.stdout.lower()
    # Both EXE and Folder variants should appear
    assert "exe" in r.stdout.lower() or "exe" in r.stdout
    assert "folder" in r.stdout.lower() or "Folder" in r.stdout


def test_prefetch_keyword_found():
    r = run("prefetch")
    assert r.returncode == 0


def test_artifact_json_has_artifacts_array():
    r = run("userassist", "--format", "json")
    assert r.returncode == 0
    v = json.loads(r.stdout)
    artifacts = v.get("artifacts", [])
    assert len(artifacts) > 0
    assert "id" in artifacts[0]
    assert "triage_priority" in artifacts[0]


# ---------------------------------------------------------------------------
# MITRE technique lookup
# ---------------------------------------------------------------------------


def test_mitre_t1547_found():
    r = run("T1547.001")
    assert r.returncode == 0


def test_mitre_json_has_artifacts():
    r = run("T1547.001", "--format", "json")
    assert r.returncode == 0
    v = json.loads(r.stdout)
    assert len(v.get("artifacts", [])) > 0


def test_unknown_mitre_exits_nonzero():
    r = run("T9999.999")
    assert r.returncode != 0


# ---------------------------------------------------------------------------
# Triage
# ---------------------------------------------------------------------------


def test_triage_exits_zero():
    r = run("--triage")
    assert r.returncode == 0


def test_triage_json_first_entry_is_critical():
    r = run("--triage", "--format", "json")
    assert r.returncode == 0
    v = json.loads(r.stdout)
    artifacts = v.get("artifacts", [])
    assert len(artifacts) > 0
    assert artifacts[0]["triage_priority"] == "critical"


# ---------------------------------------------------------------------------
# dump
# ---------------------------------------------------------------------------


def test_dump_json_exits_zero():
    r = run("dump", "--format", "json")
    assert r.returncode == 0


def test_dump_json_has_all_keys():
    r = run("dump", "--format", "json")
    v = json.loads(r.stdout)
    for key in ("lolbas_windows", "lolbas_linux", "lolbas_macos",
                "lolbas_windows_cmdlets", "lolbas_windows_mmc",
                "lolbas_windows_wmi", "abusable_sites", "catalog"):
        assert key in v, f"missing key: {key}"


def test_dump_yaml_exits_zero():
    r = run("dump", "--format", "yaml")
    assert r.returncode == 0
    assert "lolbas_windows:" in r.stdout


def test_dump_dataset_lolbas_excludes_catalog():
    r = run("dump", "--format", "json", "--dataset", "lolbas")
    v = json.loads(r.stdout)
    assert "lolbas_windows" in v
    assert "catalog" not in v


def test_dump_dataset_catalog_excludes_lolbas():
    r = run("dump", "--format", "json", "--dataset", "catalog")
    v = json.loads(r.stdout)
    assert "catalog" in v
    assert "lolbas_windows" not in v


# ---------------------------------------------------------------------------
# help
# ---------------------------------------------------------------------------


def test_help_exits_zero():
    r = run("--help")
    assert r.returncode == 0


def test_dump_help_exits_zero():
    r = run("dump", "--help")
    assert r.returncode == 0
