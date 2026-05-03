"""Integration tests for bindings/python/4n6query.py.

These tests exercise the Python CLI as a subprocess, verifying that it
delegates correctly to the underlying `4n6query` Rust binary and that
its --help / --json flags work end-to-end.

Prerequisite: run `cargo build -p forensicnomicon-cli` so the binary is on
PATH or at the default cargo output location. The fixture below resolves the
binary from `$CARGO_TARGET_DIR` → `target/debug/4n6query` relative to the
repo root, then passes it via the `FORENSICNOMICON_BIN` environment variable.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
CLI_PY = REPO_ROOT / "bindings" / "python" / "4n6query.py"

# Resolve the Rust binary to inject into the subprocess environment.
_target = os.environ.get("CARGO_TARGET_DIR", str(REPO_ROOT / "target"))
RUST_BIN = Path(_target) / "debug" / "4n6query"


def run(*args, **kwargs):
    """Run 4n6query.py with given args; returns CompletedProcess."""
    env = {**os.environ, "FORENSICNOMICON_BIN": str(RUST_BIN)}
    return subprocess.run(
        [sys.executable, str(CLI_PY), *args],
        capture_output=True,
        text=True,
        env=env,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# lolbas lookup
# ---------------------------------------------------------------------------


def test_lolbas_lookup_windows_certutil_exits_zero():
    r = run("lolbas", "lookup", "windows", "certutil.exe")
    assert r.returncode == 0


def test_lolbas_lookup_windows_certutil_stdout_contains_name():
    r = run("lolbas", "lookup", "windows", "certutil.exe")
    assert "certutil.exe" in r.stdout


def test_lolbas_lookup_unknown_exits_nonzero():
    r = run("lolbas", "lookup", "windows", "xyzzy_no_such_binary_99999")
    assert r.returncode != 0


def test_lolbas_lookup_json_is_valid_json():
    r = run("lolbas", "lookup", "windows", "certutil.exe", "--format", "json")
    assert r.returncode == 0
    v = json.loads(r.stdout)
    assert v["name"] == "certutil.exe"
    assert v["platform"] == "windows"
    assert isinstance(v["mitre_techniques"], list)


# ---------------------------------------------------------------------------
# sites lookup
# ---------------------------------------------------------------------------


def test_sites_lookup_github_raw_exits_zero():
    r = run("sites", "lookup", "raw.githubusercontent.com")
    assert r.returncode == 0
    assert "raw.githubusercontent.com" in r.stdout


def test_sites_lookup_unknown_exits_nonzero():
    r = run("sites", "lookup", "this-domain-is-definitely-not-real.example.com")
    assert r.returncode != 0


def test_sites_lookup_json_is_valid_json():
    r = run("sites", "lookup", "raw.githubusercontent.com", "--format", "json")
    assert r.returncode == 0
    v = json.loads(r.stdout)
    assert v["domain"] == "raw.githubusercontent.com"
    assert v["blocking_risk"] == "critical"


# ---------------------------------------------------------------------------
# catalog search
# ---------------------------------------------------------------------------


def test_catalog_search_prefetch_exits_zero():
    r = run("catalog", "search", "prefetch")
    assert r.returncode == 0


def test_catalog_search_unknown_exits_nonzero():
    r = run("catalog", "search", "xyzzy_no_such_artifact_99999")
    assert r.returncode != 0


def test_catalog_search_json_is_array():
    r = run("catalog", "search", "prefetch", "--format", "json")
    assert r.returncode == 0
    v = json.loads(r.stdout)
    assert isinstance(v, list)
    assert len(v) > 0


# ---------------------------------------------------------------------------
# catalog show
# ---------------------------------------------------------------------------


def test_catalog_show_userassist_exits_zero():
    r = run("catalog", "show", "userassist_exe")
    assert r.returncode == 0
    assert "userassist" in r.stdout.lower()


def test_catalog_show_unknown_exits_nonzero():
    r = run("catalog", "show", "xyzzy_no_such_id_99999")
    assert r.returncode != 0


def test_catalog_show_json_has_id_field():
    r = run("catalog", "show", "userassist_exe", "--format", "json")
    assert r.returncode == 0
    v = json.loads(r.stdout)
    assert v["id"] == "userassist_exe"


# ---------------------------------------------------------------------------
# catalog mitre
# ---------------------------------------------------------------------------


def test_catalog_mitre_t1547_exits_zero():
    r = run("catalog", "mitre", "T1547.001")
    assert r.returncode == 0


def test_catalog_mitre_unknown_exits_nonzero():
    r = run("catalog", "mitre", "T9999.999")
    assert r.returncode != 0


def test_catalog_mitre_json_is_array():
    r = run("catalog", "mitre", "T1547.001", "--format", "json")
    assert r.returncode == 0
    v = json.loads(r.stdout)
    assert isinstance(v, list)
    assert len(v) > 0


# ---------------------------------------------------------------------------
# catalog triage
# ---------------------------------------------------------------------------


def test_catalog_triage_exits_zero():
    r = run("catalog", "triage")
    assert r.returncode == 0


def test_catalog_triage_json_first_entry_is_critical():
    r = run("catalog", "triage", "--format", "json")
    assert r.returncode == 0
    v = json.loads(r.stdout)
    assert isinstance(v, list)
    assert v[0]["triage_priority"] == "critical"


# ---------------------------------------------------------------------------
# catalog list
# ---------------------------------------------------------------------------


def test_catalog_list_exits_zero():
    r = run("catalog", "list")
    assert r.returncode == 0
    assert "userassist_exe" in r.stdout


def test_catalog_list_json_has_many_entries():
    r = run("catalog", "list", "--format", "json")
    assert r.returncode == 0
    v = json.loads(r.stdout)
    assert isinstance(v, list)
    assert len(v) > 1000, f"expected 6,548 entries, got {len(v)}"


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


def test_lolbas_help_exits_zero():
    r = run("lolbas", "--help")
    assert r.returncode == 0


def test_catalog_help_exits_zero():
    r = run("catalog", "--help")
    assert r.returncode == 0


def test_sites_help_exits_zero():
    r = run("sites", "--help")
    assert r.returncode == 0


def test_dump_help_exits_zero():
    r = run("dump", "--help")
    assert r.returncode == 0
