//! PyO3 native Python extension for the forensicnomicon DFIR catalog.
//!
//! Exposes five functions:
//! - `lolbas_lookup(name, platform=None)` — LOLBin/GTFOBin lookup
//! - `catalog_search(keyword)` — artifact catalog full-text search
//! - `catalog_show(id)` — single artifact by ID
//! - `triage_list()` — all artifacts sorted Critical-first
//! - `sites_lookup(domain)` — abusable site lookup

use ::forensicnomicon::abusable_sites::{abusable_site_info, BlockingRisk, ABUSABLE_SITES};
use ::forensicnomicon::catalog::{TriagePriority, CATALOG};
use ::forensicnomicon::lolbins::{LolbasEntry, LOLBAS_LINUX, LOLBAS_MACOS, LOLBAS_WINDOWS};
use pyo3::prelude::*;
use pyo3::types::PyDict;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn triage_priority_str(p: TriagePriority) -> &'static str {
    match p {
        TriagePriority::Critical => "Critical",
        TriagePriority::High => "High",
        TriagePriority::Medium => "Medium",
        TriagePriority::Low => "Low",
        // non_exhaustive: fall back gracefully
        _ => "Unknown",
    }
}

fn blocking_risk_str(r: BlockingRisk) -> &'static str {
    match r {
        BlockingRisk::Low => "Low",
        BlockingRisk::Medium => "Medium",
        BlockingRisk::High => "High",
        BlockingRisk::Critical => "Critical",
    }
}

/// Build the dict representation of an ArtifactDescriptor.
fn descriptor_to_dict(
    py: Python<'_>,
    d: &::forensicnomicon::catalog::ArtifactDescriptor,
) -> PyResult<PyObject> {
    let dict = PyDict::new_bound(py);
    dict.set_item("id", d.id)?;
    dict.set_item("name", d.name)?;
    dict.set_item("triage_priority", triage_priority_str(d.triage_priority))?;
    let techniques: Vec<&str> = d.mitre_techniques.to_vec();
    dict.set_item("mitre_techniques", techniques)?;
    dict.set_item("meaning", d.meaning)?;
    dict.set_item("key_path", d.key_path)?;
    Ok(dict.into())
}

// ── lolbas_lookup ─────────────────────────────────────────────────────────────

/// Look up LOLBin / GTFOBin entries by name (case-insensitive).
///
/// Args:
///     name: binary or script name, e.g. ``"certutil.exe"``
///     platform: optional filter — ``"windows"``, ``"linux"``, or ``"macos"``
///
/// Returns a list of dicts, each with ``name``, ``platform``,
/// ``mitre_techniques``, ``use_cases``, and ``description`` keys.
/// Returns an empty list when nothing matches.
#[pyfunction]
#[pyo3(signature = (name, platform=None))]
fn lolbas_lookup(py: Python<'_>, name: &str, platform: Option<&str>) -> PyResult<Vec<PyObject>> {
    let lower = name.to_ascii_lowercase();

    struct CatalogEntry {
        platform: &'static str,
        catalog: &'static [LolbasEntry],
    }

    let catalogs = [
        CatalogEntry { platform: "windows", catalog: LOLBAS_WINDOWS },
        CatalogEntry { platform: "linux", catalog: LOLBAS_LINUX },
        CatalogEntry { platform: "macos", catalog: LOLBAS_MACOS },
    ];

    let mut results = Vec::new();

    for cat in &catalogs {
        // Skip if platform filter is set and doesn't match
        if let Some(p) = platform {
            if cat.platform != p.to_ascii_lowercase().as_str() {
                continue;
            }
        }

        for entry in cat.catalog {
            if entry.name.to_ascii_lowercase() != lower {
                continue;
            }
            let dict = PyDict::new_bound(py);
            dict.set_item("name", entry.name)?;
            dict.set_item("platform", cat.platform)?;
            let techniques: Vec<&str> = entry.mitre_techniques.to_vec();
            dict.set_item("mitre_techniques", techniques)?;
            dict.set_item("use_cases", entry.use_cases)?;
            dict.set_item("description", entry.description)?;
            results.push(dict.into());
        }
    }

    Ok(results)
}

// ── catalog_search ────────────────────────────────────────────────────────────

/// Search the forensic artifact catalog by keyword (case-insensitive).
///
/// Matches against artifact name and meaning fields.
///
/// Args:
///     keyword: search term, e.g. ``"userassist"``
///
/// Returns a list of dicts with ``id``, ``name``, ``triage_priority``,
/// ``mitre_techniques``, ``meaning``, and ``key_path`` keys.
#[pyfunction]
fn catalog_search(py: Python<'_>, keyword: &str) -> PyResult<Vec<PyObject>> {
    let matches = CATALOG.filter_by_keyword(keyword);
    let mut results = Vec::with_capacity(matches.len());
    for d in matches {
        results.push(descriptor_to_dict(py, d)?);
    }
    Ok(results)
}

// ── catalog_show ─────────────────────────────────────────────────────────────

/// Look up a single artifact descriptor by its exact ID.
///
/// Args:
///     artifact_id: e.g. ``"userassist_exe"``
///
/// Returns a dict if found, ``None`` otherwise.
#[pyfunction]
fn catalog_show(py: Python<'_>, artifact_id: &str) -> PyResult<Option<PyObject>> {
    match CATALOG.by_id(artifact_id) {
        Some(d) => Ok(Some(descriptor_to_dict(py, d)?)),
        None => Ok(None),
    }
}

// ── triage_list ───────────────────────────────────────────────────────────────

/// Return all catalog artifacts sorted by triage priority (Critical first).
///
/// Returns a list of dicts with the same keys as :func:`catalog_search`.
#[pyfunction]
fn triage_list(py: Python<'_>) -> PyResult<Vec<PyObject>> {
    let sorted = CATALOG.for_triage();
    let mut results = Vec::with_capacity(sorted.len());
    for d in sorted {
        results.push(descriptor_to_dict(py, d)?);
    }
    Ok(results)
}

// ── sites_lookup ──────────────────────────────────────────────────────────────

/// Look up abusable site records by domain (exact, case-insensitive).
///
/// Args:
///     domain: bare domain name, e.g. ``"raw.githubusercontent.com"``
///
/// Returns a list of dicts (usually one or zero entries) with ``domain``,
/// ``provider``, ``risk``, ``mitre_techniques``, and ``abuse_tags`` keys.
#[pyfunction]
fn sites_lookup(py: Python<'_>, domain: &str) -> PyResult<Vec<PyObject>> {
    let lower = domain.to_ascii_lowercase();
    let mut results = Vec::new();

    for site in ABUSABLE_SITES {
        if site.domain.to_ascii_lowercase() != lower {
            continue;
        }
        let dict = PyDict::new_bound(py);
        dict.set_item("domain", site.domain)?;
        dict.set_item("provider", site.provider)?;
        dict.set_item("risk", blocking_risk_str(site.blocking_risk))?;
        let techniques: Vec<&str> = site.mitre_techniques.to_vec();
        dict.set_item("mitre_techniques", techniques)?;
        dict.set_item("abuse_tags", site.abuse_tags)?;
        results.push(dict.into());
    }

    // Also try the helper as a fallback (covers exact-match)
    if results.is_empty() {
        if let Some(site) = abusable_site_info(domain) {
            let dict = PyDict::new_bound(py);
            dict.set_item("domain", site.domain)?;
            dict.set_item("provider", site.provider)?;
            dict.set_item("risk", blocking_risk_str(site.blocking_risk))?;
            let techniques: Vec<&str> = site.mitre_techniques.to_vec();
            dict.set_item("mitre_techniques", techniques)?;
            dict.set_item("abuse_tags", site.abuse_tags)?;
            results.push(dict.into());
        }
    }

    Ok(results)
}

// ── Module ────────────────────────────────────────────────────────────────────

#[pymodule]
fn forensicnomicon(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_function(wrap_pyfunction!(lolbas_lookup, m)?)?;
    m.add_function(wrap_pyfunction!(catalog_search, m)?)?;
    m.add_function(wrap_pyfunction!(catalog_show, m)?)?;
    m.add_function(wrap_pyfunction!(triage_list, m)?)?;
    m.add_function(wrap_pyfunction!(sites_lookup, m)?)?;
    Ok(())
}
