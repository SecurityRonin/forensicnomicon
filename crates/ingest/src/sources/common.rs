//! Helpers shared by the source adapters.

use std::time::Duration;

use crate::github::github_client;

/// A GitHub repository listing plus where to download each listed file from.
pub struct GithubFiles<'a> {
    /// Source label, used to attribute warnings.
    pub source: &'a str,
    /// Listing endpoint. Both GitHub shapes are accepted: a git-trees response
    /// (`{"tree": [...]}`) and a contents response (a bare array). The trees
    /// API truncates on large repositories; the contents API does not, which is
    /// why sources pick different ones.
    pub listing_url: &'a str,
    /// Prefix a listed path is appended to for the raw download.
    pub raw_base: &'a str,
    /// Pause between raw downloads.
    pub delay: Duration,
}

/// Paths of every entry in a GitHub listing that satisfies `keep`.
///
/// Returns `None` when the JSON is neither listing shape — an error response
/// (rate limit, 404) deserializes cleanly into some *other* object, and
/// treating that as "no files" would report a failed fetch as an empty corpus.
pub fn listing_paths(
    listing: &serde_json::Value,
    keep: impl Fn(&str) -> bool,
) -> Option<Vec<String>> {
    let items = listing
        .get("tree")
        .and_then(serde_json::Value::as_array)
        .or_else(|| listing.as_array())?;
    Some(
        items
            .iter()
            .filter_map(|item| item.get("path").and_then(serde_json::Value::as_str))
            .filter(|path| keep(path))
            .map(str::to_string)
            .collect(),
    )
}

/// Fetch every file in a GitHub listing whose path satisfies `keep`, handing
/// each `(path, content)` to `visit` as it arrives. Returns the number of files
/// visited.
///
/// Contents are streamed rather than collected: the corpora run to thousands of
/// files, and no caller needs more than one at a time.
///
/// Failing to *list* is a bootstrap failure and returns `Err` — it is not the
/// same as a repository with no matching files. Failing to fetch one listed file
/// is a per-artifact miss: it warns and the walk continues.
pub fn for_each_github_file(
    spec: &GithubFiles<'_>,
    keep: impl Fn(&str) -> bool,
    mut visit: impl FnMut(&str, &str),
) -> Result<usize, Box<dyn std::error::Error>> {
    let client = github_client()?;
    let listing: serde_json::Value = client.get(spec.listing_url).send()?.json()?;

    let Some(paths) = listing_paths(&listing, keep) else {
        let mut body = listing.to_string();
        body.truncate(300);
        return Err(format!(
            "{}: listing at {} is neither a tree object nor an array; body was: {body}",
            spec.source, spec.listing_url
        )
        .into());
    };

    let mut visited = 0;
    for path in paths {
        let url = format!("{}{path}", spec.raw_base);
        std::thread::sleep(spec.delay);
        match client
            .get(&url)
            .send()
            .and_then(reqwest::blocking::Response::error_for_status)
            .and_then(reqwest::blocking::Response::text)
        {
            Ok(content) => {
                visit(&path, &content);
                visited += 1;
            }
            Err(e) => eprintln!("WARN: {}: failed to fetch {url}: {e}", spec.source),
        }
    }
    Ok(visited)
}

/// Pull ATT&CK technique IDs (`T1234`, `T1234.001`) out of free text.
///
/// Upstream corpora put technique IDs in prose comments, so the IDs are
/// recovered by pattern rather than from a dedicated field.
pub fn extract_mitre(text: &str) -> Vec<String> {
    // Constant valid regex; degrade to no matches rather than panic if it ever
    // fails to compile.
    let Ok(re) = regex::Regex::new(r"T\d{4}(?:\.\d{3})?") else {
        return Vec::new();
    };
    re.find_iter(text).map(|m| m.as_str().to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listing_paths_reads_the_git_trees_shape() {
        let listing = serde_json::json!({
            "tree": [
                {"path": "Targets/Browsers/Chrome.tkape"},
                {"path": "Targets/README.md"},
                {"path": "Modules/Foo.mkape"},
            ]
        });
        let kept = listing_paths(&listing, |p| {
            p.starts_with("Targets/") && p.ends_with(".tkape")
        });
        assert_eq!(
            kept,
            Some(vec!["Targets/Browsers/Chrome.tkape".to_string()])
        );
    }

    #[test]
    fn listing_paths_reads_the_contents_shape() {
        let listing = serde_json::json!([
            {"path": "ETWProvidersCSVs/Internal/Foo.csv"},
            {"path": "ETWProvidersCSVs/Internal/README.md"},
        ]);
        let kept = listing_paths(&listing, |p| p.ends_with(".csv"));
        assert_eq!(
            kept,
            Some(vec!["ETWProvidersCSVs/Internal/Foo.csv".to_string()])
        );
    }

    #[test]
    fn listing_paths_rejects_an_error_response_rather_than_calling_it_empty() {
        // What GitHub actually returns when the rate limit is hit. Reporting
        // this as zero files would be indistinguishable from a clean fetch of a
        // repository with no matching files.
        let listing = serde_json::json!({
            "message": "API rate limit exceeded for 203.0.113.1.",
            "documentation_url": "https://docs.github.com/rest/overview/rate-limits-for-the-rest-api"
        });
        assert_eq!(listing_paths(&listing, |_| true), None);
    }

    #[test]
    fn listing_paths_keeps_an_empty_listing_distinct_from_a_bad_shape() {
        assert_eq!(
            listing_paths(&serde_json::json!([]), |_| true),
            Some(vec![])
        );
        assert_eq!(
            listing_paths(&serde_json::json!({"tree": []}), |_| true),
            Some(vec![])
        );
    }

    #[test]
    fn finds_bare_and_sub_techniques() {
        assert_eq!(
            extract_mitre("Persistence via Run key (T1547.001) and T1112"),
            vec!["T1547.001".to_string(), "T1112".to_string()]
        );
    }

    #[test]
    fn returns_empty_for_text_without_techniques() {
        assert!(extract_mitre("Port proxying - lateral movement indicator").is_empty());
        assert!(extract_mitre("").is_empty());
    }

    #[test]
    fn ignores_tokens_that_only_look_like_technique_ids() {
        // Too few digits to be a technique ID.
        assert!(extract_mitre("T123 tcp").is_empty());
    }
}
