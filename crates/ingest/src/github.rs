//! Shared GitHub HTTP client with optional token auth.
//!
//! Reads `GITHUB_TOKEN` or `GH_TOKEN` from the environment and adds an
//! `Authorization: Bearer` header if found. Without a token, GitHub's
//! unauthenticated rate limit is 60 req/hour; with one it's 5000/hour.

use reqwest::blocking::{Client, ClientBuilder};

/// Build a reqwest blocking client configured for GitHub API access.
///
/// Picks up `GITHUB_TOKEN` or `GH_TOKEN` from the environment for auth.
/// Falls back to unauthenticated if neither is set.
pub fn github_client() -> Result<Client, reqwest::Error> {
    let token = std::env::var("GITHUB_TOKEN")
        .or_else(|_| std::env::var("GH_TOKEN"))
        .ok();

    let mut builder = ClientBuilder::new()
        .user_agent("forensicnomicon-ingest/0.1")
        .timeout(std::time::Duration::from_secs(30));

    if let Some(tok) = token {
        let mut headers = reqwest::header::HeaderMap::new();
        if let Ok(val) = reqwest::header::HeaderValue::from_str(&format!("Bearer {tok}")) {
            headers.insert(reqwest::header::AUTHORIZATION, val);
        }
        builder = builder.default_headers(headers);
    }

    builder.build()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    /// Ways to obtain an HTTP client that bypass [`github_client`], and with it
    /// the token this module exists to attach.
    const CLIENT_CONSTRUCTORS: &[&str] = &[
        "Client::builder",
        "ClientBuilder::new",
        "blocking::get(",
        "reqwest::get(",
    ];

    fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(dir).expect("read src dir").flatten() {
            let path = entry.path();
            if path.is_dir() {
                rust_sources(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }

    /// A source that builds its own client runs unauthenticated, at GitHub's 60
    /// requests/hour limit — the exact failure this module exists to prevent.
    /// Enforced structurally because a green offline test run cannot see it:
    /// the symptom only appears mid-fetch, as HTTP 403, against the live API.
    #[test]
    fn no_source_builds_its_own_http_client() {
        let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let this_file = src.join("github.rs");
        let mut files = Vec::new();
        rust_sources(&src, &mut files);
        assert!(files.len() > 1, "found no sources under {}", src.display());

        let mut offenders = Vec::new();
        for file in files.iter().filter(|f| **f != this_file) {
            let text = fs::read_to_string(file).expect("read source");
            for (n, line) in text.lines().enumerate() {
                if let Some(found) = CLIENT_CONSTRUCTORS.iter().find(|c| line.contains(**c)) {
                    let name = file.file_name().unwrap_or_default().to_string_lossy();
                    offenders.push(format!("{name}:{}: {found}", n + 1));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "these build an HTTP client outside github.rs, so they run \
             unauthenticated at 60 req/hour — call github_client() instead:\n  {}",
            offenders.join("\n  ")
        );
    }
}
