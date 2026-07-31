//! Helpers shared by the source adapters.

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
