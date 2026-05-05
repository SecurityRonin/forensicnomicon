/// Fuzzy-substring search over a flattened text index.
///
/// Each entry has a pre-computed lowercase search string (all relevant fields
/// joined). Scoring: exact prefix match > substring match > no match.
/// Results are returned sorted by score descending.

#[derive(Debug, Clone)]
pub struct SearchEntry {
    /// The flattened, lowercased text to search against.
    pub index: String,
    /// Original display index into the source slice.
    pub source_idx: usize,
}

impl SearchEntry {
    pub fn new(index: impl Into<String>, source_idx: usize) -> Self {
        Self {
            index: index.into(),
            source_idx,
        }
    }
}

/// Score a query against a search entry.
/// Returns `None` if no match, `Some(score)` otherwise.
/// Higher score = better match.
pub fn score(query: &str, entry: &SearchEntry) -> Option<i32> {
    if query.is_empty() {
        return Some(0);
    }
    let q = query.to_ascii_lowercase();
    if entry.index.starts_with(&q) {
        Some(100)
    } else if entry.index.contains(&q) {
        Some(50)
    } else {
        None
    }
}

/// Filter and rank a list of entries against a query.
///
/// Returns a vec of `source_idx` values in score order (highest first).
/// When query is empty, returns all entries in original order.
pub fn filter(query: &str, entries: &[SearchEntry]) -> Vec<usize> {
    if query.is_empty() {
        return entries.iter().map(|e| e.source_idx).collect();
    }
    let mut scored: Vec<(i32, usize)> = entries
        .iter()
        .filter_map(|e| score(query, e).map(|s| (s, e.source_idx)))
        .collect();
    // stable sort: primary = score desc, secondary = original order (already stable)
    scored.sort_by(|a, b| b.0.cmp(&a.0));
    scored.into_iter().map(|(_, idx)| idx).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries() -> Vec<SearchEntry> {
        vec![
            SearchEntry::new("prefetch_file windows execution", 0),
            SearchEntry::new("run_key_hklm windows persistence", 1),
            SearchEntry::new("shimcache windows execution", 2),
            SearchEntry::new("prefetch_volume windows file", 3),
        ]
    }

    #[test]
    fn empty_query_returns_all_in_order() {
        let result = filter("", &entries());
        assert_eq!(result, vec![0, 1, 2, 3]);
    }

    #[test]
    fn query_filters_non_matching() {
        let result = filter("linux", &entries());
        assert!(result.is_empty());
    }

    #[test]
    fn query_returns_matching_entries() {
        let result = filter("prefetch", &entries());
        assert_eq!(result.len(), 2);
        assert!(result.contains(&0));
        assert!(result.contains(&3));
    }

    #[test]
    fn prefix_match_scores_higher_than_substring() {
        // "prefetch_file" starts with "prefetch_f" → score 100
        // "prefetch_volume" contains "prefetch_" → score 100 (also prefix match)
        // Let's use a query that only starts one entry
        let es = vec![
            SearchEntry::new("shimcache execution prefetch", 0), // contains
            SearchEntry::new("prefetch_file windows", 1),        // prefix
        ];
        let result = filter("prefetch", &es);
        // prefix match (idx 1) should come first
        assert_eq!(result[0], 1);
        assert_eq!(result[1], 0);
    }

    #[test]
    fn score_returns_none_for_no_match() {
        let e = SearchEntry::new("shimcache windows", 0);
        assert!(score("linux", &e).is_none());
    }

    #[test]
    fn score_returns_100_for_prefix_match() {
        let e = SearchEntry::new("prefetch_file windows", 0);
        assert_eq!(score("prefetch", &e), Some(100));
    }

    #[test]
    fn score_returns_50_for_substring_match() {
        let e = SearchEntry::new("windows prefetch execution", 0);
        assert_eq!(score("prefetch", &e), Some(50));
    }

    #[test]
    fn score_empty_query_returns_some_zero() {
        let e = SearchEntry::new("anything", 0);
        assert_eq!(score("", &e), Some(0));
    }

    #[test]
    fn filter_is_case_insensitive() {
        let es = vec![SearchEntry::new("prefetch_file windows", 0)];
        assert!(!filter("PREFETCH", &es).is_empty());
    }

    #[test]
    fn filter_single_char_query() {
        let result = filter("p", &entries());
        // "prefetch_file", "run_key_hklm" (no p), "shimcache" (no p), "prefetch_volume"
        assert!(result.contains(&0));
        assert!(result.contains(&3));
        assert!(!result.contains(&2)); // shimcache has no 'p'
    }
}
