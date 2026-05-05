//! Compound multi-indicator scoring for zero-dep evidence fusion.

/// Accumulate a weighted indicator score.
///
/// Each element is `(hit: bool, weight: u8)`. Returns the sum of weights
/// for true indicators, clamped to 100.
#[must_use]
pub fn indicator_score(indicators: &[(bool, u8)]) -> u8 {
    let sum: u32 = indicators
        .iter()
        .filter(|(hit, _)| *hit)
        .map(|(_, w)| u32::from(*w))
        .sum();
    sum.min(100) as u8
}

/// Probabilistic confidence combination: `P(A∨B) = 1 − (1−A)(1−B)`.
///
/// Inputs and output are 0–100 (percent). Independent evidence.
#[must_use]
pub fn combine_confidence(c1: u8, c2: u8) -> u8 {
    // work in f32: convert percent → probability, combine, convert back
    let p1 = f32::from(c1) / 100.0;
    let p2 = f32::from(c2) / 100.0;
    let combined = 1.0 - (1.0 - p1) * (1.0 - p2);
    (combined * 100.0).round() as u8
}

/// Returns `true` if `score` meets or exceeds `threshold`.
#[must_use]
pub fn exceeds_threshold(score: u8, threshold: u8) -> bool {
    score >= threshold
}

/// Combine a slice of confidence values probabilistically.
///
/// Empty slice returns 0. Single element returns that element.
#[must_use]
pub fn combine_all_confidence(confidences: &[u8]) -> u8 {
    match confidences {
        [] => 0,
        [single] => *single,
        [first, rest @ ..] => rest.iter().fold(*first, |acc, &c| combine_confidence(acc, c)),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_indicators_scores_zero() {
        assert_eq!(indicator_score(&[]), 0);
    }

    #[test]
    fn single_true_indicator_scores_its_weight() {
        assert_eq!(indicator_score(&[(true, 40)]), 40);
    }

    #[test]
    fn single_false_indicator_scores_zero() {
        assert_eq!(indicator_score(&[(false, 40)]), 0);
    }

    #[test]
    fn multiple_true_indicators_sum_clamped_to_100() {
        // weights sum to 150 → clamped at 100
        let indicators = [(true, 50u8), (true, 50), (true, 50)];
        assert_eq!(indicator_score(&indicators), 100);
    }

    #[test]
    fn combine_confidence_independent_events() {
        // P(A∨B) = 1 − (1−0.5)(1−0.5) = 0.75 → 75
        assert_eq!(combine_confidence(50, 50), 75);
    }

    #[test]
    fn combine_confidence_zero_with_any() {
        // P(A∨B) = 1 − (1−0)(1−0.8) = 0.8 → 80
        assert_eq!(combine_confidence(0, 80), 80);
    }

    #[test]
    fn combine_confidence_full_certainty() {
        // P(A∨B) = 1 − (1−1)(1−0.5) = 1.0 → 100
        assert_eq!(combine_confidence(100, 50), 100);
    }

    #[test]
    fn exceeds_threshold_equal_returns_true() {
        assert!(exceeds_threshold(75, 75));
    }

    #[test]
    fn exceeds_threshold_below_returns_false() {
        assert!(!exceeds_threshold(74, 75));
    }

    #[test]
    fn combine_all_empty_returns_zero() {
        assert_eq!(combine_all_confidence(&[]), 0);
    }

    #[test]
    fn combine_all_single_returns_value() {
        assert_eq!(combine_all_confidence(&[60]), 60);
    }

    #[test]
    fn combine_all_multiple_probabilistic() {
        // combine(50, 50) = 75, combine(75, 50) = 87 (rounded)
        // 1 - (1-0.5)(1-0.5)(1-0.5) = 1 - 0.125 = 0.875 → 87 or 88
        let result = combine_all_confidence(&[50, 50, 50]);
        assert!(result == 87 || result == 88, "expected 87 or 88, got {result}");
    }
}
