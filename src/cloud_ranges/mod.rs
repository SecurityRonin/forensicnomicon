//! Cloud-provider attribution for IPv4 destinations.
//!
//! Enriches a network destination with the cloud provider that publishes its IP
//! range (AWS / Google Cloud / Cloudflare), or `None` when the address is in no
//! known provider range. For triage, a connection to an *unknown* destination is
//! a stronger signal than one to a well-known provider — most enterprise egress
//! lands on major clouds/CDNs, so "unknown destination" narrows the field.
//!
//! ## Data
//!
//! The ranges are a committed snapshot of the providers' publicly-published IPv4
//! feeds (see `generated.rs` header for the snapshot date), globally merged into
//! disjoint ascending intervals so [`classify_ipv4`] is a single binary search.
//! Regenerate with `tools/gen_cloud_ranges.py` — that command is the provenance.
//!
//! **Staleness caveat:** cloud ranges change frequently (weekly for AWS). A miss
//! (`None`) may mean a genuinely unknown host *or* a range added after the
//! snapshot; a positive attribution is reliable for the snapshot epoch. Refresh
//! before relying on absence.
//!
//! **Coverage gap:** Azure is omitted — its ServiceTags feed requires an
//! authenticated, periodically-changing download URL, so it is not a stable
//! open-data source. An Azure-hosted destination therefore classifies as `None`.
//!
//! Findings are observations: cloud attribution states *where* a destination is
//! hosted, not intent — both benign and malicious infrastructure use these clouds.

use std::net::Ipv4Addr;

mod generated;

/// A cloud/CDN provider that publishes the range containing a destination IP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum CloudProvider {
    /// Amazon Web Services.
    Aws,
    /// Google Cloud.
    Gcp,
    /// Cloudflare.
    Cloudflare,
}

impl CloudProvider {
    /// Stable lower-case token for output/serialization.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Aws => "aws",
            Self::Gcp => "gcp",
            Self::Cloudflare => "cloudflare",
        }
    }
}

/// Classify an IPv4 address to its cloud provider, if any range contains it.
///
/// Binary search over the disjoint ascending [`generated::CLOUD_RANGES`]:
/// find the last interval whose start is `<= ip`, then confirm `ip <= end`.
/// Panic-free.
#[must_use]
pub fn classify_ipv4(ip: Ipv4Addr) -> Option<CloudProvider> {
    let key = u32::from(ip);
    let ranges = generated::CLOUD_RANGES;
    // Last interval whose start is <= key (intervals are disjoint + ascending).
    let idx = ranges.partition_point(|(start, _, _)| *start <= key);
    if idx == 0 {
        return None;
    }
    let (start, end, provider) = ranges[idx - 1];
    if key >= start && key <= end {
        Some(provider)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn classify_ipv4_below_first_range_is_none() {
        use std::net::Ipv4Addr;
        // 0.0.0.0 sorts below every cloud range start -> partition_point == 0.
        assert_eq!(classify_ipv4(Ipv4Addr::UNSPECIFIED), None);
    }
    use super::*;

    // Sample addresses taken verbatim from the committed snapshot (the start of a
    // known interval for each provider), so they are guaranteed present.
    #[test]
    fn known_aws_address_classifies_as_aws() {
        assert_eq!(
            classify_ipv4(Ipv4Addr::new(1, 178, 1, 0)),
            Some(CloudProvider::Aws)
        );
    }

    #[test]
    fn known_gcp_address_classifies_as_gcp() {
        assert_eq!(
            classify_ipv4(Ipv4Addr::new(8, 34, 208, 0)),
            Some(CloudProvider::Gcp)
        );
    }

    #[test]
    fn known_cloudflare_address_classifies_as_cloudflare() {
        assert_eq!(
            classify_ipv4(Ipv4Addr::new(103, 21, 244, 0)),
            Some(CloudProvider::Cloudflare)
        );
    }

    #[test]
    fn private_address_is_unknown() {
        assert_eq!(classify_ipv4(Ipv4Addr::new(10, 0, 0, 1)), None);
    }

    #[test]
    fn ranges_are_disjoint_and_sorted() {
        // Guards the binary-search precondition the generator promises.
        let r = generated::CLOUD_RANGES;
        for w in r.windows(2) {
            assert!(w[0].0 <= w[0].1, "interval start must be <= end");
            assert!(w[0].1 < w[1].0, "intervals must be disjoint and ascending");
        }
    }

    #[test]
    fn as_str_tokens() {
        assert_eq!(CloudProvider::Aws.as_str(), "aws");
        assert_eq!(CloudProvider::Gcp.as_str(), "gcp");
        assert_eq!(CloudProvider::Cloudflare.as_str(), "cloudflare");
    }
}
