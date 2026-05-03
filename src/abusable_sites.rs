//! Cloud services, CDNs, and online platforms systematically abused by
//! attackers for phishing, C2, payload delivery, and data exfiltration.
//!
//! # Why BlockingRisk is the key dimension
//!
//! Attackers do not choose sites like `raw.githubusercontent.com` or
//! `*.amazonaws.com` by accident. They choose them precisely because these
//! domains carry a [`BlockingRisk`] of `Critical` — defenders cannot block
//! them without also breaking their own development pipelines, CI/CD systems,
//! and cloud-deployed workloads. This is the same logic behind LOL/LOFL binary
//! abuse: the tool's legitimate ubiquity is the defence evasion mechanism.
//!
//! `BlockingRisk` is therefore the primary triage dimension. A domain with
//! `BlockingRisk::Low` (e.g. `pastebin.com`) should be blocked at the proxy
//! and DNS layers immediately. A domain with `BlockingRisk::Critical` (e.g.
//! `*.amazonaws.com`) requires a detection-and-alerting strategy instead.
//! Use [`sites_above_risk`] to find domains in each risk tier.
//!
//! # Upstream sources
//!
//! | Upstream | Source |
//! |----------|---------|
//! | LOTS Project (Living Off Trusted Sites) | <https://lots-project.com/> · GitHub: <https://github.com/SigmaHQ/lots-project> · 175+ entries as of 2025-Q4 |
//! | URLhaus / abuse.ch | <https://urlhaus.abuse.ch/> · active malware distribution feed |
//! | MISP taxonomies | <https://github.com/MISP/misp-taxonomies> · `circl:threat-type` / `enisa:threats` alignment |
//!
//! # ATT&CK coverage
//!
//! - T1102 — Web Service (C2 over legitimate hosted services):
//!   <https://attack.mitre.org/techniques/T1102/>
//! - T1567 — Exfiltration Over Web Service:
//!   <https://attack.mitre.org/techniques/T1567/>
//! - T1105 — Ingress Tool Transfer (payload delivery via trusted domains):
//!   <https://attack.mitre.org/techniques/T1105/>
//! - T1566.002 — Phishing: Spearphishing Link (abuse of trusted sharing URLs):
//!   <https://attack.mitre.org/techniques/T1566/002/>

//! ## Design
//!
//! This module provides a **static, zero-allocation** lookup table of domains
//! that are legitimately trusted by enterprises but routinely weaponised by
//! threat actors.  The key insight — borrowed from web proxy vendor taxonomy —
//! is that the *legitimate category* of a site determines *why* it is hard to
//! block, while the *abuse tags* describe what attackers actually do with it.
//!
//! The `blocking_risk` field encodes the organisational cost of blocking the
//! domain outright.  High-risk sites (GitHub, AWS) are the most attractive to
//! attackers precisely because defenders cannot block them without crippling
//! business operations.
//!
//! ## Sources
//!
//! - [LOTS Project](https://lots-project.com/) — Living Off Trusted Sites; 175+ curated domains
//! - [URLhaus / abuse.ch](https://urlhaus.abuse.ch/) — active malware distribution URLs
//! - [MITRE ATT&CK](https://attack.mitre.org/techniques/T1102/) — T1102, T1567, T1105, T1566.002

// ---------------------------------------------------------------------------
// Abuse tag bitfield — composable via bitwise OR
// ---------------------------------------------------------------------------

/// The site is used to host or deliver phishing pages or credential harvesters.
pub const TAG_PHISHING: u8 = 0x01;

/// The site is used as a C2 (command-and-control) channel or beacon endpoint.
/// Maps to MITRE ATT&CK T1102 — Web Service.
pub const TAG_C2: u8 = 0x02;

/// The site is used to download malware payloads or staged implants.
/// Maps to MITRE ATT&CK T1105 — Ingress Tool Transfer.
pub const TAG_DOWNLOAD: u8 = 0x04;

/// The site is used to exfiltrate data out of the victim environment.
/// Maps to MITRE ATT&CK T1567 — Exfiltration Over Web Service.
pub const TAG_EXFIL: u8 = 0x08;

/// The site hosts exploit kits or is used in drive-by download attacks.
pub const TAG_EXPLOIT: u8 = 0x10;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// Functional category describing the site's *legitimate* primary use.
///
/// This is the reason the domain is trusted and therefore hard to block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "snake_case")
)]
pub enum SiteCategory {
    /// Source-code hosting and version control (GitHub, GitLab, Bitbucket).
    CodeRepository,
    /// Cloud object storage (S3, Azure Blob, GCS, Mega).
    CloudStorage,
    /// Content delivery network (CloudFront, Cloudflare, Fastly).
    Cdn,
    /// Real-time messaging platform (Discord, Slack, Telegram).
    Messaging,
    /// Paste / snippet service (Pastebin, paste.ee, Hastebin).
    PasteService,
    /// General-purpose cloud hosting / PaaS (Heroku, Replit, Glitch).
    CloudHosting,
    /// Productivity / document collaboration (Google Docs, OneDrive, Notion).
    Collaboration,
    /// URL shortener — obscures true destination.
    UrlShortener,
    /// DNS / certificate service — abused for domain fronting or ACME staging.
    DnsService,
    /// Other / not categorised.
    Other,
}

/// Estimated organisational cost of blocking the domain outright.
///
/// Attackers deliberately choose high-risk sites because defenders cannot
/// block them without crippling legitimate business workflows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "snake_case")
)]
pub enum BlockingRisk {
    /// Blocking causes no meaningful disruption; domain has few legitimate uses.
    Low,
    /// Blocking affects some workflows but is manageable with exceptions.
    Medium,
    /// Blocking causes significant disruption to development / business tools.
    High,
    /// Blocking would break critical infrastructure or universal tooling.
    Critical,
}

// ---------------------------------------------------------------------------
// AbusableSite record
// ---------------------------------------------------------------------------

/// A domain (or wildcard pattern) known to be abused for attacks, together
/// with metadata explaining *why* it is hard to block and *how* it is misused.
///
/// # Wildcard patterns
///
/// `domain` may be a wildcard such as `"*.amazonaws.com"` or an exact
/// hostname such as `"raw.githubusercontent.com"`.  Matching logic is left
/// to the caller; [`is_abusable_site`] performs exact case-insensitive lookup
/// while [`abusable_site_info`] returns the full record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct AbusableSite {
    /// Bare domain or wildcard pattern (no scheme, no trailing slash).
    pub domain: &'static str,
    /// Human-readable name of the cloud / CDN / platform provider.
    pub provider: &'static str,
    /// Legitimate functional category — explains why blocking is costly.
    pub legitimate_category: SiteCategory,
    /// Bitfield of `TAG_*` constants describing observed abuse types.
    pub abuse_tags: u8,
    /// Organisational cost of a blanket block on this domain.
    pub blocking_risk: BlockingRisk,
    /// Relevant MITRE ATT&CK technique IDs (e.g. `"T1102"`, `"T1567.002"`).
    pub mitre_techniques: &'static [&'static str],
}

impl AbusableSite {
    /// Returns `true` if this site is used for C2 (TAG_C2 set).
    #[inline]
    pub fn is_c2(&self) -> bool {
        self.abuse_tags & TAG_C2 != 0
    }

    /// Returns `true` if this site is used for phishing (TAG_PHISHING set).
    #[inline]
    pub fn is_phishing(&self) -> bool {
        self.abuse_tags & TAG_PHISHING != 0
    }

    /// Returns `true` if this site is used for payload download (TAG_DOWNLOAD set).
    #[inline]
    pub fn is_download(&self) -> bool {
        self.abuse_tags & TAG_DOWNLOAD != 0
    }

    /// Returns `true` if this site is used for exfiltration (TAG_EXFIL set).
    #[inline]
    pub fn is_exfil(&self) -> bool {
        self.abuse_tags & TAG_EXFIL != 0
    }
}

// ---------------------------------------------------------------------------
// Static catalog — LOTS Project data
// ---------------------------------------------------------------------------

/// Static catalog of domains abused for phishing, C2, download, and
/// exfiltration.  Sourced from the LOTS Project and abuse.ch URLhaus.
///
/// Wildcard entries (e.g. `"*.amazonaws.com"`) denote entire subdomains
/// where the abuse pattern applies across all tenants.
pub const ABUSABLE_SITES: &[AbusableSite] = &[
    // ╔══════════════════════════════════════════════════════════════════════╗
    // ║  CRITICAL  — cannot block without breaking core business operations  ║
    // ║  Strategy: detect + alert; allowlist by IP range or authenticated    ║
    // ║  user-agent where possible. Never block outright.                    ║
    // ╚══════════════════════════════════════════════════════════════════════╝

    // ── Code repositories (Critical) ───────────────────────────────────────
    AbusableSite {
        domain: "raw.githubusercontent.com",
        provider: "GitHub",
        legitimate_category: SiteCategory::CodeRepository,
        abuse_tags: TAG_C2 | TAG_DOWNLOAD | TAG_PHISHING,
        blocking_risk: BlockingRisk::Critical,
        mitre_techniques: &["T1102", "T1105", "T1583.001"],
    },
    AbusableSite {
        domain: "github.com",
        provider: "GitHub",
        legitimate_category: SiteCategory::CodeRepository,
        abuse_tags: TAG_DOWNLOAD | TAG_PHISHING,
        blocking_risk: BlockingRisk::Critical,
        mitre_techniques: &["T1105", "T1583.001"],
    },

    // ── Cloud storage (Critical) ───────────────────────────────────────────
    AbusableSite {
        domain: "*.amazonaws.com",
        provider: "Amazon Web Services",
        legitimate_category: SiteCategory::CloudStorage,
        abuse_tags: TAG_PHISHING | TAG_DOWNLOAD | TAG_EXFIL | TAG_C2,
        blocking_risk: BlockingRisk::Critical,
        mitre_techniques: &["T1102", "T1105", "T1567.002", "T1583.006"],
    },
    AbusableSite {
        domain: "*.blob.core.windows.net",
        provider: "Microsoft Azure",
        legitimate_category: SiteCategory::CloudStorage,
        abuse_tags: TAG_PHISHING | TAG_DOWNLOAD | TAG_EXFIL,
        blocking_risk: BlockingRisk::Critical,
        mitre_techniques: &["T1105", "T1567.002"],
    },
    AbusableSite {
        domain: "*.azurewebsites.net",
        provider: "Microsoft Azure",
        legitimate_category: SiteCategory::CloudHosting,
        abuse_tags: TAG_PHISHING | TAG_DOWNLOAD | TAG_EXFIL | TAG_C2,
        blocking_risk: BlockingRisk::Critical,
        mitre_techniques: &["T1102", "T1105", "T1567.002"],
    },
    AbusableSite {
        domain: "drive.google.com",
        provider: "Google",
        legitimate_category: SiteCategory::CloudStorage,
        abuse_tags: TAG_PHISHING | TAG_DOWNLOAD | TAG_EXFIL,
        blocking_risk: BlockingRisk::Critical,
        mitre_techniques: &["T1105", "T1567.002"],
    },
    AbusableSite {
        domain: "docs.google.com",
        provider: "Google",
        legitimate_category: SiteCategory::Collaboration,
        abuse_tags: TAG_PHISHING | TAG_C2,
        blocking_risk: BlockingRisk::Critical,
        mitre_techniques: &["T1102", "T1566.002"],
    },
    AbusableSite {
        domain: "storage.googleapis.com",
        provider: "Google Cloud",
        legitimate_category: SiteCategory::CloudStorage,
        abuse_tags: TAG_PHISHING | TAG_DOWNLOAD | TAG_EXFIL | TAG_C2,
        blocking_risk: BlockingRisk::Critical,
        mitre_techniques: &["T1102", "T1105", "T1567.002"],
    },

    // ── CDN (Critical) ─────────────────────────────────────────────────────
    AbusableSite {
        domain: "*.cloudfront.net",
        provider: "Amazon CloudFront",
        legitimate_category: SiteCategory::Cdn,
        abuse_tags: TAG_PHISHING | TAG_C2 | TAG_DOWNLOAD,
        blocking_risk: BlockingRisk::Critical,
        mitre_techniques: &["T1102", "T1105"],
    },

    // ── Collaboration (Critical) ───────────────────────────────────────────
    AbusableSite {
        domain: "sharepoint.com",
        provider: "Microsoft",
        legitimate_category: SiteCategory::Collaboration,
        abuse_tags: TAG_PHISHING | TAG_DOWNLOAD | TAG_EXFIL,
        blocking_risk: BlockingRisk::Critical,
        mitre_techniques: &["T1105", "T1566.002", "T1567.002"],
    },

    // ╔══════════════════════════════════════════════════════════════════════╗
    // ║  HIGH  — blocking causes significant friction; prefer proxy          ║
    // ║  inspection, DLP rules, and anomaly alerting over outright blocks.   ║
    // ╚══════════════════════════════════════════════════════════════════════╝

    // ── Code repositories (High) ───────────────────────────────────────────
    AbusableSite {
        domain: "*.github.io",
        provider: "GitHub",
        legitimate_category: SiteCategory::CodeRepository,
        abuse_tags: TAG_PHISHING | TAG_C2,
        blocking_risk: BlockingRisk::High,
        mitre_techniques: &["T1102", "T1583.001"],
    },
    AbusableSite {
        domain: "gitlab.com",
        provider: "GitLab",
        legitimate_category: SiteCategory::CodeRepository,
        abuse_tags: TAG_DOWNLOAD | TAG_PHISHING | TAG_C2,
        blocking_risk: BlockingRisk::High,
        mitre_techniques: &["T1102", "T1105", "T1583.001"],
    },
    AbusableSite {
        domain: "bitbucket.org",
        provider: "Atlassian",
        legitimate_category: SiteCategory::CodeRepository,
        abuse_tags: TAG_DOWNLOAD | TAG_PHISHING,
        blocking_risk: BlockingRisk::High,
        mitre_techniques: &["T1105", "T1583.001"],
    },
    AbusableSite {
        domain: "gist.github.com",
        provider: "GitHub",
        legitimate_category: SiteCategory::PasteService,
        abuse_tags: TAG_C2 | TAG_DOWNLOAD,
        blocking_risk: BlockingRisk::High,
        mitre_techniques: &["T1102", "T1105"],
    },

    // ── Cloud storage (High) ───────────────────────────────────────────────
    AbusableSite {
        domain: "1drv.ms",
        provider: "Microsoft OneDrive",
        legitimate_category: SiteCategory::CloudStorage,
        abuse_tags: TAG_PHISHING,
        blocking_risk: BlockingRisk::High,
        mitre_techniques: &["T1566.002"],
    },
    AbusableSite {
        domain: "dropbox.com",
        provider: "Dropbox",
        legitimate_category: SiteCategory::CloudStorage,
        abuse_tags: TAG_PHISHING | TAG_DOWNLOAD | TAG_EXFIL | TAG_C2,
        blocking_risk: BlockingRisk::High,
        mitre_techniques: &["T1102", "T1105", "T1567.002"],
    },
    AbusableSite {
        domain: "firebasestorage.googleapis.com",
        provider: "Google Firebase",
        legitimate_category: SiteCategory::CloudStorage,
        abuse_tags: TAG_PHISHING | TAG_EXFIL | TAG_C2 | TAG_DOWNLOAD,
        blocking_risk: BlockingRisk::High,
        mitre_techniques: &["T1102", "T1105", "T1567.002"],
    },

    // ── Cloud hosting (High) ───────────────────────────────────────────────
    AbusableSite {
        domain: "*.workers.dev",
        provider: "Cloudflare Workers",
        legitimate_category: SiteCategory::CloudHosting,
        abuse_tags: TAG_PHISHING | TAG_C2 | TAG_DOWNLOAD,
        blocking_risk: BlockingRisk::High,
        mitre_techniques: &["T1102", "T1105", "T1090.002"],
    },
    AbusableSite {
        domain: "*.pages.dev",
        provider: "Cloudflare Pages",
        legitimate_category: SiteCategory::CloudHosting,
        abuse_tags: TAG_PHISHING | TAG_C2,
        blocking_risk: BlockingRisk::High,
        mitre_techniques: &["T1102"],
    },
    AbusableSite {
        domain: "*.web.app",
        provider: "Google Firebase",
        legitimate_category: SiteCategory::CloudHosting,
        abuse_tags: TAG_PHISHING | TAG_C2,
        blocking_risk: BlockingRisk::High,
        mitre_techniques: &["T1102"],
    },

    // ── Messaging (High) ───────────────────────────────────────────────────
    AbusableSite {
        domain: "slack.com",
        provider: "Slack",
        legitimate_category: SiteCategory::Messaging,
        abuse_tags: TAG_C2,
        blocking_risk: BlockingRisk::High,
        mitre_techniques: &["T1102"],
    },

    // ── Collaboration (High) ───────────────────────────────────────────────
    AbusableSite {
        domain: "notion.so",
        provider: "Notion",
        legitimate_category: SiteCategory::Collaboration,
        abuse_tags: TAG_PHISHING | TAG_C2,
        blocking_risk: BlockingRisk::High,
        mitre_techniques: &["T1102"],
    },

    // ╔══════════════════════════════════════════════════════════════════════╗
    // ║  MEDIUM  — blocking is feasible with an exception process.           ║
    // ║  Evaluate per-org tolerance; block at DNS/proxy where possible.      ║
    // ╚══════════════════════════════════════════════════════════════════════╝

    // ── Cloud storage / hosting (Medium) ──────────────────────────────────
    AbusableSite {
        domain: "mega.nz",
        provider: "Mega Limited",
        legitimate_category: SiteCategory::CloudStorage,
        abuse_tags: TAG_PHISHING | TAG_DOWNLOAD | TAG_EXFIL,
        blocking_risk: BlockingRisk::Medium,
        mitre_techniques: &["T1105", "T1567.002"],
    },
    AbusableSite {
        domain: "*.herokuapp.com",
        provider: "Heroku",
        legitimate_category: SiteCategory::CloudHosting,
        abuse_tags: TAG_PHISHING | TAG_DOWNLOAD | TAG_EXFIL | TAG_C2,
        blocking_risk: BlockingRisk::Medium,
        mitre_techniques: &["T1102", "T1105", "T1567.002"],
    },
    AbusableSite {
        domain: "*.replit.app",
        provider: "Replit",
        legitimate_category: SiteCategory::CloudHosting,
        abuse_tags: TAG_PHISHING | TAG_C2 | TAG_DOWNLOAD,
        blocking_risk: BlockingRisk::Medium,
        mitre_techniques: &["T1102", "T1105"],
    },

    // ── Messaging (Medium) ─────────────────────────────────────────────────
    AbusableSite {
        domain: "discord.com",
        provider: "Discord",
        legitimate_category: SiteCategory::Messaging,
        abuse_tags: TAG_C2 | TAG_EXFIL | TAG_DOWNLOAD,
        blocking_risk: BlockingRisk::Medium,
        mitre_techniques: &["T1102", "T1567.002"],
    },
    AbusableSite {
        domain: "cdn.discordapp.com",
        provider: "Discord",
        legitimate_category: SiteCategory::Cdn,
        abuse_tags: TAG_DOWNLOAD | TAG_C2,
        blocking_risk: BlockingRisk::Medium,
        mitre_techniques: &["T1102", "T1105"],
    },
    AbusableSite {
        domain: "api.telegram.org",
        provider: "Telegram",
        legitimate_category: SiteCategory::Messaging,
        abuse_tags: TAG_C2 | TAG_EXFIL,
        blocking_risk: BlockingRisk::Medium,
        mitre_techniques: &["T1102", "T1567"],
    },

    // ── Collaboration (Medium) ─────────────────────────────────────────────
    AbusableSite {
        domain: "trello.com",
        provider: "Atlassian",
        legitimate_category: SiteCategory::Collaboration,
        abuse_tags: TAG_C2 | TAG_PHISHING,
        blocking_risk: BlockingRisk::Medium,
        mitre_techniques: &["T1102"],
    },

    // ── URL shorteners (Medium) ────────────────────────────────────────────
    AbusableSite {
        domain: "t.co",
        provider: "Twitter/X",
        legitimate_category: SiteCategory::UrlShortener,
        abuse_tags: TAG_PHISHING,
        blocking_risk: BlockingRisk::Medium,
        mitre_techniques: &["T1566.002"],
    },

    // ╔══════════════════════════════════════════════════════════════════════╗
    // ║  LOW  — block at DNS and proxy layer; minimal legitimate enterprise  ║
    // ║  use. Exception requests are a yellow flag worth investigating.      ║
    // ╚══════════════════════════════════════════════════════════════════════╝

    // ── Paste services (Low) ───────────────────────────────────────────────
    AbusableSite {
        domain: "pastebin.com",
        provider: "Pastebin",
        legitimate_category: SiteCategory::PasteService,
        abuse_tags: TAG_C2 | TAG_DOWNLOAD | TAG_PHISHING,
        blocking_risk: BlockingRisk::Low,
        mitre_techniques: &["T1102", "T1105"],
    },
    AbusableSite {
        domain: "paste.ee",
        provider: "Paste.ee",
        legitimate_category: SiteCategory::PasteService,
        abuse_tags: TAG_C2 | TAG_DOWNLOAD,
        blocking_risk: BlockingRisk::Low,
        mitre_techniques: &["T1102", "T1105"],
    },
    AbusableSite {
        domain: "hastebin.com",
        provider: "Hastebin",
        legitimate_category: SiteCategory::PasteService,
        abuse_tags: TAG_C2 | TAG_DOWNLOAD,
        blocking_risk: BlockingRisk::Low,
        mitre_techniques: &["T1102", "T1105"],
    },

    // ── URL shorteners (Low) ───────────────────────────────────────────────
    AbusableSite {
        domain: "bit.ly",
        provider: "Bitly",
        legitimate_category: SiteCategory::UrlShortener,
        abuse_tags: TAG_PHISHING | TAG_DOWNLOAD,
        blocking_risk: BlockingRisk::Low,
        mitre_techniques: &["T1566.002"],
    },
    AbusableSite {
        domain: "tinyurl.com",
        provider: "TinyURL",
        legitimate_category: SiteCategory::UrlShortener,
        abuse_tags: TAG_PHISHING | TAG_DOWNLOAD,
        blocking_risk: BlockingRisk::Low,
        mitre_techniques: &["T1566.002"],
    },

    // ╔══════════════════════════════════════════════════════════════════════╗
    // ║  LOTS Project expansion — sourced from https://lots-project.com/     ║
    // ║  175 known entries; gaps against base catalog promoted here.         ║
    // ╚══════════════════════════════════════════════════════════════════════╝

    // ── Microsoft Graph API / OneDrive (Critical) ──────────────────────────
    // Source: https://lots-project.com/
    // ATT&CK: T1071.001 (C2 via HTTPS), T1530 (data from cloud storage)
    AbusableSite {
        domain: "graph.microsoft.com",
        provider: "Microsoft",
        legitimate_category: SiteCategory::CloudStorage,
        abuse_tags: TAG_C2 | TAG_EXFIL | TAG_DOWNLOAD,
        blocking_risk: BlockingRisk::Critical,
        mitre_techniques: &["T1071.001", "T1530", "T1567.002"],
    },
    AbusableSite {
        domain: "onedrive.live.com",
        provider: "Microsoft OneDrive",
        legitimate_category: SiteCategory::CloudStorage,
        abuse_tags: TAG_PHISHING | TAG_DOWNLOAD | TAG_EXFIL,
        blocking_risk: BlockingRisk::Critical,
        mitre_techniques: &["T1105", "T1567.002", "T1566.002"],
    },

    // ── Cloudflare Quick Tunnels (Critical) ───────────────────────────────
    // T1090.003 — Multi-hop Proxy; zero-config C2 tunnels through Cloudflare
    AbusableSite {
        domain: "*.trycloudflare.com",
        provider: "Cloudflare",
        legitimate_category: SiteCategory::CloudHosting,
        abuse_tags: TAG_C2 | TAG_DOWNLOAD | TAG_PHISHING,
        blocking_risk: BlockingRisk::Critical,
        mitre_techniques: &["T1090.003", "T1102", "T1105"],
    },

    // ── Netlify (Critical CDN/hosting) ────────────────────────────────────
    // T1102/T1583.006 — phishing pages and payload CDN delivery
    AbusableSite {
        domain: "*.netlify.app",
        provider: "Netlify",
        legitimate_category: SiteCategory::CloudHosting,
        abuse_tags: TAG_PHISHING | TAG_C2 | TAG_DOWNLOAD,
        blocking_risk: BlockingRisk::Critical,
        mitre_techniques: &["T1102", "T1105", "T1583.006"],
    },

    // ── ngrok (High) ──────────────────────────────────────────────────────
    // T1090.003 — NAT-piercing tunnels; dominant Red Team and malware C2 relay
    AbusableSite {
        domain: "*.ngrok.io",
        provider: "ngrok",
        legitimate_category: SiteCategory::Other,
        abuse_tags: TAG_C2 | TAG_DOWNLOAD,
        blocking_risk: BlockingRisk::High,
        mitre_techniques: &["T1090.003", "T1102"],
    },
    AbusableSite {
        domain: "*.ngrok-free.app",
        provider: "ngrok",
        legitimate_category: SiteCategory::Other,
        abuse_tags: TAG_C2 | TAG_DOWNLOAD,
        blocking_risk: BlockingRisk::High,
        mitre_techniques: &["T1090.003", "T1102"],
    },

    // ── Box (High) ────────────────────────────────────────────────────────
    // T1567.002 — Exfiltration to Cloud Storage
    AbusableSite {
        domain: "*.box.com",
        provider: "Box",
        legitimate_category: SiteCategory::CloudStorage,
        abuse_tags: TAG_PHISHING | TAG_EXFIL | TAG_DOWNLOAD,
        blocking_risk: BlockingRisk::High,
        mitre_techniques: &["T1567.002", "T1105", "T1566.002"],
    },

    // ── Gitee (High) ──────────────────────────────────────────────────────
    // T1102 — dead-drop resolver; used by APT groups (Lazarus, APT41) as C2
    AbusableSite {
        domain: "gitee.com",
        provider: "Gitee",
        legitimate_category: SiteCategory::CodeRepository,
        abuse_tags: TAG_C2 | TAG_DOWNLOAD,
        blocking_risk: BlockingRisk::High,
        mitre_techniques: &["T1102", "T1105", "T1583.001"],
    },

    // ── Anonymous file hosts (High) ───────────────────────────────────────
    // T1105 — Ingress Tool Transfer; widely seen in commodity malware delivery
    AbusableSite {
        domain: "transfer.sh",
        provider: "transfer.sh",
        legitimate_category: SiteCategory::CloudStorage,
        abuse_tags: TAG_DOWNLOAD | TAG_EXFIL,
        blocking_risk: BlockingRisk::High,
        mitre_techniques: &["T1105", "T1567.002"],
    },
    AbusableSite {
        domain: "file.io",
        provider: "file.io",
        legitimate_category: SiteCategory::CloudStorage,
        abuse_tags: TAG_DOWNLOAD | TAG_EXFIL,
        blocking_risk: BlockingRisk::High,
        mitre_techniques: &["T1105", "T1567.002"],
    },
    AbusableSite {
        domain: "4shared.com",
        provider: "4shared",
        legitimate_category: SiteCategory::CloudStorage,
        abuse_tags: TAG_DOWNLOAD | TAG_PHISHING,
        blocking_risk: BlockingRisk::High,
        mitre_techniques: &["T1105", "T1566.002"],
    },
    AbusableSite {
        domain: "mediafire.com",
        provider: "MediaFire",
        legitimate_category: SiteCategory::CloudStorage,
        abuse_tags: TAG_DOWNLOAD | TAG_PHISHING,
        blocking_risk: BlockingRisk::High,
        mitre_techniques: &["T1105", "T1566.002"],
    },

    // ── Webhook / serverless relay (Medium) ───────────────────────────────
    // T1041/T1071 — exfil via webhook; C2 relay through legitimate platforms
    AbusableSite {
        domain: "webhook.site",
        provider: "webhook.site",
        legitimate_category: SiteCategory::Other,
        abuse_tags: TAG_C2 | TAG_EXFIL,
        blocking_risk: BlockingRisk::Medium,
        mitre_techniques: &["T1041", "T1071.001"],
    },
    AbusableSite {
        domain: "*.pipedream.net",
        provider: "Pipedream",
        legitimate_category: SiteCategory::Other,
        abuse_tags: TAG_C2 | TAG_EXFIL,
        blocking_risk: BlockingRisk::Medium,
        mitre_techniques: &["T1041", "T1102"],
    },

    // ── IP geolocation / victim-filter APIs (Medium) ──────────────────────
    // T1016/T1590 — network discovery; used in malware check-in/geo-filter
    AbusableSite {
        domain: "ipinfo.io",
        provider: "ipinfo.io",
        legitimate_category: SiteCategory::Other,
        abuse_tags: TAG_C2,
        blocking_risk: BlockingRisk::Medium,
        mitre_techniques: &["T1016", "T1590.005"],
    },
    AbusableSite {
        domain: "api.ipify.org",
        provider: "ipify",
        legitimate_category: SiteCategory::Other,
        abuse_tags: TAG_C2,
        blocking_risk: BlockingRisk::Medium,
        mitre_techniques: &["T1016"],
    },
    AbusableSite {
        domain: "checkip.amazonaws.com",
        provider: "Amazon Web Services",
        legitimate_category: SiteCategory::Other,
        abuse_tags: TAG_C2,
        blocking_risk: BlockingRisk::Medium,
        mitre_techniques: &["T1016"],
    },
];

// ---------------------------------------------------------------------------
// Query functions
// ---------------------------------------------------------------------------

/// Returns `true` if `domain` exactly matches a known abusable site
/// (case-insensitive, no wildcard expansion).
///
/// For wildcard entries like `"*.amazonaws.com"`, this function will NOT match
/// `"evil.amazonaws.com"` — use [`abusable_site_info`] and inspect the record
/// for wildcard patterns in your caller.
pub fn is_abusable_site(domain: &str) -> bool {
    let lower = domain.to_ascii_lowercase();
    ABUSABLE_SITES
        .iter()
        .any(|s| s.domain.to_ascii_lowercase() == lower)
}

/// Returns the [`AbusableSite`] record for `domain` if it is a known abusable
/// site (exact, case-insensitive match), or `None` otherwise.
pub fn abusable_site_info(domain: &str) -> Option<&'static AbusableSite> {
    let lower = domain.to_ascii_lowercase();
    ABUSABLE_SITES
        .iter()
        .find(|s| s.domain.to_ascii_lowercase() == lower)
}

/// Returns an iterator over all abusable sites tagged with the given `tag`
/// (one of the `TAG_*` constants).
pub fn sites_with_tag(tag: u8) -> impl Iterator<Item = &'static AbusableSite> {
    ABUSABLE_SITES.iter().filter(move |s| s.abuse_tags & tag != 0)
}

/// Returns an iterator over all abusable sites at or above the given
/// `minimum_risk` threshold.
pub fn sites_above_risk(minimum_risk: BlockingRisk) -> impl Iterator<Item = &'static AbusableSite> {
    ABUSABLE_SITES
        .iter()
        .filter(move |s| s.blocking_risk >= minimum_risk)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abusable_sites_is_nonempty() {
        assert!(!ABUSABLE_SITES.is_empty());
    }

    #[test]
    fn contains_github_raw() {
        assert!(ABUSABLE_SITES
            .iter()
            .any(|s| s.domain == "raw.githubusercontent.com"));
    }

    #[test]
    fn contains_telegram_api() {
        assert!(ABUSABLE_SITES
            .iter()
            .any(|s| s.domain == "api.telegram.org"));
    }

    #[test]
    fn contains_pastebin() {
        assert!(ABUSABLE_SITES
            .iter()
            .any(|s| s.domain == "pastebin.com"));
    }

    #[test]
    fn is_abusable_site_detects_github_raw() {
        assert!(is_abusable_site("raw.githubusercontent.com"));
    }

    #[test]
    fn is_abusable_site_case_insensitive() {
        assert!(is_abusable_site("RAW.GITHUBUSERCONTENT.COM"));
    }

    #[test]
    fn is_abusable_site_rejects_unknown() {
        assert!(!is_abusable_site("example.com"));
    }

    #[test]
    fn empty_string_not_abusable() {
        assert!(!is_abusable_site(""));
    }

    #[test]
    fn abusable_site_info_returns_record() {
        let info = abusable_site_info("raw.githubusercontent.com").unwrap();
        assert_eq!(info.provider, "GitHub");
        assert_eq!(info.legitimate_category, SiteCategory::CodeRepository);
        assert_eq!(info.blocking_risk, BlockingRisk::Critical);
        assert!(info.is_c2());
        assert!(info.is_download());
    }

    #[test]
    fn abusable_site_info_returns_none_for_unknown() {
        assert!(abusable_site_info("totally-unknown.example").is_none());
    }

    #[test]
    fn sites_with_tag_c2_nonempty() {
        let c2_sites: Vec<_> = sites_with_tag(TAG_C2).collect();
        assert!(!c2_sites.is_empty());
    }

    #[test]
    fn sites_with_tag_c2_includes_telegram() {
        assert!(sites_with_tag(TAG_C2).any(|s| s.domain == "api.telegram.org"));
    }

    #[test]
    fn sites_with_tag_download_includes_github() {
        assert!(sites_with_tag(TAG_DOWNLOAD)
            .any(|s| s.domain == "raw.githubusercontent.com"));
    }

    #[test]
    fn sites_above_risk_critical_nonempty() {
        let critical: Vec<_> = sites_above_risk(BlockingRisk::Critical).collect();
        assert!(!critical.is_empty());
    }

    #[test]
    fn sites_above_risk_critical_includes_aws() {
        assert!(sites_above_risk(BlockingRisk::Critical)
            .any(|s| s.domain == "*.amazonaws.com"));
    }

    #[test]
    fn github_raw_has_mitre_techniques() {
        let info = abusable_site_info("raw.githubusercontent.com").unwrap();
        assert!(info.mitre_techniques.contains(&"T1102"));
    }

    #[test]
    fn pastebin_is_low_blocking_risk() {
        let info = abusable_site_info("pastebin.com").unwrap();
        assert_eq!(info.blocking_risk, BlockingRisk::Low);
    }

    #[test]
    fn discord_cdn_is_download() {
        let info = abusable_site_info("cdn.discordapp.com").unwrap();
        assert!(info.is_download());
    }

    #[test]
    fn all_sites_have_at_least_one_mitre_technique() {
        for site in ABUSABLE_SITES {
            assert!(
                !site.mitre_techniques.is_empty(),
                "site {} has no MITRE techniques",
                site.domain
            );
        }
    }

    #[test]
    fn all_sites_have_nonzero_abuse_tags() {
        for site in ABUSABLE_SITES {
            assert!(
                site.abuse_tags != 0,
                "site {} has no abuse tags",
                site.domain
            );
        }
    }
}

#[cfg(all(test, feature = "serde"))]
mod serde_tests {
    use super::*;

    #[test]
    fn site_category_serializes_to_snake_case_string() {
        let json = serde_json::to_string(&SiteCategory::CodeRepository).unwrap();
        assert_eq!(json, r#""code_repository""#);
    }

    #[test]
    fn blocking_risk_serializes_to_snake_case_string() {
        let json = serde_json::to_string(&BlockingRisk::Critical).unwrap();
        assert_eq!(json, r#""critical""#);
    }

    #[test]
    fn blocking_risk_all_variants_round_trip() {
        for risk in [
            BlockingRisk::Low,
            BlockingRisk::Medium,
            BlockingRisk::High,
            BlockingRisk::Critical,
        ] {
            let json = serde_json::to_string(&risk).unwrap();
            let decoded: BlockingRisk = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, risk);
        }
    }

    #[test]
    fn site_category_all_variants_round_trip() {
        for cat in [
            SiteCategory::CodeRepository,
            SiteCategory::CloudStorage,
            SiteCategory::Cdn,
            SiteCategory::Messaging,
            SiteCategory::PasteService,
            SiteCategory::CloudHosting,
            SiteCategory::Collaboration,
            SiteCategory::UrlShortener,
            SiteCategory::DnsService,
            SiteCategory::Other,
        ] {
            let json = serde_json::to_string(&cat).unwrap();
            let decoded: SiteCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, cat);
        }
    }

    #[test]
    fn abusable_site_serializes_domain_field() {
        let site = abusable_site_info("raw.githubusercontent.com").unwrap();
        let json = serde_json::to_string(site).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["domain"], "raw.githubusercontent.com");
    }

    #[test]
    fn abusable_site_serializes_blocking_risk_field() {
        let site = abusable_site_info("raw.githubusercontent.com").unwrap();
        let json = serde_json::to_string(site).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        // BlockingRisk::Critical → "critical"
        assert_eq!(v["blocking_risk"], "critical");
    }

    #[test]
    fn abusable_site_serializes_mitre_techniques_as_array() {
        let site = abusable_site_info("raw.githubusercontent.com").unwrap();
        let json = serde_json::to_string(site).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v["mitre_techniques"].is_array());
        assert!(v["mitre_techniques"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("T1102")));
    }

    #[test]
    fn full_catalog_serializes_to_json_array() {
        let json = serde_json::to_string(ABUSABLE_SITES).unwrap();
        let arr: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert!(arr.len() >= 30, "expected ≥30 sites, got {}", arr.len());
        assert!(arr.iter().all(|v| v["domain"].is_string()));
        assert!(arr.iter().all(|v| v["blocking_risk"].is_string()));
    }
}

// ── ABUSABLE_SITES LOTS Project expansion (RED) ───────────────────────────────
// Source: https://lots-project.com/ (175 entries as of 2025-Q4)
//         Gap analysis: 140 entries missing from our 35-entry catalog.
//         Prioritised by blocking_risk and detection prevalence.
#[cfg(test)]
mod expansion_tests {
    use super::*;

    // Critical — cloud infra / CDN
    #[test]
    fn sites_contains_graph_microsoft_com() {
        // T1071.001/T1530 — O365/Azure C2 and data access; cannot block
        assert!(abusable_site_info("graph.microsoft.com").is_some());
    }
    #[test]
    fn sites_contains_trycloudflare() {
        // T1090.003/T1102 — Cloudflare Quick Tunnels; zero-config C2 infra
        assert!(abusable_site_info("*.trycloudflare.com").is_some());
    }
    #[test]
    fn sites_contains_ngrok() {
        // T1090.003 — tunnel C2 through NAT; common in Red Team and malware
        assert!(abusable_site_info("*.ngrok.io").is_some());
    }
    #[test]
    fn sites_contains_netlify() {
        // T1102/T1583.006 — phishing pages, payload hosting on CDN
        assert!(abusable_site_info("*.netlify.app").is_some());
    }
    #[test]
    fn sites_contains_onedrive() {
        // T1567.002 — exfil via OneDrive API; critical-risk Microsoft service
        assert!(abusable_site_info("onedrive.live.com").is_some());
    }
    #[test]
    fn sites_contains_azure_blob() {
        // T1105/T1567 — payload staging + exfil on Azure Blob
        assert!(abusable_site_info("*.blob.core.windows.net").is_some());
    }

    // High — code hosting / file transfer
    #[test]
    fn sites_contains_transfer_sh() {
        // T1105/T1567 — anonymous file hosting; widely used in post-ex
        assert!(abusable_site_info("transfer.sh").is_some());
    }
    #[test]
    fn sites_contains_file_io() {
        // T1105 — temporary file hosting; seen in commodity malware delivery
        assert!(abusable_site_info("file.io").is_some());
    }
    #[test]
    fn sites_contains_gitee() {
        // T1102 — Chinese Git hosting; used by APT groups as C2 dead-drop
        assert!(abusable_site_info("gitee.com").is_some());
    }
    #[test]
    fn sites_contains_box() {
        // T1567.002 — enterprise file sharing; abused for exfiltration
        assert!(abusable_site_info("*.box.com").is_some());
    }
    #[test]
    fn sites_contains_4shared() {
        // T1105 — file hosting; used for payload distribution
        assert!(abusable_site_info("4shared.com").is_some());
    }
    #[test]
    fn sites_contains_mediafire() {
        // T1105 — file hosting; used for payload distribution
        assert!(abusable_site_info("mediafire.com").is_some());
    }

    // Medium — utility / comms
    #[test]
    fn sites_contains_webhook_site() {
        // T1041/T1071 — exfil via webhook; used in C2 and data capture
        assert!(abusable_site_info("webhook.site").is_some());
    }
    #[test]
    fn sites_contains_pipedream() {
        // T1041/T1102 — serverless webhook; C2 relay
        assert!(abusable_site_info("*.pipedream.net").is_some());
    }
    #[test]
    fn sites_contains_discord_cdn() {
        // T1102/T1071 — Discord CDN used for payload hosting
        assert!(abusable_site_info("cdn.discordapp.com").is_some());
    }
    #[test]
    fn sites_contains_ipinfo() {
        // T1016/T1590 — IP geolocation; used in recon and victim filtering
        assert!(abusable_site_info("ipinfo.io").is_some());
    }
    #[test]
    fn sites_contains_ipify() {
        // T1016 — public IP lookup; prevalent in malware check-in logic
        assert!(abusable_site_info("api.ipify.org").is_some());
    }

    // Verify counts grew
    #[test]
    fn abusable_sites_has_at_least_50_entries() {
        assert!(
            ABUSABLE_SITES.len() >= 50,
            "expected ≥50 sites after LOTS expansion, got {}",
            ABUSABLE_SITES.len()
        );
    }
}
