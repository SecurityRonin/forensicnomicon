//! Kerberos Account Logon descriptors — Security.evtx events 4768, 4769, 4771.
//!
//! The Kerberos half of Account Logon auditing lives only on domain controllers:
//! the KDC records the AS exchange that issues a TGT (4768), the TGS exchange
//! that issues a service ticket (4769), and pre-authentication failures (4771).
//! Two audit subcategories gate them — Audit Kerberos Authentication Service
//! (4768, 4771) and Audit Kerberos Service Ticket Operations (4769) — so an
//! absent event is as often a policy fact as an activity fact.
//!
//! Two things make these events readable that the rest of the catalog did not
//! carry: the Kerberos encryption-type (etype) code values, which is what turns
//! "0x17" into "RC4, the algorithm whose long-term key IS the NT hash"; and the
//! field block added to 4768/4769 by the January 14 2025 (or later) cumulative
//! update on Windows Server 2016 and later, which prints the advertised etypes,
//! the session encryption type, the accounts' supported-encryption-type flags,
//! and per-ticket hashes.
//!
//! Field names and value tables are taken from the Microsoft Learn event
//! reference pages, [MS-KILE], the IANA Kerberos parameter registry, and the
//! Kerberos RFCs; every description is written here rather than copied.
//!
//! Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768>
//! Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769>
//! Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4771>
//! Source: <https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos>
//! Source: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/6cfc7b50-11ed-4b4d-846d-6f08f0812919>
//! Source: <https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml>
//! Source: <https://www.rfc-editor.org/rfc/rfc4120>
//! Source: <https://www.rfc-editor.org/rfc/rfc4757>

use super::super::types::{
    ArtifactDescriptor, ArtifactLocation, DataScope, Decoder, FieldSchema, OsScope, TriagePriority,
    ValueType,
};

/// Field schema for Security event 4768 — a Kerberos TGT was requested.
///
/// Fields are listed in the order the event renders them: Account Information,
/// Service Information, Domain Controller Information, Network Information,
/// Additional Information, Certificate Information, Ticket Information. Entries
/// marked "post-January-2025" are absent from the event on an unpatched
/// Windows Server 2016, so a missing field is a build fact, not an evidence
/// fact.
///
/// Names in parentheses are the raw `EventData/Data@Name` attributes, which is
/// what an EVTX parser sees; the unparenthesised name is the Event Viewer label.
///
/// Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768>
/// Source: <https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos>
pub(crate) static EVTX_KERBEROS_TGT_REQUEST_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "event_id",
        value_type: ValueType::UnsignedInt,
        description: "Always 4768. Success and failure share the id — read Result Code, not the id, to tell them apart",
        is_uid_component: true,
    },
    FieldSchema {
        name: "timestamp",
        value_type: ValueType::Timestamp,
        description: "When the KDC processed the AS request (UTC). This is the domain-account logon time as the DC saw it, which is earlier than the 4624 on the host the account then reaches",
        is_uid_component: false,
    },
    FieldSchema {
        name: "account_name",
        value_type: ValueType::Text,
        description: "(TargetUserName) Account the TGT was requested for. A trailing $ marks a computer account — machine-account TGT requests from an address that is not that machine are worth pulling",
        is_uid_component: true,
    },
    FieldSchema {
        name: "supplied_realm_name",
        value_type: ValueType::Text,
        description: "(TargetDomainName) Kerberos realm the account belongs to. Rendered inconsistently as NetBIOS name, lowercase FQDN or uppercase FQDN, so normalise before grouping; a realm other than your own indicates a cross-realm request",
        is_uid_component: false,
    },
    FieldSchema {
        name: "user_id",
        value_type: ValueType::Text,
        description: "(TargetSid) SID of the requesting account — the identity to pivot on, since the name can be reused. NULL SID on failure records, so SID-based joins silently drop the failures",
        is_uid_component: false,
    },
    FieldSchema {
        name: "service_name",
        value_type: ValueType::Text,
        description: "(ServiceName) Service the request was addressed to — 'krbtgt' on a normal TGT request, and typically the krbtgt/REALM_NAME form on failures",
        is_uid_component: false,
    },
    FieldSchema {
        name: "service_id",
        value_type: ValueType::Text,
        description: "(ServiceSid) SID of the krbtgt service account, which carries the well-known RID 502. NULL SID on failure records",
        is_uid_component: false,
    },
    FieldSchema {
        name: "account_msds_supported_encryption_types",
        value_type: ValueType::Text,
        description: "(AccountSupportedEncryptionTypes) Post-January-2025. The account's processed msDS-SupportedEncryptionTypes as hex plus names — the bit flags are 0x1 DES-CBC-CRC, 0x2 DES-CBC-MD5, 0x4 RC4-HMAC, 0x8 AES128-CTS-HMAC-SHA1-96, 0x10 AES256-CTS-HMAC-SHA1-96, 0x20 AES256-CTS-HMAC-SHA1-96-SK, 0x40 AES128-CTS-HMAC-SHA256-128, 0x80 AES256-CTS-HMAC-SHA384-192 ([MS-KILE] 2.2.7). Use it to decide whether an RC4 ticket was a downgrade or the only thing this account could do. 'N/A' means the value could not be queried",
        is_uid_component: false,
    },
    FieldSchema {
        name: "account_available_keys",
        value_type: ValueType::Text,
        description: "(AccountAvailableKeys) Post-January-2025. Long-term keys actually stored in AD for the account, generated at each password set. No AES entry means the password has not been changed since AES support arrived, which is the usual reason an account is stuck on RC4",
        is_uid_component: false,
    },
    FieldSchema {
        name: "service_msds_supported_encryption_types",
        value_type: ValueType::Text,
        description: "(ServiceSupportedEncryptionTypes) Post-January-2025. Same bit flags, read from the account the target service is registered against — the target side of a downgrade question",
        is_uid_component: false,
    },
    FieldSchema {
        name: "service_available_keys",
        value_type: ValueType::Text,
        description: "(ServiceAvailableKeys) Post-January-2025. Keys stored in AD for the service account",
        is_uid_component: false,
    },
    FieldSchema {
        name: "dc_msds_supported_encryption_types",
        value_type: ValueType::Text,
        description: "(DCSupportedEncryptionTypes) Post-January-2025. The issuing domain controller's own supported encryption types, set by its Kerberos encryption policy. This is the third party to any downgrade: a weak result can come from the DC's policy rather than either principal",
        is_uid_component: false,
    },
    FieldSchema {
        name: "dc_available_keys",
        value_type: ValueType::Text,
        description: "(DCAvailableKeys) Post-January-2025. Keys available to the domain controller account",
        is_uid_component: false,
    },
    FieldSchema {
        name: "client_address",
        value_type: ValueType::Text,
        description: "(IpAddress) Address the AS request arrived from, as IPv4, IPv6 or the ::ffff:IPv4 mapped form. ::1 means the request was made on the DC itself, so the account was logged on to a domain controller",
        is_uid_component: false,
    },
    FieldSchema {
        name: "client_port",
        value_type: ValueType::UnsignedInt,
        description: "(IpPort) Client source port; 0 for local requests. Microsoft flags a value above 0 and below 1024 as worth examining, since a well-known port was used for an outbound connection",
        is_uid_component: false,
    },
    FieldSchema {
        name: "advertized_etypes",
        value_type: ValueType::Text,
        description: "(ClientAdvertizedEncryptionTypes) Post-January-2025, and Microsoft spells it with a z. The etypes the client offered for this exchange, printed as names (a bare number means the KDC did not recognise the type). A client offering only RC4 names identifies a legacy or deliberately downgraded requester",
        is_uid_component: false,
    },
    FieldSchema {
        name: "ticket_options",
        value_type: ValueType::Text,
        description: "(TicketOptions) KDC-option flag word in hex, MSB-0 numbering per RFC 4120 — bit 1 Forwardable, 2 Forwarded, 8 Renewable, 15 Name-canonicalize, 27 Renewable-ok. 0x40810010 and 0x40810000 are the everyday values; delegation-relevant flags are the ones to notice",
        is_uid_component: false,
    },
    FieldSchema {
        name: "result_code",
        value_type: ValueType::Text,
        description: "(Status) KDC result, 0x0 on success. 0x6 KDC_ERR_C_PRINCIPAL_UNKNOWN (no such account) in bursts is the shape of account enumeration; 0x12 KDC_ERR_CLIENT_REVOKED means disabled, expired or locked out; 0xC KDC_ERR_POLICY means a logon restriction refused it. 0x10 and 0x18 never appear here — those route to 4771",
        is_uid_component: false,
    },
    FieldSchema {
        name: "ticket_encryption_type",
        value_type: ValueType::Text,
        description: "(TicketEncryptionType) Algorithm the issued TGT is encrypted under: 0x1 DES-CBC-CRC, 0x3 DES-CBC-MD5, 0x11 AES128-CTS-HMAC-SHA1-96, 0x12 AES256-CTS-HMAC-SHA1-96, 0x17 RC4-HMAC, 0x18 RC4-HMAC-EXP. 0xFFFFFFFF is not an algorithm — it is the placeholder on Audit Failure records, where no ticket was issued. Treat anything other than 0x11/0x12 as a finding to explain",
        is_uid_component: false,
    },
    FieldSchema {
        name: "session_encryption_type",
        value_type: ValueType::Text,
        description: "(SessionKeyEncryptionType) Post-January-2025. Algorithm of the ticket session key, same code table as Ticket Encryption Type. It is distinct from the ticket's own etype and can be the weaker of the two, so an RC4 downgrade shows here while the TGT itself stays AES",
        is_uid_component: false,
    },
    FieldSchema {
        name: "pre_authentication_type",
        value_type: ValueType::Text,
        description: "(PreAuthType) How the client proved itself: 0 = no pre-authentication (the account carries 'Do not require Kerberos preauthentication', which is what makes an AS-REP roastable), 2 PA-ENC-TIMESTAMP for password logon, 15/16/17 for smart-card logon, 138 PA-ENCRYPTED-CHALLENGE for Kerberos armoring (FAST)",
        is_uid_component: false,
    },
    FieldSchema {
        name: "pre_authentication_encryption_type",
        value_type: ValueType::Text,
        description: "(PreAuthEncryptionType) Post-January-2025, rendered as one run-together word in the event. Algorithm chosen for the pre-authentication exchange, same code table as Ticket Encryption Type",
        is_uid_component: false,
    },
    FieldSchema {
        name: "certificate_issuer_name",
        value_type: ValueType::Text,
        description: "(CertIssuerName) Issuing CA of the smart-card certificate, populated only on certificate-based (PKINIT) logons. A CA outside your PKI is the check Microsoft calls out",
        is_uid_component: false,
    },
    FieldSchema {
        name: "certificate_serial_number",
        value_type: ValueType::Text,
        description: "(CertSerialNumber) Serial number of the logon certificate — the handle for tying the logon to an issued certificate in CA records",
        is_uid_component: false,
    },
    FieldSchema {
        name: "certificate_thumbprint",
        value_type: ValueType::Text,
        description: "(CertThumbprint) Thumbprint of the logon certificate, the stable identifier when serials repeat across CAs",
        is_uid_component: false,
    },
    FieldSchema {
        name: "response_ticket_hash",
        value_type: ValueType::Text,
        description: "(ResponseTicket, rendered as 'Response ticket hash') Post-January-2025. Base64 digest of the TGT the DC returned. It is the join key to event 4769: the same value appears there as Request ticket hash when that TGT is presented for a service ticket",
        is_uid_component: false,
    },
];

/// Security event 4768 — a Kerberos authentication ticket (TGT) was requested.
///
/// The AS exchange (RFC 4120 §3.1) recorded from the KDC's side. The event is
/// written only on domain controllers and only when the Audit Kerberos
/// Authentication Service subcategory is enabled, and it covers both outcomes:
/// a Result Code of 0x0 issued a TGT, anything else refused one. Two codes are
/// deliberately absent — 0x10 and 0x18 are reported as event 4771 instead — so
/// a bad password is a 4771 while a nonexistent, disabled or expired account is
/// a 4768 with a non-zero Result Code. That split is the reason both events
/// have to be read together before saying what failed.
///
/// Since the January 14 2025 or later cumulative update on Windows Server 2016
/// and later, the event also prints what each principal could have negotiated:
/// the account's, the service's and the DC's msDS-SupportedEncryptionTypes and
/// available keys, the etypes the client advertised, the session encryption
/// type separately from the ticket encryption type, and a base64 hash of the
/// issued ticket.
///
/// Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768>
/// Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-kerberos-authentication-service>
/// Source: <https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos>
/// Source: <https://www.rfc-editor.org/rfc/rfc4120>
pub(crate) static EVTX_KERBEROS_TGT_REQUEST: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_kerberos_tgt_request",
    name: "Kerberos TGT Request (Security 4768)",
    artifact_type: ArtifactLocation::EventLog,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Security.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Domain-controller record of the Kerberos AS exchange: the KDC issued, or refused, a \
Ticket Granting Ticket. Written ONLY on domain controllers, and only under the Audit Kerberos \
Authentication Service subcategory. Records the Account Name and User ID (SID) the TGT was for, the \
Client Address the request came from, the Ticket Options, the Pre-Authentication Type, the Ticket \
Encryption Type, and a Result Code that is 0x0 on success. This is the domain-wide view of account \
logon that host-side 4624 records cannot give: the DC sees every domain authentication regardless \
of which member server the account then reaches. Result Codes 0x10 and 0x18 do NOT appear here — \
Microsoft routes them to event 4771 — so a wrong password surfaces as 4771 while a nonexistent \
(0x6), revoked/disabled (0x12) or policy-refused (0xC) account surfaces as a 4768 failure; a burst \
of 0x6 is the shape of account enumeration. Pre-Authentication Type 0 means the account is \
configured with 'Do not require Kerberos preauthentication', the condition that makes an AS-REP \
roastable. Ticket Encryption Type decodes as 0x1 DES-CBC-CRC, 0x3 DES-CBC-MD5, 0x11 AES128-CTS-\
HMAC-SHA1-96, 0x12 AES256-CTS-HMAC-SHA1-96, 0x17 RC4-HMAC, 0x18 RC4-HMAC-EXP, with 0xFFFFFFFF a \
placeholder on Audit Failure records rather than a real algorithm; the RC4-HMAC long-term key is \
the NT password hash itself (RFC 4757 section 2), so an actor holding only an NT hash is \
structurally confined to 0x17. Since the January 14 2025 or later cumulative update on Windows \
Server 2016 and later the event adds MSDS-SupportedEncryptionTypes and Available Keys under both \
Account Information and Service Information, a new Domain Controller Information block, Advertized \
Etypes (Microsoft's spelling) listing the client-offered etypes, a Session Encryption Type distinct \
from the Ticket Encryption Type, a Pre-Authentication EncryptionType, and a Response ticket hash \
that joins this TGT to the 4769 requests later made with it.",
    mitre_techniques: &[
        "T1558.004", // Steal or Forge Kerberos Tickets: AS-REP Roasting
        "T1078.002", // Valid Accounts: Domain Accounts
        "T1087.002", // Account Discovery: Domain Account
    ],
    fields: EVTX_KERBEROS_TGT_REQUEST_FIELDS,
    retention: Some("Security.evtx is a rolling channel sized by policy; Microsoft rates this subcategory High volume on a KDC, so the retained window on a busy DC is short"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[
        "evtx_kerberos_service_ticket",
        "evtx_kerberos_preauth_failed",
        "evtx_security",
        "evtx_ntlm",
    ],
    sources: &[
        // Microsoft — Event 4768: subcategory, DC-only generation, the 0x10/0x18 routing to 4771,
        // the post-January-2025 field set, Table 4 encryption types, Table 5 pre-auth types:
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768",
        // Microsoft — Audit Kerberos Authentication Service: the gating subcategory, its event
        // list (4768/4771/4772) and the High volume rating on KDCs:
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-kerberos-authentication-service",
        // Microsoft — Detect and Remediate RC4 Usage in Kerberos: which fields the January 2025
        // cumulative update adds, the msDS-SupportedEncryptionTypes value table, and the
        // processed-value caveats:
        "https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos",
        // [MS-KILE] 2.2.7 Supported Encryption Types Bit Flags — the msDS-SupportedEncryptionTypes
        // bit layout (DES/RC4/AES128/AES256/AES256-SK/SHA2 bits):
        "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/6cfc7b50-11ed-4b4d-846d-6f08f0812919",
        // IANA Kerberos Encryption Type Numbers — the upstream registry the etype codes come
        // from (1/3 DES deprecated, 17/18 AES-CTS-HMAC-SHA1, 23/24 RC4 deprecated):
        "https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml",
        // RFC 4120 — the AS exchange (section 3.1) and KDC option/ticket flag semantics:
        "https://www.rfc-editor.org/rfc/rfc4120",
        // RFC 4757 section 2 — the RC4-HMAC key is MD4(UTF-16LE(password)), i.e. the NT hash:
        "https://www.rfc-editor.org/rfc/rfc4757",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Generated only on domain controllers and only when the Audit Kerberos Authentication Service subcategory is enabled — absence proves nothing about authentication until the audit policy in force at the time is established",
        "Every DC keeps its own Security log, so one DC's log is a partial view of domain authentication; a complete account timeline needs the logs of every DC that could have served the account",
        "The post-January-2025 fields (MSDS-SupportedEncryptionTypes, Available Keys, Domain Controller Information, Advertized Etypes, Session Encryption Type, Pre-Authentication EncryptionType, ticket hashes) are absent on builds without the January 14 2025 or later cumulative update — a missing field is a patch-level fact, not an evidence fact",
        "MSDS-SupportedEncryptionTypes is a PROCESSED value, not the raw AD attribute: on Windows Server 2022 and earlier it always shows DES and RC4 regardless of configuration, and from Windows Server 2025 it shows only AES-SHA1 and stronger — so it will legitimately disagree with the attribute stored in AD",
        "Available Keys lists RC4 regardless of whether RC4 was used, so its presence is not evidence of RC4 negotiation",
        "Ticket Encryption Type 0xFFFFFFFF on a failure record means no ticket was issued; reading it as an algorithm code invents an encryption type that was never negotiated",
        "A machine account requesting a TGT is ordinary background activity; the signal is the Client Address, the timing and the etype, not the request itself",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "EVTX channel; oldest records purged when the configured maximum size is reached, and KDC authentication volume fills it quickly",
};

/// Field schema for Security event 4769 — a Kerberos service ticket was requested.
///
/// Logon GUID is the field that makes this event a pivot rather than a log
/// line: the same GUID appears in 4624/4648/4964 on the host the ticket was
/// used against, joining the DC-side grant to the host-side logon.
///
/// Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769>
/// Source: <https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos>
pub(crate) static EVTX_KERBEROS_SERVICE_TICKET_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "event_id",
        value_type: ValueType::UnsignedInt,
        description: "Always 4769. Success and failure share the id — read Failure Code to separate them",
        is_uid_component: true,
    },
    FieldSchema {
        name: "timestamp",
        value_type: ValueType::Timestamp,
        description: "When the KDC processed the TGS request (UTC). It precedes the access it authorises, so it dates the intent to reach the service rather than the access itself",
        is_uid_component: false,
    },
    FieldSchema {
        name: "account_name",
        value_type: ValueType::Text,
        description: "(TargetUserName) Requesting account in implicit-UPN form, user@FULL.DOMAIN — built from sAMAccountName plus the domain, NOT the userPrincipalName attribute, so do not match it against UPNs read from AD. Optional and occasionally empty",
        is_uid_component: true,
    },
    FieldSchema {
        name: "account_domain",
        value_type: ValueType::Text,
        description: "(TargetDomainName) Realm of the requesting account, rendered as NetBIOS name or FQDN in either case. Optional and occasionally empty",
        is_uid_component: false,
    },
    FieldSchema {
        name: "logon_guid",
        value_type: ValueType::Guid,
        description: "(LogonGuid) THE correlation key. The same GUID appears in events 4624, 4648 and 4964 on the computer the service ticket was issued for, joining this DC-side grant to the host-side logon it produced. An all-zero GUID means it was not captured, which breaks the join rather than indicating anything",
        is_uid_component: false,
    },
    FieldSchema {
        name: "service_name",
        value_type: ValueType::Text,
        description: "(ServiceName) The account or computer the ticket was requested FOR — the destination. A computer account (trailing $) names the host being reached; a user account with an SPN names a service, and service tickets for such accounts are what Kerberoasting collects. Optional and occasionally empty",
        is_uid_component: true,
    },
    FieldSchema {
        name: "service_id",
        value_type: ValueType::Text,
        description: "(ServiceSid) SID of that destination principal — the stable identifier when names are ambiguous or reused. NULL SID on failure records",
        is_uid_component: false,
    },
    FieldSchema {
        name: "account_msds_supported_encryption_types",
        value_type: ValueType::Text,
        description: "(AccountSupportedEncryptionTypes) Post-January-2025. Same [MS-KILE] 2.2.7 bit flags as in 4768, but Microsoft populates this only during account lookup — in a 4769 it is routinely 'N/A' and the service-side field is the one that carries the answer",
        is_uid_component: false,
    },
    FieldSchema {
        name: "account_available_keys",
        value_type: ValueType::Text,
        description: "(AccountAvailableKeys) Post-January-2025. Keys stored in AD for the requesting account; commonly 'N/A' here for the same reason",
        is_uid_component: false,
    },
    FieldSchema {
        name: "service_msds_supported_encryption_types",
        value_type: ValueType::Text,
        description: "(ServiceSupportedEncryptionTypes) Post-January-2025. The destination service account's supported encryption types. A value of 0x4 means RC4 only, which explains an RC4 service ticket without a downgrade, and marks an account whose tickets are offline-crackable",
        is_uid_component: false,
    },
    FieldSchema {
        name: "service_available_keys",
        value_type: ValueType::Text,
        description: "(ServiceAvailableKeys) Post-January-2025. Keys AD actually holds for the service account. No AES entry means the service password predates AES support and has never been rotated",
        is_uid_component: false,
    },
    FieldSchema {
        name: "dc_msds_supported_encryption_types",
        value_type: ValueType::Text,
        description: "(DCSupportedEncryptionTypes) Post-January-2025. The issuing DC's own supported encryption types, so a weak result can be attributed to DC policy rather than to either principal",
        is_uid_component: false,
    },
    FieldSchema {
        name: "dc_available_keys",
        value_type: ValueType::Text,
        description: "(DCAvailableKeys) Post-January-2025. Keys available to the domain controller account",
        is_uid_component: false,
    },
    FieldSchema {
        name: "client_address",
        value_type: ValueType::Text,
        description: "(IpAddress) Where the TGS request came from — the requester's host, not the destination. ::1 means the request was made on the DC itself, so the account was logged on to a domain controller. A single source address requesting tickets for many distinct services in a short window is the shape of SPN sweeping",
        is_uid_component: false,
    },
    FieldSchema {
        name: "client_port",
        value_type: ValueType::UnsignedInt,
        description: "(IpPort) Client source port; 0 for local requests. Microsoft flags values above 0 and below 1024 as worth examining",
        is_uid_component: false,
    },
    FieldSchema {
        name: "advertized_etypes",
        value_type: ValueType::Text,
        description: "(ClientAdvertizedEncryptionTypes) Post-January-2025, spelled with a z. Etypes the client offered for this TGS exchange, as names. A client that advertises AES elsewhere but offers only RC4 here is requesting a crackable ticket by choice",
        is_uid_component: false,
    },
    FieldSchema {
        name: "ticket_options",
        value_type: ValueType::Text,
        description: "(TicketOptions) KDC-option flag word in hex, MSB-0 numbering per RFC 4120. 0x40810000 is the everyday value; forwarded and proxy flags are the delegation-relevant ones",
        is_uid_component: false,
    },
    FieldSchema {
        name: "ticket_encryption_type",
        value_type: ValueType::Text,
        description: "(TicketEncryptionType) Algorithm of the issued service ticket: 0x1 DES-CBC-CRC, 0x3 DES-CBC-MD5, 0x11 AES128-CTS-HMAC-SHA1-96, 0x12 AES256-CTS-HMAC-SHA1-96, 0x17 RC4-HMAC, 0x18 RC4-HMAC-EXP; 0xFFFFFFFF is the Audit Failure placeholder, not an algorithm. 0x17 for a service ticket against a user account with an SPN is the classic Kerberoasting signature, because the ticket is encrypted with the NT hash of the service account and can be cracked offline",
        is_uid_component: false,
    },
    FieldSchema {
        name: "session_encryption_type",
        value_type: ValueType::Text,
        description: "(SessionKeyEncryptionType) Post-January-2025. Algorithm of the session key, same code table. Read it alongside Ticket Encryption Type — the two can differ, and the weaker one is where a downgrade lands",
        is_uid_component: false,
    },
    FieldSchema {
        name: "failure_code",
        value_type: ValueType::Text,
        description: "(Status) 0x0 on success. 0x20 KRB_AP_ERR_TKT_EXPIRED is routine ticket expiry and carries little security meaning; 0xE KDC_ERR_ETYPE_NOTSUPP means the KDC would not issue the requested encryption type, which is what an AES-only hardening change looks like from the failure side; 0x7 KDC_ERR_S_PRINCIPAL_UNKNOWN in bursts is SPN enumeration",
        is_uid_component: false,
    },
    FieldSchema {
        name: "transited_services",
        value_type: ValueType::Text,
        description: "(TransmittedServices) SPNs involved when constrained Kerberos delegation was used — a populated value means the ticket was obtained on another principal's behalf, which is the delegation-abuse trail",
        is_uid_component: false,
    },
    FieldSchema {
        name: "request_ticket_hash",
        value_type: ValueType::Text,
        description: "(RequestTicketHash) Post-January-2025. Base64 digest of the ticket the client presented — the TGT. It matches the Response ticket hash of the 4768 that issued that TGT, which is how a service-ticket grant is traced back to the logon that funded it",
        is_uid_component: false,
    },
    FieldSchema {
        name: "response_ticket_hash",
        value_type: ValueType::Text,
        description: "(ResponseTicketHash) Post-January-2025. Base64 digest of the service ticket the DC returned — the per-ticket identifier for the credential that was then presented to the destination service",
        is_uid_component: false,
    },
];

/// Security event 4769 — a Kerberos service ticket was requested.
///
/// The TGS exchange (RFC 4120 §3.3) from the KDC's side, and the most useful
/// single event for lateral movement: it names the destination principal
/// (Service Name / Service ID), the requester's address, and — through Logon
/// GUID — joins to the 4624 on the host that was reached.
///
/// It is also where Kerberoasting is visible. Microsoft documents the attack
/// against this event directly: RC4 service tickets can be captured and cracked
/// offline, and a Ticket Encryption Type of 0x17 against a user account holding
/// an SPN is that pattern, because the RC4-HMAC ticket key is the service
/// account's NT hash (RFC 4757 §2).
///
/// Volume is the practical constraint — Microsoft rates the gating subcategory
/// Very High on a KDC, so retention is short and collection has to be
/// deliberate.
///
/// Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769>
/// Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-kerberos-service-ticket-operations>
/// Source: <https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos>
pub(crate) static EVTX_KERBEROS_SERVICE_TICKET: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_kerberos_service_ticket",
    name: "Kerberos Service Ticket Request (Security 4769)",
    artifact_type: ArtifactLocation::EventLog,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Security.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Domain-controller record of the Kerberos TGS exchange: an account presented its TGT \
and asked for a ticket to a named service. Written ONLY on domain controllers, under the Audit \
Kerberos Service Ticket Operations subcategory. Service Name and Service ID identify the \
DESTINATION — a computer account (trailing $) is the host being reached, a user account carrying \
an SPN is a service — while Client Address identifies where the request came from, so one event \
carries both ends of an intended access. Logon GUID is the correlation key that joins this DC-side \
grant to the host side: the same GUID appears in events 4624, 4648 and 4964 on the computer the \
ticket was issued for. Ticket Encryption Type decodes as 0x1 DES-CBC-CRC, 0x3 DES-CBC-MD5, 0x11 \
AES128-CTS-HMAC-SHA1-96, 0x12 AES256-CTS-HMAC-SHA1-96, 0x17 RC4-HMAC, 0x18 RC4-HMAC-EXP, with \
0xFFFFFFFF a placeholder on Audit Failure records. Microsoft documents Kerberoasting against this \
exchange: RC4 service tickets are captured and cracked offline, and because the RC4-HMAC key is the \
service account's NT hash (RFC 4757 section 2), a 0x17 ticket for a user account with an SPN is \
that pattern in the log. Failure Code 0x20 (ticket expired) is routine noise; 0xE \
KDC_ERR_ETYPE_NOTSUPP is what an AES-only hardening change looks like from the failure side; \
repeated 0x7 against many distinct Service Names is SPN enumeration. Since the January 14 2025 or \
later cumulative update on Windows Server 2016 and later the event adds MSDS-SupportedEncryptionTypes \
and Available Keys, a Domain Controller Information block, Advertized Etypes, a Session Encryption \
Type separate from the Ticket Encryption Type, and a Request/Response ticket-hash pair — the \
Request ticket hash equals the Response ticket hash of the 4768 that issued the presented TGT.",
    mitre_techniques: &[
        "T1558.003", // Steal or Forge Kerberos Tickets: Kerberoasting
        "T1550.003", // Use Alternate Authentication Material: Pass the Ticket
        "T1078.002", // Valid Accounts: Domain Accounts
        "T1021.002", // Remote Services: SMB/Windows Admin Shares
    ],
    fields: EVTX_KERBEROS_SERVICE_TICKET_FIELDS,
    retention: Some("Security.evtx is a rolling channel sized by policy; Microsoft rates this subcategory Very High volume on a KDC, so the retained window on a busy DC is often hours"),
    triage_priority: TriagePriority::Critical,
    related_artifacts: &[
        "evtx_kerberos_tgt_request",
        "evtx_kerberos_preauth_failed",
        "evtx_security",
        "evtx_ntlm",
    ],
    sources: &[
        // Microsoft — Event 4769: DC-only generation, Logon GUID correlation with 4624/4648/4964,
        // Service Name/Service ID semantics, the encryption-type table, the failure codes, the
        // KdcExtraLogLevel dependency for ETYPE/SPN-unknown errors, post-January-2025 fields:
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769",
        // Microsoft — Audit Kerberos Service Ticket Operations: the gating subcategory, its event
        // list (4769/4770/4773) and the Very High volume rating on KDCs:
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-kerberos-service-ticket-operations",
        // Microsoft — Detect and Remediate RC4 Usage in Kerberos: names Kerberoasting against
        // service tickets, documents the January 2025 field additions, and shows a worked 4769
        // with Failure Code 0xE after RC4 was disabled:
        "https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos",
        // [MS-KILE] 2.2.7 Supported Encryption Types Bit Flags:
        "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/6cfc7b50-11ed-4b4d-846d-6f08f0812919",
        // IANA Kerberos Encryption Type Numbers — the upstream registry the etype codes come
        // from (17/18 AES-CTS-HMAC-SHA1 current, 23/24 RC4 deprecated):
        "https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml",
        // RFC 4120 — the TGS exchange (section 3.3):
        "https://www.rfc-editor.org/rfc/rfc4120",
        // RFC 4757 section 2 — RC4-HMAC key = MD4(UTF-16LE(password)) = the NT hash, which is what
        // makes an RC4 service ticket offline-crackable:
        "https://www.rfc-editor.org/rfc/rfc4757",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Generated only on domain controllers and only under the Audit Kerberos Service Ticket Operations subcategory; on member servers and workstations the subcategory produces nothing at all",
        "A service ticket was ISSUED, not used — 4769 proves the KDC granted a credential for the destination, not that the destination was reached; the 4624 carrying the same Logon GUID on that host is what closes the loop",
        "Windows caches service tickets, so an access can occur with no contemporaneous 4769 and a 4769 can occur with no access following it",
        "Some failure codes are suppressed unless the KdcExtraLogLevel registry value is set (0x01 for SPN-unknown errors, 0x10 for encryption-type and bad-option errors), so absence of those failures measures the KDC's logging configuration",
        "Failure Code 0x20 (ticket expired) is high-volume routine noise and should be filtered before any rate-based reasoning",
        "Ticket Encryption Type 0x17 is not by itself Kerberoasting: an account or service whose msDS-SupportedEncryptionTypes is RC4-only will legitimately receive RC4 tickets — read the service-side supported types and Advertized Etypes before calling it a downgrade",
        "Ticket Encryption Type 0xFFFFFFFF on a failure record means no ticket was issued and is not an algorithm code",
        "Account Name is the implicit UPN built from sAMAccountName plus domain, not the userPrincipalName attribute; matching it against AD UPNs will miss accounts whose UPN was set independently",
        "The Request ticket hash joins to a 4768 that may have been served by a DIFFERENT domain controller — a request hash with no matching 4768 is only meaningful once every DC's Security log covering the TGT lifetime is in scope",
        "Both ticket-hash fields require the January 14 2025 or later cumulative update; on older builds the join key simply does not exist",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "EVTX channel with Very High record volume on a KDC; oldest records purged rapidly when the configured maximum size is reached",
};

/// Field schema for Security event 4771 — Kerberos pre-authentication failed.
///
/// A short event by design: it carries the failing identity, the source, and a
/// Failure Code. The certificate fields exist in the schema but Microsoft
/// documents them as always empty here.
///
/// Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4771>
pub(crate) static EVTX_KERBEROS_PREAUTH_FAILED_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "event_id",
        value_type: ValueType::UnsignedInt,
        description: "Always 4771. There is no success variant — the event exists only to record a failure",
        is_uid_component: true,
    },
    FieldSchema {
        name: "timestamp",
        value_type: ValueType::Timestamp,
        description: "When the KDC rejected the pre-authentication (UTC). Inter-arrival times across a run of these are what separate a mistyped password from an automated guessing loop",
        is_uid_component: false,
    },
    FieldSchema {
        name: "security_id",
        value_type: ValueType::Text,
        description: "(TargetSid) SID of the account whose pre-authentication failed. Unlike the failure form of 4768 this is populated, so failures can be grouped by identity rather than by name",
        is_uid_component: false,
    },
    FieldSchema {
        name: "account_name",
        value_type: ValueType::Text,
        description: "(TargetUserName) Account name presented. A trailing $ marks a computer account, whose pre-auth failures usually mean a broken secure channel rather than an attack",
        is_uid_component: true,
    },
    FieldSchema {
        name: "service_name",
        value_type: ValueType::Text,
        description: "(ServiceName) The ticket-granting service addressed, as krbtgt/DOMAIN_NETBIOS_NAME or krbtgt/DOMAIN_FULL_NAME — the realm the credential was tried against",
        is_uid_component: false,
    },
    FieldSchema {
        name: "client_address",
        value_type: ValueType::Text,
        description: "(IpAddress) Source of the failed attempt, as IPv4, IPv6 or the ::ffff:IPv4 mapped form. This is the field that turns a password-failure count into an attribution: one address against many accounts is spraying, many addresses against one account is not",
        is_uid_component: false,
    },
    FieldSchema {
        name: "client_port",
        value_type: ValueType::UnsignedInt,
        description: "(IpPort) Client source port; 0 for local attempts. ::1 with port 0 means the attempt was made on the DC itself",
        is_uid_component: false,
    },
    FieldSchema {
        name: "ticket_options",
        value_type: ValueType::Text,
        description: "(TicketOptions) KDC-option flag word in hex, MSB-0 numbering per RFC 4120; 0x40810010 is the everyday value. Rarely discriminating on a failure, but an unusual flag set distinguishes a non-Windows client",
        is_uid_component: false,
    },
    FieldSchema {
        name: "failure_code",
        value_type: ValueType::Text,
        description: "(Status) Why pre-authentication failed. 0x18 KDC_ERR_PREAUTH_FAILED is the wrong password — repeated occurrences against one or many accounts is the brute-force/spraying signal Microsoft calls out; 0x17 KDC_ERR_KEY_EXPIRED is an expired password, an operational event rather than an attack; 0x10 KDC_ERR_PADATA_TYPE_NOSUPP is a smart-card/PKINIT problem, typically a missing or wrong-template DC certificate",
        is_uid_component: false,
    },
    FieldSchema {
        name: "pre_authentication_type",
        value_type: ValueType::Text,
        description: "(PreAuthType) What the client attempted: 2 PA-ENC-TIMESTAMP for password logon, 15/16/17 for smart-card logon, 138 PA-ENCRYPTED-CHALLENGE for Kerberos armoring (FAST). A value other than the one your environment mandates identifies a client that is not following policy",
        is_uid_component: false,
    },
    FieldSchema {
        name: "certificate_issuer_name",
        value_type: ValueType::Text,
        description: "(CertIssuerName) Present in the schema but documented as always empty for 4771 — do not treat a blank as a missing-certificate finding",
        is_uid_component: false,
    },
    FieldSchema {
        name: "certificate_serial_number",
        value_type: ValueType::Text,
        description: "(CertSerialNumber) Present in the schema but documented as always empty for 4771",
        is_uid_component: false,
    },
    FieldSchema {
        name: "certificate_thumbprint",
        value_type: ValueType::Text,
        description: "(CertThumbprint) Present in the schema but documented as always empty for 4771",
        is_uid_component: false,
    },
];

/// Security event 4771 — Kerberos pre-authentication failed.
///
/// The event that carries the wrong-password case. Microsoft routes Result
/// Codes 0x10 and 0x18 away from event 4768 and reports them here, so a
/// password-guessing run against domain accounts is a stream of 4771s with
/// Failure Code 0x18 while a 4768 failure means something else entirely
/// (unknown, disabled, expired or policy-refused account).
///
/// Its central limitation is structural rather than configurable: the event is
/// not generated at all for an account with "Do not require Kerberos
/// preauthentication" set — precisely the accounts that are AS-REP roastable —
/// so the population it can never cover is the population most worth watching.
///
/// Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4771>
/// Source: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-kerberos-authentication-service>
pub(crate) static EVTX_KERBEROS_PREAUTH_FAILED: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_kerberos_preauth_failed",
    name: "Kerberos Pre-Authentication Failed (Security 4771)",
    artifact_type: ArtifactLocation::EventLog,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("%SystemRoot%\\System32\\winevt\\Logs\\Security.evtx"),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Domain-controller record that the KDC refused to issue a TGT because \
pre-authentication did not verify. Written ONLY on domain controllers, under the Audit Kerberos \
Authentication Service subcategory — the same subcategory as 4768. The split between the two events \
is the thing to know: Microsoft states that event 4768 does NOT generate for Result Codes 0x10 and \
0x18 and that 4771 generates instead, so a bad password is a 4771 with Failure Code 0x18 while a \
nonexistent (0x6), revoked/disabled (0x12) or policy-refused (0xC) account is a 4768 failure. \
Reading either event alone therefore under-counts failed domain authentication. Failure Code 0x17 \
KDC_ERR_KEY_EXPIRED is an expired password and 0x10 KDC_ERR_PADATA_TYPE_NOSUPP is a smart-card/\
PKINIT problem such as a missing or wrong-template DC certificate. The event records Security ID, \
Account Name, Service Name (krbtgt/DOMAIN), Client Address and Client Port, Ticket Options, Failure \
Code and Pre-Authentication Type; the three certificate fields exist but Microsoft documents them \
as always empty here. Client Address is what turns a count of failures into an attribution — one \
source address against many accounts is password spraying, and Microsoft explicitly flags repeated \
0x18 in a short window as a possible brute-force attack on the account password. The blind spot is \
structural: the event is NOT generated for an account configured with 'Do not require Kerberos \
preauthentication', which is exactly the configuration that makes an account AS-REP roastable — for \
those accounts, look to 4768 with Pre-Authentication Type 0 instead.",
    mitre_techniques: &[
        "T1110.001", // Brute Force: Password Guessing
        "T1110.003", // Brute Force: Password Spraying
        "T1078.002", // Valid Accounts: Domain Accounts
    ],
    fields: EVTX_KERBEROS_PREAUTH_FAILED_FIELDS,
    retention: Some("Security.evtx is a rolling channel sized by policy; Microsoft rates this subcategory High volume on a KDC"),
    triage_priority: TriagePriority::High,
    related_artifacts: &[
        "evtx_kerberos_tgt_request",
        "evtx_kerberos_service_ticket",
        "evtx_security",
        "evtx_ntlm",
    ],
    sources: &[
        // Microsoft — Event 4771: DC-only generation, the "not generated if 'Do not require Kerberos
        // preauthentication' is set" rule, the failure-code table, the always-empty certificate
        // fields, and the 0x18 brute-force monitoring recommendation:
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4771",
        // Microsoft — Event 4768: the statement that 4768 does not generate for Result Codes 0x10
        // and 0x18 and that 4771 generates instead (the routing rule this descriptor turns on):
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768",
        // Microsoft — Audit Kerberos Authentication Service: the gating subcategory, which states
        // it contains the failed pre-authentication events (wrong password / expired password):
        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-kerberos-authentication-service",
        // RFC 4120 section 7.5.9 — the KRB-ERROR code values the Failure Code field carries:
        "https://www.rfc-editor.org/rfc/rfc4120",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "NOT generated for an account with 'Do not require Kerberos preauthentication' set — the AS-REP-roastable accounts are invisible to this event by construction, and their failures must be sought in 4768 with Pre-Authentication Type 0",
        "Generated only on domain controllers and only under the Audit Kerberos Authentication Service subcategory; establish the audit policy in force before reading absence as absence of attempts",
        "Counting failed domain logons from 4771 alone under-counts: unknown, disabled, expired and policy-refused accounts fail as 4768 records with a non-zero Result Code and never appear here",
        "Failure Code 0x17 (expired password) and computer-account failures are ordinary operational noise that will dominate the volume in most environments",
        "Each DC logs only the attempts it served; a spraying run spread across DCs looks small in any single log",
        "The three certificate fields are documented as always empty for this event — their blankness carries no meaning",
    ],
    volatility: Some(crate::volatility::VolatilityClass::RotatingBuffer),
    volatility_rationale: "EVTX channel; oldest records purged when the configured maximum size is reached, and failure bursts accelerate the rollover",
};
