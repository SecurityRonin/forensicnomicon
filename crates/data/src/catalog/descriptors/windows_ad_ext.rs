//! Active Directory account-object attributes recovered from NTDS.dit.
//!
//! The catalog already models NTDS.dit as a credential source (`ntds_dit` —
//! secrets for every domain account). The same ESE database also holds the
//! *authorization* state of each account object, and one slice of it decides
//! which compromised host exposes which other principals: the Kerberos
//! delegation configuration. This module covers that slice — the
//! `userAccountControl` delegation bits, `msDS-AllowedToDelegateTo`,
//! `msDS-AllowedToActOnBehalfOfOtherIdentity`, and the Protected Users
//! membership that overrides them.
//!
//! Field descriptions are written from the Microsoft Open Specifications and
//! the AD schema reference; no third-party prose is copied.
//!
//! Primary sources:
//! - [MS-ADTS] section 2.2.16, userAccountControl Bits — the flag values and
//!   their Kerberos semantics.
//! - [MS-SFU] Abstract Data Model — the mapping from KDC behaviour to the AD
//!   attributes that configure it.
//! - AD Schema reference for `ms-DS-Allowed-To-Delegate-To`,
//!   `ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity`, and
//!   `Repl-Property-Meta-Data`.

use super::super::types::{
    ArtifactDescriptor, ArtifactLocation, DataScope, Decoder, FieldSchema, OsScope, TriagePriority,
    ValueType,
};

/// Field schema for the Kerberos delegation configuration of one AD account object.
///
/// Every field is an attribute of a single `user`, `computer` or managed
/// service account object in NTDS.dit, except `protected_users_member`
/// (derived from the account's group membership) and
/// `delegation_last_originating_change` (derived from the object's
/// `replPropertyMetaData` stamp for the delegation attribute).
///
/// Source: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/dd302fd1-0aa7-406b-ad91-2a6b35738557>
/// Source: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/0b4d13c4-d459-4598-8f08-1584ca1e24c9>
pub(crate) static AD_ACCOUNT_DELEGATION_CONFIG_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "distinguished_name",
        value_type: ValueType::Text,
        description: "distinguishedName of the account object the delegation setting sits on. Identifies the principal whose trust configuration is being read",
        is_uid_component: true,
    },
    FieldSchema {
        name: "sam_account_name",
        value_type: ValueType::Text,
        description: "sAMAccountName of the account. Match it against the hosts and service accounts already in scope to see whether something already compromised is also a delegation front-end",
        is_uid_component: true,
    },
    FieldSchema {
        name: "object_class",
        value_type: ValueType::Text,
        description: "Structural class of the object — user, computer, or a managed service account class. The AD schema documents msDS-AllowedToDelegateTo as an attribute of service account objects, which may be either a computer OR a user account, so do not restrict the sweep to computer objects",
        is_uid_component: false,
    },
    FieldSchema {
        name: "object_sid",
        value_type: ValueType::Text,
        description: "objectSid of the account. Needed to resolve the SIDs found inside a resource account's msDS-AllowedToActOnBehalfOfOtherIdentity descriptor back to named principals",
        is_uid_component: false,
    },
    FieldSchema {
        name: "user_account_control",
        value_type: ValueType::UnsignedInt,
        description: "Raw 32-bit userAccountControl flags word. Decode the delegation bits from this value rather than trusting a management-tool checkbox: the flags are cumulative, and Microsoft documents the default as 0x200 for a typical user, 0x1000 for a workstation or member server, and 0x82000 for a domain controller",
        is_uid_component: false,
    },
    FieldSchema {
        name: "trusted_for_delegation",
        value_type: ValueType::Bool,
        description: "userAccountControl bit TRUSTED_FOR_DELEGATION (0x00080000 / 524288). Per [MS-ADTS] it sets the 'OK as Delegate' ticket flag; Microsoft's operational description is that any service running under the account can impersonate a client that requests the service — i.e. unconstrained delegation. Treat every principal that authenticated to this host as potentially exposed",
        is_uid_component: false,
    },
    FieldSchema {
        name: "trusted_to_auth_for_delegation",
        value_type: ValueType::Bool,
        description: "userAccountControl bit TRUSTED_TO_AUTH_FOR_DELEGATION (0x01000000 / 16777216). Per [MS-ADTS] the KDC sets the forwardable flag in the S4U2self service ticket the account obtains, so the account can assume a client's identity without that client ever contacting it. Present with an msDS-AllowedToDelegateTo list, this is constrained delegation with protocol transition",
        is_uid_component: false,
    },
    FieldSchema {
        name: "not_delegated",
        value_type: ValueType::Bool,
        description: "userAccountControl bit NOT_DELEGATED (0x00100000 / 1048576) — the 'Account is sensitive and cannot be delegated' setting. Per [MS-ADTS] the account's TGTs and the service tickets it obtains are not marked forwardable or proxiable even when requested, so it is the one attribute that lets you rule a principal OUT of delegation exposure",
        is_uid_component: false,
    },
    FieldSchema {
        name: "ms_ds_allowed_to_delegate_to",
        value_type: ValueType::List,
        description: "msDS-AllowedToDelegateTo — the multi-valued list of Service Principal Names this account may obtain service tickets for on a user's behalf (classic constrained delegation). Each SPN names a downstream service reachable from this account; read it as the blast radius of compromising this account",
        is_uid_component: false,
    },
    FieldSchema {
        name: "ms_ds_allowed_to_act_on_behalf_of_other_identity",
        value_type: ValueType::Bytes,
        description: "msDS-AllowedToActOnBehalfOfOtherIdentity — a single-valued NT security descriptor on the RESOURCE account (Windows Server 2012 schema and later), naming which principals may act on behalf of other identities against services running as this account. The direction is inverted from msDS-AllowedToDelegateTo: parse the DACL and resolve each SID, because those principals are the ones that can reach this resource as any user",
        is_uid_component: false,
    },
    FieldSchema {
        name: "service_principal_name",
        value_type: ValueType::List,
        description: "servicePrincipalName values the account itself serves. Identifies what a delegation front-end actually is (HOST/, HTTP/, MSSQLSvc/, …) and lets you match another account's msDS-AllowedToDelegateTo entries back to this object",
        is_uid_component: false,
    },
    FieldSchema {
        name: "protected_users_member",
        value_type: ValueType::Bool,
        description: "Membership of the Protected Users group (SID S-1-5-<domain>-525), resolved from the account's group membership. At Windows Server 2012 R2 domain functional level members cannot be delegated by unconstrained OR constrained delegation, so this can rule out exposure independently of NOT_DELEGATED — Microsoft notes a protected member may show no 'Account is sensitive' setting at all, so check both",
        is_uid_component: false,
    },
    FieldSchema {
        name: "delegation_last_originating_change",
        value_type: ValueType::Timestamp,
        description: "Originating-change time for the delegation attribute, read from the object's replPropertyMetaData stamp (ftimeLastOriginatingChange in the public DS_REPL_ATTR_META_DATA form). This is what separates delegation that IT configured years ago from delegation written during the intrusion; the accompanying dwVersion counts originating modifications, and replication does not disturb either value",
        is_uid_component: false,
    },
];

/// Kerberos delegation configuration on an Active Directory account object.
///
/// Four settings decide whether compromising one account exposes other
/// principals, and all four are attributes of the account object inside the
/// same NTDS.dit the catalog already models as `ntds_dit`:
///
/// - `userAccountControl` TRUSTED_FOR_DELEGATION (0x00080000) — unconstrained
///   delegation. Microsoft's own description is that any service running under
///   the account can impersonate a client that requests the service.
/// - `userAccountControl` TRUSTED_TO_AUTH_FOR_DELEGATION (0x01000000) —
///   protocol transition; the KDC marks the account's S4U2self service tickets
///   forwardable.
/// - `msDS-AllowedToDelegateTo` — the SPN list for classic constrained
///   delegation, held on the front-end account.
/// - `msDS-AllowedToActOnBehalfOfOtherIdentity` — the resource-side security
///   descriptor (Windows Server 2012 schema and later) naming who may act on
///   behalf of others against this account's services.
///
/// Two settings work the other way and let a principal be ruled OUT:
/// `userAccountControl` NOT_DELEGATED (0x00100000), which stops the account's
/// tickets being marked forwardable or proxiable, and Protected Users
/// membership, which at Windows Server 2012 R2 domain functional level blocks
/// both constrained and unconstrained delegation.
///
/// [MS-SFU] states the mapping directly: the KDC's
/// ServicesAllowedToSendForwardedTicketsTo is backed by
/// `msDS-AllowedToDelegateTo`, ServicesAllowedToReceiveForwardedTicketsFrom by
/// `msDS-AllowedToActOnBehalfOfOtherIdentity`, DelegationNotAllowed by the ND
/// flag, and TrustedToAuthenticationForDelegation by the TA flag.
///
/// Source: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/dd302fd1-0aa7-406b-ad91-2a6b35738557>
/// Source: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/0b4d13c4-d459-4598-8f08-1584ca1e24c9>
/// Source: <https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-allowedtodelegateto>
/// Source: <https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-allowedtoactonbehalfofotheridentity>
pub(crate) static AD_ACCOUNT_DELEGATION_CONFIG: ArtifactDescriptor = ArtifactDescriptor {
    id: "ad_account_delegation_config",
    name: "AD Account Kerberos Delegation Configuration (NTDS.dit)",
    artifact_type: ArtifactLocation::EseDatabase,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Windows\NTDS\NTDS.dit"),
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::EseDatabase,
    meaning: "Kerberos delegation trust configuration of one Active Directory account object, read \
from the same NTDS.dit ESE database as ntds_dit. It answers a question the credential material does \
not: which principals a compromised account can impersonate, and which accounts are shielded. Four \
settings grant delegation. userAccountControl TRUSTED_FOR_DELEGATION (0x00080000 / 524288) is \
unconstrained delegation — Microsoft's description is that any service running under the account can \
impersonate a client requesting the service, so every principal that authenticated to the host is \
potentially exposed. userAccountControl TRUSTED_TO_AUTH_FOR_DELEGATION (0x01000000 / 16777216) is \
protocol transition: per [MS-ADTS] the KDC sets the forwardable flag in the account's S4U2self \
service tickets, so it can assume a client identity without that client ever contacting it. \
msDS-AllowedToDelegateTo holds the multi-valued SPN list for classic constrained delegation on the \
FRONT-END account. msDS-AllowedToActOnBehalfOfOtherIdentity (Windows Server 2012 schema and later) \
is an NT security descriptor on the RESOURCE account naming who may act on behalf of other \
identities against services running as that account — the inverse direction, so it must be \
enumerated resource-side or it is missed entirely. Two settings deny delegation and are how an \
account is ruled OUT: userAccountControl NOT_DELEGATED (0x00100000 / 1048576), the 'Account is \
sensitive and cannot be delegated' setting, under which the account's TGTs and service tickets are \
not marked forwardable or proxiable; and Protected Users membership (SID S-1-5-<domain>-525), which \
at Windows Server 2012 R2 domain functional level blocks unconstrained AND constrained delegation. \
[MS-SFU] ties the KDC behaviour to these attributes by name. Read the replPropertyMetaData \
originating-change stamp for the delegation attribute to date the configuration — that is what \
separates a long-standing IT design from an attacker write. Cross-reference ntds_dit for the \
credential material in the same database.",
    mitre_techniques: &[
        "T1098",     // Account Manipulation — writing a delegation attribute onto an account
        "T1550.003", // Use Alternate Authentication Material: Pass the Ticket
    ],
    fields: AD_ACCOUNT_DELEGATION_CONFIG_FIELDS,
    retention: Some("Persists in the directory until the attribute is changed; historical values are not retained on the object, only the replPropertyMetaData stamp of the most recent originating change"),
    triage_priority: TriagePriority::High,
    related_artifacts: &["ntds_dit", "evtx_security"],
    sources: &[
        // MS-ADTS 2.2.16 — TD 0x00080000, ND 0x00100000, TA 0x01000000 and their Kerberos semantics:
        "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/dd302fd1-0aa7-406b-ad91-2a6b35738557",
        // MS — the full flag table in hex and decimal, plus the documented defaults (typical user 0x200, workstation/server 0x1000, domain controller 0x82000):
        "https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties",
        // MS-SFU Abstract Data Model — ServicesAllowedToSendForwardedTicketsTo -> msDS-AllowedToDelegateTo; ServicesAllowedToReceiveForwardedTicketsFrom -> msDS-AllowedToActOnBehalfOfOtherIdentity; DelegationNotAllowed -> ND flag; TrustedToAuthenticationForDelegation -> TA flag:
        "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/0b4d13c4-d459-4598-8f08-1584ca1e24c9",
        // MS-SFU — S4U2self and S4U2proxy let an application service obtain a Kerberos service ticket on behalf of a user:
        "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/3bff5864-8135-400e-bdd9-33b552051d94",
        // AD schema — msDS-AllowedToDelegateTo: multi-valued String(Unicode) list of SPNs, Windows Server 2003 and later:
        "https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-allowedtodelegateto",
        // AD schema — msDS-AllowedToActOnBehalfOfOtherIdentity: single-valued String(NT-Sec-Desc), Windows Server 2012:
        "https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-allowedtoactonbehalfofotheridentity",
        // MS — Protected Users restrictions at Windows Server 2012 R2 DFL, including "Be delegated by using unconstrained or constrained delegation":
        "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/how-to-configure-protected-accounts",
        // MS — Protected Users SID S-1-5-<domain>-525:
        "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers",
        // AD schema — replPropertyMetaData tracks replication state for every DS object:
        "https://learn.microsoft.com/en-us/windows/win32/adschema/a-replpropertymetadata",
        // MS — DS_REPL_ATTR_META_DATA, the public form of the per-attribute stamp (dwVersion, ftimeLastOriginatingChange, uuidLastOriginatingDsaInvocationID, usnOriginatingChange):
        "https://learn.microsoft.com/en-us/windows/win32/api/ntdsapi/ns-ntdsapi-ds_repl_attr_meta_data",
    ],
    evidence_strength: Some(crate::evidence::EvidenceStrength::Strong),
    evidence_tier: None,
    evidence_caveats: &[
        "Delegation is a supported product feature with legitimate deployments — IIS/SQL tiers, print and file servers, and management tooling routinely use constrained delegation. The configuration establishes EXPOSURE, not that it was abused; corroborate with ticket-request evidence before concluding use",
        "TRUSTED_FOR_DELEGATION on a domain controller computer account is the documented default, not an anomaly: Microsoft gives the default domain-controller userAccountControl as 0x82000, which is SERVER_TRUST_ACCOUNT (0x2000) plus TRUSTED_FOR_DELEGATION (0x80000)",
        "msDS-AllowedToActOnBehalfOfOtherIdentity points the opposite way to msDS-AllowedToDelegateTo — it sits on the resource being reached, not on the account doing the reaching. Enumerating only front-end accounts misses resource-based delegation entirely",
        "msDS-AllowedToActOnBehalfOfOtherIdentity is a security descriptor, not a name list: a populated value says nothing until the DACL is parsed and each SID resolved back to a named principal",
        "NOT_DELEGATED and Protected Users membership are independent shields — Microsoft notes that a Protected Users member may have no 'Account is sensitive and cannot be delegated' setting configured, so an account with the flag clear can still be protected. Check both before reporting a principal as exposed",
        "Protected Users delegation blocking requires Windows Server 2012 R2 domain functional level; below that DFL, membership alone does not stop delegation",
        "The object stores only the current value. A delegation attribute that was set and then reverted leaves no value behind — the replPropertyMetaData stamp records the time and version of the most recent originating change, not a history",
    ],
    volatility: Some(crate::volatility::VolatilityClass::Persistent),
    volatility_rationale: "Directory attribute in the AD database; persists until the attribute is rewritten or the account is deleted",
};
