package com.cognesis.framework.common;

/**
 * Taxonomy of evidence signal types. The core is designed so that new signal
 * families (DNS, Cloud, Identity, Email, API, IoT, Endpoint, Threat Intelligence)
 * plug into the observatory without touching the decision core.
 */
public enum EvidenceType {
    // DNS family
    DNS_DOMAIN_AGE,
    DNS_REGISTRAR_HISTORY,
    DNS_DNSSEC,
    DNS_FAST_FLUX,
    DNS_DGA,
    DNS_CERTIFICATE,
    DNS_WHOIS,
    DNS_TYPOSQUATTING,
    DNS_HOMOGRAPH,
    DNS_SUBDOMAIN_BEHAVIOUR,
    DNS_HISTORICAL_TRUST,
    ACTG,
    // Cross-cutting families
    POLICY,
    THREAT_MEMORY,
    USER_BEHAVIOUR,
    NETWORK_BEHAVIOUR,
    IDENTITY,
    EMAIL,
    // Email family (VOID)
    EMAIL_AUTH,
    EMAIL_SENDER_AGE,
    EMAIL_SPOOF,
    EMAIL_LINKS,
    EMAIL_ATTACHMENTS,
    EMAIL_SENDER_REP,
    CLOUD,
    API,
    IOT,
    ENDPOINT,
    THREAT_INTEL,
    CONTEXT
}
