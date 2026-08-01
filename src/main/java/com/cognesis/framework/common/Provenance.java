package com.cognesis.framework.common;

/**
 * Where a piece of evidence came from. Provenance feeds directly into the
 * confidence computation: high-assurance sources (live traffic, signed certs)
 * out-rank guessy ones (third-party OSINT feeds).
 */
public enum Provenance {
    LIVE_TRAFFIC,
    DNS_RESPONSE,
    CERTIFICATE_TRANSPARENCY,
    WHOIS,
    THREAT_INTEL_FEED,
    OSINT,
    PAST_DECISION,
    POLICY_ANNOTATION,
    ANALYST_INPUT,
    TELEMETRY,
    CONFIGURATION
}
