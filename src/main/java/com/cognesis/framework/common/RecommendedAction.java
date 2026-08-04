package com.cognesis.framework.common;

/**
 * Concrete operational actions recommended by the PACT recommendation engine.
 * These are the actuators the framework suggests to a downstream security stack
 * (firewall, EDR, identity provider, analyst queue, etc.).
 */
public enum RecommendedAction {
    NONE,
    ALLOW,
    ALERT_ONLY,
    MONITOR_ONGOING,
    WARN_NOTIFY,
    CHALLENGE_VERIFY,
    REQUIRE_MFA,
    ESCALATE_TO_ANALYST,
    ENRICH_INTELLIGENCE,
    INCREASE_MONITORING,
    RATE_LIMIT,
    QUARANTINE_DOMAIN,
    QUARANTINE_IP,
    SUSPEND_ACCOUNT,
    QUARANTINE_ENDPOINT,
    ISOLATE_ASSET,
    BLOCK_DOMAIN,
    BLOCK_IP,
    BLOCK_USER,
    REVOKE_CERTIFICATE
}
