package com.cognesis.framework.common;

/**
 * Concrete operational actions recommended by the PACT recommendation engine.
 * These are the actuators the framework suggests to a downstream security stack
 * (firewall, EDR, identity provider, analyst queue, etc.).
 */
public enum RecommendedAction {
    ALLOW,
    ALERT_ONLY,
    ESCALATE_TO_ANALYST,
    ENRICH_INTELLIGENCE,
    INCREASE_MONITORING,
    REQUIRE_MFA,
    QUARANTINE_ENDPOINT,
    BLOCK_DOMAIN,
    BLOCK_IP,
    BLOCK_USER,
    REVOKE_CERTIFICATE,
    ISOLATE_ASSET
}
