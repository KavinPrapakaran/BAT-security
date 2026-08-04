package com.cognesis.framework.common;

/**
 * The seven canonical security decisions emitted by the COGNESIS framework.
 * Ordered from least to most restrictive so that comparison and escalation
 * logic can rely on {@link #ordinal()}.
 *
 * <pre>
 *   ALLOW      - no adversarial signal worth acting on
 *   MONITOR    - noteworthy; keep passive watch and telemetry
 *   WARN       - present to the operator as a warning
 *   CHALLENGE  - require additional verification (re-auth, MFA, step-up)
 *   ESCALATE   - hand to a human analyst / raise priority
 *   ISOLATE    - contain the entity (quarantine) but keep it observable
 *   BLOCK      - deny outright
 * </pre>
 */
public enum Decision {
    ALLOW,
    MONITOR,
    WARN,
    CHALLENGE,
    ESCALATE,
    ISOLATE,
    BLOCK
}
