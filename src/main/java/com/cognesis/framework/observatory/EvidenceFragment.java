package com.cognesis.framework.observatory;

import com.cognesis.framework.common.EvidenceType;
import com.cognesis.framework.common.Provenance;

import java.time.Instant;

/**
 * A normalized, self-describing piece of evidence. Everything the framework
 * reasons about - DNS signals today, Cloud/Identity/Email/API/IoT/Endpoint
 * tomorrow - arrives as evidence fragments so the decision core never changes
 * when a new domain of security telemetry is plugged in.
 *
 * @param entityId    entity the evidence is about
 * @param entityType  entity type (DOMAIN, IP, USER, ...)
 * @param type        evidence family
 * @param strength    how strongly this evidence indicates risk, [0,1]
 * @param confidence  reliability of this fragment, [0,1]
 * @param explanation audit-ready explanation
 * @param provenance  source class
 * @param observedAt  when the evidence was observed
 */
public record EvidenceFragment(
        String entityId,
        String entityType,
        EvidenceType type,
        double strength,
        double confidence,
        String explanation,
        Provenance provenance,
        Instant observedAt) {

    public EvidenceFragment {
        strength = Math.max(0.0, Math.min(1.0, strength));
        confidence = Math.max(0.0, Math.min(1.0, confidence));
        observedAt = observedAt != null ? observedAt : Instant.now();
    }
}
