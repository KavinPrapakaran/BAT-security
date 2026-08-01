package com.cognesis.framework.trust;

import java.time.Instant;
import java.util.List;

/**
 * Result of a trust assessment: the dynamic trust value plus the confidence in
 * it and a summary of the observation history that produced it.
 */
public record TrustAssessment(
        String entityId,
        double trust,
        double confidence,
        long observationCount,
        Instant lastUpdated,
        List<TrustEvent> recentEvents) {

    public TrustAssessment {
        recentEvents = recentEvents != null ? List.copyOf(recentEvents) : List.of();
    }
}
