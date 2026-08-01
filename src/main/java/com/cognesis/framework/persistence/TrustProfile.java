package com.cognesis.framework.persistence;

import java.time.Instant;

/**
 * Snapshot of an entity's trust profile for persistence.
 */
public record TrustProfile(
        String entityId,
        String entityType,
        double trust,
        double confidence,
        long observationCount,
        Instant lastUpdated) {
}
