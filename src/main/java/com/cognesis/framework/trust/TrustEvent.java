package com.cognesis.framework.trust;

import java.time.Instant;

/**
 * A single observation that moves an entity's trust.
 *
 * @param entityId  affected entity
 * @param eventType POSITIVE | NEGATIVE | DECAY
 * @param strength  magnitude in [0,1]
 * @param narrative human-readable description of why the event happened
 */
public record TrustEvent(
        String entityId,
        EventType eventType,
        double strength,
        String narrative,
        Instant occurredAt) {

    public enum EventType {
        POSITIVE,
        NEGATIVE,
        DECAY
    }

    public TrustEvent {
        occurredAt = occurredAt != null ? occurredAt : Instant.now();
        strength = Math.max(0.0, Math.min(1.0, strength));
    }

    public TrustEvent(String entityId, EventType eventType, double strength, String narrative) {
        this(entityId, eventType, strength, narrative, Instant.now());
    }
}
