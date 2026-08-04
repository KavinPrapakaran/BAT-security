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

    /**
     * Semantic trust events for realistic trust evolution. A trust score is
     * never static: environmental changes and confirmed behaviour move it down,
     * exactly as an analyst's opinion would.
     */
    public static final class Events {

        private Events() {
        }

        public static TrustEvent certificateChanged(String entityId) {
            return new TrustEvent(entityId, EventType.NEGATIVE, 0.4,
                    "certificate changed unexpectedly");
        }

        public static TrustEvent dnsChanged(String entityId) {
            return new TrustEvent(entityId, EventType.NEGATIVE, 0.3,
                    "DNS infrastructure changed unexpectedly");
        }

        public static TrustEvent suspiciousBehaviour(String entityId, String detail) {
            return new TrustEvent(entityId, EventType.NEGATIVE, 0.7,
                    "suspicious behaviour: " + detail);
        }

        public static TrustEvent maliciousConfirmed(String entityId) {
            return new TrustEvent(entityId, EventType.NEGATIVE, 1.0,
                    "malicious activity confirmed");
        }

        public static TrustEvent positive(String entityId, String detail) {
            return new TrustEvent(entityId, EventType.POSITIVE, 0.8,
                    detail == null ? "positive observation" : detail);
        }
    }
}
