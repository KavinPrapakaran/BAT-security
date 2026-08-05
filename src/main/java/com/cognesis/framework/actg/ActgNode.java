package com.cognesis.framework.actg;

import java.time.Instant;
import java.util.Map;

/**
 * A node in the ACTG graph: an entity plus its accumulated risk and last
 * observed time. {@code risk} is an aggregate of everything the framework has
 * seen about this entity.
 */
public record ActgNode(
        String key,
        ActgEntityType entityType,
        String label,
        double risk,
        Instant lastSeen,
        Map<String, Object> properties) {

    public ActgNode {
        risk = Math.max(0.0, Math.min(1.0, risk));
        properties = properties != null ? Map.copyOf(properties) : Map.of();
    }

    public static String key(ActgEntityType entityType, String id) {
        return entityType.name() + ":" + id;
    }
}
