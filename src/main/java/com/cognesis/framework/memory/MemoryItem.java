package com.cognesis.framework.memory;

import java.time.Instant;
import java.util.Map;

/**
 * A remembered entity surfaced by a memory recall, annotated with its current
 * activation (salience). Higher activation = more influential on the next
 * decision.
 */
public record MemoryItem(
        String nodeKey,
        String nodeType,
        String label,
        double activation,
        double baseWeight,
        Instant lastSeen,
        Map<String, Object> properties) {

    public MemoryItem {
        properties = properties != null ? Map.copyOf(properties) : Map.of();
    }
}
