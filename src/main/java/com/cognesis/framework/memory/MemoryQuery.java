package com.cognesis.framework.memory;

import java.util.List;

/**
 * A recall request against the memory engine.
 *
 * @param entityId       entity to recall memories about
 * @param entityType     type of that entity
 * @param includeRelated whether to also return strongly-related neighbours
 * @param limit          max items returned
 */
public record MemoryQuery(String entityId, String entityType, boolean includeRelated, int limit) {

    public MemoryQuery(String entityId, String entityType) {
        this(entityId, entityType, true, 20);
    }

    public MemoryQuery {
        limit = Math.max(1, Math.min(200, limit));
    }
}
