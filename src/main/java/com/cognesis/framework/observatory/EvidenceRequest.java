package com.cognesis.framework.observatory;

import java.util.Map;

/**
 * A request to gather evidence about an entity.
 *
 * @param entityId   entity under evaluation
 * @param entityType entity type
 * @param context    situational details (user, source ip, app, ...)
 */
public record EvidenceRequest(String entityId, String entityType, Map<String, Object> context) {

    public EvidenceRequest {
        context = context != null ? Map.copyOf(context) : Map.of();
    }

    public EvidenceRequest(String entityId, String entityType) {
        this(entityId, entityType, Map.of());
    }
}
