package com.cognesis.framework.orchestrator;

import java.util.List;
import java.util.Map;

/**
 * A general-purpose decision request handled by the orchestrator. Any entity
 * type (DOMAIN, IP, USER, DEVICE, API, EMAIL, ...) can be evaluated as long as
 * an evidence provider exists for it.
 *
 * @param entityId         entity under evaluation
 * @param entityType       entity type
 * @param requestor        principal requesting the decision
 * @param affectedAssetIds assets that could be affected
 * @param activity         what is being attempted
 * @param context          free-form situational context
 */
public record DecisionRequest(
        String entityId,
        String entityType,
        String requestor,
        List<String> affectedAssetIds,
        String activity,
        Map<String, Object> context) {

    public DecisionRequest {
        affectedAssetIds = affectedAssetIds != null ? List.copyOf(affectedAssetIds) : List.of();
        context = context != null ? Map.copyOf(context) : Map.of();
    }

    public DecisionRequest(String entityId, String entityType, String requestor) {
        this(entityId, entityType, requestor, List.of(), "unknown-activity", Map.of());
    }
}
