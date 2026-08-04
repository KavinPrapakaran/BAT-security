package com.cognesis.framework.context;

import java.util.Map;

/**
 * Input to the CONTEXT engine: the situational environment in which a decision
 * is being made.
 *
 * @param context    activity/context label (e.g. "dns-resolution", "authentication", "api-call")
 * @param entityType type of entity under evaluation
 * @param metadata   free-form situational facts (env, geo, sourceIp, ...)
 */
public record ContextInput(
        String context,
        String entityType,
        Map<String, Object> metadata) {

    public ContextInput {
        metadata = metadata != null ? Map.copyOf(metadata) : Map.of();
    }
}
