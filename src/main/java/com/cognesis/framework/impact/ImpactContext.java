package com.cognesis.framework.impact;

import java.util.List;

/**
 * Input to the RESOLVE impact engine.
 *
 * @param requestor         principal/process triggering the decision
 * @param affectedAssetIds  asset ids potentially at risk
 * @param activity          description of the action under evaluation
 */
public record ImpactContext(String requestor, List<String> affectedAssetIds, String activity) {

    public ImpactContext {
        affectedAssetIds = affectedAssetIds != null ? List.copyOf(affectedAssetIds) : List.of();
    }

    public ImpactContext(String requestor) {
        this(requestor, List.of(), "unknown-activity");
    }
}
