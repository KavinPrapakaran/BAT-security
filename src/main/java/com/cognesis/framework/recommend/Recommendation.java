package com.cognesis.framework.recommend;

import com.cognesis.framework.common.RecommendedAction;

/**
 * Output of the PACT recommendation engine: a concrete actuator recommendation
 * plus a human-readable justification.
 */
public record Recommendation(
        RecommendedAction action,
        String target,
        String justification) {

    public Recommendation(RecommendedAction action, String target) {
        this(action, target, "no justification provided");
    }
}
