package com.cognesis.framework.common;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * The final, fully explainable outcome of a BAT security decision.
 * Produced by the decision orchestrator after fusing every reasoning engine.
 */
public record DecisionResult(
        UUID decisionId,
        String entityId,
        String entityType,
        Decision decision,
        RecommendedAction recommendedAction,
        double riskScore,
        double trustScore,
        double confidenceScore,
        double businessImpactScore,
        String rationale,
        List<ReasoningStep> reasoningChain,
        Instant decidedAt) {

    public DecisionResult {
        decisionId = decisionId != null ? decisionId : UUID.randomUUID();
        decidedAt = decidedAt != null ? decidedAt : Instant.now();
        reasoningChain = reasoningChain != null ? List.copyOf(reasoningChain) : List.of();
    }
}
