package com.cognesis.framework.learning;

import java.util.UUID;

/**
 * Ground-truth feedback about a past decision, used by LORE to adapt the
 * SYNAPSE weights online.
 *
 * @param decisionId   the decision being evaluated
 * @param realizedRisk analyst/automated label of how risky it really was (0..1)
 * @param wasCorrect   whether the framework's verdict was correct in hindsight
 * @param notes        free-text annotation
 */
public record Outcome(UUID decisionId, double realizedRisk, boolean wasCorrect, String notes) {

    public Outcome {
        realizedRisk = Math.max(0.0, Math.min(1.0, realizedRisk));
    }
}
