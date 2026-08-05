package com.cognesis.framework.learning;

import java.util.List;
import java.util.UUID;

/**
 * Ground-truth feedback about a past decision, used by LORE to adapt the
 * SYNAPSE weights online.
 *
 * @param decisionId      the decision being evaluated
 * @param realizedRisk    analyst/automated label of how risky it really was (0..1)
 * @param wasCorrect      whether the framework's verdict was correct in hindsight
 * @param kind            ground-truth classification of the entity
 * @param signalStrengths strengths (0..1) of the signals that drove the decision,
 *                        so LORE can reward or punish the exact senses that fired
 * @param notes           free-text annotation
 */
public record Outcome(UUID decisionId, double realizedRisk, boolean wasCorrect,
                      FeedbackKind kind, List<Double> signalStrengths, String notes) {

    public enum FeedbackKind {
        /** The entity really was malicious and the framework should strengthen the signal. */
        CONFIRMED_MALICIOUS,
        /** The entity was benign; the framework over-flagged and should weaken the signal. */
        FALSE_POSITIVE,
        /** The entity was benign and the framework correctly allowed it. */
        CONFIRMED_BENIGN
    }

    public Outcome {
        realizedRisk = Math.max(0.0, Math.min(1.0, realizedRisk));
        kind = kind != null ? kind : (wasCorrect ? FeedbackKind.CONFIRMED_BENIGN : FeedbackKind.FALSE_POSITIVE);
        signalStrengths = signalStrengths != null ? List.copyOf(signalStrengths) : List.of();
        notes = notes != null ? notes : "";
    }

    public Outcome(UUID decisionId, double realizedRisk, boolean wasCorrect, String notes) {
        this(decisionId, realizedRisk, wasCorrect, null, List.of(), notes);
    }
}
