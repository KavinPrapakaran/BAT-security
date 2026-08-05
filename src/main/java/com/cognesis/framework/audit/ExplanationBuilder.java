package com.cognesis.framework.audit;

import com.cognesis.framework.common.Decision;
import com.cognesis.framework.common.DecisionResult;
import com.cognesis.framework.common.ReasoningStep;

import java.util.List;

/**
 * AUDITOR - turns the numeric reasoning chain into a human-readable narrative.
 * This is what makes BAT security decisions defensible in an enterprise: every
 * verdict can be replayed to an analyst, a regulator, or a board member in
 * plain language.
 */
public final class ExplanationBuilder {

    private ExplanationBuilder() {
    }

    public static String buildRationale(String entityId, Decision decision,
                                        List<ReasoningStep> steps,
                                        double risk, double trust, double confidence, double impact) {
        StringBuilder sb = new StringBuilder();
        sb.append("Decision ").append(decision)
                .append(" for ").append(entityId)
                .append(": risk ").append(pct(risk))
                .append(", trust ").append(pct(trust))
                .append(", confidence ").append(pct(confidence))
                .append(", business impact ").append(pct(impact)).append(". ");
        if (steps.isEmpty()) {
            sb.append("No reasoning steps were produced.");
            return sb.toString();
        }
        sb.append("Reasoning: ");
        for (int i = 0; i < Math.min(steps.size(), 8); i++) {
            ReasoningStep step = steps.get(i);
            sb.append(step.engine()).append(" reports '").append(step.claim())
                    .append("' (score ").append(String.format("%.2f", step.score()))
                    .append(", confidence ").append(String.format("%.2f", step.confidence())).append(")");
            if (i < Math.min(steps.size(), 8) - 1) {
                sb.append("; ");
            }
        }
        return sb.toString();
    }

    /** A compact one-liner used in logs and dashboards. */
    public static String oneLine(DecisionResult result) {
        return String.format("%s %s risk=%.2f trust=%.2f conf=%.2f impact=%.2f -> %s",
                result.decision(), result.entityId(),
                result.riskScore(), result.trustScore(), result.confidenceScore(),
                result.businessImpactScore(), result.recommendedAction());
    }

    private static String pct(double v) {
        return String.format("%.0f%%", v * 100.0);
    }
}
