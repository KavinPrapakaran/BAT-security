package com.cognesis.framework.context;

/**
 * Output of the CONTEXT engine.
 *
 * @param contextRisk   situational risk modifier in [0,1] (0.5 = neutral environment)
 * @param contextWeight how much the environment informs this decision in [0,1]
 * @param description   human-readable description of the environment
 */
public record ContextAssessment(
        double contextRisk,
        double contextWeight,
        String description) {

    public ContextAssessment {
        contextRisk = clamp(contextRisk);
        contextWeight = clamp(contextWeight);
    }

    private static double clamp(double v) {
        return Math.max(0.0, Math.min(1.0, v));
    }
}
