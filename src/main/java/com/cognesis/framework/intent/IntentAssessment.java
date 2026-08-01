package com.cognesis.framework.intent;

import java.util.Map;

/**
 * Output of the MOTIVE intent engine.
 *
 * @param intentProbability probability the behaviour is adversarial in [0,1]
 * @param primaryIntent     human-readable best guess (e.g. "PHISHING", "C2")
 * @param intentBreakdown   probability per intent category
 */
public record IntentAssessment(
        double intentProbability,
        String primaryIntent,
        Map<String, Double> intentBreakdown) {

    public IntentAssessment {
        intentBreakdown = intentBreakdown != null ? Map.copyOf(intentBreakdown) : Map.of();
        intentProbability = Math.max(0.0, Math.min(1.0, intentProbability));
    }
}
