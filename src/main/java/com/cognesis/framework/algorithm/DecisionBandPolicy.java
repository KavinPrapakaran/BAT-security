package com.cognesis.framework.algorithm;

import com.cognesis.framework.common.Decision;

/**
 * Maps the continuous risk score R and confidence K into one of the four
 * canonical decisions using risk-tolerance-scaled thresholds.
 * <p>
 * Thresholds are scaled by a per-asset tolerance factor {@code tolerance} in
 * (0, 2]. tolerance &lt; 1 makes the estate stricter (lower thresholds),
 * tolerance &gt; 1 is more permissive. An optional low-confidence escalation
 * nudges ALLOW-&gt;WARN and WARN-&gt;MONITOR when the evidence pool is too
 * uncertain to be believed.
 */
public record DecisionBandPolicy(
        double warn,
        double monitor,
        double block,
        double tolerance,
        double lowConfidenceThreshold,
        boolean escalateWhenUncertain) {

    public static DecisionBandPolicy defaults() {
        return new DecisionBandPolicy(0.32, 0.55, 0.80, 1.0, 0.25, true);
    }

    public DecisionBandPolicy {
        warn = clamp(warn);
        monitor = clamp(monitor);
        block = clamp(block);
        tolerance = Math.max(0.05, tolerance);
        lowConfidenceThreshold = clamp(lowConfidenceThreshold);
    }

    public Decision mapRisk(double risk, double confidence) {
        double w = clamp(warn * tolerance);
        double m = clamp(Math.max(monitor * tolerance, w + 0.01));
        double b = clamp(Math.max(block * tolerance, m + 0.01));

        Decision decision;
        if (risk >= b) {
            decision = Decision.BLOCK;
        } else if (risk >= m) {
            decision = Decision.MONITOR;
        } else if (risk >= w) {
            decision = Decision.WARN;
        } else {
            decision = Decision.ALLOW;
        }

        if (escalateWhenUncertain && confidence < lowConfidenceThreshold) {
            decision = switch (decision) {
                case ALLOW -> Decision.WARN;
                case WARN -> Decision.MONITOR;
                case MONITOR -> Decision.MONITOR;
                case BLOCK -> Decision.BLOCK;
            };
        }
        return decision;
    }

    private static double clamp(double v) {
        return Math.max(0.0, Math.min(1.0, v));
    }
}
