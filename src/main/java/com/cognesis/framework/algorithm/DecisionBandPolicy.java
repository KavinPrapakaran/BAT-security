package com.cognesis.framework.algorithm;

import com.cognesis.framework.common.Decision;

/**
 * Maps the continuous risk score R and confidence K into one of the seven
 * canonical decisions using risk-tolerance-scaled thresholds.
 * <p>
 * Thresholds are scaled by a per-asset tolerance factor {@code tolerance} in
 * (0, 2]. tolerance &lt; 1 makes the estate stricter (lower thresholds),
 * tolerance &gt; 1 is more permissive. An optional low-confidence escalation
 * nudges a decision one rung up the ladder (ALLOW-&gt;MONITOR-&gt;WARN-&gt;
 * CHALLENGE-&gt;ESCALATE-&gt;ISOLATE) when the evidence pool is too uncertain
 * to be believed.
 */
public record DecisionBandPolicy(
        double monitor,
        double warn,
        double challenge,
        double escalate,
        double isolate,
        double block,
        double tolerance,
        double lowConfidenceThreshold,
        boolean escalateWhenUncertain) {

    public static DecisionBandPolicy defaults() {
        return new DecisionBandPolicy(0.30, 0.45, 0.58, 0.68, 0.82, 0.92, 1.0, 0.25, true);
    }

    public DecisionBandPolicy {
        monitor = clamp(monitor);
        warn = clamp(warn);
        challenge = clamp(challenge);
        escalate = clamp(escalate);
        isolate = clamp(isolate);
        block = clamp(block);
        tolerance = Math.max(0.05, tolerance);
        lowConfidenceThreshold = clamp(lowConfidenceThreshold);
    }

    public Decision mapRisk(double risk, double confidence) {
        double m = clamp(monitor * tolerance);
        double w = clamp(Math.max(warn * tolerance, m + 0.01));
        double c = clamp(Math.max(challenge * tolerance, w + 0.01));
        double e = clamp(Math.max(escalate * tolerance, c + 0.01));
        double i = clamp(Math.max(isolate * tolerance, e + 0.01));
        double b = clamp(Math.max(block * tolerance, i + 0.01));

        Decision decision;
        if (risk >= b) {
            decision = Decision.BLOCK;
        } else if (risk >= i) {
            decision = Decision.ISOLATE;
        } else if (risk >= e) {
            decision = Decision.ESCALATE;
        } else if (risk >= c) {
            decision = Decision.CHALLENGE;
        } else if (risk >= w) {
            decision = Decision.WARN;
        } else if (risk >= m) {
            decision = Decision.MONITOR;
        } else {
            decision = Decision.ALLOW;
        }

        if (escalateWhenUncertain && confidence < lowConfidenceThreshold) {
            decision = promote(decision);
        }
        return decision;
    }

    /** One rung up the severity ladder; BLOCK is the ceiling. */
    private static Decision promote(Decision decision) {
        return switch (decision) {
            case ALLOW -> Decision.MONITOR;
            case MONITOR -> Decision.WARN;
            case WARN -> Decision.CHALLENGE;
            case CHALLENGE -> Decision.ESCALATE;
            case ESCALATE -> Decision.ISOLATE;
            case ISOLATE, BLOCK -> decision;
        };
    }

    private static double clamp(double v) {
        return Math.max(0.0, Math.min(1.0, v));
    }
}
