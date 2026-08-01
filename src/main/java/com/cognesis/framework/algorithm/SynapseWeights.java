package com.cognesis.framework.algorithm;

/**
 * Tuning weights for SYNAPSE. The first six weights scale the per-signal log-odds
 * contributions; {@code likelihoodWeight} (lambda) chooses how the compromise
 * likelihood L and business impact B are blended into the decision risk R:
 * <pre>
 * R = L^lambda * B^(1-lambda)
 * </pre>
 * Lambda=1 means likelihood-only, lambda=0 means impact-only. Weights are
 * adapted online by the LORE learning engine.
 */
public record SynapseWeights(
        double evidence,
        double trust,
        double memory,
        double intent,
        double prediction,
        double deviation,
        double likelihoodWeight) {

    public static SynapseWeights defaults() {
        return new SynapseWeights(0.50, 0.15, 0.08, 0.08, 0.05, 0.04, 0.70);
    }

    public SynapseWeights {
        evidence = nonNegative(evidence);
        trust = nonNegative(trust);
        memory = nonNegative(memory);
        intent = nonNegative(intent);
        prediction = nonNegative(prediction);
        deviation = nonNegative(deviation);
        likelihoodWeight = clamp01(likelihoodWeight);
    }

    private static double nonNegative(double v) {
        return Math.max(0.0, v);
    }

    private static double clamp01(double v) {
        return Math.max(0.0, Math.min(1.0, v));
    }
}
