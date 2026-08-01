package com.cognesis.framework.trust;

/**
 * Tuning parameters for the FIDES trust engine.
 *
 * @param defaultTrust                 trust assigned to never-seen entities
 * @param positiveGain                 alpha_p in the update rule
 * @param negativeGain                 alpha_n (asymmetric, usually &gt; alpha_p)
 * @param decayRate                    lambda: rate of regression toward neutral
 * @param observationsForFullConfidence N0: observations at which confidence ~= 0.63
 * @param trustGraphInfluence          share of neighbour influence in graph mode
 */
public record TrustProperties(
        double defaultTrust,
        double positiveGain,
        double negativeGain,
        double decayRate,
        double observationsForFullConfidence,
        double trustGraphInfluence) {

    public static TrustProperties defaults() {
        return new TrustProperties(0.5, 0.15, 0.35, 0.005, 60.0, 0.30);
    }

    public TrustProperties {
        defaultTrust = clamp(defaultTrust);
        positiveGain = clamp(positiveGain);
        negativeGain = clamp(negativeGain);
        decayRate = Math.max(0.0, decayRate);
        observationsForFullConfidence = Math.max(1.0, observationsForFullConfidence);
        trustGraphInfluence = clamp(trustGraphInfluence);
    }

    private static double clamp(double v) {
        return Math.max(0.0, Math.min(1.0, v));
    }
}
