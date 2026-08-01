package com.cognesis.framework.math;

/**
 * Statistical helpers backing the SYNAPSE decision algorithm.
 * <p>
 * SYNAPSE fuses independent evidence signals in log-odds space and converts the
 * result back to a probability. Working in log-odds space is why contributions
 * from separate engines compose additively and can be attributed per-signal,
 * which is what makes every decision decomposable into an explainable chain.
 */
public final class LogitOps {

    private static final double EPSILON = 1e-6;
    private static final double CLAMP_LO = EPSILON;
    private static final double CLAMP_HI = 1.0 - EPSILON;

    private LogitOps() {
    }

    public static double clamp01(double v) {
        return Math.max(0.0, Math.min(1.0, v));
    }

    /** Sigmoid (logistic) function. Maps any real number into (0,1). */
    public static double sigmoid(double x) {
        if (x >= 0) {
            double e = Math.exp(-x);
            return 1.0 / (1.0 + e);
        }
        double e = Math.exp(x);
        return e / (1.0 + e);
    }

    /** Logit: the inverse of the sigmoid. Maps (0,1) into (-inf, +inf). */
    public static double logit(double p) {
        p = Math.max(CLAMP_LO, Math.min(CLAMP_HI, p));
        return Math.log(p / (1.0 - p));
    }

    /**
     * Bayesian-style belief fusion in log-odds space.
     *
     * <pre>
     * logit(posterior) = logit(prior)
     *                    + sum_k w_k * c_k * (logit(s_k) - logit(0.5))
     * </pre>
     *
     * Working relative to the neutral strength 0.5 means a neutral/absent signal
     * (s_k ~ 0.5) contributes nothing, strong signals push toward risk, and weak
     * signals (e.g. a policy allowlist) push toward safety.
     *
     * @param prior       prior probability of the hypothesis (e.g. "entity malicious")
     * @param strengths   per-signal hypothesis strengths s_k in [0,1]
     * @param weights     per-signal weights w_k (need not sum to 1)
     * @param reliability per-signal confidence c_k in [0,1]
     */
    public static double fusedProbability(double prior,
                                          double[] strengths,
                                          double[] weights,
                                          double[] reliability) {
        double odds = logit(prior);
        double neutral = logit(0.5);
        for (int k = 0; k < strengths.length; k++) {
            odds += weights[k] * reliability[k] * (logit(clamp01(strengths[k])) - neutral);
        }
        return sigmoid(odds);
    }

    /** Shannon entropy (bits) of a binary distribution with probability p. In [0,1]. */
    public static double binaryEntropy(double p) {
        p = clamp01(p);
        if (p <= EPSILON || p >= 1.0 - EPSILON) {
            return 0.0;
        }
        return -(p * log2(p) + (1.0 - p) * log2(1.0 - p));
    }

    /** Decisiveness of a posterior: 1 - entropy. High when the answer is clear. */
    public static double decisiveness(double p) {
        return 1.0 - binaryEntropy(p);
    }

    /**
     * Weighted geometric mean. Used where dimensions with different units must be
     * blended into one quantity (e.g. likelihood and business impact).
     */
    public static double weightedGeometricMean(double[] values, double[] exponents) {
        double sum = 0.0;
        double logSum = 0.0;
        for (int k = 0; k < values.length; k++) {
            double v = clamp01(values[k]);
            double e = exponents[k];
            sum += e;
            logSum += e * Math.log(Math.max(v, EPSILON));
        }
        if (sum <= 0.0) {
            return 0.0;
        }
        return Math.exp(logSum / sum);
    }

    private static double log2(double v) {
        return Math.log(v) / Math.log(2.0);
    }
}
