package com.cognesis.framework.algorithm;

import com.cognesis.framework.common.EvidenceConfidence;
import com.cognesis.framework.math.LogitOps;

/**
 * SYNAPSE - SYNthesized Probabilistic Assessment of Network Security Evidence.
 * The original core decision algorithm of the BAT security framework.
 *
 * <h2>How it works</h2>
 * <pre>
 * 1. Likelihood. Trust (FIDES) defines a prior of maliciousness. Every reasoning
 *    engine contributes a signal s_k in [0,1]. SYNAPSE fuses the signals in
 *    log-odds space, scaling each contribution by its weight and reliability:
 *
 *        L = sigmoid( logit(0.5) + sum_k w_k * c_k * logit(s_k) )
 *
 *    where s_trust = 1 - T and its reliability is the trust confidence.
 *
 * 2. Impact blending. The compromise likelihood L is blended with the business
 *    impact B using a weighted geometric mean:
 *
 *        R = L^lambda * B^(1-lambda)
 *
 *    Lambda near 1 keeps the decision likelihood-driven; lambda near 0 makes
 *    the decision impact-driven (protecting crown jewels).
 *
 * 3. Confidence. Five factors combine via a weighted geometric mean:
 *    posterior decisiveness (1 - entropy), source agreement, coverage,
 *    freshness, and provenance quality, plus situational context.
 *
 * 4. Band mapping. R is mapped through DecisionBandPolicy into
 *    ALLOW | WARN | MONITOR | BLOCK, with risk-tolerance scaling and an
 *    optional low-confidence escalation.
 * </pre>
 */
public class SynapseEngine {

    private final DecisionBandPolicy bandPolicy;

    public SynapseEngine(DecisionBandPolicy bandPolicy) {
        this.bandPolicy = bandPolicy != null ? bandPolicy : DecisionBandPolicy.defaults();
    }

    /** The band policy used when no org-specific policy is supplied. */
    public DecisionBandPolicy bandPolicy() {
        return bandPolicy;
    }

    /**
     * Evaluate a single decision. This method is pure: it has no side effects
     * and can be unit-tested exhaustively.
     */
    public SynapseDecision evaluate(SynapseInput input, SynapseWeights weights) {
        return evaluate(input, weights, bandPolicy);
    }

    /**
     * Evaluate with a caller-supplied band policy (e.g. one scaled by an
     * organization's risk tolerance).
     */
    public SynapseDecision evaluate(SynapseInput input, SynapseWeights weights,
                                    DecisionBandPolicy band) {
        double[] strengths = {
                input.evidenceStrength(),
                input.memorySalience(),
                input.intent(),
                input.prediction(),
                input.historicalDeviation(),
                1.0 - input.trust()
        };
        double[] w = {
                weights.evidence(),
                weights.memory(),
                weights.intent(),
                weights.prediction(),
                weights.deviation(),
                weights.trust()
        };
        double[] c = {
                reliabilityOfEvidence(input.confidence()),
                input.confidence().freshness(),
                reliabilityOfIntent(input.confidence()),
                reliabilityOfPrediction(input.confidence()),
                reliabilityOfDeviation(input.confidence()),
                input.trustConfidence()
        };

        double likelihood = LogitOps.fusedProbability(0.5, strengths, w, c);
        double impact = LogitOps.clamp01(input.businessImpact());
        double risk = LogitOps.clamp01(Math.pow(likelihood, weights.likelihoodWeight())
                * Math.pow(impact, 1.0 - weights.likelihoodWeight()));

        double confidence = computeConfidence(input, likelihood);
        risk = LogitOps.clamp01(risk * (1.0 + 0.10 * (1.0 - LogitOps.clamp01(input.contextWeight()))));

        var decision = band.mapRisk(risk, confidence);
        return new SynapseDecision(risk, likelihood, confidence, impact, decision);
    }

    /** Fused confidence from evidence quality factors and posterior sharpness. */
    private double computeConfidence(SynapseInput input, double likelihood) {
        double decisiveness = LogitOps.decisiveness(likelihood);
        EvidenceConfidence q = input.confidence();
        // Weighted arithmetic mean: no single near-zero factor zeroes the
        // confidence (unlike a geometric mean), so sparse or disagreeing
        // evidence lowers confidence without annihilating it.
        double[] values = {
                decisiveness,
                q.agreement(),
                q.coverage(),
                q.freshness(),
                q.provenanceQuality(),
                LogitOps.clamp01(input.contextWeight())
        };
        double[] exponents = {0.25, 0.20, 0.15, 0.15, 0.15, 0.10};
        double k = 0.0;
        for (int i = 0; i < values.length; i++) {
            k += exponents[i] * LogitOps.clamp01(values[i]);
        }
        return LogitOps.clamp01(k);
    }

    private double reliabilityOfEvidence(EvidenceConfidence q) {
        return LogitOps.clamp01(q.provenanceQuality() * 0.7 + q.freshness() * 0.3);
    }

    private double reliabilityOfIntent(EvidenceConfidence q) {
        return LogitOps.clamp01(q.agreement() * 0.5 + q.provenanceQuality() * 0.5);
    }

    private double reliabilityOfPrediction(EvidenceConfidence q) {
        return LogitOps.clamp01(q.freshness() * 0.6 + q.agreement() * 0.4);
    }

    private double reliabilityOfDeviation(EvidenceConfidence q) {
        return LogitOps.clamp01(q.coverage() * 0.5 + q.freshness() * 0.5);
    }
}
