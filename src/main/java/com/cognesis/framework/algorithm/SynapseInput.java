package com.cognesis.framework.algorithm;

import com.cognesis.framework.common.EvidenceConfidence;

/**
 * All inputs to the SYNAPSE decision algorithm. Every value is normalized to
 * [0,1] so the fusion math is dimension-free and explainable.
 *
 * @param evidenceStrength    E - fused strength of current evidence (OBSERVATORY)
 * @param trust               T - entity trust in [0,1], 1 = fully trusted (FIDES)
 * @param memorySalience      M - salience of recalled history (MNEMONIC)
 * @param intent              I - probability of malicious intent (MOTIVE)
 * @param prediction          P - predicted near-future risk (SEER)
 * @param businessImpact      B - value at risk, 0..1 (RESOLVE)
 * @param historicalDeviation H - deviation from behavioural baseline (MNEMONIC)
 * @param contextWeight       C - situational context coverage, 0..1 (RESOLVE)
 * @param trustConfidence     confidence of the trust estimate, 0..1 (FIDES)
 * @param confidence          evidence quality factors (OBSERVATORY)
 */
public record SynapseInput(
        double evidenceStrength,
        double trust,
        double memorySalience,
        double intent,
        double prediction,
        double businessImpact,
        double historicalDeviation,
        double contextWeight,
        double trustConfidence,
        EvidenceConfidence confidence) {

    public SynapseInput {
        evidenceStrength = clamp(evidenceStrength);
        trust = clamp(trust);
        memorySalience = clamp(memorySalience);
        intent = clamp(intent);
        prediction = clamp(prediction);
        businessImpact = clamp(businessImpact);
        historicalDeviation = clamp(historicalDeviation);
        contextWeight = clamp(contextWeight);
        trustConfidence = clamp(trustConfidence);
        confidence = confidence != null ? confidence : EvidenceConfidence.neutral();
    }

    private static double clamp(double v) {
        return Math.max(0.0, Math.min(1.0, v));
    }
}
