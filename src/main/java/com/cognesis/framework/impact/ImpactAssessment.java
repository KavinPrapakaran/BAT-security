package com.cognesis.framework.impact;

/**
 * Output of the RESOLVE impact engine.
 *
 * @param businessImpact value-at-risk in [0,1] (this becomes B in SYNAPSE)
 * @param topAsset       asset driving the impact score, if any
 * @param rationale      why this impact was chosen
 */
public record ImpactAssessment(double businessImpact, String topAsset, String rationale) {

    public ImpactAssessment {
        businessImpact = Math.max(0.0, Math.min(1.0, businessImpact));
    }
}
