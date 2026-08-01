package com.cognesis.framework.common;

/**
 * Confidence factors that qualify how much the evidence pool can be believed.
 * <ul>
 *   <li>agreement  - how much the evidence sources agree (1 - dispersion)</li>
 *   <li>coverage   - fraction of expected signal types that were observed</li>
 *   <li>freshness  - age-weighted recency of the observations</li>
 *   <li>provenance - average reliability of the evidence sources</li>
 * </ul>
 * All values are in [0,1].
 */
public record EvidenceConfidence(
        double agreement,
        double coverage,
        double freshness,
        double provenanceQuality) {

    public EvidenceConfidence {
        agreement = clamp(agreement);
        coverage = clamp(coverage);
        freshness = clamp(freshness);
        provenanceQuality = clamp(provenanceQuality);
    }

    public static EvidenceConfidence neutral() {
        return new EvidenceConfidence(0.5, 0.3, 0.5, 0.5);
    }

    private static double clamp(double v) {
        return Math.max(0.0, Math.min(1.0, v));
    }
}
