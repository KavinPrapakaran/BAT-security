package com.cognesis.framework.observatory;

import com.cognesis.framework.common.EvidenceConfidence;

import java.util.List;

/**
 * The fused output of the OBSERVATORY evidence aggregator: a single evidence
 * strength E and the quality factors that become SYNAPSE's confidence inputs.
 */
public record AggregatedEvidence(
        double evidenceStrength,
        EvidenceConfidence confidence,
        List<EvidenceFragment> fragments) {

    public AggregatedEvidence {
        evidenceStrength = Math.max(0.0, Math.min(1.0, evidenceStrength));
        fragments = fragments != null ? List.copyOf(fragments) : List.of();
    }
}
