package com.cognesis.framework.algorithm;

import com.cognesis.framework.common.Decision;

/**
 * Numeric output of the SYNAPSE algorithm before the orchestrator attaches the
 * reasoning chain and recommended action.
 *
 * @param riskScore           R - blended decision risk in [0,1]
 * @param likelihoodScore     L - probability the entity/behaviour is malicious in [0,1]
 * @param confidenceScore     K - overall confidence in [0,1]
 * @param businessImpactScore B - value at risk in [0,1]
 * @param decision            mapped verdict: ALLOW | WARN | MONITOR | BLOCK
 */
public record SynapseDecision(
        double riskScore,
        double likelihoodScore,
        double confidenceScore,
        double businessImpactScore,
        Decision decision) {
}
