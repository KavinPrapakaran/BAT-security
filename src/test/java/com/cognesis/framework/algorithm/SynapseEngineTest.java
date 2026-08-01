package com.cognesis.framework.algorithm;

import com.cognesis.framework.common.Decision;
import com.cognesis.framework.common.EvidenceConfidence;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SynapseEngineTest {

    private final SynapseEngine engine = new SynapseEngine(DecisionBandPolicy.defaults());
    private final SynapseWeights weights = SynapseWeights.defaults();

    private SynapseInput input(double evidence, double trust, double impact) {
        return new SynapseInput(evidence, trust, 0.1, evidence * 0.9, evidence * 0.8, impact,
                0.2, 0.8, 0.9, new EvidenceConfidence(0.8, 0.8, 0.9, 0.8));
    }

    @Test
    void highEvidenceAndLowTrustBlocks() {
        SynapseDecision d = engine.evaluate(input(0.95, 0.1, 0.8), weights);
        assertEquals(Decision.BLOCK, d.decision());
        assertTrue(d.riskScore() > 0.8);
        assertTrue(d.likelihoodScore() > 0.7);
    }

    @Test
    void highTrustAndLowEvidenceAllows() {
        SynapseDecision d = engine.evaluate(input(0.05, 0.95, 0.6), weights);
        assertEquals(Decision.ALLOW, d.decision());
        assertTrue(d.riskScore() < 0.3);
    }

    @Test
    void highImpactShiftsRiskUpEvenWhenLikelihoodIsModerate() {
        SynapseDecision lowImpact = engine.evaluate(input(0.5, 0.5, 0.2), weights);
        SynapseDecision highImpact = engine.evaluate(input(0.5, 0.5, 0.95), weights);
        assertTrue(highImpact.riskScore() > lowImpact.riskScore());
    }

    @Test
    void lowConfidenceEscalatesDecision() {
        SynapseInput uncertain = new SynapseInput(0.1, 0.5, 0.1, 0.1, 0.1, 0.5,
                0.1, 0.1, 0.1, new EvidenceConfidence(0.2, 0.1, 0.1, 0.1));
        SynapseDecision d = engine.evaluate(uncertain, weights);
        assertTrue(d.decision() == Decision.WARN || d.decision() == Decision.MONITOR,
                "uncertain evidence should escalate past ALLOW, got " + d.decision());
    }

    @Test
    void allScoresWithinUnitInterval() {
        for (double e = 0.0; e <= 1.0; e += 0.25) {
            SynapseDecision d = engine.evaluate(input(e, 0.5, 0.5), weights);
            assertTrue(d.riskScore() >= 0 && d.riskScore() <= 1);
            assertTrue(d.confidenceScore() >= 0 && d.confidenceScore() <= 1);
            assertTrue(d.businessImpactScore() >= 0 && d.businessImpactScore() <= 1);
        }
    }

    @Test
    void decisionBandsAreOrdered() {
        DecisionBandPolicy policy = new DecisionBandPolicy(0.3, 0.55, 0.8, 1.0, 0.2, false);
        assertEquals(Decision.ALLOW, policy.mapRisk(0.1, 0.9));
        assertEquals(Decision.WARN, policy.mapRisk(0.45, 0.9));
        assertEquals(Decision.MONITOR, policy.mapRisk(0.65, 0.9));
        assertEquals(Decision.BLOCK, policy.mapRisk(0.9, 0.9));
    }
}
