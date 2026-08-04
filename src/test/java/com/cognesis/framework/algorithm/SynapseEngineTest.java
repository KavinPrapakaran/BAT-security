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
    void highEvidenceAndLowTrustIsolateOrBlock() {
        SynapseDecision d = engine.evaluate(input(0.95, 0.1, 0.8), weights);
        assertTrue(d.decision() == Decision.ISOLATE || d.decision() == Decision.BLOCK,
                "high evidence + low trust must land in a containment band, got " + d.decision());
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
        assertTrue(d.decision() == Decision.CHALLENGE || d.decision() == Decision.ESCALATE,
                "uncertain evidence should escalate up the ladder, got " + d.decision());
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
    void sevenDecisionBandsAreOrdered() {
        DecisionBandPolicy policy = DecisionBandPolicy.defaults();
        assertEquals(Decision.ALLOW, policy.mapRisk(0.1, 0.9));
        assertEquals(Decision.MONITOR, policy.mapRisk(0.35, 0.9));
        assertEquals(Decision.WARN, policy.mapRisk(0.5, 0.9));
        assertEquals(Decision.CHALLENGE, policy.mapRisk(0.6, 0.9));
        assertEquals(Decision.ESCALATE, policy.mapRisk(0.7, 0.9));
        assertEquals(Decision.ISOLATE, policy.mapRisk(0.85, 0.9));
        assertEquals(Decision.BLOCK, policy.mapRisk(0.95, 0.9));
    }
}
