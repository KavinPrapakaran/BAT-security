package com.cognesis.framework.acde;

import com.cognesis.framework.algorithm.DecisionBandPolicy;
import com.cognesis.framework.algorithm.SynapseEngine;
import com.cognesis.framework.algorithm.SynapseWeights;
import com.cognesis.framework.common.Decision;
import com.cognesis.framework.common.DecisionResult;
import com.cognesis.framework.context.SituationalContextEngine;
import com.cognesis.framework.impact.InMemoryAssetRegistry;
import com.cognesis.framework.impact.ResolveImpactEngine;
import com.cognesis.framework.intent.MotiveIntentEngine;
import com.cognesis.framework.learning.InMemoryWeightStore;
import com.cognesis.framework.memory.MnemonicMemoryEngine;
import com.cognesis.framework.observatory.EvidenceIngestor;
import com.cognesis.framework.persistence.DecisionLogDao;
import com.cognesis.framework.prediction.SeerPredictionEngine;
import com.cognesis.framework.profile.ProfileEvaluationEngine;
import com.cognesis.framework.recommend.PactRecommendationEngine;
import com.cognesis.framework.trust.FidesTrustEngine;
import com.cognesis.framework.trust.TrustProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * The organization profile must reach the real decision path: an org-scoped
 * rule hard-blocks inside the ACDE, and a different org is not affected.
 */
class OrgPolicyAcdeTest {

    private AcdeEngine acde;

    @BeforeEach
    void setUp() {
        acde = new AcdeEngine(
                List.of(), new EvidenceIngestor(), new FidesTrustEngine(TrustProperties.defaults()),
                new MnemonicMemoryEngine(0.02, 20),
                new SituationalContextEngine(), new SeerPredictionEngine(), new MotiveIntentEngine(),
                new ResolveImpactEngine(new InMemoryAssetRegistry()), new PactRecommendationEngine(),
                new SynapseEngine(DecisionBandPolicy.defaults()),
                new InMemoryWeightStore(SynapseWeights.defaults()),
                new DecisionLogDao() {
                }, null, ProfileEvaluationEngine.withDefaults());
    }

    @Test
    void orgScopedRuleHardBlocksInsideAcde() {
        DecisionResult result = acde.evaluate(new DecisionRequest(
                "bank-verify.example", "DOMAIN", "alice", List.of(), "dns-resolution",
                Map.of("organizationId", "bank")));
        assertEquals(Decision.BLOCK, result.decision());
    }

    @Test
    void otherOrganizationIsNotBlockedByBankRule() {
        DecisionResult result = acde.evaluate(new DecisionRequest(
                "bank-verify.example", "DOMAIN", "alice", List.of(), "dns-resolution",
                Map.of("organizationId", "university")));
        assertNotEquals(Decision.BLOCK, result.decision(),
                "the university profile must not inherit the bank's org-scoped rule");
    }
}
