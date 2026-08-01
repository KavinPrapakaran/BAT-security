package com.cognesis.framework.orchestrator;

import com.cognesis.framework.algorithm.DecisionBandPolicy;
import com.cognesis.framework.algorithm.SynapseEngine;
import com.cognesis.framework.algorithm.SynapseWeights;
import com.cognesis.framework.common.Decision;
import com.cognesis.framework.common.DecisionResult;
import com.cognesis.framework.common.EvidenceType;
import com.cognesis.framework.common.Provenance;
import com.cognesis.framework.impact.ImpactAssessment;
import com.cognesis.framework.intent.IntentAssessment;
import com.cognesis.framework.learning.InMemoryWeightStore;
import com.cognesis.framework.memory.MemoryEngine;
import com.cognesis.framework.memory.MemoryItem;
import com.cognesis.framework.memory.MemoryQuery;
import com.cognesis.framework.memory.MemoryRecall;
import com.cognesis.framework.observatory.EvidenceFragment;
import com.cognesis.framework.observatory.EvidenceIngestor;
import com.cognesis.framework.observatory.EvidenceProvider;
import com.cognesis.framework.observatory.EvidenceRequest;
import com.cognesis.framework.persistence.DecisionLogDao;
import com.cognesis.framework.prediction.PredictionEngine;
import com.cognesis.framework.prediction.PredictionResult;
import com.cognesis.framework.recommend.Recommendation;
import com.cognesis.framework.recommend.RecommendationEngine;
import com.cognesis.framework.trust.TrustAssessment;
import com.cognesis.framework.trust.TrustEngine;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyDouble;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DecisionOrchestratorTest {

    @Mock
    private EvidenceProvider evidenceProvider;
    @Mock
    private TrustEngine trustEngine;
    @Mock
    private MemoryEngine memoryEngine;
    @Mock
    private PredictionEngine predictionEngine;
    @Mock
    private com.cognesis.framework.intent.IntentEngine intentEngine;
    @Mock
    private com.cognesis.framework.impact.ImpactEngine impactEngine;
    @Mock
    private RecommendationEngine recommendationEngine;
    @Mock
    private DecisionLogDao decisionLogDao;

    private DecisionOrchestrator orchestrator() {
        return new DecisionOrchestrator(
                List.of(evidenceProvider),
                new EvidenceIngestor(),
                trustEngine, memoryEngine, predictionEngine, intentEngine, impactEngine,
                recommendationEngine,
                new SynapseEngine(DecisionBandPolicy.defaults()),
                new InMemoryWeightStore(SynapseWeights.defaults()),
                decisionLogDao);
    }

    @Test
    void orchestratorAssemblesExplainableResult() {
        when(evidenceProvider.provide(any(EvidenceRequest.class))).thenReturn(List.of(
                new EvidenceFragment("api-gw-7", "API", EvidenceType.API, 0.9, 0.9,
                        "credential stuffing pattern", Provenance.LIVE_TRAFFIC, Instant.now())));
        when(trustEngine.assess("api-gw-7", "API"))
                .thenReturn(new TrustAssessment("api-gw-7", 0.3, 0.8, 12, Instant.now(), List.of()));
        when(memoryEngine.recall(any(MemoryQuery.class)))
                .thenReturn(new MemoryRecall(List.of(new MemoryItem("api-gw-7", "API", "api-gw-7",
                        0.7, 0.5, Instant.now(), Map.of())), Map.of()));
        when(memoryEngine.deviation(any(), any(), anyDouble())).thenReturn(0.6);
        when(predictionEngine.predict(any(), anyDouble(), anyDouble()))
                .thenReturn(new PredictionResult(0.7, 0.6, 1, "test-model"));
        when(intentEngine.assess(any()))
                .thenReturn(new IntentAssessment(0.9, "CREDENTIAL_ABUSE", Map.of()));
        when(impactEngine.assess(any()))
                .thenReturn(new ImpactAssessment(0.85, "asset-billing", "crown jewel exposed"));
        when(recommendationEngine.recommend(any(), anyDouble(), anyDouble(), any(), any()))
                .thenReturn(new Recommendation(com.cognesis.framework.common.RecommendedAction.BLOCK_IP, "api-gw-7"));

        DecisionResult result = orchestrator().evaluate(
                new DecisionRequest("api-gw-7", "API", "soc-analyst",
                        List.of("asset-billing"), "api-authentication", Map.of("geo", "anon")));

        assertEquals(Decision.BLOCK, result.decision());
        assertEquals("api-gw-7", result.entityId());
        assertTrue(result.riskScore() > 0.7);
        assertTrue(result.reasoningChain().size() >= 8, "full chain expected");
        assertTrue(result.reasoningChain().stream()
                .anyMatch(s -> s.engine().equals("SYNAPSE")));

        ArgumentCaptor<DecisionResult> captor = ArgumentCaptor.forClass(DecisionResult.class);
        verify(decisionLogDao).save(captor.capture());
        assertEquals(result.decisionId(), captor.getValue().decisionId());
    }
}
