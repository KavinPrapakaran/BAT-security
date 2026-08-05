package com.cognesis.framework.email;

import com.cognesis.framework.acde.AcdeEngine;
import com.cognesis.framework.algorithm.DecisionBandPolicy;
import com.cognesis.framework.algorithm.SynapseEngine;
import com.cognesis.framework.algorithm.SynapseWeights;
import com.cognesis.framework.common.Decision;
import com.cognesis.framework.common.ReasoningStep;
import com.cognesis.framework.context.SituationalContextEngine;
import com.cognesis.framework.email.analyzer.AttachmentAnalyzer;
import com.cognesis.framework.email.analyzer.EmailAuthAnalyzer;
import com.cognesis.framework.email.analyzer.LinkAnalyzer;
import com.cognesis.framework.email.analyzer.SenderDomainAgeAnalyzer;
import com.cognesis.framework.email.analyzer.SenderReputationAnalyzer;
import com.cognesis.framework.email.analyzer.SpoofingAnalyzer;
import com.cognesis.framework.email.analyzer.ThreatIntelEmailAnalyzer;
import com.cognesis.framework.impact.InMemoryAssetRegistry;
import com.cognesis.framework.impact.ResolveImpactEngine;
import com.cognesis.framework.intent.MotiveIntentEngine;
import com.cognesis.framework.learning.InMemoryWeightStore;
import com.cognesis.framework.memory.MnemonicMemoryEngine;
import com.cognesis.framework.observatory.EvidenceIngestor;
import com.cognesis.framework.persistence.DecisionLogDao;
import com.cognesis.framework.policy.InMemoryPolicyEvaluator;
import com.cognesis.framework.policy.PolicyEvaluator;
import com.cognesis.framework.prediction.SeerPredictionEngine;
import com.cognesis.framework.recommend.PactRecommendationEngine;
import com.cognesis.framework.trust.FidesTrustEngine;
import com.cognesis.framework.trust.TrustEngine;
import com.cognesis.framework.trust.TrustEvent;
import com.cognesis.framework.trust.TrustProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EmailIntelligenceEngineTest {

    private EmailIntelligenceEngine engine;

    @BeforeEach
    void setUp() {
        TrustEngine trustEngine = new FidesTrustEngine(TrustProperties.defaults());
        for (int i = 0; i < 30; i++) {
            trustEngine.recordEvent(new TrustEvent("paypal.com", TrustEvent.EventType.POSITIVE, 0.9, "steady history"));
            trustEngine.recordEvent(new TrustEvent("corp.example.com", TrustEvent.EventType.POSITIVE, 0.9, "corporate zone"));
        }

        PolicyEvaluator policy = new InMemoryPolicyEvaluator(List.of());

        AcdeEngine acde = new AcdeEngine(
                List.of(), new EvidenceIngestor(), trustEngine, new MnemonicMemoryEngine(0.02, 20),
                new SituationalContextEngine(), new SeerPredictionEngine(), new MotiveIntentEngine(),
                new ResolveImpactEngine(new InMemoryAssetRegistry()), new PactRecommendationEngine(),
                new SynapseEngine(DecisionBandPolicy.defaults()),
                new InMemoryWeightStore(SynapseWeights.defaults()),
                new DecisionLogDao() {
                }, policy);

        engine = new EmailIntelligenceEngineImpl(
                new InMemoryEmailFactsRepository(),
                List.of(new EmailAuthAnalyzer(), new SenderDomainAgeAnalyzer(), new SpoofingAnalyzer(),
                        new LinkAnalyzer(), new AttachmentAnalyzer(), new SenderReputationAnalyzer(),
                        new ThreatIntelEmailAnalyzer()),
                acde);
    }

    @Test
    void authenticatedLegitimateMailAllows() {
        EmailDecision decision = engine.evaluate(EmailEvaluationRequest.of("msg-001", "alice@corp.example.com"));
        assertEquals(Decision.ALLOW, decision.decision());
        assertFalse(decision.summary().isEmpty(), "decision must carry an explainable chain");
    }

    @Test
    void phishingSpoorAllowsNothing() {
        EmailDecision decision = engine.evaluate(EmailEvaluationRequest.of("msg-002", "alice@corp.example.com"));
        assertTrue(decision.decision() != Decision.ALLOW, "young lookalike domain with failed auth must not be allowed");
        assertTrue(decision.riskScore() > 0.6, "phishing payload should be high-risk");
    }

    @Test
    void phishingIsRiskierThanCleanMail() {
        EmailDecision clean = engine.evaluate(EmailEvaluationRequest.of("msg-001", "alice@corp.example.com"));
        EmailDecision phish = engine.evaluate(EmailEvaluationRequest.of("msg-002", "alice@corp.example.com"));
        assertTrue(phish.riskScore() > clean.riskScore(), "phishing must be riskier than a clean message");
    }

    @Test
    void internalCorporateMailIsLowRisk() {
        EmailDecision decision = engine.evaluate(EmailEvaluationRequest.of("msg-003", "bob@corp.example.com"));
        assertEquals(Decision.ALLOW, decision.decision());
        assertTrue(decision.riskScore() < 0.4, "internal mail must stay low-risk");
    }

    @Test
    void reasoningChainContainsVoidAndCoreEngines() {
        EmailDecision decision = engine.evaluate(EmailEvaluationRequest.of("msg-002", "alice@corp.example.com"));
        List<String> engines = decision.outcome().reasoningChain().stream()
                .map(ReasoningStep::engine).toList();
        assertTrue(engines.stream().anyMatch(e -> e.startsWith("VOID:")), "must include email senses");
        assertTrue(engines.contains("FIDES"), "must include trust reasoning");
        assertTrue(engines.contains("CONTEXT"), "must include environment reasoning");
        assertTrue(engines.contains("SYNAPSE"), "must include fused decision");
        assertTrue(engines.contains("PACT"), "must include recommendation");
    }
}
