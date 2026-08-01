package com.cognesis.framework.dns;

import com.cognesis.framework.algorithm.DecisionBandPolicy;
import com.cognesis.framework.algorithm.SynapseEngine;
import com.cognesis.framework.common.Decision;
import com.cognesis.framework.common.ReasoningStep;
import com.cognesis.framework.dns.analyzer.DomainAgeAnalyzer;
import com.cognesis.framework.impact.InMemoryAssetRegistry;
import com.cognesis.framework.impact.ResolveImpactEngine;
import com.cognesis.framework.intent.MotiveIntentEngine;
import com.cognesis.framework.learning.InMemoryWeightStore;
import com.cognesis.framework.memory.MemoryEngine;
import com.cognesis.framework.memory.MnemonicMemoryEngine;
import com.cognesis.framework.observatory.EvidenceIngestor;
import com.cognesis.framework.persistence.DecisionLogDao;
import com.cognesis.framework.policy.InMemoryPolicyEvaluator;
import com.cognesis.framework.policy.PolicyEvaluator;
import com.cognesis.framework.policy.PolicyRule;
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

class CognitiveDnsEngineTest {

    private CognitiveDnsEngine engine;
    private TrustEngine trustEngine;

    @BeforeEach
    void setUp() {
        trustEngine = new FidesTrustEngine(TrustProperties.defaults());
        MemoryEngine memoryEngine = new MnemonicMemoryEngine(0.02, 20);

        // Fides learns that long-lived well-known domains are trustworthy.
        trustEngine.recordEvent(new TrustEvent("google.com", TrustEvent.EventType.POSITIVE, 0.9, "long history"));
        trustEngine.recordEvent(new TrustEvent("google.com", TrustEvent.EventType.POSITIVE, 0.8, "validated brand"));
        trustEngine.recordEvent(new TrustEvent("corp.example.com", TrustEvent.EventType.POSITIVE, 0.9, "corporate zone"));

        PolicyEvaluator policy = new InMemoryPolicyEvaluator(List.of(
                new PolicyRule("malware blocklist", "BLOCK_LIST", "example-malware.test", "BLOCK", 10)));

        engine = new CognitiveDnsEngineImpl(
                new InMemoryDnsFactsRepository(),
                List.of(new DomainAgeAnalyzer()),
                trustEngine, memoryEngine, new SeerPredictionEngine(), new MotiveIntentEngine(),
                new ResolveImpactEngine(new InMemoryAssetRegistry()), new PactRecommendationEngine(),
                new SynapseEngine(DecisionBandPolicy.defaults()),
                new InMemoryWeightStore(com.cognesis.framework.algorithm.SynapseWeights.defaults()),
                new EvidenceIngestor(), new DecisionLogDao() {
                }, policy);
    }

    @Test
    void wellKnownDomainAllows() {
        DnsDecision decision = engine.evaluate(DnsResolutionRequest.of("google.com", "alice", "10.1.1.5"));
        assertEquals(Decision.ALLOW, decision.decision());
        assertFalse(decision.summary().isEmpty(), "decision must carry an explainable chain");
    }

    @Test
    void blocklistedDomainIsHardBlocked() {
        DnsDecision decision = engine.evaluate(DnsResolutionRequest.of("example-malware.test", "alice", "10.1.1.5"));
        assertEquals(Decision.BLOCK, decision.decision());
        assertEquals(1.0, decision.riskScore(), 1e-9);
        assertTrue(decision.verdictExplanation().contains("policy"),
                "policy override should explain itself");
    }

    @Test
    void typosquatDomainIsRiskierThanCleanDomain() {
        DnsDecision clean = engine.evaluate(DnsResolutionRequest.of("google.com", "alice", "10.1.1.5"));
        DnsDecision typo = engine.evaluate(DnsResolutionRequest.of("go0gle.com", "alice", "10.1.1.5"));
        assertTrue(typo.riskScore() > clean.riskScore(), "typosquat must be riskier than the real brand");
        assertTrue(typo.decision() != Decision.ALLOW, "typosquat must not be allowed outright");
    }

    @Test
    void reasoningChainContainsCoreEngines() {
        DnsDecision decision = engine.evaluate(DnsResolutionRequest.of("paypa1.com", "alice", "10.1.1.5"));
        List<String> engines = decision.outcome().reasoningChain().stream()
                .map(ReasoningStep::engine).toList();
        assertTrue(engines.stream().anyMatch(e -> e.startsWith("CODE:")), "must include DNS senses");
        assertTrue(engines.contains("FIDES"), "must include trust reasoning");
        assertTrue(engines.contains("SYNAPSE"), "must include fused decision");
        assertTrue(engines.contains("PACT"), "must include recommendation");
    }
}
