package com.cognesis.framework.dns;

import com.cognesis.framework.acde.AcdeEngine;
import com.cognesis.framework.algorithm.DecisionBandPolicy;
import com.cognesis.framework.algorithm.SynapseEngine;
import com.cognesis.framework.algorithm.SynapseWeights;
import com.cognesis.framework.common.Decision;
import com.cognesis.framework.common.ReasoningStep;
import com.cognesis.framework.context.SituationalContextEngine;
import com.cognesis.framework.dns.analyzer.DomainAgeAnalyzer;
import com.cognesis.framework.dns.analyzer.ThreatIntelAnalyzer;
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
import com.cognesis.framework.prediction.SeerPredictionEngine;
import com.cognesis.framework.recommend.PactRecommendationEngine;
import com.cognesis.framework.trust.FidesTrustEngine;
import com.cognesis.framework.trust.TrustEngine;
import com.cognesis.framework.trust.TrustProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Proves the threat-intel loop end to end: a domain flagged by the live IOC
 * feed (which lands in the facts repository via flagMalicious) must produce a
 * strictly riskier verdict than the same domain unflagged.
 */
class IocEscalationTest {

    private CognitiveDnsEngine engine;
    private InMemoryDnsFactsRepository repo;

    @BeforeEach
    void setUp() {
        repo = new InMemoryDnsFactsRepository();
        TrustEngine trustEngine = new FidesTrustEngine(TrustProperties.defaults());
        MemoryEngine memoryEngine = new MnemonicMemoryEngine(0.02, 20);
        PolicyEvaluator policy = new InMemoryPolicyEvaluator(List.of());

        AcdeEngine acde = new AcdeEngine(
                List.of(), new EvidenceIngestor(), trustEngine, memoryEngine,
                new SituationalContextEngine(), new SeerPredictionEngine(), new MotiveIntentEngine(),
                new ResolveImpactEngine(new InMemoryAssetRegistry()), new PactRecommendationEngine(),
                new SynapseEngine(DecisionBandPolicy.defaults()),
                new InMemoryWeightStore(SynapseWeights.defaults()),
                new DecisionLogDao() {
                }, policy);

        engine = new CognitiveDnsEngineImpl(repo,
                List.of(new DomainAgeAnalyzer(), new ThreatIntelAnalyzer()),
                acde);
    }

    @Test
    void feedFlaggedDomainIsStrictlyRiskierThanUnflagged() {
        String domain = "clean-looking.example";

        DnsDecision before = engine.evaluate(DnsResolutionRequest.of(domain, "alice", "10.1.1.5"));

        repo.flagMalicious(domain);

        DnsDecision after = engine.evaluate(DnsResolutionRequest.of(domain, "alice", "10.1.1.5"));

        assertTrue(after.riskScore() > before.riskScore(),
                "feed flag must raise risk: %.2f -> %.2f".formatted(before.riskScore(), after.riskScore()));
        assertTrue(after.decision().compareTo(before.decision()) >= 0,
                "decision must not become more permissive after a feed flag");
    }

    @Test
    void flaggedDomainCarriesThreatIntelReasoningStep() {
        String domain = "malware-c2.example";
        repo.flagMalicious(domain);
        repo.flagMalicious(domain);

        DnsDecision decision = engine.evaluate(DnsResolutionRequest.of(domain, "alice", "10.1.1.5"));

        boolean hasThreatIntelStep = decision.outcome().reasoningChain().stream()
                .filter(s -> s.engine().startsWith("CODE:THREAT_INTEL"))
                .anyMatch(s -> s.claim().toLowerCase().contains("flag"));
        assertTrue(hasThreatIntelStep, "reasoning chain must surface the feed flag");
        assertTrue(decision.decision() != Decision.ALLOW, "twice-flagged domain must not be allowed outright");
    }
}
