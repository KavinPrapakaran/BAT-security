package com.cognesis.framework.dns;

import com.cognesis.framework.acde.AcdeEngine;
import com.cognesis.framework.actg.ActgEntityType;
import com.cognesis.framework.actg.ActgGraph;
import com.cognesis.framework.actg.ActgNode;
import com.cognesis.framework.actg.SecurityKnowledgeGraph;
import com.cognesis.framework.algorithm.DecisionBandPolicy;
import com.cognesis.framework.algorithm.SynapseEngine;
import com.cognesis.framework.algorithm.SynapseWeights;
import com.cognesis.framework.context.SituationalContextEngine;
import com.cognesis.framework.dns.analyzer.ActgAnalyzer;
import com.cognesis.framework.dns.analyzer.ThreatIntelAnalyzer;
import com.cognesis.framework.impact.InMemoryAssetRegistry;
import com.cognesis.framework.impact.ResolveImpactEngine;
import com.cognesis.framework.intent.MotiveIntentEngine;
import com.cognesis.framework.learning.InMemoryWeightStore;
import com.cognesis.framework.memory.MnemonicMemoryEngine;
import com.cognesis.framework.observatory.EvidenceIngestor;
import com.cognesis.framework.persistence.DecisionLogDao;
import com.cognesis.framework.policy.InMemoryPolicyEvaluator;
import com.cognesis.framework.trust.FidesTrustEngine;
import com.cognesis.framework.trust.TrustProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end ACTG behaviour: a clean-looking domain that shares infrastructure
 * (a resolved IP) with a previously-confirmed bad domain must carry elevated
 * neighborhood risk even though the domain itself was never seen before.
 */
class ActgEngineTest {

    private static final String DIRTY_IP = "45.155.205.233";

    private final ActgGraph graph = new SecurityKnowledgeGraph();
    private DnsIntelligenceEngineImpl engine;

    @BeforeEach
    void setUp() {
        DnsFactsRepository repo = new DnsFactsRepository() {
            @Override
            public DnsFacts factsFor(String domain) {
                if (domain.equals("dirty-infra.example")) {
                    // flagged by the feed, resolves to a dirty IP
                    return new DnsFacts(domain, 1, false, 1, 2, 0.6,
                            List.of(), "enabled", Instant.now().minusSeconds(600),
                            1, false, 1, List.of(DIRTY_IP));
                }
                if (domain.equals("fresh-dirty.example")) {
                    // looks clean, but sits on the same dirty IP
                    return new DnsFacts(domain, 30, true, 1, 0, 0.05,
                            List.of("www"), "disabled", Instant.now().minusSeconds(86400 * 30),
                            2, true, 0, List.of(DIRTY_IP));
                }
                if (domain.equals("clean-control.example")) {
                    return new DnsFacts(domain, 30, true, 1, 0, 0.05,
                            List.of("www"), "disabled", Instant.now().minusSeconds(86400 * 30),
                            2, true, 0, List.of("142.250.72.14"));
                }
                return new DnsFacts(domain, 3, false, 1, 1, 0.45,
                        List.of(), "enabled", Instant.now().minusSeconds(86400),
                        1, false, 0, List.of());
            }
        };

        AcdeEngine acde = new AcdeEngine(
                List.of(), new EvidenceIngestor(), new FidesTrustEngine(TrustProperties.defaults()),
                new MnemonicMemoryEngine(0.02, 20),
                new SituationalContextEngine(), new com.cognesis.framework.prediction.SeerPredictionEngine(),
                new MotiveIntentEngine(),
                new ResolveImpactEngine(new InMemoryAssetRegistry()),
                new com.cognesis.framework.recommend.PactRecommendationEngine(),
                new SynapseEngine(DecisionBandPolicy.defaults()),
                new InMemoryWeightStore(SynapseWeights.defaults()),
                new DecisionLogDao() {
                }, new InMemoryPolicyEvaluator(List.of()));

        engine = new DnsIntelligenceEngineImpl(repo,
                List.of(new ThreatIntelAnalyzer(), new ActgAnalyzer(graph)), acde, graph, null);

        // Seed the graph: the confirmed-bad domain resolves to a dirty IP.
        engine.evaluate(DnsResolutionRequest.of("dirty-infra.example", "alice", "10.0.0.1"));
    }

    @Test
    void cleanDomainOnDirtyIpInheritsRiskOnFirstLookup() {
        DnsDecision dirty = engine.evaluate(DnsResolutionRequest.of("fresh-dirty.example", "bob", "10.0.0.2"));
        DnsDecision clean = engine.evaluate(DnsResolutionRequest.of("clean-control.example", "bob", "10.0.0.2"));

        assertTrue(dirty.riskScore() > clean.riskScore(),
                "a clean domain sharing a dirty IP must be riskier than an identical clean domain on a clean IP");
    }

    @Test
    void repeatedExposureCompoundsNeighborhoodRisk() {
        String domainKey = ActgNode.key(ActgEntityType.DOMAIN, "fresh-dirty.example");
        engine.evaluate(DnsResolutionRequest.of("fresh-dirty.example", "bob", "10.0.0.2"));
        double first = graph.neighborhoodRisk(domainKey);
        engine.evaluate(DnsResolutionRequest.of("fresh-dirty.example", "carol", "10.0.0.3"));
        double second = graph.neighborhoodRisk(domainKey);

        assertTrue(second > first,
                "repeated exposure to the same dirty neighborhood must compound the signal: "
                        + first + " -> " + second);
    }

    @Test
    void actgNeighborhoodGrowsAsDomainsAreObserved() {
        engine.evaluate(DnsResolutionRequest.of("fresh-dirty.example", "dave", "10.0.0.4"));
        assertTrue(graph.edgeCount() > 0, "evaluations must populate the knowledge graph");
    }
}
