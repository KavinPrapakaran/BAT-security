package com.cognesis.framework.dns;

import com.cognesis.framework.acde.AcdeEngine;
import com.cognesis.framework.acde.DecisionRequest;
import com.cognesis.framework.actg.ActgEntityType;
import com.cognesis.framework.actg.ActgGraph;
import com.cognesis.framework.actg.ActgNode;
import com.cognesis.framework.actg.ActgRelation;
import com.cognesis.framework.actg.SecurityKnowledgeGraph;
import com.cognesis.framework.common.DecisionResult;
import com.cognesis.framework.common.ReasoningStep;
import com.cognesis.framework.metrics.CognesisMetrics;
import com.cognesis.framework.observatory.EvidenceFragment;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * DIE - DNS Intelligence Engine. This is a DNS evidence module: it runs the DNS
 * senses (the analyzers), converts them into normalized evidence fragments,
 * and delegates the actual decision to the ACDE. DIE no longer decides - it
 * sees, the ACDE decides.
 *
 * <p>Every evaluation also feeds the ACTG graph: the domain, the IPs it
 * resolved to, the requesting user, and any incidents are linked as nodes and
 * edges so that a later request touching the same neighborhood inherits its
 * accumulated risk.
 */
public class DnsIntelligenceEngineImpl implements DnsIntelligenceEngine {

    private static final Logger log = LoggerFactory.getLogger(DnsIntelligenceEngineImpl.class);

    private final DnsFactsRepository factsRepository;
    private final List<DnsSignalAnalyzer> analyzers;
    private final AcdeEngine acde;
    private final ActgGraph actgGraph;
    private final CognesisMetrics metrics;

    public DnsIntelligenceEngineImpl(DnsFactsRepository factsRepository,
                                     List<DnsSignalAnalyzer> analyzers,
                                     AcdeEngine acde) {
        this(factsRepository, analyzers, acde, new SecurityKnowledgeGraph(), null);
    }

    public DnsIntelligenceEngineImpl(DnsFactsRepository factsRepository,
                                     List<DnsSignalAnalyzer> analyzers,
                                     AcdeEngine acde,
                                     ActgGraph actgGraph,
                                     CognesisMetrics metrics) {
        this.factsRepository = factsRepository;
        this.analyzers = analyzers != null ? List.copyOf(analyzers) : List.of();
        this.acde = acde;
        this.actgGraph = actgGraph != null ? actgGraph : new SecurityKnowledgeGraph();
        this.metrics = metrics;
    }

    @Override
    public DnsDecision evaluate(DnsResolutionRequest request) {
        long start = System.nanoTime();

        DnsFacts facts = factsRepository.factsFor(request.domain());

        // 1. Link this observation into the ACTG graph BEFORE the senses run,
        //    so a request touching known-bad infrastructure is flagged on the
        //    very first evaluation, not the second.
        recordActgLinks(request, facts);

        // 2. Senses: every analyzer emits one signal, converted to evidence.
        List<DnsSignal> signals = analyzers.stream()
                .map(a -> a.analyze(request, facts))
                .toList();

        // 3. Merge the observed risk into the graph nodes.
        recordActgRisk(facts, signals);

        List<EvidenceFragment> fragments = signals.stream()
                .map(s -> new EvidenceFragment(request.domain(), "DOMAIN", s.type(),
                        s.strength(), s.confidence(), s.explanation(), s.provenance(), Instant.now()))
                .toList();
        List<ReasoningStep> dnsSteps = signals.stream()
                .map(s -> new ReasoningStep("DIE:" + s.type().name(), s.explanation(),
                        s.strength(), s.confidence(), s.explanation()))
                .toList();

        // 4. Delegate the decision to the ACDE (the single decision-maker).
        Map<String, Object> context = new HashMap<>();
        context.put("sourceIp", request.sourceIp());
        context.put("deviation.feature", "subdomain_count");
        context.put("deviation.observed", facts.subdomains().size());
        String organizationId = request.context().get("organizationId");
        if (organizationId != null && !organizationId.isBlank()) {
            context.put("organizationId", organizationId);
        }
        context.put("actg.neighborhoodRisk", actgGraph.neighborhoodRisk(
                ActgNode.key(ActgEntityType.DOMAIN, facts.domain())));
        context.put("actg.relationships", actgGraph.neighborhood(
                ActgNode.key(ActgEntityType.DOMAIN, facts.domain())).size());

        DecisionRequest decisionRequest = new DecisionRequest(
                request.domain(), "DOMAIN", request.requestingUser(),
                List.of(), "dns-resolution", context);

        DecisionResult result = acde.evaluate(decisionRequest, fragments, dnsSteps);

        long elapsedMs = (System.nanoTime() - start) / 1_000_000;
        log.info("DIE verdict for {}: {} in {}ms (risk={})",
                request.domain(), result.decision(), elapsedMs,
                String.format("%.2f", result.riskScore()));
        return DnsDecision.from(result);
    }

    /**
     * Records the structural relationships of one DNS observation before the
     * senses run, so the ACTG analyzer can see this request's neighborhood
     * immediately. Nodes are created at neutral risk; {@link #recordActgRisk}
     * merges the actual signal strength in afterwards.
     */
    private void recordActgLinks(DnsResolutionRequest request, DnsFacts facts) {
        String domainKey = ActgNode.key(ActgEntityType.DOMAIN, facts.domain());
        int associations = 0;
        for (String ip : facts.resolvedIps()) {
            actgGraph.recordAssociation(domainKey, ActgEntityType.DOMAIN,
                    ActgNode.key(ActgEntityType.IP, ip), ActgEntityType.IP, ActgRelation.RESOLVES_TO);
            associations++;
        }
        String user = request.requestingUser();
        if (user != null && !user.isBlank()) {
            actgGraph.recordAssociation(ActgNode.key(ActgEntityType.USER, user), ActgEntityType.USER,
                    domainKey, ActgEntityType.DOMAIN, ActgRelation.REQUESTED_BY);
            associations++;
        }
        String sourceIp = request.sourceIp();
        if (sourceIp != null && !sourceIp.isBlank() && !"unknown".equalsIgnoreCase(sourceIp)) {
            actgGraph.recordAssociation(ActgNode.key(ActgEntityType.IP, sourceIp), ActgEntityType.IP,
                    domainKey, ActgEntityType.DOMAIN, ActgRelation.SOURCE_FROM);
            associations++;
        }
        if (facts.maliciousFlagCount() > 0) {
            actgGraph.recordAssociation(domainKey, ActgEntityType.DOMAIN,
                    ActgNode.key(ActgEntityType.INCIDENT, facts.domain()), ActgEntityType.INCIDENT,
                    ActgRelation.TARGET_OF);
            associations++;
        }
        if (metrics != null && associations > 0) {
            metrics.recordActgAssociations(associations);
        }
    }

    /**
     * Merges the observed risk into the graph: the domain inherits its
     * strongest signal this round, the IPs it resolves to inherit a fraction,
     * and flagged domains record an incident. A domain that was never seen
     * before already inherits neighborhood risk from {@link #recordActgLinks};
     * this is what makes repeated exposure and shared infrastructure compound.
     */
    private void recordActgRisk(DnsFacts facts, List<DnsSignal> signals) {
        double maxRisk = signals.stream().mapToDouble(DnsSignal::strength).max().orElse(0.0);
        String domainKey = ActgNode.key(ActgEntityType.DOMAIN, facts.domain());
        actgGraph.recordObservation(domainKey, ActgEntityType.DOMAIN, maxRisk);
        for (String ip : facts.resolvedIps()) {
            actgGraph.recordObservation(ActgNode.key(ActgEntityType.IP, ip), ActgEntityType.IP, maxRisk * 0.8);
        }
        if (facts.maliciousFlagCount() > 0) {
            actgGraph.recordObservation(ActgNode.key(ActgEntityType.INCIDENT, facts.domain()),
                    ActgEntityType.INCIDENT, 0.9);
        }
    }
}
