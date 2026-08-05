package com.cognesis.framework.email;

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
 * VOID - the email intelligence engine. Runs the email senses (the analyzers),
 * converts them into normalized evidence fragments, and delegates the decision
 * to the ACDE - the same single decision-maker the DNS engine uses. VOID sees,
 * the ACDE decides.
 *
 * <p>Every evaluation feeds the ACTG graph: the sender domain, the client IP,
 * the recipient and any incidents are linked as nodes and edges, so a later
 * message from the same sender or network neighborhood inherits accumulated
 * risk.
 */
public class EmailIntelligenceEngineImpl implements EmailIntelligenceEngine {

    private static final Logger log = LoggerFactory.getLogger(EmailIntelligenceEngineImpl.class);

    private final EmailFactsRepository factsRepository;
    private final List<EmailSignalAnalyzer> analyzers;
    private final AcdeEngine acde;
    private final ActgGraph actgGraph;
    private final CognesisMetrics metrics;

    public EmailIntelligenceEngineImpl(EmailFactsRepository factsRepository,
                                       List<EmailSignalAnalyzer> analyzers,
                                       AcdeEngine acde) {
        this(factsRepository, analyzers, acde, new SecurityKnowledgeGraph(), null);
    }

    public EmailIntelligenceEngineImpl(EmailFactsRepository factsRepository,
                                       List<EmailSignalAnalyzer> analyzers,
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
    public EmailDecision evaluate(EmailEvaluationRequest request) {
        long start = System.nanoTime();

        EmailFacts facts = factsRepository.factsFor(request.messageId());

        // 1. Link this observation into the ACTG graph BEFORE the senses run,
        //    so a message from a sender that already sits in a risky
        //    neighborhood is flagged on the very first evaluation.
        recordActgLinks(request, facts);

        // 2. Senses: every analyzer emits one signal, converted to evidence.
        List<EmailSignal> signals = analyzers.stream()
                .map(a -> a.analyze(request, facts))
                .toList();

        // 3. Merge the observed risk into the graph nodes.
        recordActgRisk(facts, signals);

        List<EvidenceFragment> fragments = signals.stream()
                .map(s -> new EvidenceFragment(request.messageId(), "EMAIL", s.type(),
                        s.strength(), s.confidence(), s.explanation(), s.provenance(), Instant.now()))
                .toList();
        List<ReasoningStep> emailSteps = signals.stream()
                .map(s -> new ReasoningStep("VOID:" + s.type().name(), s.explanation(),
                        s.strength(), s.confidence(), s.explanation()))
                .toList();

        // 4. Delegate the decision to the ACDE (the single decision-maker).
        Map<String, Object> context = new HashMap<>();
        context.put("sourceIp", request.clientIp());
        context.put("recipient", request.recipient());
        context.put("deviation.feature", "suspicious_links");
        context.put("deviation.observed", facts.suspiciousLinkCount());
        String organizationId = request.context().get("organizationId");
        if (organizationId != null && !organizationId.isBlank()) {
            context.put("organizationId", organizationId);
        }
        context.put("actg.neighborhoodRisk", actgGraph.neighborhoodRisk(
                ActgNode.key(ActgEntityType.DOMAIN, facts.senderDomain())));
        context.put("actg.relationships", actgGraph.neighborhood(
                ActgNode.key(ActgEntityType.DOMAIN, facts.senderDomain())).size());

        DecisionRequest decisionRequest = new DecisionRequest(
                request.messageId(), "EMAIL", request.recipient(),
                List.of(), "email", context);

        DecisionResult result = acde.evaluate(decisionRequest, fragments, emailSteps);

        long elapsedMs = (System.nanoTime() - start) / 1_000_000;
        log.info("VOID verdict for {}: {} in {}ms (risk={})",
                request.messageId(), result.decision(), elapsedMs,
                String.format("%.2f", result.riskScore()));
        return EmailDecision.from(result);
    }

    /**
     * Records the structural relationships of one message before the senses
     * run, so the ACTG analyzer can see this message's neighborhood
     * immediately. The sender domain is the hub; the client IP, the recipient
     * and any prior incident attach to it.
     */
    private void recordActgLinks(EmailEvaluationRequest request, EmailFacts facts) {
        String senderKey = ActgNode.key(ActgEntityType.DOMAIN, facts.senderDomain());
        int associations = 0;
        String clientIp = request.clientIp();
        if (clientIp != null && !clientIp.isBlank() && !"unknown".equalsIgnoreCase(clientIp)) {
            actgGraph.recordAssociation(senderKey, ActgEntityType.DOMAIN,
                    ActgNode.key(ActgEntityType.IP, clientIp), ActgEntityType.IP, ActgRelation.ASSOCIATED_WITH);
            associations++;
        }
        String recipient = request.recipient();
        if (recipient != null && !recipient.isBlank()) {
            actgGraph.recordAssociation(ActgNode.key(ActgEntityType.USER, recipient), ActgEntityType.USER,
                    senderKey, ActgEntityType.DOMAIN, ActgRelation.REQUESTED_BY);
            associations++;
        }
        if (facts.maliciousFlagCount() > 0) {
            actgGraph.recordAssociation(senderKey, ActgEntityType.DOMAIN,
                    ActgNode.key(ActgEntityType.INCIDENT, facts.senderDomain()), ActgEntityType.INCIDENT,
                    ActgRelation.TARGET_OF);
            associations++;
        }
        if (metrics != null && associations > 0) {
            metrics.recordActgAssociations(associations);
        }
    }

    /**
     * Merges the observed risk into the graph: the sender domain inherits its
     * strongest signal this round, the client IP inherits a fraction, and
     * flagged senders record an incident.
     */
    private void recordActgRisk(EmailFacts facts, List<EmailSignal> signals) {
        double maxRisk = signals.stream().mapToDouble(EmailSignal::strength).max().orElse(0.0);
        String senderKey = ActgNode.key(ActgEntityType.DOMAIN, facts.senderDomain());
        actgGraph.recordObservation(senderKey, ActgEntityType.DOMAIN, maxRisk);
        if (facts.maliciousFlagCount() > 0) {
            actgGraph.recordObservation(ActgNode.key(ActgEntityType.INCIDENT, facts.senderDomain()),
                    ActgEntityType.INCIDENT, 0.9);
        }
    }
}
