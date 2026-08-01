package com.cognesis.framework.dns;

import com.cognesis.framework.algorithm.SynapseDecision;
import com.cognesis.framework.algorithm.SynapseEngine;
import com.cognesis.framework.algorithm.SynapseInput;
import com.cognesis.framework.algorithm.SynapseWeights;
import com.cognesis.framework.audit.ExplanationBuilder;
import com.cognesis.framework.common.Decision;
import com.cognesis.framework.common.EvidenceType;
import com.cognesis.framework.common.Provenance;
import com.cognesis.framework.common.ReasoningStep;
import com.cognesis.framework.common.RecommendedAction;
import com.cognesis.framework.dns.analyzer.DgaAnalyzer;
import com.cognesis.framework.dns.analyzer.DomainAgeAnalyzer;
import com.cognesis.framework.dns.analyzer.FastFluxAnalyzer;
import com.cognesis.framework.dns.analyzer.HistoricalTrustAnalyzer;
import com.cognesis.framework.dns.analyzer.HomographAnalyzer;
import com.cognesis.framework.dns.analyzer.NetworkBehaviourAnalyzer;
import com.cognesis.framework.dns.analyzer.PolicyAnalyzer;
import com.cognesis.framework.dns.analyzer.RegistrarHistoryAnalyzer;
import com.cognesis.framework.dns.analyzer.SubdomainBehaviourAnalyzer;
import com.cognesis.framework.dns.analyzer.ThreatMemoryAnalyzer;
import com.cognesis.framework.dns.analyzer.TyposquattingAnalyzer;
import com.cognesis.framework.dns.analyzer.UserBehaviourAnalyzer;
import com.cognesis.framework.dns.analyzer.WhoisAnalyzer;
import com.cognesis.framework.dns.analyzer.CertificateTransparencyAnalyzer;
import com.cognesis.framework.dns.analyzer.DnssecAnalyzer;
import com.cognesis.framework.impact.ImpactAssessment;
import com.cognesis.framework.impact.ImpactEngine;
import com.cognesis.framework.impact.ImpactContext;
import com.cognesis.framework.intent.IntentAssessment;
import com.cognesis.framework.intent.IntentContext;
import com.cognesis.framework.intent.IntentEngine;
import com.cognesis.framework.learning.WeightStore;
import com.cognesis.framework.memory.MemoryEngine;
import com.cognesis.framework.memory.MemoryIncident;
import com.cognesis.framework.memory.MemoryQuery;
import com.cognesis.framework.memory.MemoryRecall;
import com.cognesis.framework.observatory.EvidenceFragment;
import com.cognesis.framework.observatory.AggregatedEvidence;
import com.cognesis.framework.observatory.EvidenceIngestor;
import com.cognesis.framework.persistence.DecisionLogDao;
import com.cognesis.framework.policy.PolicyEvaluator;
import com.cognesis.framework.policy.PolicyVerdict;
import com.cognesis.framework.prediction.PredictionEngine;
import com.cognesis.framework.prediction.PredictionResult;
import com.cognesis.framework.recommend.Recommendation;
import com.cognesis.framework.recommend.RecommendationEngine;
import com.cognesis.framework.trust.TrustAssessment;
import com.cognesis.framework.trust.TrustEngine;
import com.cognesis.framework.common.DecisionResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Reference implementation of the Cognitive DNS Engine. It runs the full
 * pipeline - senses, memory, trust, intent, prediction, impact - and fuses the
 * results with SYNAPSE. Every analyzer and engine contributes an auditable
 * reasoning step.
 */
public class CognitiveDnsEngineImpl implements CognitiveDnsEngine {

    private static final Logger log = LoggerFactory.getLogger(CognitiveDnsEngineImpl.class);

    private final DnsFactsRepository factsRepository;
    private final List<DnsSignalAnalyzer> analyzers;
    private final TrustEngine trustEngine;
    private final MemoryEngine memoryEngine;
    private final PredictionEngine predictionEngine;
    private final IntentEngine intentEngine;
    private final ImpactEngine impactEngine;
    private final RecommendationEngine recommendationEngine;
    private final SynapseEngine synapseEngine;
    private final WeightStore weightStore;
    private final EvidenceIngestor evidenceIngestor;
    private final DecisionLogDao decisionLogDao;
    private final PolicyEvaluator policyEvaluator;

    public CognitiveDnsEngineImpl(DnsFactsRepository factsRepository,
                                  List<DnsSignalAnalyzer> analyzers,
                                  TrustEngine trustEngine,
                                  MemoryEngine memoryEngine,
                                  PredictionEngine predictionEngine,
                                  IntentEngine intentEngine,
                                  ImpactEngine impactEngine,
                                  RecommendationEngine recommendationEngine,
                                  SynapseEngine synapseEngine,
                                  WeightStore weightStore,
                                  EvidenceIngestor evidenceIngestor,
                                  DecisionLogDao decisionLogDao) {
        this(factsRepository, analyzers, trustEngine, memoryEngine, predictionEngine, intentEngine,
                impactEngine, recommendationEngine, synapseEngine, weightStore, evidenceIngestor,
                decisionLogDao, null);
    }

    public CognitiveDnsEngineImpl(DnsFactsRepository factsRepository,
                                  List<DnsSignalAnalyzer> analyzers,
                                  TrustEngine trustEngine,
                                  MemoryEngine memoryEngine,
                                  PredictionEngine predictionEngine,
                                  IntentEngine intentEngine,
                                  ImpactEngine impactEngine,
                                  RecommendationEngine recommendationEngine,
                                  SynapseEngine synapseEngine,
                                  WeightStore weightStore,
                                  EvidenceIngestor evidenceIngestor,
                                  DecisionLogDao decisionLogDao,
                                  PolicyEvaluator policyEvaluator) {
        this.factsRepository = factsRepository;
        this.analyzers = analyzers != null ? List.copyOf(analyzers) : defaultAnalyzers(trustEngine, memoryEngine);
        this.trustEngine = trustEngine;
        this.memoryEngine = memoryEngine;
        this.predictionEngine = predictionEngine;
        this.intentEngine = intentEngine;
        this.impactEngine = impactEngine;
        this.recommendationEngine = recommendationEngine;
        this.synapseEngine = synapseEngine;
        this.weightStore = weightStore;
        this.evidenceIngestor = evidenceIngestor;
        this.decisionLogDao = decisionLogDao;
        this.policyEvaluator = policyEvaluator;
    }

    @Override
    public DnsDecision evaluate(DnsResolutionRequest request) {
        long start = System.nanoTime();

        // 0. Hard policy override: deterministic blocklists/allowlists win.
        if (policyEvaluator != null) {
            PolicyVerdict verdict = policyEvaluator.evaluate(request.domain(), "DOMAIN");
            if (verdict.decision() == Decision.BLOCK) {
                return hardPolicyDecision(request, verdict);
            }
        }

        List<ReasoningStep> steps = new ArrayList<>();

        DnsFacts facts = factsRepository.factsFor(request.domain());

        // 1. Senses: every analyzer emits one signal.
        List<DnsSignal> signals = analyzers.stream()
                .map(a -> a.analyze(request, facts))
                .toList();
        List<EvidenceFragment> fragments = signals.stream()
                .map(s -> new EvidenceFragment(request.domain(), "DOMAIN", s.type(),
                        s.strength(), s.confidence(), s.explanation(), s.provenance(), Instant.now()))
                .toList();
        for (DnsSignal s : signals) {
            steps.add(new ReasoningStep("CODE:" + s.type().name(), s.explanation(),
                    s.strength(), s.confidence(), s.explanation()));
        }
        AggregatedEvidence evidence = evidenceIngestor.aggregate(fragments);

        // 2. Trust (FIDES).
        TrustAssessment trust = trustEngine.assess(request.domain(), "DOMAIN");
        steps.add(new ReasoningStep("FIDES", "domain trust",
                trust.trust(), trust.confidence(),
                "FIDES trust=" + String.format("%.2f", trust.trust()) + " over "
                        + trust.observationCount() + " observations"));

        // 3. Memory (MNEMONIC).
        MemoryRecall recall = memoryEngine.recall(new MemoryQuery(request.domain(), "DOMAIN", true, 10));
        double memorySalience = recall.aggregateSalience();
        double deviation = memoryEngine.deviation(request.domain(), "subdomain_count", facts.subdomains().size());
        steps.add(new ReasoningStep("MNEMONIC", "memory salience",
                memorySalience, Math.min(1.0, recall.items().size() / 5.0),
                "recalled " + recall.items().size() + " memory item(s)"));
        steps.add(new ReasoningStep("MNEMONIC", "behavioural deviation",
                deviation, 0.5, "deviation from baseline feature 'subdomain_count'"));

        // 4. Prediction (SEER).
        PredictionResult prediction = predictionEngine.predict(request.domain(), evidence.evidenceStrength(), memorySalience);
        steps.add(new ReasoningStep("SEER", "predicted risk",
                prediction.predictedRisk(), prediction.confidence(),
                "trend=" + prediction.trend() + " model=" + prediction.model()));

        // 5. Intent (MOTIVE) - only signal families with meaningful strength count.
        List<String> evidenceTypes = signals.stream()
                .filter(s -> s.strength() >= 0.4)
                .map(s -> s.type().name())
                .distinct()
                .toList();
        IntentAssessment intent = intentEngine.assess(new IntentContext(evidenceTypes, "DOMAIN"));
        steps.add(new ReasoningStep("MOTIVE", "intent: " + intent.primaryIntent(),
                intent.intentProbability(), intent.intentProbability(),
                "fused " + evidenceTypes.size() + " evidence families"));

        // 6. Impact (RESOLVE).
        ImpactAssessment impact = impactEngine.assess(new ImpactContext(request.requestingUser(), List.of(), "dns-resolution"));
        steps.add(new ReasoningStep("RESOLVE", "business impact",
                impact.businessImpact(), 0.7, impact.rationale()));

        // 7. SYNAPSE fusion.
        SynapseWeights weights = weightStore.load();
        SynapseInput input = new SynapseInput(
                evidence.evidenceStrength(),
                trust.trust(),
                memorySalience,
                intent.intentProbability(),
                prediction.predictedRisk(),
                impact.businessImpact(),
                deviation,
                0.8,
                trust.confidence(),
                evidence.confidence());
        SynapseDecision decision = synapseEngine.evaluate(input, weights);
        steps.add(new ReasoningStep("SYNAPSE", "fused decision",
                decision.riskScore(), decision.confidenceScore(),
                "likelihood=" + String.format("%.2f", decision.likelihoodScore())
                        + " blended with impact=" + String.format("%.2f", impact.businessImpact())));

        // 8. Recommendation (PACT).
        Recommendation recommendation = recommendationEngine.recommend(
                decision.decision(), decision.riskScore(), decision.businessImpactScore(),
                request.domain(), "DOMAIN");
        steps.add(new ReasoningStep("PACT", "recommended action",
                decision.riskScore(), decision.confidenceScore(), recommendation.justification()));

        // 9. Rationale + persist + learn.
        String rationale = ExplanationBuilder.buildRationale(request.domain(), decision.decision(),
                steps, decision.riskScore(), trust.trust(), decision.confidenceScore(), decision.businessImpactScore());

        DecisionResult result = new DecisionResult(UUID.randomUUID(), request.domain(), "DOMAIN",
                decision.decision(), recommendation.action(), decision.riskScore(), trust.trust(),
                decision.confidenceScore(), decision.businessImpactScore(), rationale, steps, Instant.now());

        decisionLogDao.save(result);
        predictionEngine.recordRisk(request.domain(), decision.riskScore(), decision.confidenceScore());
        if (decision.decision() == Decision.BLOCK) {
            memorizeBlockedDomain(request);
        }

        long elapsedMs = (System.nanoTime() - start) / 1_000_000;
        log.info("CODE verdict for {}: {} in {}ms (risk={})",
                request.domain(), decision.decision(), elapsedMs,
                String.format("%.2f", decision.riskScore()));
        return DnsDecision.from(result);
    }

    private void memorizeBlockedDomain(DnsResolutionRequest request) {
        MemoryIncident incident = new MemoryIncident(
                request.domain(),
                "DOMAIN",
                java.util.Map.of(
                        "REQUESTED_BY", request.requestingUser() == null ? List.of() : List.of("user:" + request.requestingUser()),
                        "ORIGINATED_FROM", request.sourceIp() == null ? List.of() : List.of("ip:" + request.sourceIp())),
                List.of("DNS_BLOCK", "SYNAPSE"),
                "BLOCKED_DOMAIN",
                0.9,
                Instant.now());
        memoryEngine.memorize(incident);
    }

    /**
     * Short-circuit for hard policy blocks: full audit trail, no statistical
     * fusion required. Deterministic policy always outranks inference.
     */
    private DnsDecision hardPolicyDecision(DnsResolutionRequest request, PolicyVerdict verdict) {
        TrustAssessment trust = trustEngine.assess(request.domain(), "DOMAIN");
        ImpactAssessment impact = impactEngine.assess(new ImpactContext(request.requestingUser(), List.of(), "dns-resolution"));
        List<ReasoningStep> steps = List.of(
                new ReasoningStep("POLICY", "hard block",
                        1.0, 1.0, "policy rule(s) matched: " + verdict.matchedRules()));

        DecisionResult result = new DecisionResult(UUID.randomUUID(), request.domain(), "DOMAIN",
                Decision.BLOCK, RecommendedAction.BLOCK_DOMAIN, 1.0, trust.trust(), 1.0,
                impact.businessImpact(),
                "Hard policy block: " + verdict.matchedRules()
                        + " take precedence over statistical inference.",
                steps, Instant.now());
        decisionLogDao.save(result);
        predictionEngine.recordRisk(request.domain(), 1.0, 1.0);
        memorizeBlockedDomain(request);
        log.info("CODE hard-policy block for {}", request.domain());
        return DnsDecision.from(result);
    }

    /** Default analyzer set so the engine works without explicit wiring. */
    public static List<DnsSignalAnalyzer> defaultAnalyzers(TrustEngine trustEngine, MemoryEngine memoryEngine) {
        return List.of(
                new DomainAgeAnalyzer(),
                new DgaAnalyzer(),
                new HomographAnalyzer(),
                new TyposquattingAnalyzer(),
                new FastFluxAnalyzer(),
                new DnssecAnalyzer(),
                new RegistrarHistoryAnalyzer(),
                new WhoisAnalyzer(),
                new CertificateTransparencyAnalyzer(),
                new SubdomainBehaviourAnalyzer(),
                new HistoricalTrustAnalyzer(trustEngine),
                new ThreatMemoryAnalyzer(memoryEngine),
                new UserBehaviourAnalyzer(trustEngine),
                new NetworkBehaviourAnalyzer(trustEngine));
    }
}
