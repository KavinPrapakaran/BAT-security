package com.cognesis.framework.orchestrator;

import com.cognesis.framework.algorithm.SynapseDecision;
import com.cognesis.framework.algorithm.SynapseEngine;
import com.cognesis.framework.algorithm.SynapseInput;
import com.cognesis.framework.algorithm.SynapseWeights;
import com.cognesis.framework.audit.ExplanationBuilder;
import com.cognesis.framework.common.Decision;
import com.cognesis.framework.common.DecisionResult;
import com.cognesis.framework.common.ReasoningStep;
import com.cognesis.framework.impact.ImpactAssessment;
import com.cognesis.framework.impact.ImpactContext;
import com.cognesis.framework.impact.ImpactEngine;
import com.cognesis.framework.intent.IntentAssessment;
import com.cognesis.framework.intent.IntentContext;
import com.cognesis.framework.intent.IntentEngine;
import com.cognesis.framework.learning.WeightStore;
import com.cognesis.framework.memory.MemoryEngine;
import com.cognesis.framework.memory.MemoryQuery;
import com.cognesis.framework.memory.MemoryRecall;
import com.cognesis.framework.observatory.AggregatedEvidence;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * The decision orchestrator: the "analyst in the chair". It coordinates every
 * reasoning engine - OBSERVATORY evidence, FIDES trust, MNEMONIC memory, SEER
 * prediction, MOTIVE intent, RESOLVE impact, SYNAPSE fusion and PACT actions -
 * into one explainable {@link DecisionResult}.
 *
 * <p>Because every engine is behind an interface, the orchestrator is unchanged
 * when new evidence providers (Cloud, Identity, Email, API, IoT, Endpoint,
 * Threat Intelligence) or new engines are added.</p>
 */
public class DecisionOrchestrator {

    private static final Logger log = LoggerFactory.getLogger(DecisionOrchestrator.class);

    private final List<EvidenceProvider> evidenceProviders;
    private final EvidenceIngestor evidenceIngestor;
    private final TrustEngine trustEngine;
    private final MemoryEngine memoryEngine;
    private final PredictionEngine predictionEngine;
    private final IntentEngine intentEngine;
    private final ImpactEngine impactEngine;
    private final RecommendationEngine recommendationEngine;
    private final SynapseEngine synapseEngine;
    private final WeightStore weightStore;
    private final DecisionLogDao decisionLogDao;

    public DecisionOrchestrator(List<EvidenceProvider> evidenceProviders,
                                EvidenceIngestor evidenceIngestor,
                                TrustEngine trustEngine,
                                MemoryEngine memoryEngine,
                                PredictionEngine predictionEngine,
                                IntentEngine intentEngine,
                                ImpactEngine impactEngine,
                                RecommendationEngine recommendationEngine,
                                SynapseEngine synapseEngine,
                                WeightStore weightStore,
                                DecisionLogDao decisionLogDao) {
        this.evidenceProviders = evidenceProviders != null ? List.copyOf(evidenceProviders) : List.of();
        this.evidenceIngestor = evidenceIngestor;
        this.trustEngine = trustEngine;
        this.memoryEngine = memoryEngine;
        this.predictionEngine = predictionEngine;
        this.intentEngine = intentEngine;
        this.impactEngine = impactEngine;
        this.recommendationEngine = recommendationEngine;
        this.synapseEngine = synapseEngine;
        this.weightStore = weightStore;
        this.decisionLogDao = decisionLogDao;
    }

    public DecisionResult evaluate(DecisionRequest request) {
        List<ReasoningStep> steps = new ArrayList<>();

        // 1. Evidence (OBSERVATORY).
        List<EvidenceFragment> fragments = new ArrayList<>();
        for (EvidenceProvider provider : evidenceProviders) {
            fragments.addAll(provider.provide(new EvidenceRequest(
                    request.entityId(), request.entityType(), request.context())));
        }
        AggregatedEvidence evidence = evidenceIngestor.aggregate(fragments);
        steps.add(new ReasoningStep("OBSERVATORY", "fused evidence",
                evidence.evidenceStrength(), evidence.confidence().coverage(),
                fragments.size() + " evidence fragment(s) from " + evidenceProviders.size() + " provider(s)"));

        // 2. Trust (FIDES).
        TrustAssessment trust = trustEngine.assess(request.entityId(), request.entityType());
        steps.add(new ReasoningStep("FIDES", "entity trust",
                trust.trust(), trust.confidence(),
                "trust=" + String.format("%.2f", trust.trust()) + " over "
                        + trust.observationCount() + " observations"));

        // 3. Memory (MNEMONIC).
        MemoryRecall recall = memoryEngine.recall(new MemoryQuery(request.entityId(), request.entityType()));
        double memorySalience = recall.aggregateSalience();
        steps.add(new ReasoningStep("MNEMONIC", "memory salience",
                memorySalience, Math.min(1.0, recall.items().size() / 5.0),
                "recalled " + recall.items().size() + " memory item(s)"));

        // 4. Prediction (SEER).
        PredictionResult prediction = predictionEngine.predict(
                request.entityId(), evidence.evidenceStrength(), memorySalience);
        steps.add(new ReasoningStep("SEER", "predicted risk",
                prediction.predictedRisk(), prediction.confidence(),
                "model=" + prediction.model()));

        // 5. Intent (MOTIVE) - only signal families with meaningful strength count.
        List<String> evidenceTypes = fragments.stream()
                .filter(f -> f.strength() >= 0.4)
                .map(f -> f.type().name()).distinct().toList();
        IntentAssessment intent = intentEngine.assess(new IntentContext(evidenceTypes, request.entityType()));
        steps.add(new ReasoningStep("MOTIVE", "intent: " + intent.primaryIntent(),
                intent.intentProbability(), intent.intentProbability(),
                "fused " + evidenceTypes.size() + " evidence families"));

        // 6. Impact (RESOLVE).
        ImpactAssessment impact = impactEngine.assess(new ImpactContext(
                request.requestor(), request.affectedAssetIds(), request.activity()));
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
                memoryEngine.deviation(request.entityId(), "generic_activity", 0.5),
                contextWeight(request),
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
                request.entityId(), request.entityType());
        steps.add(new ReasoningStep("PACT", "recommended action",
                decision.riskScore(), decision.confidenceScore(), recommendation.justification()));

        String rationale = ExplanationBuilder.buildRationale(request.entityId(), decision.decision(),
                steps, decision.riskScore(), trust.trust(), decision.confidenceScore(), decision.businessImpactScore());

        DecisionResult result = new DecisionResult(UUID.randomUUID(), request.entityId(), request.entityType(),
                decision.decision(), recommendation.action(), decision.riskScore(), trust.trust(),
                decision.confidenceScore(), decision.businessImpactScore(), rationale, steps, Instant.now());

        decisionLogDao.save(result);
        predictionEngine.recordRisk(request.entityId(), decision.riskScore(), decision.confidenceScore());
        log.info("ORCHESTRATOR decision for {} ({}): {}",
                request.entityId(), request.entityType(), decision.decision());
        return result;
    }

    private double contextWeight(DecisionRequest request) {
        if (request.context() == null || request.context().isEmpty()) {
            return 0.4;
        }
        return 0.7;
    }
}
