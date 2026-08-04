package com.cognesis.framework.acde;

import com.cognesis.framework.algorithm.SynapseDecision;
import com.cognesis.framework.algorithm.SynapseEngine;
import com.cognesis.framework.algorithm.SynapseInput;
import com.cognesis.framework.algorithm.SynapseWeights;
import com.cognesis.framework.audit.ExplanationBuilder;
import com.cognesis.framework.common.Decision;
import com.cognesis.framework.common.DecisionResult;
import com.cognesis.framework.common.ReasoningStep;
import com.cognesis.framework.common.RecommendedAction;
import com.cognesis.framework.context.ContextAssessment;
import com.cognesis.framework.context.ContextEngine;
import com.cognesis.framework.context.ContextInput;
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
import com.cognesis.framework.policy.PolicyEvaluator;
import com.cognesis.framework.policy.PolicyVerdict;
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
 * ACDE - Adaptive Cognitive Decision Engine. This is the single decision-maker
 * of the COGNESIS framework: every module (DNS, Email, API, Endpoint, Cloud,
 * Identity, ...) feeds it evidence, and it alone decides.
 *
 * <p>It collects evidence from every engine, normalizes each contribution into
 * a [0,1] slice, fuses them with SYNAPSE, produces one explainable decision
 * with a recommended action, and stores the reasoning path in the memory
 * engine for future recall.</p>
 *
 * <p>The reasoning chain always follows the canonical order:
 * Evidence -&gt; Trust -&gt; Context -&gt; Intent -&gt; Prediction -&gt;
 * Business Impact -&gt; Confidence/Decision -&gt; Action.</p>
 */
public class AcdeEngine {

    private static final Logger log = LoggerFactory.getLogger(AcdeEngine.class);

    private final List<EvidenceProvider> evidenceProviders;
    private final EvidenceIngestor evidenceIngestor;
    private final TrustEngine trustEngine;
    private final MemoryEngine memoryEngine;
    private final ContextEngine contextEngine;
    private final PredictionEngine predictionEngine;
    private final IntentEngine intentEngine;
    private final ImpactEngine impactEngine;
    private final RecommendationEngine recommendationEngine;
    private final SynapseEngine synapseEngine;
    private final WeightStore weightStore;
    private final DecisionLogDao decisionLogDao;
    private final PolicyEvaluator policyEvaluator;

    public AcdeEngine(List<EvidenceProvider> evidenceProviders,
                      EvidenceIngestor evidenceIngestor,
                      TrustEngine trustEngine,
                      MemoryEngine memoryEngine,
                      ContextEngine contextEngine,
                      PredictionEngine predictionEngine,
                      IntentEngine intentEngine,
                      ImpactEngine impactEngine,
                      RecommendationEngine recommendationEngine,
                      SynapseEngine synapseEngine,
                      WeightStore weightStore,
                      DecisionLogDao decisionLogDao) {
        this(evidenceProviders, evidenceIngestor, trustEngine, memoryEngine, contextEngine,
                predictionEngine, intentEngine, impactEngine, recommendationEngine, synapseEngine,
                weightStore, decisionLogDao, null);
    }

    public AcdeEngine(List<EvidenceProvider> evidenceProviders,
                      EvidenceIngestor evidenceIngestor,
                      TrustEngine trustEngine,
                      MemoryEngine memoryEngine,
                      ContextEngine contextEngine,
                      PredictionEngine predictionEngine,
                      IntentEngine intentEngine,
                      ImpactEngine impactEngine,
                      RecommendationEngine recommendationEngine,
                      SynapseEngine synapseEngine,
                      WeightStore weightStore,
                      DecisionLogDao decisionLogDao,
                      PolicyEvaluator policyEvaluator) {
        this.evidenceProviders = evidenceProviders != null ? List.copyOf(evidenceProviders) : List.of();
        this.evidenceIngestor = evidenceIngestor;
        this.trustEngine = trustEngine;
        this.memoryEngine = memoryEngine;
        this.contextEngine = contextEngine;
        this.predictionEngine = predictionEngine;
        this.intentEngine = intentEngine;
        this.impactEngine = impactEngine;
        this.recommendationEngine = recommendationEngine;
        this.synapseEngine = synapseEngine;
        this.weightStore = weightStore;
        this.decisionLogDao = decisionLogDao;
        this.policyEvaluator = policyEvaluator;
    }

    /** Full evaluation: evidence is gathered from all registered providers. */
    public DecisionResult evaluate(DecisionRequest request) {
        List<EvidenceFragment> fragments = new ArrayList<>();
        for (EvidenceProvider provider : evidenceProviders) {
            fragments.addAll(provider.provide(new EvidenceRequest(
                    request.entityId(), request.entityType(), request.context())));
        }
        return evaluate(request, fragments, List.of());
    }

    /** Evaluation with caller-supplied evidence and prefix reasoning steps. */
    public DecisionResult evaluate(DecisionRequest request,
                                   List<EvidenceFragment> fragments,
                                   List<ReasoningStep> prefixSteps) {
        if (policyEvaluator != null) {
            PolicyVerdict verdict = policyEvaluator.evaluate(request.entityId(), request.entityType());
            if (verdict.decision() == Decision.BLOCK) {
                return hardPolicyDecision(request, verdict);
            }
        }

        List<ReasoningStep> steps = new ArrayList<>(prefixSteps != null ? prefixSteps : List.of());

        AggregatedEvidence evidence = evidenceIngestor.aggregate(fragments != null ? fragments : List.of());
        steps.add(new ReasoningStep("OBSERVATORY", "fused evidence",
                evidence.evidenceStrength(), evidence.confidence().coverage(),
                (fragments == null ? 0 : fragments.size()) + " evidence fragment(s) from "
                        + evidenceProviders.size() + " provider(s)"));

        TrustAssessment trust = trustEngine.assess(request.entityId(), request.entityType());
        steps.add(new ReasoningStep("FIDES", "entity trust",
                trust.trust(), trust.confidence(),
                "trust=" + String.format("%.2f", trust.trust()) + " over "
                        + trust.observationCount() + " observations"));

        MemoryRecall recall = memoryEngine.recall(new MemoryQuery(request.entityId(), request.entityType(), true, 10));
        double memorySalience = recall.aggregateSalience();
        steps.add(new ReasoningStep("MNEMONIC", "memory salience",
                memorySalience, Math.min(1.0, recall.items().size() / 5.0),
                "recalled " + recall.items().size() + " memory item(s)"));

        String devFeature = stringMeta(request, "deviation.feature", "generic_activity");
        double devObserved = doubleMeta(request, "deviation.observed", 0.5);
        double deviation = memoryEngine.deviation(request.entityId(), devFeature, devObserved);
        steps.add(new ReasoningStep("MNEMONIC", "behavioural deviation",
                deviation, 0.5, "deviation from baseline feature '" + devFeature + "'"));

        ContextAssessment context = contextEngine.assess(
                new ContextInput(request.activity(), request.entityType(), request.context()));
        steps.add(new ReasoningStep("CONTEXT", "environment",
                context.contextRisk(), context.contextWeight(), context.description()));

        List<String> evidenceTypes;
        if (fragments == null || fragments.isEmpty()) {
            evidenceTypes = List.of();
        } else {
            evidenceTypes = fragments.stream()
                    .filter(f -> f.strength() >= 0.4)
                    .map(f -> f.type().name()).distinct().toList();
        }
        IntentAssessment intent = intentEngine.assess(new IntentContext(evidenceTypes, request.entityType()));
        steps.add(new ReasoningStep("MOTIVE", "intent: " + intent.primaryIntent(),
                intent.intentProbability(), intent.intentProbability(),
                "fused " + evidenceTypes.size() + " evidence families"));

        PredictionResult prediction = predictionEngine.predict(
                request.entityId(), evidence.evidenceStrength(), memorySalience);
        steps.add(new ReasoningStep("SEER", "predicted risk",
                prediction.predictedRisk(), prediction.confidence(),
                "trend=" + prediction.trend() + " model=" + prediction.model()));

        ImpactAssessment impact = impactEngine.assess(new ImpactContext(
                request.requestor(), request.affectedAssetIds(), request.activity()));
        steps.add(new ReasoningStep("RESOLVE", "business impact",
                impact.businessImpact(), 0.7, impact.rationale()));

        SynapseWeights weights = weightStore.load();
        SynapseInput input = new SynapseInput(
                evidence.evidenceStrength(),
                trust.trust(),
                memorySalience,
                intent.intentProbability(),
                prediction.predictedRisk(),
                impact.businessImpact(),
                deviation,
                context.contextWeight(),
                trust.confidence(),
                evidence.confidence());
        SynapseDecision decision = synapseEngine.evaluate(input, weights);
        steps.add(new ReasoningStep("SYNAPSE", "fused decision",
                decision.riskScore(), decision.confidenceScore(),
                "likelihood=" + String.format("%.2f", decision.likelihoodScore())
                        + " blended with impact=" + String.format("%.2f", impact.businessImpact())));

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
        memoryEngine.recordDecision(result);
        log.info("ACDE decision for {} ({}): {} (risk={})",
                request.entityId(), request.entityType(), decision.decision(),
                String.format("%.2f", decision.riskScore()));
        return result;
    }

    /** Deterministic hard-policy block: no statistical fusion required. */
    private DecisionResult hardPolicyDecision(DecisionRequest request, PolicyVerdict verdict) {
        TrustAssessment trust = trustEngine.assess(request.entityId(), request.entityType());
        ImpactAssessment impact = impactEngine.assess(new ImpactContext(
                request.requestor(), request.affectedAssetIds(), request.activity()));
        List<ReasoningStep> steps = List.of(
                new ReasoningStep("POLICY", "hard block",
                        1.0, 1.0, "policy rule(s) matched: " + verdict.matchedRules()));

        DecisionResult result = new DecisionResult(UUID.randomUUID(), request.entityId(), request.entityType(),
                Decision.BLOCK, RecommendedAction.BLOCK_DOMAIN, 1.0, trust.trust(), 1.0,
                impact.businessImpact(),
                "Hard policy block: " + verdict.matchedRules()
                        + " take precedence over statistical inference.",
                steps, Instant.now());
        decisionLogDao.save(result);
        predictionEngine.recordRisk(request.entityId(), 1.0, 1.0);
        memoryEngine.recordDecision(result);
        log.info("ACDE hard-policy block for {}: {}", request.entityId(), verdict.matchedRules());
        return result;
    }

    private static String stringMeta(DecisionRequest request, String key, String def) {
        Object v = request.context().get(key);
        return v == null ? def : String.valueOf(v);
    }

    private static double doubleMeta(DecisionRequest request, String key, double def) {
        Object v = request.context().get(key);
        if (v instanceof Number n) {
            return n.doubleValue();
        }
        try {
            return v == null ? def : Double.parseDouble(String.valueOf(v));
        } catch (NumberFormatException e) {
            return def;
        }
    }
}
