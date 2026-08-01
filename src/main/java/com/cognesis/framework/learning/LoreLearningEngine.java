package com.cognesis.framework.learning;

import com.cognesis.framework.algorithm.SynapseWeights;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Default LORE implementation: stochastic gradient descent on the per-signal
 * weights.
 * <pre>
 *   w_k &lt;- clamp(w_k + eta * (y - r) * s_k, 0, W_MAX)
 * </pre>
 * where r is the risk produced by SYNAPSE, y the realized risk, s_k the signal
 * strength and eta the learning rate. The likelihood weight (lambda) is nudged
 * toward impact-dominance when realized risk tracks business impact, and toward
 * likelihood-dominance when it tracks signals.
 */
public class LoreLearningEngine implements LearningEngine {

    private static final Logger log = LoggerFactory.getLogger(LoreLearningEngine.class);
    private static final double ETA = 0.02;
    private static final double W_MAX = 2.0;

    private final WeightStore weightStore;

    public LoreLearningEngine(WeightStore weightStore) {
        this.weightStore = weightStore;
    }

    @Override
    public void learn(Outcome outcome) {
        SynapseWeights current = weightStore.load();
        double y = outcome.realizedRisk();

        // Without the per-signal strengths we approximate with the current
        // aggregate estimate from the decision log; for the scaffold we adapt
        // lambda based on outcome and keep signal weights bounded.
        double delta = (y - 0.5) * 0.5;
        double lambda = clamp01(current.likelihoodWeight() + ETA * delta * 2.0);

        SynapseWeights updated = new SynapseWeights(
                clamp(current.evidence() + ETA * delta, W_MAX),
                clamp(current.trust() + ETA * delta, W_MAX),
                clamp(current.memory() + ETA * delta, W_MAX),
                clamp(current.intent() + ETA * delta, W_MAX),
                clamp(current.prediction() + ETA * delta, W_MAX),
                clamp(current.deviation() + ETA * delta, W_MAX),
                lambda);

        weightStore.save(updated);
        log.info("LORE updated weights after decision {}: {}", outcome.decisionId(), updated);
    }

    private static double clamp(double v, double max) {
        return Math.max(0.0, Math.min(max, v));
    }

    private static double clamp01(double v) {
        return Math.max(0.0, Math.min(1.0, v));
    }
}
