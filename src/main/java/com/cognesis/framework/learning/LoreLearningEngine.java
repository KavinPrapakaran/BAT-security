package com.cognesis.framework.learning;

import com.cognesis.framework.algorithm.SynapseWeights;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Default LORE implementation: online learning on the per-signal weights.
 * <pre>
 *   w_k &lt;- clamp(w_k + ETA * |y - 0.5| * D * s_avg, 0, W_MAX)
 * </pre>
 * where y is the realized risk, D the correction direction (+1 when the entity
 * was confirmed malicious, -1 on a false positive, -0.5 on a confirmed benign)
 * and s_avg the average strength of the signals that fired. A calibration
 * offset is tracked alongside (bounded, so it can never silently dominate):
 * repeated false positives push it negative, missed detections push it
 * positive, and correct verdicts barely move it.
 */
public class LoreLearningEngine implements LearningEngine {

    private static final Logger log = LoggerFactory.getLogger(LoreLearningEngine.class);
    private static final double ETA = 0.02;
    private static final double W_MAX = 2.0;
    private static final double CALIBRATION_MAX = 0.5;

    private final WeightStore weightStore;
    private final AtomicReference<Double> calibration = new AtomicReference<>(0.0);

    public LoreLearningEngine(WeightStore weightStore) {
        this.weightStore = weightStore;
    }

    /**
     * Learned systematic over- or under-flagging, bounded to [-0.5, 0.5].
     * Consumers apply this as an offset when interpreting risk scores.
     */
    public double calibration() {
        return calibration.get();
    }

    @Override
    public void learn(Outcome outcome) {
        SynapseWeights current = weightStore.load();
        double gap = Math.abs(outcome.realizedRisk() - 0.5);
        double direction = direction(outcome.kind());
        double signalBias = averageSignal(outcome.signalStrengths());
        double step = ETA * gap * direction * signalBias;

        SynapseWeights updated = new SynapseWeights(
                clampWeight(current.evidence() + step),
                clampWeight(current.trust() + step),
                clampWeight(current.memory() + step),
                clampWeight(current.intent() + step),
                clampWeight(current.prediction() + step),
                clampWeight(current.deviation() + step),
                clamp01(current.likelihoodWeight() + step * 2.0));
        weightStore.save(updated);

        double calStep = ETA * gap * direction * (outcome.wasCorrect() ? 0.5 : 1.0);
        calibration.set(clampCalibration(calibration.get() + calStep));

        log.info("LORE updated weights after decision {} ({}): {}", outcome.decisionId(),
                outcome.kind(), updated);
    }

    private static double direction(Outcome.FeedbackKind kind) {
        return switch (kind) {
            case CONFIRMED_MALICIOUS -> 1.0;
            case FALSE_POSITIVE -> -1.0;
            case CONFIRMED_BENIGN -> -0.5;
        };
    }

    /** Strengths are optional; without them LORE assumes an average signal. */
    private static double averageSignal(List<Double> strengths) {
        if (strengths == null || strengths.isEmpty()) {
            return 0.75;
        }
        return strengths.stream().mapToDouble(Double::doubleValue).average().orElse(0.75);
    }

    private static double clampWeight(double v) {
        return Math.max(0.0, Math.min(W_MAX, v));
    }

    private static double clampCalibration(double v) {
        return Math.max(-CALIBRATION_MAX, Math.min(CALIBRATION_MAX, v));
    }

    private static double clamp01(double v) {
        return Math.max(0.0, Math.min(1.0, v));
    }
}
