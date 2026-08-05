package com.cognesis.framework.learning;

import com.cognesis.framework.algorithm.SynapseWeights;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LoreLearningEngineTest {

    private InMemoryWeightStore weightStore;
    private LoreLearningEngine engine;

    @BeforeEach
    void setUp() {
        weightStore = new InMemoryWeightStore(SynapseWeights.defaults());
        engine = new LoreLearningEngine(weightStore);
    }

    private static Outcome outcome(Outcome.FeedbackKind kind, double risk, boolean correct, double signal) {
        return new Outcome(UUID.randomUUID(), risk, correct, kind, List.of(signal), "test");
    }

    @Test
    void confirmedMaliciousStrengthensEvidenceWeight() {
        double before = weightStore.load().evidence();
        engine.learn(outcome(Outcome.FeedbackKind.CONFIRMED_MALICIOUS, 0.95, true, 0.9));
        double after = weightStore.load().evidence();
        assertTrue(after > before, "confirming a malicious entity must strengthen the evidence weight");
    }

    @Test
    void falsePositiveWeakensEvidenceWeight() {
        double before = weightStore.load().evidence();
        engine.learn(outcome(Outcome.FeedbackKind.FALSE_POSITIVE, 0.2, false, 0.9));
        double after = weightStore.load().evidence();
        assertTrue(after < before, "a false positive must weaken the evidence weight");
    }

    @Test
    void confirmedMaliciousRaisesCalibration() {
        for (int i = 0; i < 50; i++) {
            engine.learn(outcome(Outcome.FeedbackKind.CONFIRMED_MALICIOUS, 0.95, false, 0.9));
        }
        assertTrue(engine.calibration() > 0.0,
                "repeatedly confirmed (and missed) malicious entities must push calibration positive");
    }

    @Test
    void falsePositivesPushCalibrationNegative() {
        for (int i = 0; i < 50; i++) {
            engine.learn(outcome(Outcome.FeedbackKind.FALSE_POSITIVE, 0.2, false, 0.9));
        }
        assertTrue(engine.calibration() < 0.0,
                "repeated false positives must push calibration negative");
    }

    @Test
    void calibrationStaysBounded() {
        for (int i = 0; i < 500; i++) {
            engine.learn(outcome(Outcome.FeedbackKind.FALSE_POSITIVE, 0.1, false, 0.9));
        }
        assertTrue(engine.calibration() >= -0.5, "calibration must never exceed its lower bound");
        assertTrue(engine.calibration() <= 0.5, "calibration must never exceed its upper bound");
    }

    @Test
    void weightsStayBoundedAfterManyConfirms() {
        for (int i = 0; i < 500; i++) {
            engine.learn(outcome(Outcome.FeedbackKind.CONFIRMED_MALICIOUS, 0.95, true, 0.9));
        }
        SynapseWeights weights = weightStore.load();
        assertTrue(weights.evidence() <= 2.0, "evidence weight must be capped at W_MAX");
        assertEquals(2.0, weights.evidence(), 1e-9, "repeated confirms must drive evidence to the cap");
    }

    @Test
    void strongerSignalsProduceBiggerUpdates() {
        engine.learn(outcome(Outcome.FeedbackKind.CONFIRMED_MALICIOUS, 0.95, true, 0.1));
        double weak = weightStore.load().evidence();
        weightStore.save(SynapseWeights.defaults());
        engine.learn(outcome(Outcome.FeedbackKind.CONFIRMED_MALICIOUS, 0.95, true, 0.95));
        double strong = weightStore.load().evidence();
        assertTrue(strong - 0.5 > weak - 0.5,
                "the signal strength of a confirmed signal must scale the weight update");
    }
}
