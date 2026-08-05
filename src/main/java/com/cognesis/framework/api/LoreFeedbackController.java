package com.cognesis.framework.api;

import com.cognesis.framework.learning.LoreLearningEngine;
import com.cognesis.framework.learning.Outcome;
import com.cognesis.framework.memory.MemoryEngine;
import com.cognesis.framework.metrics.CognesisMetrics;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/feedback")
public class LoreFeedbackController {

    private final LoreLearningEngine loreLearningEngine;
    private final MemoryEngine memoryEngine;
    private final CognesisMetrics metrics;

    public LoreFeedbackController(LoreLearningEngine loreLearningEngine,
                                  MemoryEngine memoryEngine,
                                  CognesisMetrics metrics) {
        this.loreLearningEngine = loreLearningEngine;
        this.memoryEngine = memoryEngine;
        this.metrics = metrics;
    }

    @PostMapping
    public ResponseEntity<Map<String, Object>> submitFeedback(@RequestBody FeedbackRequest request) {
        UUID decisionId = UUID.fromString(request.decisionId());
        double realizedRisk = Math.max(0.0, Math.min(1.0, request.realizedRisk()));
        Outcome.FeedbackKind kind = resolveKind(request.classification(), request.wasCorrect());
        boolean wasCorrect = request.wasCorrect();
        String notes = request.notes() != null ? request.notes() : "";
        List<Double> signalStrengths = request.signalStrengths() != null ? request.signalStrengths() : List.of();

        loreLearningEngine.learn(new Outcome(decisionId, realizedRisk, wasCorrect, kind, signalStrengths, notes));
        memoryEngine.recordOutcome(decisionId.toString(), realizedRisk, wasCorrect, notes);
        metrics.recordFeedback(1);

        return ResponseEntity.accepted().body(Map.of(
                "decisionId", request.decisionId(),
                "realizedRisk", realizedRisk,
                "wasCorrect", wasCorrect,
                "classification", kind.name(),
                "calibration", loreLearningEngine.calibration(),
                "status", "accepted"));
    }

    private static Outcome.FeedbackKind resolveKind(String classification, boolean wasCorrect) {
        if (classification == null || classification.isBlank()) {
            return wasCorrect ? Outcome.FeedbackKind.CONFIRMED_BENIGN : Outcome.FeedbackKind.FALSE_POSITIVE;
        }
        try {
            return Outcome.FeedbackKind.valueOf(classification.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            return wasCorrect ? Outcome.FeedbackKind.CONFIRMED_BENIGN : Outcome.FeedbackKind.FALSE_POSITIVE;
        }
    }

    public record FeedbackRequest(String decisionId, double realizedRisk, boolean wasCorrect,
                                  String classification, List<Double> signalStrengths, String notes) {}
}
