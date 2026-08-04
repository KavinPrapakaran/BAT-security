package com.cognesis.framework.api;

import com.cognesis.framework.learning.LearningEngine;
import com.cognesis.framework.learning.Outcome;
import com.cognesis.framework.memory.MemoryEngine;
import com.cognesis.framework.persistence.DecisionLogDao;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/feedback")
public class LoreFeedbackController {

    private final LearningEngine loreLearningEngine;
    private final MemoryEngine memoryEngine;

    public LoreFeedbackController(LearningEngine loreLearningEngine, MemoryEngine memoryEngine) {
        this.loreLearningEngine = loreLearningEngine;
        this.memoryEngine = memoryEngine;
    }

    @PostMapping
    public ResponseEntity<Map<String, Object>> submitFeedback(@RequestBody FeedbackRequest request) {
        UUID decisionId = UUID.fromString(request.decisionId());
        double realizedRisk = Math.max(0.0, Math.min(1.0, request.realizedRisk()));
        boolean wasCorrect = request.wasCorrect();
        String notes = request.notes() != null ? request.notes() : "";

        loreLearningEngine.learn(new Outcome(decisionId, realizedRisk, wasCorrect, notes));
        memoryEngine.recordOutcome(decisionId.toString(), realizedRisk, wasCorrect, notes);

        return ResponseEntity.accepted().body(Map.of(
                "decisionId", request.decisionId(),
                "realizedRisk", realizedRisk,
                "wasCorrect", wasCorrect,
                "status", "accepted"));
    }

    public record FeedbackRequest(String decisionId, double realizedRisk, boolean wasCorrect, String notes) {}
}
