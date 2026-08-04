package com.cognesis.framework.memory;

import com.cognesis.framework.common.Decision;
import com.cognesis.framework.common.DecisionResult;
import com.cognesis.framework.common.ReasoningStep;
import com.cognesis.framework.common.RecommendedAction;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MnemonicDecisionMemoryTest {

    private final MnemonicMemoryEngine memory = new MnemonicMemoryEngine(0.02, 50);

    private DecisionResult result(String entityId, Decision decision, double risk) {
        return new DecisionResult(UUID.randomUUID(), entityId, "DOMAIN", decision,
                RecommendedAction.WARN_NOTIFY, risk, 0.5, 0.8, 0.4,
                "test rationale",
                List.of(new ReasoningStep("SYNAPSE", "fused", risk, 0.8, "x")),
                Instant.now());
    }

    @Test
    void recordDecisionStoresDecisionNodeLinkedToEntity() {
        DecisionResult decision = result("paypa1.com", Decision.WARN, 0.6);
        memory.recordDecision(decision);

        MemoryRecall recall = memory.recall(new MemoryQuery("paypa1.com", "DOMAIN", true, 50));
        assertTrue(recall.items().stream().anyMatch(i -> i.nodeKey().equals("decision:" + decision.decisionId())),
                "decision node must be recalled");
        assertTrue(recall.items().stream().anyMatch(i -> i.nodeType().equals("DECISION")),
                "decision node must carry type DECISION");
        MemoryItem decisionItem = recall.items().stream()
                .filter(i -> i.nodeKey().equals("decision:" + decision.decisionId())).findFirst().orElseThrow();
        assertEquals("WARN", decisionItem.properties().get("decision"));
        assertEquals(0.6, decisionItem.properties().get("risk"));
        assertNotNull(decisionItem.properties().get("chain"), "reasoning path must be stored for recall");
    }

    @Test
    void recordOutcomeClosesTheLoopFromDecisionToOutcome() {
        DecisionResult decision = result("malware.test", Decision.BLOCK, 0.9);
        memory.recordDecision(decision);

        memory.recordOutcome(decision.decisionId().toString(), 0.95, true, "confirmed by sandbox");

        MemoryRecall recall = memory.recall(new MemoryQuery("decision:" + decision.decisionId(), "DECISION", true, 50));
        assertTrue(recall.items().stream().anyMatch(i -> i.nodeKey().equals("outcome:" + decision.decisionId())),
                "outcome node must be reachable from the decision via OUTCOME_OF");
        assertTrue(recall.items().stream().anyMatch(i -> i.nodeType().equals("OUTCOME")),
                "outcome node must carry type OUTCOME");
    }

    @Test
    void relationshipInferenceRecognisesKnownEntityTypes() {
        memory.memorize(new MemoryIncident("user:alice", "USER",
                java.util.Map.of("RESOLVES_TO", List.of("domain:evil.example"),
                        "USES_TECHNIQUE", List.of("technique:spearphishing")),
                List.of("PHISHING"), "SUSPECTED", 0.8, Instant.now()));

        MemoryRecall recall = memory.recall(new MemoryQuery("user:alice", "USER", true, 50));
        assertTrue(recall.items().stream().anyMatch(i -> i.nodeType().equals("DOMAIN")),
                "domain:evil.example should be typed DOMAIN");
        assertTrue(recall.items().stream().anyMatch(i -> i.nodeType().equals("TECHNIQUE")),
                "technique:spearphishing should be typed TECHNIQUE");
    }
}
