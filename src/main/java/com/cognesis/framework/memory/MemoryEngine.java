package com.cognesis.framework.memory;

import com.cognesis.framework.common.DecisionResult;

/**
 * MNEMONIC - the cyber memory engine. It remembers entities, attacks, decisions,
 * outcomes and their relationships as a time-decaying knowledge graph, and it
 * maintains behavioural baselines so future reasoning can quantify deviation.
 */
public interface MemoryEngine {

    /** Persist an incident into the knowledge graph (learn). */
    void memorize(MemoryIncident incident);

    /** Retrieve the most salient memories relevant to an entity. */
    MemoryRecall recall(MemoryQuery query);

    /**
     * Deviation from the behavioural baseline for a feature, in [0,1].
     * 0.5 means the observed value sits exactly on the baseline mean.
     */
    double deviation(String entityId, String featureName, double observedValue);

    /** Feed a behavioural observation into the baseline. */
    void observeBehaviour(String entityId, String featureName, double value);

    /**
     * Store a decision and its full reasoning path in memory: a DECISION node
     * linked to the entity via DECIDED_ON, so future recalls can surface "we
     * decided X about this entity, and here is why".
     */
    void recordDecision(DecisionResult decision);

    /**
     * Close the loop on a past decision: link the DECISION node to an OUTCOME
     * node (realized risk, correctness) via OUTCOME_OF, enabling
     * decision-vs-outcome reasoning.
     */
    void recordOutcome(String decisionId, double realizedRisk, boolean wasCorrect, String notes);
}
