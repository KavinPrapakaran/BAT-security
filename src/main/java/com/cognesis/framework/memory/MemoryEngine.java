package com.cognesis.framework.memory;

/**
 * MNEMONIC - the cyber memory engine. It remembers entities, attacks, decisions
 * and relationships as a time-decaying knowledge graph, and it maintains
 * behavioural baselines so future reasoning can quantify deviation.
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
}
