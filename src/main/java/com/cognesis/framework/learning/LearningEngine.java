package com.cognesis.framework.learning;

/**
 * LORE - the learning engine. It closes the loop: after outcomes are known, it
 * adjusts the SYNAPSE weights so the framework continuously improves without
 * losing explainability (weights are still attributable per signal).
 */
public interface LearningEngine {

    void learn(Outcome outcome);
}
