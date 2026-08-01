package com.cognesis.framework.prediction;

/**
 * SEER - the predictive engine. It turns the framework's history and current
 * signal stream into a short-horizon forecast of risk so decisions are made
 * about where a situation is heading, not just where it is now.
 */
public interface PredictionEngine {

    /**
     * Predict near-future risk for an entity given the currently observed risk
     * estimate and the salience of recalled memory.
     */
    PredictionResult predict(String entityId, double currentRiskEstimate, double memorySalience);

    /** Feed the realized risk back so the trend model can learn. */
    void recordRisk(String entityId, double risk, double confidence);
}
