package com.cognesis.framework.prediction;

/**
 * Result of the SEER predictive engine.
 *
 * @param predictedRisk near-future risk probability in [0,1]
 * @param confidence    confidence in the prediction in [0,1]
 * @param trend         -1 falling, 0 flat, +1 rising
 * @param model         description of the model/features used
 */
public record PredictionResult(
        double predictedRisk,
        double confidence,
        int trend,
        String model) {

    public PredictionResult {
        predictedRisk = Math.max(0.0, Math.min(1.0, predictedRisk));
        confidence = Math.max(0.0, Math.min(1.0, confidence));
        trend = Math.max(-1, Math.min(1, trend));
    }
}
