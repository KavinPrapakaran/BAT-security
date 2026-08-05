package com.cognesis.framework.benchmark;

import java.util.List;

/**
 * The result of running a decision benchmark over a labeled scenario catalog.
 *
 * @param brierScore         mean squared error between predicted risk and ground truth (lower is better)
 * @param calibrationError   mean |predicted - observed| over populated bins (lower is better)
 * @param baselineBrierScore Brier of the "always predict the base rate" baseline
 * @param meanPredictedPositive mean risk assigned to genuinely malicious cases
 * @param meanPredictedNegative mean risk assigned to genuinely benign cases
 * @param separation         meanPredictedPositive - meanPredictedNegative (higher is better)
 * @param bins               calibration bins
 * @param total              number of evaluated cases
 */
public record BenchmarkReport(
        double brierScore,
        double calibrationError,
        double baselineBrierScore,
        double meanPredictedPositive,
        double meanPredictedNegative,
        double separation,
        List<CalibrationBin> bins,
        int total) {

    /** The engine is better than guessing the base rate. */
    public boolean beatsBaseline() {
        return brierScore < baselineBrierScore;
    }

    /** The engine separates malicious from benign on average risk. */
    public boolean separates() {
        return separation > 0.0;
    }
}
