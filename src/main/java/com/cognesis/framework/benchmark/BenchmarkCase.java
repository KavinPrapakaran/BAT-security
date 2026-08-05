package com.cognesis.framework.benchmark;

/**
 * One labeled calibration case: a known-good or known-bad entity. The
 * benchmark treats the engine's risk score as a predicted probability of
 * maliciousness and compares it against this ground truth.
 *
 * @param id          scenario identifier (entity id the engine will evaluate)
 * @param groundTruth 1.0 if genuinely malicious, 0.0 if benign
 */
public record BenchmarkCase(String id, double groundTruth) {

    public BenchmarkCase {
        groundTruth = Math.max(0.0, Math.min(1.0, groundTruth));
    }

    public static BenchmarkCase malicious(String id) {
        return new BenchmarkCase(id, 1.0);
    }

    public static BenchmarkCase benign(String id) {
        return new BenchmarkCase(id, 0.0);
    }
}
