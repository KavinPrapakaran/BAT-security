package com.cognesis.framework.benchmark;

/**
 * One calibration bin: the engine's predicted risks in this band compared with
 * the fraction that actually turned out malicious. A well-calibrated engine
 * has predicted close to observed in every band.
 *
 * @param low       bin lower bound (inclusive), in [0,1]
 * @param high      bin upper bound (exclusive except the last), in [0,1]
 * @param predicted mean predicted risk of cases in this bin
 * @param observed  fraction of cases in this bin that were malicious
 * @param count     number of cases in this bin
 */
public record CalibrationBin(
        double low,
        double high,
        double predicted,
        double observed,
        int count) {

    /** Absolute |predicted - observed| for this bin. */
    public double error() {
        return Math.abs(predicted - observed);
    }
}
