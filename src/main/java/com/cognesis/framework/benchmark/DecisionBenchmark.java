package com.cognesis.framework.benchmark;

import com.cognesis.framework.common.DecisionResult;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * Calibration harness for the framework's decision engines. Every domain engine
 * (DIE for DNS, VOID for email) emits a risk score per evaluation; that score
 * is meant to be a calibrated probability that the entity is malicious. This
 * harness quantifies how well that claim holds:
 *
 * <ul>
 *   <li><b>Brier score</b> - mean squared error between predicted risk and the
 *       ground truth label. Baseline: always predicting the observed base rate.</li>
 *   <li><b>Bin calibration</b> - predicted risk vs observed fraction per risk
 *       band; calibration error is the mean absolute deviation.</li>
 *   <li><b>Separation</b> - mean risk assigned to positives minus mean risk
 *       assigned to negatives.</li>
 * </ul>
 *
 * <p>The harness is domain-agnostic: any engine that yields a
 * {@link DecisionResult} per scenario id can be benchmarked, so new engines can
 * be proven calibrated before they are trusted on the hot path.
 */
public final class DecisionBenchmark {

    private static final int BIN_COUNT = 5;

    private DecisionBenchmark() {
    }

    /**
     * Run the benchmark over a labeled catalog.
     *
     * @param cases    labeled scenarios; the key is the entity id handed to the evaluator
     * @param evaluate produces the decision for a scenario id
     */
    public static BenchmarkReport run(Map<String, Double> cases,
                                      Function<String, DecisionResult> evaluate) {
        if (cases.isEmpty()) {
            return new BenchmarkReport(0.0, 0.0, 0.0, 0.0, 0.0, 0.0, List.of(), 0);
        }

        List<double[]> rows = new ArrayList<>();
        double baseRate = cases.values().stream().mapToDouble(Double::doubleValue).average().orElse(0.0);
        double brier = 0.0;
        double sumPos = 0.0;
        double sumNeg = 0.0;
        int pos = 0;
        int neg = 0;

        for (Map.Entry<String, Double> entry : cases.entrySet()) {
            double truth = entry.getValue();
            DecisionResult result = evaluate.apply(entry.getKey());
            double predicted = result == null ? 0.0 : result.riskScore();
            rows.add(new double[]{predicted, truth});
            brier += (predicted - truth) * (predicted - truth);
            if (truth >= 0.5) {
                sumPos += predicted;
                pos++;
            } else {
                sumNeg += predicted;
                neg++;
            }
        }
        brier /= rows.size();

        double baselineBrier = baselineBrier(cases.values(), baseRate);
        List<CalibrationBin> bins = bins(rows);
        double calibrationError = bins.stream()
                .filter(b -> b.count() > 0)
                .mapToDouble(CalibrationBin::error)
                .average().orElse(0.0);

        double meanPos = pos > 0 ? sumPos / pos : 0.0;
        double meanNeg = neg > 0 ? sumNeg / neg : 0.0;

        return new BenchmarkReport(brier, calibrationError, baselineBrier,
                meanPos, meanNeg, meanPos - meanNeg, bins, rows.size());
    }

    private static double baselineBrier(Iterable<Double> truths, double baseRate) {
        double sum = 0.0;
        int n = 0;
        for (double truth : truths) {
            sum += (baseRate - truth) * (baseRate - truth);
            n++;
        }
        return n > 0 ? sum / n : 0.0;
    }

    private static List<CalibrationBin> bins(List<double[]> rows) {
        List<CalibrationBin> bins = new ArrayList<>();
        for (int b = 0; b < BIN_COUNT; b++) {
            double low = (double) b / BIN_COUNT;
            double high = (double) (b + 1) / BIN_COUNT;
            double predSum = 0.0;
            double obsSum = 0.0;
            int count = 0;
            for (double[] row : rows) {
                double p = row[0];
                boolean inBin = p >= low && (p < high || (b == BIN_COUNT - 1 && p <= high));
                if (inBin) {
                    predSum += p;
                    obsSum += row[1];
                    count++;
                }
            }
            bins.add(new CalibrationBin(low, high,
                    count > 0 ? predSum / count : 0.0,
                    count > 0 ? obsSum / count : 0.0,
                    count));
        }
        return bins;
    }
}
