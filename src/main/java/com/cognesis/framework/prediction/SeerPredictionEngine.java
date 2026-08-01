package com.cognesis.framework.prediction;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Default SEER implementation using an exponentially-weighted moving average
 * with a momentum term:
 * <pre>
 *   predicted = last + momentum * (last - previous)
 * </pre>
 * Confidence grows with the number of recorded observations. The trend sign is
 * taken from the momentum direction. This is deliberately simple - a research
 * deployment can swap in ARIMA/Prophet/RU-EWMA behind the same interface.
 */
public class SeerPredictionEngine implements PredictionEngine {

    private static final double MOMENTUM = 0.35;
    private static final double FULL_CONFIDENCE_OBSERVATIONS = 12.0;

    private static final class Series {
        final Deque<Double> history = new ArrayDeque<>();
    }

    private final Map<String, Series> series = new ConcurrentHashMap<>();

    @Override
    public PredictionResult predict(String entityId, double currentRiskEstimate, double memorySalience) {
        Series s = series.get(entityId);
        if (s == null || s.history.isEmpty()) {
            double base = clamp01(0.30 + memorySalience * 0.35 + currentRiskEstimate * 0.5);
            return new PredictionResult(base, 0.15, 0, "seer-ewma(no-history)");
        }
        double last = s.history.peekLast();
        double prev = s.history.size() >= 2
                ? s.history.stream().skip(s.history.size() - 2).findFirst().orElse(last)
                : last;
        double momentum = last - prev;
        double predicted = clamp01(last + MOMENTUM * momentum + 0.15 * (currentRiskEstimate - last));
        double confidence = 1.0 - Math.exp(-s.history.size() / FULL_CONFIDENCE_OBSERVATIONS);
        int trend = momentum > 0.02 ? 1 : momentum < -0.02 ? -1 : 0;
        return new PredictionResult(predicted, confidence, trend, "seer-ewma-momentum");
    }

    @Override
    public void recordRisk(String entityId, double risk, double confidence) {
        Series s = series.computeIfAbsent(entityId, k -> new Series());
        s.history.addLast(clamp01(risk));
        if (s.history.size() > 200) {
            s.history.removeFirst();
        }
    }

    private static double clamp01(double v) {
        return Math.max(0.0, Math.min(1.0, v));
    }
}
