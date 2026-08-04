package com.cognesis.framework.context;

import java.util.Locale;
import java.util.Map;

/**
 * Default CONTEXT implementation. Maps the situational context label to a base
 * risk modifier and weight, refined by metadata. Neutral context (unknown or
 * empty) yields 0.5 risk and a low weight so it never moves a decision.
 */
public class SituationalContextEngine implements ContextEngine {

    private static final Map<String, double[]> BASE = Map.of(
            // label              -> {baseRisk, weight}
            "dns-resolution", new double[]{0.40, 0.70},
            "authentication", new double[]{0.55, 0.80},
            "login", new double[]{0.55, 0.80},
            "api-call", new double[]{0.45, 0.70},
            "email", new double[]{0.60, 0.80},
            "file-download", new double[]{0.55, 0.70},
            "privilege-change", new double[]{0.65, 0.85},
            "data-transfer", new double[]{0.60, 0.80});

    @Override
    public ContextAssessment assess(ContextInput input) {
        String label = input == null || input.context() == null
                ? "" : input.context().trim().toLowerCase(Locale.ROOT);

        double[] base = BASE.getOrDefault(label, new double[]{0.5, 0.4});
        double risk = base[0];
        double weight = base[1];

        Map<String, Object> meta = input == null ? Map.of() : input.metadata();
        Object env = meta.get("env");
        if ("prod".equalsIgnoreCase(String.valueOf(env)) || "production".equalsIgnoreCase(String.valueOf(env))) {
            weight = Math.min(1.0, weight + 0.10);
        }
        Object geo = meta.get("geo");
        if ("anon".equalsIgnoreCase(String.valueOf(geo)) || "tor".equalsIgnoreCase(String.valueOf(geo))) {
            risk = Math.min(1.0, risk + 0.15);
        }
        Object sourceIp = meta.get("sourceIp");
        if (sourceIp != null && !String.valueOf(sourceIp).isBlank()) {
            weight = Math.min(1.0, weight + 0.05);
        }

        String description = label.isBlank()
                ? "unknown environment; neutral context assumed"
                : "context '" + label + "' (weight " + String.format("%.2f", weight) + ")";
        return new ContextAssessment(risk, weight, description);
    }
}
