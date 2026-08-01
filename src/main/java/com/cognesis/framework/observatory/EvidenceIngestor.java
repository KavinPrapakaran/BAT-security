package com.cognesis.framework.observatory;

import com.cognesis.framework.common.EvidenceConfidence;
import com.cognesis.framework.common.EvidenceType;
import com.cognesis.framework.common.Provenance;

import java.time.Duration;
import java.time.Instant;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Aggregates evidence fragments into one evidence strength and the four
 * confidence factors (agreement, coverage, freshness, provenance).
 *
 * <pre>
 *   evidenceStrength = confidence-weighted mean of fragment strengths
 *   agreement        = 1 - min(1, dispersion / 0.5)
 *   coverage         = min(1, observedSignalTypes / EXPECTED_SIGNAL_TYPES)
 *   freshness        = mean over fragments of max(0, 1 - ageHours / 72)
 *   provenance       = mean provenance reliability
 * </pre>
 */
public class EvidenceIngestor {

    private static final int EXPECTED_SIGNAL_TYPES = 8;

    private static final Map<Provenance, Double> PROVENANCE_RELIABILITY = new EnumMap<>(Provenance.class);

    static {
        PROVENANCE_RELIABILITY.put(Provenance.LIVE_TRAFFIC, 0.95);
        PROVENANCE_RELIABILITY.put(Provenance.DNS_RESPONSE, 0.90);
        PROVENANCE_RELIABILITY.put(Provenance.CERTIFICATE_TRANSPARENCY, 0.90);
        PROVENANCE_RELIABILITY.put(Provenance.POLICY_ANNOTATION, 0.90);
        PROVENANCE_RELIABILITY.put(Provenance.ANALYST_INPUT, 0.85);
        PROVENANCE_RELIABILITY.put(Provenance.PAST_DECISION, 0.80);
        PROVENANCE_RELIABILITY.put(Provenance.TELEMETRY, 0.80);
        PROVENANCE_RELIABILITY.put(Provenance.WHOIS, 0.70);
        PROVENANCE_RELIABILITY.put(Provenance.CONFIGURATION, 0.70);
        PROVENANCE_RELIABILITY.put(Provenance.THREAT_INTEL_FEED, 0.60);
        PROVENANCE_RELIABILITY.put(Provenance.OSINT, 0.50);
    }

    public AggregatedEvidence aggregate(List<EvidenceFragment> fragments) {
        if (fragments == null || fragments.isEmpty()) {
            return new AggregatedEvidence(0.0, EvidenceConfidence.neutral(), List.of());
        }

        double weightSum = 0.0;
        double weightedStrength = 0.0;
        double freshnessSum = 0.0;
        double provenanceSum = 0.0;
        for (EvidenceFragment f : fragments) {
            double c = f.confidence();
            weightedStrength += f.strength() * c;
            weightSum += c;
            freshnessSum += freshness(f.observedAt());
            provenanceSum += PROVENANCE_RELIABILITY.getOrDefault(f.provenance(), 0.5);
        }

        double evidenceStrength = weightSum > 0 ? weightedStrength / weightSum : 0.0;

        // Dominant-signal rule: a single decisive, high-confidence signal (e.g. a
        // confirmed IOC hit at strength 1.0) must not be diluted by averaging.
        double dominant = fragments.stream()
                .filter(f -> f.strength() >= 0.85 && f.confidence() >= 0.8)
                .mapToDouble(EvidenceFragment::strength)
                .max().orElse(0.0);
        evidenceStrength = Math.max(evidenceStrength, dominant);

        double freshness = freshnessSum / fragments.size();
        double provenanceQuality = provenanceSum / fragments.size();

        long distinctTypes = fragments.stream().map(EvidenceFragment::type).distinct().count();
        double coverage = Math.min(1.0, (double) distinctTypes / EXPECTED_SIGNAL_TYPES);

        double agreement = 1.0 - Math.min(1.0, dispersion(fragments) / 0.5);

        return new AggregatedEvidence(
                evidenceStrength,
                new EvidenceConfidence(agreement, coverage, freshness, provenanceQuality),
                fragments);
    }

    private double freshness(Instant observedAt) {
        if (observedAt == null) {
            return 0.5;
        }
        double ageHours = Math.max(0.0, Duration.between(observedAt, Instant.now()).toMinutes() / 60.0);
        return Math.max(0.0, 1.0 - ageHours / 72.0);
    }

    /** Normalized dispersion (std dev / mean) of the fragment strengths. */
    private double dispersion(List<EvidenceFragment> fragments) {
        double mean = fragments.stream().mapToDouble(EvidenceFragment::strength).average().orElse(0.5);
        double variance = fragments.stream()
                .mapToDouble(f -> Math.pow(f.strength() - mean, 2))
                .average().orElse(0.0);
        return Math.sqrt(variance) / Math.max(1e-6, mean);
    }
}
