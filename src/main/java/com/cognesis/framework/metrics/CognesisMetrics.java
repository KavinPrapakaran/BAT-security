package com.cognesis.framework.metrics;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

@Component
public class CognesisMetrics {

    private final MeterRegistry registry;
    private final Counter decisionsCounter;
    private final Counter evidenceFragmentsCounter;
    private final Timer acdeTimer;

    public CognesisMetrics(MeterRegistry registry) {
        this.registry = registry;
        this.decisionsCounter = Counter.builder("cognesis.decisions.total")
                .description("Total number of decisions made by the ACDE")
                .register(registry);
        this.evidenceFragmentsCounter = Counter.builder("cognesis.evidence.fragments.total")
                .description("Total evidence fragments processed")
                .register(registry);
        this.acdeTimer = Timer.builder("cognesis.acde.evaluation")
                .description("ACDE evaluation latency")
                .publishPercentiles(0.5, 0.95, 0.99)
                .register(registry);
    }

    public void recordDecision(String decision, String entityType) {
        decisionsCounter.increment();
        Counter.builder("cognesis.decisions.by_type")
                .tag("decision", decision)
                .tag("entityType", entityType)
                .description("Decisions by type and entity")
                .register(registry).increment();
    }

    public void recordEvidenceFragments(int count) {
        evidenceFragmentsCounter.increment(count);
    }

    public void recordAcdeEvaluation(long durationNanos) {
        acdeTimer.record(durationNanos, TimeUnit.NANOSECONDS);
    }
}
