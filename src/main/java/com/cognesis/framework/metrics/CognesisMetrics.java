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
    private final Counter feedRefreshCounter;
    private final Counter feedIocsCounter;
    private final Counter liveFactsHits;
    private final Counter liveFactsMisses;
    private final Counter liveFactsFailures;
    private final Counter graphAssociations;
    private final Counter feedbackEvents;

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
        this.feedRefreshCounter = Counter.builder("cognesis.feed.refresh.total")
                .description("Threat-intel feed refresh attempts")
                .register(registry);
        this.feedIocsCounter = Counter.builder("cognesis.feed.iocs.total")
                .description("Threat-intel IOCs ingested from feeds")
                .register(registry);
        this.liveFactsHits = Counter.builder("cognesis.live.facts.cache.hits")
                .description("Live DNS facts cache hits")
                .register(registry);
        this.liveFactsMisses = Counter.builder("cognesis.live.facts.cache.misses")
                .description("Live DNS facts cache misses")
                .register(registry);
        this.liveFactsFailures = Counter.builder("cognesis.live.facts.failures")
                .description("Live DNS facts lookups that failed all sources")
                .register(registry);
        this.graphAssociations = Counter.builder("cognesis.actg.associations.total")
                .description("ACTG graph relationships recorded")
                .register(registry);
        this.feedbackEvents = Counter.builder("cognesis.learning.feedback.total")
                .description("Decision feedback events received")
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

    public void recordFeedRefresh(int ingested) {
        feedRefreshCounter.increment();
        feedIocsCounter.increment(ingested);
    }

    public void recordLiveFactsHit() {
        liveFactsHits.increment();
    }

    public void recordLiveFactsMiss() {
        liveFactsMisses.increment();
    }

    public void recordLiveFactsFallback() {
        liveFactsFailures.increment();
    }

    public void recordActgAssociations(int count) {
        graphAssociations.increment(count);
    }

    public void recordFeedback(int count) {
        feedbackEvents.increment(count);
    }
}
