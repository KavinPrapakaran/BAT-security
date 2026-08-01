package com.cognesis.framework.memory;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MnemonicMemoryEngineTest {

    private final MnemonicMemoryEngine engine = new MnemonicMemoryEngine(0.02, 20);

    @Test
    void emptyRecallIsNeutral() {
        MemoryRecall recall = engine.recall(new MemoryQuery("unknown.example", "DOMAIN"));
        assertEquals(0.5, recall.aggregateSalience(), 1e-9, "absence of memory must be neutral");
    }

    @Test
    void memorizeThenRecallSurfacesEntity() {
        engine.memorize(new MemoryIncident("evil.example", "DOMAIN",
                java.util.Map.of("CONNECTED_TO", java.util.List.of("ip:203.0.113.66")),
                java.util.List.of("DNS_DGA"), "CONFIRMED_MALWARE", 0.9, java.time.Instant.now()));

        MemoryRecall recall = engine.recall(new MemoryQuery("evil.example", "DOMAIN"));
        assertFalse(recall.items().isEmpty(), "recalled entity should be present");
        assertTrue(recall.aggregateSalience() > 0.5, "severe incident should raise salience above neutral");
    }

    @Test
    void relatedEntitiesAreRecalledViaPropagation() {
        engine.memorize(new MemoryIncident("evil.example", "DOMAIN",
                java.util.Map.of("CONNECTED_TO", java.util.List.of("ip:203.0.113.66")),
                java.util.List.of("DNS_FAST_FLUX"), "CONFIRMED_C2", 0.95, java.time.Instant.now()));

        MemoryRecall ipRecall = engine.recall(new MemoryQuery("ip:203.0.113.66", "IP"));
        assertTrue(ipRecall.items().stream().anyMatch(i -> i.nodeKey().equals("evil.example")),
                "activation should propagate to connected nodes");
    }

    @Test
    void deviationIsNeutralWithoutBaseline() {
        assertEquals(0.5, engine.deviation("host-a", "logins_per_hour", 500.0), 1e-9);
    }

    @Test
    void baselineDeviationTracksMean() {
        for (int i = 0; i < 50; i++) {
            engine.observeBehaviour("host-a", "logins_per_hour", 10.0);
        }
        double atMean = engine.deviation("host-a", "logins_per_hour", 10.0);
        double farAbove = engine.deviation("host-a", "logins_per_hour", 100.0);
        assertTrue(Math.abs(atMean - 0.5) < 0.15, "value at baseline mean should be near neutral");
        assertTrue(farAbove > atMean, "value far above baseline mean should raise deviation");
    }
}
