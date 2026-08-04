package com.cognesis.framework.api;

import com.cognesis.framework.learning.WeightStore;
import com.cognesis.framework.trust.TrustEngine;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.ThreadMXBean;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/dashboard")
public class DashboardController {

    private final WeightStore weightStore;
    private final TrustEngine trustEngine;

    public DashboardController(WeightStore weightStore, TrustEngine trustEngine) {
        this.weightStore = weightStore;
        this.trustEngine = trustEngine;
    }

    @GetMapping
    public Map<String, Object> dashboard() {
        MemoryMXBean mem = ManagementFactory.getMemoryMXBean();
        ThreadMXBean threads = ManagementFactory.getThreadMXBean();

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("timestamp", Instant.now().toString());
        result.put("version", "1.0.0");
        result.put("status", "RUNNING");

        Map<String, Object> weights = new LinkedHashMap<>();
        var w = weightStore.load();
        weights.put("evidence", w.evidence());
        weights.put("trust", w.trust());
        weights.put("memory", w.memory());
        weights.put("intent", w.intent());
        weights.put("prediction", w.prediction());
        weights.put("deviation", w.deviation());
        weights.put("likelihoodWeight", w.likelihoodWeight());
        result.put("synapseWeights", weights);

        Map<String, Object> system = new LinkedHashMap<>();
        system.put("heapUsedMB", mem.getHeapMemoryUsage().getUsed() / (1024 * 1024));
        system.put("heapMaxMB", mem.getHeapMemoryUsage().getMax() / (1024 * 1024));
        system.put("threadCount", threads.getThreadCount());
        system.put("daemonThreadCount", threads.getDaemonThreadCount());
        result.put("system", system);

        return result;
    }
}
