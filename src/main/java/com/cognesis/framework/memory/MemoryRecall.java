package com.cognesis.framework.memory;

import java.util.List;
import java.util.Map;

/**
 * The set of memories retrieved for a query, with their activation values.
 * Salience is derived from base weight, decay over time and relationship
 * propagation.
 */
public record MemoryRecall(
        List<MemoryItem> items,
        Map<String, Double> activationByItem) {

    public MemoryRecall {
        items = items != null ? List.copyOf(items) : List.of();
        activationByItem = activationByItem != null ? Map.copyOf(activationByItem) : Map.of();
    }

    /**
     * Total salient evidence: an aggregate in [0,1] consumed by SYNAPSE as the
     * memory salience signal M. An empty recall returns the neutral value 0.5
     * so the absence of memory does not push a decision in either direction.
     */
    public double aggregateSalience() {
        if (items.isEmpty()) {
            return 0.5;
        }
        double sum = items.stream().mapToDouble(MemoryItem::activation).sum();
        return Math.max(0.0, Math.min(1.0, sum / items.size()));
    }
}
