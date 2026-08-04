package com.cognesis.framework.persistence;

import com.cognesis.framework.memory.MemoryItem;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Persistence abstraction for the MNEMONIC memory graph (nodes, edges, baselines).
 * The default implementation is a no-op so the scaffold runs in-memory; production
 * injects the JDBC store backed by the memory_node / memory_edge tables.
 */
public interface MemoryGraphDao {

    default void saveNode(String nodeKey, String nodeType, String label,
                          double baseWeight, Map<String, Object> properties) {}

    default void saveEdge(String sourceKey, String targetKey, String relation,
                          double weight) {}

    default void saveBaseline(String entityId, String featureName,
                              double mean, double m2, long count) {}

    default Optional<MemoryItem> findNode(String nodeKey) {
        return Optional.empty();
    }

    default List<MemoryItem> findNeighbors(String nodeKey) {
        return List.of();
    }

    default void loadAllNodes(java.util.function.Consumer<MemoryNode> consumer) {}

    default void loadAllEdges(java.util.function.Consumer<MemoryEdge> consumer) {}

    default void loadAllBaselines(java.util.function.Consumer<BaselineRow> consumer) {}

    record MemoryNode(String nodeKey, String nodeType, String label,
                      double baseWeight, Map<String, Object> properties,
                      java.time.Instant lastSeen) {}

    record MemoryEdge(String sourceKey, String targetKey, String relation,
                      double weight, java.time.Instant lastObserved) {}

    record BaselineRow(String entityId, String featureName,
                       double mean, double m2, long count) {}
}
