package com.cognesis.framework.actg;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe in-memory {@link ActgGraph}. Trust is not stored per entity: it
 * is recomputed on read from the entity's own risk plus the risk of everything
 * it is connected to, so a clean domain that resolves to a known-bad IP is
 * immediately suspicious even though the domain itself was never seen before.
 */
public class SecurityKnowledgeGraph implements ActgGraph {

    private static final double MAX_NODE_RISK = 1.0;
    private static final double EDGE_STRENGTHEN = 0.25;
    private static final double RISK_EPSILON = 0.0001;

    private static final class EdgeKey {
        private final String source;
        private final String target;
        private final ActgRelation relation;

        EdgeKey(String source, String target, ActgRelation relation) {
            this.source = source;
            this.target = target;
            this.relation = relation;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof EdgeKey other)) {
                return false;
            }
            return source.equals(other.source) && target.equals(other.target) && relation == other.relation;
        }

        @Override
        public int hashCode() {
            return 31 * (31 * source.hashCode() + target.hashCode()) + relation.hashCode();
        }
    }

    private static final class EdgeState {
        double weight = 1.0;
        Instant observedAt = Instant.now();
    }

    private final Map<String, ActgNode> nodes = new ConcurrentHashMap<>();
    private final Map<EdgeKey, EdgeState> edges = new ConcurrentHashMap<>();

    @Override
    public void recordAssociation(String sourceKey, ActgEntityType sourceType,
                                  String targetKey, ActgEntityType targetType,
                                  ActgRelation relation) {
        recordObservation(sourceKey, sourceType, 0.0);
        recordObservation(targetKey, targetType, 0.0);
        EdgeKey key = new EdgeKey(sourceKey, targetKey, relation);
        edges.compute(key, (k, state) -> {
            EdgeState s = state != null ? state : new EdgeState();
            s.weight = Math.min(3.0, s.weight + EDGE_STRENGTHEN);
            s.observedAt = Instant.now();
            return s;
        });
    }

    @Override
    public void recordObservation(String key, ActgEntityType entityType, double risk) {
        double clamped = Math.max(0.0, Math.min(MAX_NODE_RISK, risk));
        nodes.compute(key, (k, existing) -> {
            if (existing == null) {
                return new ActgNode(k, entityType, entityType.name().toLowerCase(), clamped,
                        Instant.now(), Map.of());
            }
            // Risk is a high-water mark: it ratchets up with each bad
            // observation and never silently erases history, so a clean
            // domain sitting next to a dirty node stays flagged.
            double merged = Math.max(existing.risk(), clamped);
            return new ActgNode(k, entityType, existing.label(), merged, Instant.now(), existing.properties());
        });
    }

    @Override
    public ActgNode node(String key) {
        return nodes.get(key);
    }

    @Override
    public List<ActgNode> neighborhood(String key) {
        List<ActgNode> result = new ArrayList<>();
        for (Map.Entry<EdgeKey, EdgeState> entry : edges.entrySet()) {
            EdgeKey edge = entry.getKey();
            if (edge.source.equals(key)) {
                ActgNode target = nodes.get(edge.target);
                if (target != null) {
                    result.add(target);
                }
            } else if (edge.target.equals(key)) {
                ActgNode source = nodes.get(edge.source);
                if (source != null) {
                    result.add(source);
                }
            }
        }
        result.sort(Comparator.comparingDouble(ActgNode::risk).reversed());
        return result;
    }

    /**
     * Aggregate risk of an entity considering its own score plus every
     * risk-bearing neighbor weighted by edge strength. Unknown neighbors (risk
     * 0.0) carry no signal and therefore do not dilute the average, so a new
     * user or source IP touching a domain cannot wash out a dirty IP's signal.
     * Zero when the entity is unknown.
     */
    @Override
    public double neighborhoodRisk(String key) {
        ActgNode own = nodes.get(key);
        if (own == null) {
            return 0.0;
        }
        double weightSum = 1.0;
        double riskSum = own.risk() * 1.0;
        for (Map.Entry<EdgeKey, EdgeState> entry : edges.entrySet()) {
            EdgeKey edge = entry.getKey();
            EdgeState state = entry.getValue();
            boolean touches = edge.source.equals(key) || edge.target.equals(key);
            if (!touches) {
                continue;
            }
            String other = edge.source.equals(key) ? edge.target : edge.source;
            ActgNode otherNode = nodes.get(other);
            if (otherNode == null || otherNode.risk() < RISK_EPSILON) {
                continue;
            }
            weightSum += state.weight;
            riskSum += otherNode.risk() * state.weight;
        }
        return Math.max(0.0, Math.min(MAX_NODE_RISK, riskSum / weightSum));
    }

    @Override
    public int edgeCount() {
        return edges.size();
    }

    @Override
    public int nodeCount() {
        return nodes.size();
    }

    @Override
    public void clear() {
        nodes.clear();
        edges.clear();
    }
}
