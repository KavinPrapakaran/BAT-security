package com.cognesis.framework.memory;

import com.cognesis.framework.common.DecisionResult;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Default MNEMONIC implementation. In-memory for the scaffold; the same
 * semantics map directly onto the memory_node / memory_edge tables and can be
 * backed by a graph database (Neo4j) in production.
 *
 * <h2>Retrieval strategy: spreading activation</h2>
 * A node's activation is its base weight decayed over time, plus a fraction of
 * the activation propagated from strongly-connected neighbours:
 * <pre>
 *   A(n) = base(n) * exp(-lambda_a * ageHours(n))
 *          + sum over neighbours n' of edge(n,n') * A(n') * propagationFactor
 * </pre>
 * Two iterations of propagation are applied; results are sorted by activation.
 */
public class MnemonicMemoryEngine implements MemoryEngine {

    private static final double PROPAGATION_FACTOR = 0.4;

    private final double activationDecay;
    private final int recallLimit;

    private final Map<String, Node> nodes = new ConcurrentHashMap<>();
    private final Map<String, Map<String, Edge>> adjacency = new ConcurrentHashMap<>();
    private final Map<String, FeatureBaseline> baselines = new ConcurrentHashMap<>();

    public MnemonicMemoryEngine(double activationDecay, int recallLimit) {
        this.activationDecay = activationDecay;
        this.recallLimit = recallLimit;
    }

    private static final class Node {
        final String key;
        final String type;
        String label;
        double baseWeight;
        Instant lastSeen;
        final Map<String, Object> properties = new ConcurrentHashMap<>();

        Node(String key, String type, String label, double baseWeight) {
            this.key = key;
            this.type = type;
            this.label = label;
            this.baseWeight = baseWeight;
            this.lastSeen = Instant.now();
        }
    }

    private static final class Edge {
        final String targetKey;
        final String relation;
        double weight;
        Instant lastObserved;

        Edge(String targetKey, String relation, double weight) {
            this.targetKey = targetKey;
            this.relation = relation;
            this.weight = weight;
            this.lastObserved = Instant.now();
        }
    }

    private static final class FeatureBaseline {
        double mean;
        double m2;
        long count;

        void add(double v) {
            count++;
            double delta = v - mean;
            mean += delta / count;
            double delta2 = v - mean;
            m2 += delta * delta2;
        }

        double stddev() {
            return count > 1 ? Math.sqrt(m2 / (count - 1)) : 1.0;
        }
    }

    @Override
    public void memorize(MemoryIncident incident) {
        Node subject = upsert(incident.subjectId(), incident.subjectType(), incident.subjectId(),
                Math.max(0.2, incident.severity()));

        Map<String, Edge> subjectEdges = adjacency.computeIfAbsent(subject.key, k -> new ConcurrentHashMap<>());
        for (Map.Entry<String, List<String>> entry : incident.relations().entrySet()) {
            String relation = entry.getKey();
            for (String target : entry.getValue()) {
                Node related = upsert(target, typeOf(target), target, 0.5);
                Edge edge = subjectEdges.computeIfAbsent(target, k -> new Edge(target, relation, 0.0));
                edge.weight = Math.min(1.0, edge.weight + incident.severity() * 0.3);
                edge.lastObserved = incident.happenedAt();
                Map<String, Edge> back = adjacency.computeIfAbsent(target, k -> new ConcurrentHashMap<>());
                Edge reverse = back.computeIfAbsent(subject.key, k -> new Edge(subject.key, relation, 0.0));
                reverse.weight = edge.weight;
                reverse.lastObserved = incident.happenedAt();
            }
        }
        subject.baseWeight = Math.min(1.0, subject.baseWeight + incident.severity() * 0.2);
        subject.lastSeen = incident.happenedAt();
    }

    @Override
    public void recordDecision(DecisionResult decision) {
        String decisionKey = "decision:" + decision.decisionId();
        Map<String, Object> props = new HashMap<>();
        props.put("entityId", decision.entityId());
        props.put("entityType", decision.entityType());
        props.put("decision", decision.decision().name());
        props.put("risk", decision.riskScore());
        props.put("confidence", decision.confidenceScore());
        props.put("rationale", decision.rationale());
        props.put("chain", decision.reasoningChain().stream()
                .map(s -> s.engine() + ": " + s.claim()).toList());

        Node decisionNode = upsert(decisionKey, "DECISION", decisionKey, clamp(decision.riskScore()));
        decisionNode.properties.putAll(props);
        link(decision.entityId(), decision.entityType(), Relations.DECIDED_ON, decisionKey, decision.riskScore(),
                decision.decidedAt());
        decisionNode.baseWeight = Math.max(decisionNode.baseWeight, clamp(decision.riskScore()));
    }

    @Override
    public void recordOutcome(String decisionId, double realizedRisk, boolean wasCorrect, String notes) {
        String decisionKey = "decision:" + decisionId;
        String outcomeKey = "outcome:" + decisionId;
        Node outcomeNode = upsert(outcomeKey, "OUTCOME", outcomeKey, clamp(realizedRisk));
        outcomeNode.properties.put("realizedRisk", realizedRisk);
        outcomeNode.properties.put("wasCorrect", wasCorrect);
        outcomeNode.properties.put("notes", notes);
        link(decisionKey, "DECISION", Relations.OUTCOME_OF, outcomeKey, clamp(realizedRisk), Instant.now());
    }

    private void link(String fromKey, String fromType, String relation, String toKey,
                      double weight, Instant at) {
        Node from = upsert(fromKey, fromType, fromKey, Math.max(0.2, weight));
        Map<String, Edge> fromEdges = adjacency.computeIfAbsent(from.key, k -> new ConcurrentHashMap<>());
        Edge edge = fromEdges.computeIfAbsent(toKey, k -> new Edge(toKey, relation, 0.0));
        edge.weight = Math.min(1.0, edge.weight + weight * 0.3);
        edge.lastObserved = at;
        Map<String, Edge> back = adjacency.computeIfAbsent(toKey, k -> new ConcurrentHashMap<>());
        Edge reverse = back.computeIfAbsent(fromKey, k -> new Edge(fromKey, relation, 0.0));
        reverse.weight = edge.weight;
        reverse.lastObserved = at;
    }

    /** Infers an entity type from a "type:key" convention, e.g. ip:x, user:y, cert:z. */
    private static String typeOf(String key) {
        int idx = key.indexOf(':');
        if (idx > 0) {
            String prefix = key.substring(0, idx).toUpperCase();
            return switch (prefix) {
                case "IP", "DOMAIN", "CERT", "CERTIFICATE", "USER", "DEVICE", "HASH",
                        "ACCOUNT", "EMAIL", "ATTACK", "TECHNIQUE", "DECISION", "OUTCOME" -> prefix.equals("CERT") ? "CERTIFICATE" : prefix;
                default -> "RELATED";
            };
        }
        return "RELATED";
    }

    @Override
    public MemoryRecall recall(MemoryQuery query) {
        Instant now = Instant.now();
        Map<String, Double> activation = new HashMap<>();
        Map<String, Integer> hop = new HashMap<>();

        Node seed = nodes.get(query.entityId());
        if (seed == null) {
            seed = nodes.get(key(query.entityId(), query.entityType()));
        }
        if (seed != null) {
            activation.put(seed.key, activationOf(seed, now));
            hop.put(seed.key, 0);
        }

        for (int iteration = 0; iteration < 2; iteration++) {
            Map<String, Double> next = new HashMap<>(activation);
            for (Map.Entry<String, Double> e : activation.entrySet()) {
                int h = hop.get(e.getKey());
                if (h >= 2) {
                    continue;
                }
                Map<String, Edge> edges = adjacency.getOrDefault(e.getKey(), Map.of());
                for (Edge edge : edges.values()) {
                    double incoming = e.getValue() * edge.weight * PROPAGATION_FACTOR;
                    next.merge(edge.targetKey, incoming, Math::max);
                    hop.merge(edge.targetKey, h + 1, Math::min);
                }
            }
            activation = next;
        }

        List<MemoryItem> items = activation.entrySet().stream()
                .map(entry -> toItem(entry.getKey(), entry.getValue()))
                .filter(i -> i != null)
                .sorted(Comparator.comparingDouble(MemoryItem::activation).reversed())
                .limit(recallLimit)
                .toList();

        return new MemoryRecall(items, activation);
    }

    @Override
    public double deviation(String entityId, String featureName, double observedValue) {
        FeatureBaseline baseline = baselines.get(key(entityId, featureName));
        if (baseline == null || baseline.count == 0) {
            return 0.5;
        }
        double z = (observedValue - baseline.mean) / Math.max(baseline.stddev(), 1e-6);
        return 1.0 / (1.0 + Math.exp(-z));
    }

    @Override
    public void observeBehaviour(String entityId, String featureName, double value) {
        baselines.computeIfAbsent(key(entityId, featureName), k -> new FeatureBaseline()).add(value);
    }

    private Node upsert(String key, String type, String label, double weight) {
        return nodes.computeIfAbsent(key, k -> new Node(k, type, label, weight));
    }

    private MemoryItem toItem(String key, double activation) {
        Node node = nodes.get(key);
        if (node == null) {
            return null;
        }
        return new MemoryItem(node.key, node.type, node.label, clamp(activation),
                node.baseWeight, node.lastSeen, node.properties);
    }

    private double activationOf(Node node, Instant now) {
        long hours = Math.max(0, Duration.between(node.lastSeen, now).toHours());
        return node.baseWeight * Math.exp(-activationDecay * hours);
    }

    private static String key(String a, String b) {
        return a + "::" + b;
    }

    private static double clamp(double v) {
        return Math.max(0.0, Math.min(1.0, v));
    }

    /** Exposes recall limit (used by tests and tooling). */
    public int recallLimit() {
        return recallLimit;
    }
}
