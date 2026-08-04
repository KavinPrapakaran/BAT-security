package com.cognesis.framework.persistence;

import com.cognesis.framework.memory.MemoryItem;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Consumer;

/**
 * JDBC-backed memory graph store. Nodes and edges are persisted so the
 * knowledge graph survives restarts and can be queried from analytics tooling.
 */
public class JdbcMemoryGraphDao implements MemoryGraphDao {

    private static final Logger log = LoggerFactory.getLogger(JdbcMemoryGraphDao.class);

    private final NamedParameterJdbcTemplate jdbc;
    private final ObjectMapper objectMapper;

    public JdbcMemoryGraphDao(JdbcTemplate jdbcTemplate, ObjectMapper objectMapper) {
        this.jdbc = new NamedParameterJdbcTemplate(jdbcTemplate);
        this.objectMapper = objectMapper;
    }

    @Override
    public void saveNode(String nodeKey, String nodeType, String label,
                         double baseWeight, Map<String, Object> properties) {
        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("nodeId", UUID.randomUUID().toString())
                .addValue("nodeKey", nodeKey)
                .addValue("nodeType", nodeType)
                .addValue("label", label)
                .addValue("baseWeight", baseWeight)
                .addValue("properties", toJson(properties))
                .addValue("now", Timestamp.from(Instant.now()));
        try {
            jdbc.update("""
                MERGE INTO memory_node (node_id, node_key, node_type, label, base_weight, properties, last_seen_at, created_at)
                KEY (node_type, node_key)
                VALUES (:nodeId, :nodeKey, :nodeType, :label, :baseWeight, :properties, :now, :now)
                """, params);
        } catch (Exception e) {
            log.warn("Could not persist memory node {}: {}", nodeKey, e.getMessage());
        }
    }

    @Override
    public void saveEdge(String sourceKey, String targetKey, String relation, double weight) {
        try {
            Long sourceId = jdbc.queryForObject(
                    "SELECT node_id FROM memory_node WHERE node_key = :key LIMIT 1",
                    new MapSqlParameterSource("key", sourceKey), Long.class);
            Long targetId = jdbc.queryForObject(
                    "SELECT node_id FROM memory_node WHERE node_key = :key LIMIT 1",
                    new MapSqlParameterSource("key", targetKey), Long.class);
            if (sourceId == null || targetId == null) return;
            MapSqlParameterSource params = new MapSqlParameterSource()
                    .addValue("edgeId", UUID.randomUUID().toString())
                    .addValue("sourceId", sourceId)
                    .addValue("targetId", targetId)
                    .addValue("relation", relation)
                    .addValue("weight", weight)
                    .addValue("now", Timestamp.from(Instant.now()));
            jdbc.update("""
                MERGE INTO memory_edge (edge_id, source_node_id, target_node_id, relation, weight, last_observed_at)
                KEY (source_node_id, target_node_id, relation)
                VALUES (:edgeId, :sourceId, :targetId, :relation, :weight, :now)
                """, params);
        } catch (Exception e) {
            log.warn("Could not persist memory edge {}->{}: {}", sourceKey, targetKey, e.getMessage());
        }
    }

    @Override
    public void saveBaseline(String entityId, String featureName, double mean, double m2, long count) {
        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("entityId", entityId)
                .addValue("featureName", featureName)
                .addValue("mean", mean)
                .addValue("m2", m2)
                .addValue("count", count)
                .addValue("now", Timestamp.from(Instant.now()));
        try {
            jdbc.update("""
                MERGE INTO behaviour_baseline (entity_id, feature_name, mean, m2, sample_count, updated_at)
                KEY (entity_id, feature_name)
                VALUES (:entityId, :featureName, :mean, :m2, :count, :now)
                """, params);
        } catch (Exception e) {
            log.warn("Could not persist baseline {}.{}: {}", entityId, featureName, e.getMessage());
        }
    }

    @Override
    public Optional<MemoryItem> findNode(String nodeKey) {
        List<MemoryItem> rows = jdbc.query("""
                SELECT node_key, node_type, label, base_weight, properties, last_seen_at
                FROM memory_node WHERE node_key = :nodeKey
                """,
                new MapSqlParameterSource("nodeKey", nodeKey),
                (rs, rowNum) -> {
                    Map<String, Object> props = parseJson(rs.getString("properties"));
                    return new MemoryItem(
                            rs.getString("node_key"),
                            rs.getString("node_type"),
                            rs.getString("label"),
                            rs.getDouble("base_weight"),
                            rs.getDouble("base_weight"),
                            rs.getTimestamp("last_seen_at").toInstant(),
                            props);
                });
        return rows.isEmpty() ? Optional.empty() : Optional.of(rows.get(0));
    }

    @Override
    public void loadAllNodes(Consumer<MemoryNode> consumer) {
        jdbc.query("SELECT node_key, node_type, label, base_weight, properties, last_seen_at FROM memory_node",
                (rs, rowNum) -> new MemoryNode(
                        rs.getString("node_key"),
                        rs.getString("node_type"),
                        rs.getString("label"),
                        rs.getDouble("base_weight"),
                        parseJson(rs.getString("properties")),
                        rs.getTimestamp("last_seen_at").toInstant()))
                .forEach(consumer);
    }

    @Override
    public void loadAllEdges(Consumer<MemoryEdge> consumer) {
        jdbc.query("""
                SELECT s.node_key AS source_key, t.node_key AS target_key,
                       e.relation, e.weight, e.last_observed_at
                FROM memory_edge e
                JOIN memory_node s ON e.source_node_id = s.node_id
                JOIN memory_node t ON e.target_node_id = t.node_id
                """,
                (rs, rowNum) -> new MemoryEdge(
                        rs.getString("source_key"),
                        rs.getString("target_key"),
                        rs.getString("relation"),
                        rs.getDouble("weight"),
                        rs.getTimestamp("last_observed_at").toInstant()))
                .forEach(consumer);
    }

    @Override
    public void loadAllBaselines(Consumer<BaselineRow> consumer) {
        jdbc.query("SELECT entity_id, feature_name, mean, m2, sample_count FROM behaviour_baseline",
                (rs, rowNum) -> new BaselineRow(
                        rs.getString("entity_id"),
                        rs.getString("feature_name"),
                        rs.getDouble("mean"),
                        rs.getDouble("m2"),
                        rs.getLong("sample_count")))
                .forEach(consumer);
    }

    private String toJson(Map<String, Object> properties) {
        try {
            return objectMapper.writeValueAsString(properties != null ? properties : Map.of());
        } catch (JsonProcessingException e) {
            return "{}";
        }
    }

    private Map<String, Object> parseJson(String json) {
        if (json == null || json.isBlank()) return Map.of();
        try {
            return objectMapper.readValue(json, HashMap.class);
        } catch (JsonProcessingException e) {
            return Map.of();
        }
    }
}
