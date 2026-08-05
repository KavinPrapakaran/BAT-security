package com.cognesis.framework.persistence;

import com.cognesis.framework.actg.ActgEntityType;
import com.cognesis.framework.actg.ActgGraph;
import com.cognesis.framework.actg.ActgNode;
import com.cognesis.framework.actg.ActgRelation;
import com.cognesis.framework.actg.SecurityKnowledgeGraph;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.List;

/**
 * JDBC-backed {@link ActgGraph} against the {@code actg_node} / {@code actg_edge}
 * tables. Writes pass through to both an in-memory {@link SecurityKnowledgeGraph}
 * (which owns the neighborhood reasoning) and the database, so the graph's
 * accumulated trust survives restarts. Call {@link #load()} at startup to
 * hydrate the in-memory graph from the database.
 *
 * <p>Uses the same portable update-then-insert upsert as {@link JdbcIocStore},
 * working on both H2 (PostgreSQL compatibility mode) and PostgreSQL.
 */
public class JdbcActgStore implements ActgGraph {

    private static final double EDGE_STRENGTHEN = 0.25;
    private static final double MAX_EDGE_WEIGHT = 3.0;

    private final NamedParameterJdbcTemplate jdbc;
    private final SecurityKnowledgeGraph delegate;

    public JdbcActgStore(NamedParameterJdbcTemplate jdbcTemplate) {
        this(jdbcTemplate, new SecurityKnowledgeGraph());
    }

    JdbcActgStore(NamedParameterJdbcTemplate jdbcTemplate, SecurityKnowledgeGraph delegate) {
        this.jdbc = jdbcTemplate;
        this.delegate = delegate;
    }

    @Override
    public void recordAssociation(String sourceKey, ActgEntityType sourceType,
                                  String targetKey, ActgEntityType targetType,
                                  ActgRelation relation) {
        delegate.recordAssociation(sourceKey, sourceType, targetKey, targetType, relation);
        persistNode(delegate.node(sourceKey));
        persistNode(delegate.node(targetKey));
        upsertEdge(sourceKey, targetKey, relation);
    }

    @Override
    public void recordObservation(String key, ActgEntityType entityType, double risk) {
        delegate.recordObservation(key, entityType, risk);
        persistNode(delegate.node(key));
    }

    @Override
    public ActgNode node(String key) {
        return delegate.node(key);
    }

    @Override
    public List<ActgNode> neighborhood(String key) {
        return delegate.neighborhood(key);
    }

    @Override
    public double neighborhoodRisk(String key) {
        return delegate.neighborhoodRisk(key);
    }

    @Override
    public int edgeCount() {
        return delegate.edgeCount();
    }

    @Override
    public int nodeCount() {
        return delegate.nodeCount();
    }

    @Override
    public void clear() {
        delegate.clear();
        jdbc.update("DELETE FROM actg_edge", new MapSqlParameterSource());
        jdbc.update("DELETE FROM actg_node", new MapSqlParameterSource());
    }

    /**
     * Rebuilds the in-memory graph from the database. Call once at startup so
     * previously observed associations and risk are available to the very first
     * evaluation of the new process.
     */
    public void load() {
        delegate.clear();
        List<ActgNode> nodes = jdbc.query("""
                        SELECT node_key, entity_type, label, risk, last_seen_at
                          FROM actg_node
                        """,
                new MapSqlParameterSource(), NODE_MAPPER);
        for (ActgNode node : nodes) {
            delegate.recordObservation(node.key(), node.entityType(), node.risk(), node.lastSeen());
        }
        List<ActgEdgeRow> edges = jdbc.query("""
                        SELECT source_key, target_key, relation, weight
                          FROM actg_edge
                        """,
                new MapSqlParameterSource(), EDGE_MAPPER);
        for (ActgEdgeRow edge : edges) {
            delegate.recordAssociation(edge.sourceKey(), edge.sourceType(),
                    edge.targetKey(), edge.targetType(), edge.relation(), edge.weight());
        }
    }

    private void persistNode(ActgNode node) {
        if (node == null) {
            return;
        }
        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("key", node.key())
                .addValue("type", node.entityType().name())
                .addValue("label", node.label())
                .addValue("risk", node.risk())
                .addValue("lastSeen", Timestamp.from(node.lastSeen()));
        int updated = jdbc.update("""
                UPDATE actg_node
                   SET entity_type = :type, label = :label, risk = :risk, last_seen_at = :lastSeen
                 WHERE node_key = :key
                """, params);
        if (updated == 0) {
            try {
                jdbc.update("""
                        INSERT INTO actg_node (node_key, entity_type, label, risk, last_seen_at)
                        VALUES (:key, :type, :label, :risk, :lastSeen)
                        """, params);
            } catch (DuplicateKeyException e) {
                jdbc.update("""
                        UPDATE actg_node
                           SET entity_type = :type, label = :label, risk = :risk, last_seen_at = :lastSeen
                         WHERE node_key = :key
                        """, params);
            }
        }
    }

    private void upsertEdge(String sourceKey, String targetKey, ActgRelation relation) {
        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("source", sourceKey)
                .addValue("target", targetKey)
                .addValue("relation", relation.name());
        int updated = jdbc.update("""
                UPDATE actg_edge
                   SET weight = LEAST(:maxWeight, weight + :strengthen), observed_at = CURRENT_TIMESTAMP
                 WHERE source_key = :source AND target_key = :target AND relation = :relation
                """, params.addValue("strengthen", EDGE_STRENGTHEN).addValue("maxWeight", MAX_EDGE_WEIGHT));
        if (updated == 0) {
            try {
                jdbc.update("""
                        INSERT INTO actg_edge (source_key, target_key, relation, weight, observed_at)
                        VALUES (:source, :target, :relation, :firstWeight, CURRENT_TIMESTAMP)
                        """, params.addValue("firstWeight", 1.0 + EDGE_STRENGTHEN));
            } catch (DuplicateKeyException e) {
                jdbc.update("""
                        UPDATE actg_edge
                           SET weight = LEAST(:maxWeight, weight + :strengthen), observed_at = CURRENT_TIMESTAMP
                         WHERE source_key = :source AND target_key = :target AND relation = :relation
                        """, params.addValue("strengthen", EDGE_STRENGTHEN).addValue("maxWeight", MAX_EDGE_WEIGHT));
            }
        }
    }

    private static final RowMapper<ActgNode> NODE_MAPPER = (rs, rowNum) -> {
        Timestamp ts = rs.getTimestamp("last_seen_at");
        return new ActgNode(
                rs.getString("node_key"),
                ActgEntityType.valueOf(rs.getString("entity_type")),
                rs.getString("label"),
                rs.getDouble("risk"),
                ts == null ? null : ts.toInstant(),
                java.util.Map.of());
    };

    private record ActgEdgeRow(String sourceKey, String targetKey, ActgRelation relation, double weight) {
        ActgEntityType sourceType() {
            return typeOf(sourceKey);
        }

        ActgEntityType targetType() {
            return typeOf(targetKey);
        }

        private static ActgEntityType typeOf(String key) {
            int idx = key == null ? -1 : key.indexOf(':');
            if (idx > 0) {
                try {
                    return ActgEntityType.valueOf(key.substring(0, idx));
                } catch (IllegalArgumentException e) {
                    // best-effort: fall through to default
                }
            }
            return ActgEntityType.USER;
        }
    }

    private static final RowMapper<ActgEdgeRow> EDGE_MAPPER = (rs, rowNum) -> new ActgEdgeRow(
            rs.getString("source_key"),
            rs.getString("target_key"),
            ActgRelation.valueOf(rs.getString("relation")),
            rs.getDouble("weight"));
}
