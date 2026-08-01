package com.cognesis.framework.persistence;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.sql.Timestamp;
import java.util.List;
import java.util.Optional;

/**
 * JDBC-backed trust profile store against the trust_profile table.
 * The Fides engine writes every trust update here; reads restore profiles at
 * startup (or on a cache miss).
 */
public class JdbcTrustProfileStore implements TrustProfileStore {

    private final NamedParameterJdbcTemplate jdbc;

    public JdbcTrustProfileStore(JdbcTemplate jdbcTemplate) {
        this.jdbc = new NamedParameterJdbcTemplate(jdbcTemplate);
    }

    @Override
    public void save(TrustProfile profile) {
        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("entityId", profile.entityId())
                .addValue("entityType", profile.entityType())
                .addValue("trust", profile.trust())
                .addValue("confidence", profile.confidence())
                .addValue("observations", profile.observationCount())
                .addValue("lastUpdated", Timestamp.from(profile.lastUpdated()));
        jdbc.update("""
                MERGE INTO trust_profile (entity_id, entity_type, trust, trust_confidence,
                                          observation_count, last_updated_at)
                KEY (entity_id)
                VALUES (:entityId, :entityType, :trust, :confidence, :observations, :lastUpdated)
                """, params);
    }

    @Override
    public Optional<TrustProfile> load(String entityId) {
        List<TrustProfile> rows = jdbc.query("""
                        SELECT entity_id, entity_type, trust, trust_confidence, observation_count, last_updated_at
                        FROM trust_profile WHERE entity_id = :entityId
                        """,
                new MapSqlParameterSource("entityId", entityId),
                (rs, rowNum) -> new TrustProfile(
                        rs.getString("entity_id"),
                        rs.getString("entity_type"),
                        rs.getDouble("trust"),
                        rs.getDouble("trust_confidence"),
                        rs.getLong("observation_count"),
                        rs.getTimestamp("last_updated_at").toInstant()));
        return rows.isEmpty() ? Optional.empty() : Optional.of(rows.get(0));
    }
}
