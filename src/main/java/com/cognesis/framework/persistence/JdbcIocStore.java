package com.cognesis.framework.persistence;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Optional;

/**
 * JDBC-backed {@link IocStore} against the {@code ioc_flag} table. Uses a
 * portable upsert (update-then-insert) that works on both H2 (PostgreSQL
 * compatibility mode) and PostgreSQL.
 */
public class JdbcIocStore implements IocStore {

    private final NamedParameterJdbcTemplate jdbc;

    public JdbcIocStore(NamedParameterJdbcTemplate jdbcTemplate) {
        this.jdbc = jdbcTemplate;
    }

    @Override
    public void flag(String domain) {
        MapSqlParameterSource params = new MapSqlParameterSource("domain", domain);
        int updated = jdbc.update("""
                UPDATE ioc_flag
                   SET flag_count = flag_count + 1, last_seen_at = CURRENT_TIMESTAMP
                 WHERE domain = :domain
                """, params);
        if (updated == 0) {
            try {
                jdbc.update("""
                        INSERT INTO ioc_flag (domain, flag_count, first_seen_at, last_seen_at)
                        VALUES (:domain, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                        """, params);
            } catch (DuplicateKeyException e) {
                jdbc.update("""
                        UPDATE ioc_flag
                           SET flag_count = flag_count + 1, last_seen_at = CURRENT_TIMESTAMP
                         WHERE domain = :domain
                        """, params);
            }
        }
    }

    @Override
    public int flagCount(String domain) {
        Long count = jdbc.query("""
                        SELECT flag_count FROM ioc_flag WHERE domain = :domain
                        """,
                new MapSqlParameterSource("domain", domain),
                rs -> rs.next() ? rs.getLong(1) : null);
        return count == null ? 0 : count.intValue();
    }
    @Override
    public int total() {
        Integer count = jdbc.queryForObject("SELECT COUNT(*) FROM ioc_flag",
                new MapSqlParameterSource(), Integer.class);
        return count == null ? 0 : count;
    }

    @Override
    public Optional<Instant> firstSeen(String domain) {
        Timestamp ts = jdbc.query("""
                        SELECT first_seen_at FROM ioc_flag WHERE domain = :domain
                        """,
                new MapSqlParameterSource("domain", domain),
                rs -> rs.next() ? rs.getTimestamp(1) : null);
        return ts == null ? Optional.empty() : Optional.of(ts.toInstant());
    }
}
