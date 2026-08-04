package com.cognesis.framework.it;

import com.cognesis.framework.CognesisApplication;
import com.cognesis.framework.common.Decision;
import com.cognesis.framework.common.DecisionResult;
import com.cognesis.framework.common.ReasoningStep;
import com.cognesis.framework.common.RecommendedAction;
import com.cognesis.framework.persistence.JdbcDecisionLogDao;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@Testcontainers
@SpringBootTest(classes = CognesisApplication.class)
class PostgresIntegrationTest {

    @Container
    static PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("cognesis_test")
                    .withUsername("test")
                    .withPassword("test");

    @DynamicPropertySource
    static void registerProps(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.datasource.driver-class-name",
                () -> "org.postgresql.Driver");
        registry.add("spring.flyway.enabled", () -> "true");
    }

    @Autowired
    JdbcTemplate jdbcTemplate;

    @Test
    void decisionLogDaoPersistsAndRecovers() {
        var dao = new JdbcDecisionLogDao(
                new NamedParameterJdbcTemplate(jdbcTemplate),
                new ObjectMapper());
        UUID id = UUID.randomUUID();
        var result = new DecisionResult(
                id, "evil.test", "DOMAIN",
                Decision.BLOCK, RecommendedAction.BLOCK_DOMAIN,
                0.92, 0.30, 0.88, 0.81, "test",
                List.of(new ReasoningStep("TEST", "assertion",
                        0.9, 0.8, "test")),
                Instant.now());
        dao.save(result);
        Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM decision_log WHERE decision_id = ?",
                Integer.class, id);
        assertEquals(1, count);
    }

    @Test
    void flywayAppliedAllMigrations() {
        Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM flyway_schema_history WHERE success = TRUE",
                Integer.class);
        assertNotNull(count);
        assertTrue(count >= 3);
    }

    @Test
    void memoryNodeTableExists() {
        jdbcTemplate.execute("""
            INSERT INTO memory_node
              (node_id, node_key, node_type, label, base_weight,
               properties, last_seen_at, created_at)
            VALUES (RANDOM_UUID(), 'test-node', 'DOMAIN', 'test.node',
                    0.8, '{}', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """);
        Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM memory_node WHERE node_key = ?",
                Integer.class, "test-node");
        assertEquals(1, count);
    }

    @Test
    void outcomeFeedbackTableExists() {
        UUID did = UUID.randomUUID();
        jdbcTemplate.execute(
                "INSERT INTO decision_log"
              + " (decision_id, entity_id, entity_type, decision,"
              + " recommended_action, risk_score, trust_score,"
              + " confidence_score, business_impact, rationale,"
              + " reasoning_chain, decided_at)"
              + " VALUES ('" + did + "', 'x', 'DOMAIN', 'BLOCK',"
              + " 'BLOCK_DOMAIN', 0.9, 0.3, 0.8, 0.7, 'r', '[]',"
              + " CURRENT_TIMESTAMP)");
        jdbcTemplate.execute(
                "INSERT INTO outcome_feedback"
              + " (decision_id, realized_risk, was_correct, notes)"
              + " VALUES ('" + did + "', 0.85, TRUE, 'confirmed')");
        Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM outcome_feedback"
              + " WHERE decision_id = ?",
                Integer.class, did);
        assertEquals(1, count);
    }
}
