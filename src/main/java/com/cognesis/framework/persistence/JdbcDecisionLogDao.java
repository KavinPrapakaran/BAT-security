package com.cognesis.framework.persistence;

import com.cognesis.framework.common.DecisionResult;
import com.cognesis.framework.common.ReasoningStep;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.sql.Timestamp;
import java.util.List;

/**
 * JDBC-backed decision log against the decision_log table. Persists the full
 * decision, including the reasoning chain as JSON, so every verdict is
 * reproducible and auditable.
 */
public class JdbcDecisionLogDao implements DecisionLogDao {

    private static final Logger log = LoggerFactory.getLogger(JdbcDecisionLogDao.class);

    private final NamedParameterJdbcTemplate jdbc;
    private final ObjectMapper objectMapper;

    public JdbcDecisionLogDao(NamedParameterJdbcTemplate jdbcTemplate, ObjectMapper objectMapper) {
        this.jdbc = jdbcTemplate;
        this.objectMapper = objectMapper;
    }

    @Override
    public void save(DecisionResult result) {
        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("decisionId", result.decisionId())
                .addValue("entityId", result.entityId())
                .addValue("entityType", result.entityType())
                .addValue("decision", result.decision().name())
                .addValue("recommendedAction", result.recommendedAction().name())
                .addValue("risk", result.riskScore())
                .addValue("trust", result.trustScore())
                .addValue("confidence", result.confidenceScore())
                .addValue("impact", result.businessImpactScore())
                .addValue("rationale", result.rationale())
                .addValue("chain", toJson(result.reasoningChain()))
                .addValue("decidedAt", Timestamp.from(result.decidedAt()));
        try {
            jdbc.update("""
                    INSERT INTO decision_log (decision_id, entity_id, entity_type, decision,
                                              recommended_action, risk_score, trust_score, confidence_score,
                                              business_impact, rationale, reasoning_chain, decided_at)
                    VALUES (:decisionId, :entityId, :entityType, :decision, :recommendedAction,
                            :risk, :trust, :confidence, :impact, :rationale, :chain, :decidedAt)
                    """, params);
        } catch (Exception e) {
            log.warn("Could not persist decision {}: {}", result.decisionId(), e.getMessage());
        }
    }

    private String toJson(List<ReasoningStep> chain) {
        try {
            return objectMapper.writeValueAsString(chain);
        } catch (JsonProcessingException e) {
            return "[]";
        }
    }
}
