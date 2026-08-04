package com.cognesis.framework.context;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SituationalContextEngineTest {

    private final SituationalContextEngine engine = new SituationalContextEngine();

    @Test
    void mapsKnownLabelsToBaselineRisk() {
        ContextAssessment dns = engine.assess(new ContextInput("dns-resolution", "DOMAIN", Map.of()));
        ContextAssessment email = engine.assess(new ContextInput("email", "USER", Map.of()));
        assertEquals(0.40, dns.contextRisk());
        assertEquals(0.70, dns.contextWeight());
        assertEquals(0.60, email.contextRisk());
    }

    @Test
    void unknownContextIsNeutralAndLowWeight() {
        ContextAssessment unknown = engine.assess(new ContextInput("anything-else", "DOMAIN", Map.of()));
        assertEquals(0.5, unknown.contextRisk());
        assertEquals(0.4, unknown.contextWeight());
    }

    @Test
    void productionEnvironmentRaisesContextWeight() {
        ContextAssessment prod = engine.assess(new ContextInput("api-call", "API", Map.of("env", "prod")));
        ContextAssessment dev = engine.assess(new ContextInput("api-call", "API", Map.of("env", "dev")));
        assertTrue(prod.contextWeight() > dev.contextWeight());
    }

    @Test
    void anonymisedSourceRaisesContextRisk() {
        ContextAssessment anon = engine.assess(new ContextInput("login", "USER", Map.of("geo", "anon")));
        ContextAssessment clean = engine.assess(new ContextInput("login", "USER", Map.of("geo", "us-east")));
        assertTrue(anon.contextRisk() > clean.contextRisk());
    }
}
