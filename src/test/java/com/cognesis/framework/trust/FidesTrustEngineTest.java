package com.cognesis.framework.trust;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FidesTrustEngineTest {

    private final FidesTrustEngine engine = new FidesTrustEngine(TrustProperties.defaults());

    @Test
    void unknownEntityGetsDefaultTrust() {
        TrustAssessment a = engine.assess("suspicious.example", "DOMAIN");
        assertEquals(0.5, a.trust(), 1e-9);
        assertEquals(0.0, a.confidence(), 1e-9);
    }

    @Test
    void negativeEventsHurtMoreThanPositiveEventsHelp() {
        engine.recordEvent(new TrustEvent("x", TrustEvent.EventType.POSITIVE, 1.0, "good"));
        TrustAssessment afterPositive = engine.assess("x", "DOMAIN");

        engine.recordEvent(new TrustEvent("x", TrustEvent.EventType.NEGATIVE, 1.0, "bad"));
        TrustAssessment afterNegative = engine.assess("x", "DOMAIN");

        assertTrue(afterPositive.trust() > 0.5, "positive event should raise trust");
        assertTrue(afterNegative.trust() < afterPositive.trust(), "negative event should lower trust");
        assertTrue(0.5 - afterNegative.trust() > afterPositive.trust() - 0.5,
                "asymmetric penalty: negative should move further from neutral");
    }

    @Test
    void trustStaysWithinUnitIntervalAfterManyEvents() {
        for (int i = 0; i < 1000; i++) {
            TrustEvent event = new TrustEvent("y", i % 2 == 0
                    ? TrustEvent.EventType.NEGATIVE : TrustEvent.EventType.POSITIVE, 1.0, "churn");
            engine.recordEvent(event);
        }
        TrustAssessment a = engine.assess("y", "IP");
        assertTrue(a.trust() >= 0.0 && a.trust() <= 1.0);
        assertTrue(a.confidence() > 0.9, "many observations should produce high confidence");
    }

    @Test
    void graphInfluenceMixesNeighbourTrust() {
        double own = engine.assess("node-a", "DEVICE").trust();
        TrustAssessment influenced = engine.assess(new TrustContext(
                "node-a", "DEVICE", java.util.Map.of("neighbour", 0.95)));
        assertEquals(0.5 * 0.7 + 0.95 * 0.3, influenced.trust(), 1e-9);
    }
}
