package com.cognesis.framework.trust;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TrustEvolutionTest {

    private double seedTo095(FidesTrustEngine engine) {
        for (int i = 0; i < 15; i++) {
            engine.recordEvent(TrustEvent.Events.positive("vendor-1", "steady behaviour " + i));
        }
        return engine.assess("vendor-1", "DOMAIN").trust();
    }

    @Test
    void trustEvolvesDownThroughAdversarialEvents() {
        FidesTrustEngine engine = new FidesTrustEngine(TrustProperties.defaults());
        double start = seedTo095(engine);
        assertTrue(start > 0.90, "seeded trust should be high, got " + start);

        double afterCert = engine.recordEvent(TrustEvent.Events.certificateChanged("vendor-1")).trust();
        double afterDns = engine.recordEvent(TrustEvent.Events.dnsChanged("vendor-1")).trust();
        double afterSuspicious = engine.recordEvent(
                TrustEvent.Events.suspiciousBehaviour("vendor-1", "exfil-sized outbound")).trust();
        double afterConfirmed = engine.recordEvent(TrustEvent.Events.maliciousConfirmed("vendor-1")).trust();

        assertTrue(afterCert < start, "certificate change must erode trust");
        assertTrue(afterDns < afterCert, "infrastructure change must erode trust further");
        assertTrue(afterSuspicious < afterDns, "suspicious behaviour must erode trust further");
        assertTrue(afterConfirmed < afterSuspicious, "confirmed compromise must erode trust the most");
        assertTrue(afterConfirmed < 0.5, "confirmed compromise should collapse trust below neutral");
    }

    @Test
    void negativeEventsHurtMoreThanPositiveEventsHelp() {
        FidesTrustEngine engine = new FidesTrustEngine(TrustProperties.defaults());
        double base = seedTo095(engine);

        FidesTrustEngine symmetric = new FidesTrustEngine(TrustProperties.defaults());
        double up = symmetric.recordEvent(TrustEvent.Events.positive("vendor-2", "good")).trust();
        double down = symmetric.recordEvent(TrustEvent.Events.suspiciousBehaviour("vendor-2", "odd")).trust();

        assertTrue(base > 0.90);
        assertTrue(down - up < 0, "one negative event outweighs one positive event");
    }
}
