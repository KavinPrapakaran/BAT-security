package com.cognesis.framework;

import com.cognesis.framework.acde.AcdeEngine;
import com.cognesis.framework.acde.DecisionRequest;
import com.cognesis.framework.dns.DnsDecision;
import com.cognesis.framework.dns.DnsIntelligenceEngine;
import com.cognesis.framework.dns.DnsResolutionRequest;
import com.cognesis.framework.persistence.JdbcDecisionLogDao;
import com.cognesis.framework.persistence.JdbcTrustProfileStore;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Full-context smoke test: boots the whole Spring wiring against the in-memory
 * H2 database and exercises the DNS engine and the ACDE end to end.
 */
@SpringBootTest
class CognesisApplicationTests {

    @Autowired
    private DnsIntelligenceEngine dnsEngine;

    @Autowired
    private AcdeEngine acde;

    @Autowired
    private JdbcDecisionLogDao decisionLogDao;

    @Autowired
    private JdbcTrustProfileStore trustProfileStore;

    @Test
    void contextLoads() {
        assertNotNull(dnsEngine);
        assertNotNull(acde);
        assertNotNull(decisionLogDao);
        assertNotNull(trustProfileStore);
    }

    @Test
    void dnsEnginePersistsDecisionToDatabase() {
        DnsDecision decision = dnsEngine.evaluate(
                DnsResolutionRequest.of("google.com", "alice", "10.1.1.5"));
        assertNotNull(decision.decisionId());
        assertTrue(decision.outcome().reasoningChain().size() >= 10);
    }

    @Test
    void acdeRunsThroughThePipeline() {
        var result = acde.evaluate(
                new DecisionRequest("paypa1.com", "DOMAIN", "soc", java.util.List.of("asset-billing"),
                        "dns-resolution", java.util.Map.of("env", "prod")));
        assertNotNull(result.decision());
        assertTrue(result.riskScore() >= 0.0 && result.riskScore() <= 1.0);
        assertEquals("paypa1.com", result.entityId());
        assertTrue(result.reasoningChain().size() >= 10);
    }
}
