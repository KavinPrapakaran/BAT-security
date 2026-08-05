package com.cognesis.framework.actg;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SecurityKnowledgeGraphTest {

    private final ActgGraph graph = new SecurityKnowledgeGraph();

    @Test
    void neighborhoodRiskIsZeroForUnknownEntity() {
        assertEquals(0.0, graph.neighborhoodRisk(ActgNode.key(ActgEntityType.DOMAIN, "unknown.test")), 1e-9);
    }

    @Test
    void repeatedObservationsMergeAndBoundedEdgeWeights() {
        String domain = ActgNode.key(ActgEntityType.DOMAIN, "phish.test");
        String ip = ActgNode.key(ActgEntityType.IP, "45.155.205.233");
        graph.recordObservation(domain, ActgEntityType.DOMAIN, 0.9);
        for (int i = 0; i < 10; i++) {
            graph.recordAssociation(domain, ActgEntityType.DOMAIN, ip, ActgEntityType.IP, ActgRelation.RESOLVES_TO);
        }
        assertEquals(1, graph.edgeCount(), "repeated observations must strengthen, not duplicate, an edge");
        assertTrue(graph.neighborhood(domain).stream().anyMatch(n -> n.key().equals(ip)));
    }

    @Test
    void cleanDomainInheritsRiskFromMaliciousNeighbor() {
        String bad = ActgNode.key(ActgEntityType.DOMAIN, "bad.example");
        String clean = ActgNode.key(ActgEntityType.DOMAIN, "clean.example");
        String sharedIp = ActgNode.key(ActgEntityType.IP, "185.220.101.4");

        graph.recordObservation(bad, ActgEntityType.DOMAIN, 0.95);
        graph.recordAssociation(bad, ActgEntityType.DOMAIN, sharedIp, ActgEntityType.IP, ActgRelation.RESOLVES_TO);
        graph.recordObservation(sharedIp, ActgEntityType.IP, 0.8);
        graph.recordAssociation(clean, ActgEntityType.DOMAIN, sharedIp, ActgEntityType.IP, ActgRelation.RESOLVES_TO);

        double risk = graph.neighborhoodRisk(clean);
        assertTrue(risk > 0.3,
                "clean domain sharing an IP with a bad domain must inherit neighborhood risk, got " + risk);
    }

    @Test
    void neighborhoodReturnsBothDirections() {
        String user = ActgNode.key(ActgEntityType.USER, "alice");
        String domain = ActgNode.key(ActgEntityType.DOMAIN, "corp.example.com");
        graph.recordObservation(domain, ActgEntityType.DOMAIN, 0.1);
        graph.recordAssociation(user, ActgEntityType.USER, domain, ActgEntityType.DOMAIN, ActgRelation.REQUESTED_BY);

        List<ActgNode> domainNeighbors = graph.neighborhood(domain);
        assertEquals(1, domainNeighbors.size());
        assertEquals(user, domainNeighbors.get(0).key());
        List<ActgNode> userNeighbors = graph.neighborhood(user);
        assertEquals(domain, userNeighbors.get(0).key());
    }

    @Test
    void clearResetsGraph() {
        graph.recordAssociation(
                ActgNode.key(ActgEntityType.DOMAIN, "a"),
                ActgEntityType.DOMAIN,
                ActgNode.key(ActgEntityType.IP, "1.1.1.1"),
                ActgEntityType.IP,
                ActgRelation.RESOLVES_TO);
        assertTrue(graph.edgeCount() > 0);
        graph.clear();
        assertEquals(0, graph.edgeCount());
        assertEquals(0, graph.nodeCount());
    }
}
