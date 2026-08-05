package com.cognesis.framework.dns.analyzer;

import com.cognesis.framework.actg.ActgEntityType;
import com.cognesis.framework.actg.ActgGraph;
import com.cognesis.framework.actg.ActgNode;
import com.cognesis.framework.common.EvidenceType;
import com.cognesis.framework.common.Provenance;
import com.cognesis.framework.dns.DnsFacts;
import com.cognesis.framework.dns.DnsResolutionRequest;
import com.cognesis.framework.dns.DnsSignal;
import com.cognesis.framework.dns.DnsSignalAnalyzer;

/**
 * ACTG sense: reads the adaptive cognitive trust graph for everything connected
 * to the requested domain. A brand-new domain that resolves to an IP shared
 * with a previously-confirmed incident is treated with suspicion even though
 * the domain itself has no history - the graph is what carries the memory.
 */
public class ActgAnalyzer implements DnsSignalAnalyzer {

    private final ActgGraph graph;

    public ActgAnalyzer(ActgGraph graph) {
        this.graph = graph;
    }

    @Override
    public DnsSignal analyze(DnsResolutionRequest request, DnsFacts facts) {
        String domainKey = ActgNode.key(ActgEntityType.DOMAIN, facts.domain());
        ActgNode domain = graph.node(domainKey);
        double risk = graph.neighborhoodRisk(domainKey);
        int edges = graph.neighborhood(domainKey).size();

        if (domain == null || edges == 0) {
            return new DnsSignal(EvidenceType.ACTG, 0.1, 0.9,
                    "No ACTG relationships observed for this domain yet",
                    Provenance.GRAPH);
        }
        double confidence = Math.min(0.9, 0.45 + edges * 0.1);
        return new DnsSignal(EvidenceType.ACTG, risk, confidence,
                "ACTG neighborhood for " + facts.domain() + " carries risk "
                        + String.format("%.2f", risk) + " across " + edges + " relationships",
                Provenance.GRAPH);
    }
}
