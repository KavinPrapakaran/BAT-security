package com.cognesis.framework.dns.analyzer;

import com.cognesis.framework.common.EvidenceType;
import com.cognesis.framework.common.Provenance;
import com.cognesis.framework.dns.DnsFacts;
import com.cognesis.framework.dns.DnsResolutionRequest;
import com.cognesis.framework.dns.DnsSignal;
import com.cognesis.framework.dns.DnsSignalAnalyzer;
import com.cognesis.framework.memory.MemoryEngine;
import com.cognesis.framework.memory.MemoryQuery;
import com.cognesis.framework.memory.MemoryRecall;

/**
 * Threat memory: recalls past incidents and relationships involving this domain
 * from MNEMONIC. A domain with a history of confirmed compromise is treated as
 * high-risk even if today's signals are quiet.
 */
public class ThreatMemoryAnalyzer implements DnsSignalAnalyzer {

    private final MemoryEngine memoryEngine;

    public ThreatMemoryAnalyzer(MemoryEngine memoryEngine) {
        this.memoryEngine = memoryEngine;
    }

    @Override
    public DnsSignal analyze(DnsResolutionRequest request, DnsFacts facts) {
        MemoryRecall recall = memoryEngine.recall(new MemoryQuery(request.domain(), "DOMAIN", true, 10));
        double salience = recall.aggregateSalience();
        double confidence = Math.min(1.0, recall.items().size() / 5.0);
        if (recall.items().isEmpty()) {
            return new DnsSignal(EvidenceType.THREAT_MEMORY, 0.2, 0.3,
                    "No memory of this domain", Provenance.PAST_DECISION);
        }
        return new DnsSignal(EvidenceType.THREAT_MEMORY, salience, confidence,
                "MNEMONIC recalls " + recall.items().size() + " salient memory item(s) for this domain",
                Provenance.PAST_DECISION);
    }
}
