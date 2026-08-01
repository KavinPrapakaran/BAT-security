package com.cognesis.framework.memory;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * An incident or event worth remembering. Mnemonic turns it into knowledge-graph
 * nodes and edges whose weights encode how strongly the framework should recall
 * them later.
 *
 * @param subjectId    primary entity (e.g. the domain or user involved)
 * @param subjectType  entity type of the subject
 * @param relations    relation type -&gt; list of related entity keys
 *                     (e.g. "CONNECTED_TO" -&gt; ["ip:203.0.113.7"])
 * @param evidenceTypes evidence signal families involved
 * @param outcome      what happened (e.g. "CONFIRMED_INFECTION", "FALSE_POSITIVE")
 * @param severity     severity in [0,1]
 * @param happenedAt   when it occurred
 */
public record MemoryIncident(
        String subjectId,
        String subjectType,
        Map<String, List<String>> relations,
        List<String> evidenceTypes,
        String outcome,
        double severity,
        Instant happenedAt) {

    public MemoryIncident {
        relations = relations != null ? relations : Map.of();
        evidenceTypes = evidenceTypes != null ? List.copyOf(evidenceTypes) : List.of();
        happenedAt = happenedAt != null ? happenedAt : Instant.now();
        severity = Math.max(0.0, Math.min(1.0, severity));
    }
}
