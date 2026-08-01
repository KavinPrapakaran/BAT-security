package com.cognesis.framework.trust;

import java.util.Map;

/**
 * Context for a trust assessment, including an optional view of the entity's
 * neighbours in the trust graph. Neighbour influence lets trust propagate along
 * relationships (a domain trusted by a trusted device inherits some of it).
 *
 * @param entityId         canonical entity identifier
 * @param entityType       e.g. DOMAIN, IP, USER, DEVICE, CERTIFICATE
 * @param neighbourTrusts  map of neighbour entity id to their trust score
 */
public record TrustContext(
        String entityId,
        String entityType,
        Map<String, Double> neighbourTrusts) {

    public TrustContext {
        neighbourTrusts = neighbourTrusts != null ? Map.copyOf(neighbourTrusts) : Map.of();
    }

    public TrustContext(String entityId, String entityType) {
        this(entityId, entityType, Map.of());
    }
}
