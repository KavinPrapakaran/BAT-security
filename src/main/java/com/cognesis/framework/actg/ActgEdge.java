package com.cognesis.framework.actg;

import java.time.Instant;

/**
 * An edge in the ACTG graph. {@code weight} grows with each repeated
 * observation (bounded) so persistent relationships outweigh one-off glances.
 */
public record ActgEdge(
        String sourceKey,
        String targetKey,
        ActgRelation relation,
        double weight,
        Instant observedAt) {

    public ActgEdge {
        weight = Math.max(0.5, Math.min(3.0, weight));
        observedAt = observedAt != null ? observedAt : Instant.now();
    }
}
