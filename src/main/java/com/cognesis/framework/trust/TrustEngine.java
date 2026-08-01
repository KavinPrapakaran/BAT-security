package com.cognesis.framework.trust;

/**
 * FIDES - the dynamic trust engine. Trust is never static: it is learned from
 * behaviour, history, policy and relationships, decays toward neutral over
 * time, and is always accompanied by an explicit confidence value.
 */
public interface TrustEngine {

    /**
     * Current trust assessment for an entity, considering only its own history.
     */
    TrustAssessment assess(String entityId, String entityType);

    /**
     * Current trust assessment for an entity, including influence from its
     * neighbours in the trust graph.
     */
    TrustAssessment assess(TrustContext context);

    /**
     * Apply an observation to the entity's trust profile and return the new
     * assessment. Negative events are penalized harder than positive events are
     * rewarded (asymmetric learning), mirroring how analysts treat evidence.
     */
    TrustAssessment recordEvent(TrustEvent event);
}
