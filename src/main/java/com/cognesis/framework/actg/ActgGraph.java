package com.cognesis.framework.actg;

import java.util.List;

/**
 * The adaptive cognitive trust graph: every observation the framework makes
 * becomes a node and a weighted edge, and trust is read as a property of the
 * neighborhood, not of a single entity in isolation.
 */
public interface ActgGraph {

    /**
     * Record that {@code source} is related to {@code target}. Missing nodes
     * are created on demand; repeated observations strengthen the edge.
     */
    void recordAssociation(String sourceKey, ActgEntityType sourceType,
                           String targetKey, ActgEntityType targetType,
                           ActgRelation relation);

    /**
     * Merge an observed risk value into a node (decays toward a plain average).
     */
    void recordObservation(String key, ActgEntityType entityType, double risk);

    /** The node for this entity, if the graph knows it. */
    ActgNode node(String key);

    /** Direct neighbors of an entity, both directions, strongest first. */
    List<ActgNode> neighborhood(String key);

    /**
     * Aggregate risk of an entity considering its own score plus every neighbor
     * weighted by edge strength. Zero when the entity is unknown.
     */
    double neighborhoodRisk(String key);

    /** How many observations (edges) the graph holds. */
    int edgeCount();

    /** How many distinct entities (nodes) the graph holds. */
    int nodeCount();

    /** Forget everything (used by tests and for a clean-slate reset). */
    void clear();
}
