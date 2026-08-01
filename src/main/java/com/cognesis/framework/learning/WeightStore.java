package com.cognesis.framework.learning;

import com.cognesis.framework.algorithm.SynapseWeights;

/**
 * Stores and mutates the current SYNAPSE weights. Kept behind an interface so
 * weights can live in memory, in the database, or in a distributed cache.
 */
public interface WeightStore {

    SynapseWeights load();

    void save(SynapseWeights weights);
}
