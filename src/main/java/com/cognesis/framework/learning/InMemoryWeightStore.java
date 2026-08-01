package com.cognesis.framework.learning;

import com.cognesis.framework.algorithm.SynapseWeights;

import java.util.concurrent.atomic.AtomicReference;

/**
 * In-memory weight store. Production deployments can back this with the
 * database or a shared cache so all instances learn together.
 */
public class InMemoryWeightStore implements WeightStore {

    private final AtomicReference<SynapseWeights> weights;

    public InMemoryWeightStore(SynapseWeights initial) {
        this.weights = new AtomicReference<>(initial != null ? initial : SynapseWeights.defaults());
    }

    @Override
    public SynapseWeights load() {
        return weights.get();
    }

    @Override
    public void save(SynapseWeights weights) {
        this.weights.set(weights);
    }
}
