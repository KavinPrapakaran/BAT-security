package com.cognesis.framework.dns;

/**
 * DIE - DNS Intelligence Engine. It does not simply filter DNS; it reasons
 * about every resolution before it is made, fusing 17+ evidence senses through
 * the SYNAPSE decision algorithm and returning an explainable verdict.
 */
public interface DnsIntelligenceEngine {

    /**
     * Evaluate one DNS resolution request and return an explainable decision.
     * This method is safe to call from a DNS proxy/forwarder on the hot path.
     */
    DnsDecision evaluate(DnsResolutionRequest request);
}
