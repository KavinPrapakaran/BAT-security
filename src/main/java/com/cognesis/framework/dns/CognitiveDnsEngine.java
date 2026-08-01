package com.cognesis.framework.dns;

/**
 * CODE - the Cognitive DNS Engine. It does not simply filter DNS; it reasons
 * about every resolution before it is made, fusing 15+ evidence senses through
 * the SYNAPSE decision algorithm and returning an explainable verdict.
 */
public interface CognitiveDnsEngine {

    /**
     * Evaluate one DNS resolution request and return an explainable decision.
     * This method is safe to call from a DNS proxy/forwarder on the hot path.
     */
    DnsDecision evaluate(DnsResolutionRequest request);
}
