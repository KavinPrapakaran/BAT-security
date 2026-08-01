package com.cognesis.framework.dns;

/**
 * A single cognitive "sense" of the DNS engine. Each analyzer inspects the
 * domain facts (plus surrounding context) and contributes one evidence signal
 * to the SYNAPSE fusion. New analyzers can be added without touching the core.
 */
@FunctionalInterface
public interface DnsSignalAnalyzer {

    /** Produce an evidence signal for the given request and facts. */
    DnsSignal analyze(DnsResolutionRequest request, DnsFacts facts);
}
