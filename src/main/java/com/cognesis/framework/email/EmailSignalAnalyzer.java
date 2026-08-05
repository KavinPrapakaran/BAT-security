package com.cognesis.framework.email;

/**
 * A single cognitive "sense" of the VOID email engine. Each analyzer inspects
 * the message facts (plus surrounding context) and contributes one evidence
 * signal to the SYNAPSE fusion. New analyzers can be added without touching
 * the core — the drop-in guarantee exercised by the second domain engine.
 */
@FunctionalInterface
public interface EmailSignalAnalyzer {

    /** Produce an evidence signal for the given request and facts. */
    EmailSignal analyze(EmailEvaluationRequest request, EmailFacts facts);
}
