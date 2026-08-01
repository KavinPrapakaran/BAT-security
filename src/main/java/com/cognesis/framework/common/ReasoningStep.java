package com.cognesis.framework.common;

import java.time.Instant;

/**
 * A single explainable step in a decision's reasoning chain.
 * Every engine that contributes to a decision emits one or more steps, so an
 * auditor can replay exactly why a verdict was reached.
 */
public record ReasoningStep(
        String engine,
        String claim,
        double score,
        double confidence,
        String explanation,
        Instant timestamp) {

    public ReasoningStep(String engine, String claim, double score, double confidence, String explanation) {
        this(engine, claim, score, confidence, explanation, Instant.now());
    }
}
