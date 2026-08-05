package com.cognesis.framework.dns;

import com.cognesis.framework.common.Decision;
import com.cognesis.framework.common.DecisionResult;
import com.cognesis.framework.common.Provenance;

import java.time.Instant;
import java.util.List;

/**
 * The verdict of the DNS Intelligence Engine for one resolution request.
 * It reuses the framework DecisionResult shape so any consumer (proxy, resolver
 * policy engine, SIEM) can act on it uniformly.
 */
public record DnsDecision(
        Decision decision,
        DecisionResult outcome,
        String verdictExplanation) {

    public static DnsDecision from(DecisionResult outcome) {
        return new DnsDecision(outcome.decision(), outcome, outcome.rationale());
    }

    /** Convenience projection of the reasoning chain for auditing. */
    public List<String> summary() {
        return outcome().reasoningChain().stream()
                .map(s -> "%s: %s (%.2f, conf %.2f)".formatted(s.engine(), s.claim(), s.score(), s.confidence()))
                .toList();
    }

    /** Convenience accessors so controllers/tests need not unwrap outcome(). */
    public java.util.UUID decisionId() {
        return outcome().decisionId();
    }

    public double riskScore() {
        return outcome().riskScore();
    }

    public double trustScore() {
        return outcome().trustScore();
    }

    public double confidenceScore() {
        return outcome().confidenceScore();
    }

    public double businessImpactScore() {
        return outcome().businessImpactScore();
    }

    public Instant decidedAt() {
        return outcome().decidedAt();
    }

    public Provenance provenance() {
        return Provenance.DNS_RESPONSE;
    }
}
