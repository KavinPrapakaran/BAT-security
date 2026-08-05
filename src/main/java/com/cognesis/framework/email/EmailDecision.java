package com.cognesis.framework.email;

import com.cognesis.framework.common.Decision;
import com.cognesis.framework.common.DecisionResult;
import com.cognesis.framework.common.Provenance;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * The verdict of the VOID email engine for one inbound message. Reuses the
 * framework DecisionResult shape so any consumer (email gateway, SOAR, SIEM)
 * can act on it uniformly.
 */
public record EmailDecision(
        Decision decision,
        DecisionResult outcome,
        String verdictExplanation) {

    public static EmailDecision from(DecisionResult outcome) {
        return new EmailDecision(outcome.decision(), outcome, outcome.rationale());
    }

    /** Convenience projection of the reasoning chain for auditing. */
    public List<String> summary() {
        return outcome().reasoningChain().stream()
                .map(s -> "%s: %s (%.2f, conf %.2f)".formatted(s.engine(), s.claim(), s.score(), s.confidence()))
                .toList();
    }

    public UUID decisionId() {
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
        return Provenance.EMAIL_GATEWAY;
    }
}
