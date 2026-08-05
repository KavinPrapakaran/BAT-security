package com.cognesis.framework.email.analyzer;

import com.cognesis.framework.common.EvidenceType;
import com.cognesis.framework.common.Provenance;
import com.cognesis.framework.email.EmailEvaluationRequest;
import com.cognesis.framework.email.EmailFacts;
import com.cognesis.framework.email.EmailSignal;
import com.cognesis.framework.email.EmailSignalAnalyzer;
import com.cognesis.framework.policy.PolicyEvaluator;
import com.cognesis.framework.policy.PolicyVerdict;

/**
 * Business policy for the mail path: blocklists, allowlists and categories are
 * hard constraints. When a rule matches the sender domain, this analyzer emits
 * a maximally-confident signal so the SYNAPSE fusion cannot overrule explicit
 * policy.
 */
public class EmailPolicyAnalyzer implements EmailSignalAnalyzer {

    private final PolicyEvaluator policyEvaluator;

    public EmailPolicyAnalyzer(PolicyEvaluator policyEvaluator) {
        this.policyEvaluator = policyEvaluator;
    }

    @Override
    public EmailSignal analyze(EmailEvaluationRequest request, EmailFacts facts) {
        PolicyVerdict verdict = policyEvaluator.evaluate(facts.senderDomain(), "DOMAIN");
        return switch (verdict.decision()) {
            case BLOCK -> new EmailSignal(EvidenceType.POLICY, 1.0, 1.0,
                    "Policy block: " + verdict.matchedRules(), Provenance.POLICY_ANNOTATION);
            case ISOLATE -> new EmailSignal(EvidenceType.POLICY, 0.82, 0.9,
                    "Policy isolate: " + verdict.matchedRules(), Provenance.POLICY_ANNOTATION);
            case ESCALATE -> new EmailSignal(EvidenceType.POLICY, 0.68, 0.9,
                    "Policy escalate: " + verdict.matchedRules(), Provenance.POLICY_ANNOTATION);
            case CHALLENGE -> new EmailSignal(EvidenceType.POLICY, 0.58, 0.9,
                    "Policy challenge: " + verdict.matchedRules(), Provenance.POLICY_ANNOTATION);
            case MONITOR -> new EmailSignal(EvidenceType.POLICY, 0.55, 0.9,
                    "Policy monitor: " + verdict.matchedRules(), Provenance.POLICY_ANNOTATION);
            case WARN -> new EmailSignal(EvidenceType.POLICY, 0.45, 0.9,
                    "Policy warn: " + verdict.matchedRules(), Provenance.POLICY_ANNOTATION);
            case ALLOW -> new EmailSignal(EvidenceType.POLICY, 0.05, 0.9,
                    "No policy violation; sender not on any restricted list",
                    Provenance.POLICY_ANNOTATION);
        };
    }
}
