package com.cognesis.framework.dns.analyzer;

import com.cognesis.framework.common.Decision;
import com.cognesis.framework.common.EvidenceType;
import com.cognesis.framework.common.Provenance;
import com.cognesis.framework.dns.DnsFacts;
import com.cognesis.framework.dns.DnsResolutionRequest;
import com.cognesis.framework.dns.DnsSignal;
import com.cognesis.framework.dns.DnsSignalAnalyzer;
import com.cognesis.framework.policy.PolicyEvaluator;
import com.cognesis.framework.policy.PolicyVerdict;

/**
 * Business policy: blocklists, allowlists and categories are hard constraints.
 * When a rule matches, this analyzer emits a maximally-confident signal so the
 * SYNAPSE fusion cannot overrule explicit policy - mirroring how analysts treat
 * signed blocklist entries as ground truth.
 */
public class PolicyAnalyzer implements DnsSignalAnalyzer {

    private final PolicyEvaluator policyEvaluator;

    public PolicyAnalyzer(PolicyEvaluator policyEvaluator) {
        this.policyEvaluator = policyEvaluator;
    }

    @Override
    public DnsSignal analyze(DnsResolutionRequest request, DnsFacts facts) {
        PolicyVerdict verdict = policyEvaluator.evaluate(request.domain(), "DOMAIN");
        return switch (verdict.decision()) {
            case BLOCK -> new DnsSignal(EvidenceType.POLICY, 1.0, 1.0,
                    "Policy block: " + verdict.matchedRules(), Provenance.POLICY_ANNOTATION);
            case ISOLATE -> new DnsSignal(EvidenceType.POLICY, 0.82, 0.9,
                    "Policy isolate: " + verdict.matchedRules(), Provenance.POLICY_ANNOTATION);
            case ESCALATE -> new DnsSignal(EvidenceType.POLICY, 0.68, 0.9,
                    "Policy escalate: " + verdict.matchedRules(), Provenance.POLICY_ANNOTATION);
            case CHALLENGE -> new DnsSignal(EvidenceType.POLICY, 0.58, 0.9,
                    "Policy challenge: " + verdict.matchedRules(), Provenance.POLICY_ANNOTATION);
            case MONITOR -> new DnsSignal(EvidenceType.POLICY, 0.55, 0.9,
                    "Policy monitor: " + verdict.matchedRules(), Provenance.POLICY_ANNOTATION);
            case WARN -> new DnsSignal(EvidenceType.POLICY, 0.45, 0.9,
                    "Policy warn: " + verdict.matchedRules(), Provenance.POLICY_ANNOTATION);
            case ALLOW -> new DnsSignal(EvidenceType.POLICY, 0.05, 0.9,
                    "No policy violation; domain not on any restricted list",
                    Provenance.POLICY_ANNOTATION);
        };
    }
}
