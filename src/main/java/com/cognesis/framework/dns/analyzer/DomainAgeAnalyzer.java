package com.cognesis.framework.dns.analyzer;

import com.cognesis.framework.common.EvidenceType;
import com.cognesis.framework.common.Provenance;
import com.cognesis.framework.dns.DnsFacts;
import com.cognesis.framework.dns.DnsResolutionRequest;
import com.cognesis.framework.dns.DnsSignal;
import com.cognesis.framework.dns.DnsSignalAnalyzer;

/**
 * Domain age is not guilt - it is uncertainty. A brand-new domain has no track
 * record, so its trust prior is weak; this signal encodes that caution with
 * confidence that grows as the domain matures.
 */
public class DomainAgeAnalyzer implements DnsSignalAnalyzer {

    @Override
    public DnsSignal analyze(DnsResolutionRequest request, DnsFacts facts) {
        long ageDays = Math.max(0, facts.ageDays());
        double strength;
        double confidence;
        String explanation;
        if (ageDays < 1) {
            strength = 0.90;
            confidence = 0.65;
            explanation = "Domain registered within the last 24 hours";
        } else if (ageDays < 7) {
            strength = 0.72;
            confidence = 0.60;
            explanation = "Domain is under a week old";
        } else if (ageDays < 30) {
            strength = 0.55;
            confidence = 0.55;
            explanation = "Domain is less than a month old";
        } else if (ageDays < 180) {
            strength = 0.38;
            confidence = 0.50;
            explanation = "Domain is less than six months old";
        } else {
            strength = 0.20;
            confidence = 0.55;
            explanation = "Domain has a long-established age (" + ageDays + " days)";
        }
        return new DnsSignal(EvidenceType.DNS_DOMAIN_AGE, strength, confidence, explanation, Provenance.WHOIS);
    }
}
