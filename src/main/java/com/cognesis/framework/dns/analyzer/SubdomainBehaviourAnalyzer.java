package com.cognesis.framework.dns.analyzer;

import com.cognesis.framework.common.EvidenceType;
import com.cognesis.framework.common.Provenance;
import com.cognesis.framework.dns.DnsFacts;
import com.cognesis.framework.dns.DnsResolutionRequest;
import com.cognesis.framework.dns.DnsSignal;
import com.cognesis.framework.dns.DnsSignalAnalyzer;

/**
 * Subdomain behaviour: malware often spins up many random-looking subdomains
 * for command channels. Uses the DGA-style entropy of subdomain labels to spot
 * such fabrications.
 */
public class SubdomainBehaviourAnalyzer implements DnsSignalAnalyzer {

    @Override
    public DnsSignal analyze(DnsResolutionRequest request, DnsFacts facts) {
        long suspicious = facts.subdomains().stream()
                .filter(sd -> sd.length() >= 10 && entropy(sd) >= 3.2)
                .count();
        if (suspicious >= 3) {
            return new DnsSignal(EvidenceType.DNS_SUBDOMAIN_BEHAVIOUR, 0.7, 0.65,
                    suspicious + " high-entropy subdomains - likely machine-generated",
                    Provenance.LIVE_TRAFFIC);
        }
        return new DnsSignal(EvidenceType.DNS_SUBDOMAIN_BEHAVIOUR, 0.2, 0.5,
                "Subdomain inventory looks normal", Provenance.LIVE_TRAFFIC);
    }

    private double entropy(String s) {
        java.util.Map<Character, Integer> counts = new java.util.HashMap<>();
        for (char c : s.toCharArray()) {
            counts.merge(c, 1, Integer::sum);
        }
        double h = 0.0;
        for (int count : counts.values()) {
            double p = (double) count / s.length();
            h -= p * (Math.log(p) / Math.log(2));
        }
        return h;
    }
}
