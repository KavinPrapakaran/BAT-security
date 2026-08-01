package com.cognesis.framework.dns.analyzer;

import com.cognesis.framework.common.EvidenceType;
import com.cognesis.framework.common.Provenance;
import com.cognesis.framework.dns.DnsFacts;
import com.cognesis.framework.dns.DnsResolutionRequest;
import com.cognesis.framework.dns.DnsSignal;
import com.cognesis.framework.dns.DnsSignalAnalyzer;

/**
 * WHOIS data: privacy protection on a brand-new domain is a weak-to-moderate
 * caution signal because legitimate small businesses also use it. The analyzer
 * deliberately returns modest strength and confidence.
 */
public class WhoisAnalyzer implements DnsSignalAnalyzer {

    @Override
    public DnsSignal analyze(DnsResolutionRequest request, DnsFacts facts) {
        long ageDays = Math.max(0, facts.ageDays());
        boolean privacy = "enabled".equalsIgnoreCase(facts.whoisPrivacy());

        if (privacy && ageDays < 60) {
            return new DnsSignal(EvidenceType.DNS_WHOIS, 0.5, 0.5,
                    "WHOIS privacy enabled on a young domain", Provenance.WHOIS);
        }
        if (privacy) {
            return new DnsSignal(EvidenceType.DNS_WHOIS, 0.3, 0.45,
                    "WHOIS privacy enabled but domain is established", Provenance.WHOIS);
        }
        return new DnsSignal(EvidenceType.DNS_WHOIS, 0.15, 0.6,
                "WHOIS records are openly available", Provenance.WHOIS);
    }
}
