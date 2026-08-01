package com.cognesis.framework.dns.analyzer;

import com.cognesis.framework.common.EvidenceType;
import com.cognesis.framework.common.Provenance;
import com.cognesis.framework.dns.DnsFacts;
import com.cognesis.framework.dns.DnsResolutionRequest;
import com.cognesis.framework.dns.DnsSignal;
import com.cognesis.framework.dns.DnsSignalAnalyzer;

/**
 * Missing DNSSEC is weak evidence on its own (most domains still lack it), so
 * this analyzer always keeps strength and confidence low. It exists so the
 * fusion can combine it with other signals rather than ignore it entirely.
 */
public class DnssecAnalyzer implements DnsSignalAnalyzer {

    @Override
    public DnsSignal analyze(DnsResolutionRequest request, DnsFacts facts) {
        if (facts.dnssecValid()) {
            return new DnsSignal(EvidenceType.DNS_DNSSEC, 0.15, 0.6,
                    "DNSSEC validation passes", Provenance.DNS_RESPONSE);
        }
        return new DnsSignal(EvidenceType.DNS_DNSSEC, 0.30, 0.4,
                "DNSSEC validation is not in place", Provenance.DNS_RESPONSE);
    }
}
