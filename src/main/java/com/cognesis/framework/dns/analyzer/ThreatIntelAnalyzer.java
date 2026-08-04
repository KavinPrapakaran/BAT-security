package com.cognesis.framework.dns.analyzer;

import com.cognesis.framework.common.EvidenceType;
import com.cognesis.framework.common.Provenance;
import com.cognesis.framework.dns.DnsFacts;
import com.cognesis.framework.dns.DnsResolutionRequest;
import com.cognesis.framework.dns.DnsSignal;
import com.cognesis.framework.dns.DnsSignalAnalyzer;

/**
 * Threat-intel sense: a domain previously flagged by a live IOC feed
 * (abuse.ch URLhaus / ThreatFox, ingested via the feed pipeline) is treated as
 * high-risk even when its other signals look quiet. This is what makes the
 * live feed data reach the decision core on the DNS evaluation path.
 */
public class ThreatIntelAnalyzer implements DnsSignalAnalyzer {

    @Override
    public DnsSignal analyze(DnsResolutionRequest request, DnsFacts facts) {
        if (facts.maliciousFlagCount() > 0) {
            double strength = Math.min(1.0, 0.55 + facts.maliciousFlagCount() * 0.2);
            return new DnsSignal(EvidenceType.THREAT_INTEL, strength, 0.85,
                    "Domain flagged " + facts.maliciousFlagCount() + " time(s) by threat-intel feed",
                    Provenance.THREAT_INTEL_FEED);
        }
        return new DnsSignal(EvidenceType.THREAT_INTEL, 0.1, 0.9,
                "No threat-intel flags for this domain",
                Provenance.THREAT_INTEL_FEED);
    }
}
