package com.cognesis.framework.dns.analyzer;

import com.cognesis.framework.common.EvidenceType;
import com.cognesis.framework.common.Provenance;
import com.cognesis.framework.dns.DnsFacts;
import com.cognesis.framework.dns.DnsResolutionRequest;
import com.cognesis.framework.dns.DnsSignal;
import com.cognesis.framework.dns.DnsSignalAnalyzer;

/**
 * Fast flux: rapid churn of A/AAAA answers and nameservers used to hide C2 or
 * phishing behind a rotating set of hosts. Combines IP churn and nameserver
 * changes into one signal.
 */
public class FastFluxAnalyzer implements DnsSignalAnalyzer {

    @Override
    public DnsSignal analyze(DnsResolutionRequest request, DnsFacts facts) {
        double ipChurn = facts.ipRecordChurn();
        int nsChanges = Math.max(0, facts.nameServerChanges());
        double score = Math.max(ipChurn * 0.75, Math.min(1.0, nsChanges * 0.25));
        if (score < 0.35) {
            return new DnsSignal(EvidenceType.DNS_FAST_FLUX, score, 0.5,
                    "Record and nameserver churn within normal bounds", Provenance.LIVE_TRAFFIC);
        }
        return new DnsSignal(EvidenceType.DNS_FAST_FLUX, Math.min(1.0, 0.5 + score * 0.5), 0.7,
                "Elevated A/AAAA churn (" + String.format("%.0f%%", ipChurn * 100)
                        + ") with " + nsChanges + " nameserver change(s) suggests fast flux",
                Provenance.LIVE_TRAFFIC);
    }
}
