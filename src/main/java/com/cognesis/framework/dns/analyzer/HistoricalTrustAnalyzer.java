package com.cognesis.framework.dns.analyzer;

import com.cognesis.framework.common.EvidenceType;
import com.cognesis.framework.common.Provenance;
import com.cognesis.framework.dns.DnsFacts;
import com.cognesis.framework.dns.DnsResolutionRequest;
import com.cognesis.framework.dns.DnsSignal;
import com.cognesis.framework.dns.DnsSignalAnalyzer;
import com.cognesis.framework.trust.TrustAssessment;
import com.cognesis.framework.trust.TrustEngine;

/**
 * Historical trust: consults FIDES for the domain's accumulated trust. A
 * high-trust, long-observed domain is a strong counter-signal; a low-trust
 * domain is a caution signal. Confidence is inherited from FIDES.
 */
public class HistoricalTrustAnalyzer implements DnsSignalAnalyzer {

    private final TrustEngine trustEngine;

    public HistoricalTrustAnalyzer(TrustEngine trustEngine) {
        this.trustEngine = trustEngine;
    }

    @Override
    public DnsSignal analyze(DnsResolutionRequest request, DnsFacts facts) {
        TrustAssessment assessment = trustEngine.assess(request.domain(), "DOMAIN");
        double strength = 1.0 - assessment.trust();
        return new DnsSignal(EvidenceType.DNS_HISTORICAL_TRUST, strength,
                Math.max(0.3, assessment.confidence()),
                "FIDES trust for this domain is " + String.format("%.2f", assessment.trust())
                        + " across " + assessment.observationCount() + " observations",
                Provenance.PAST_DECISION);
    }
}
