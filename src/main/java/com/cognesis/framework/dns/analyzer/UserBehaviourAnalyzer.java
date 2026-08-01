package com.cognesis.framework.dns.analyzer;

import com.cognesis.framework.common.EvidenceType;
import com.cognesis.framework.common.Provenance;
import com.cognesis.framework.dns.DnsFacts;
import com.cognesis.framework.dns.DnsResolutionRequest;
import com.cognesis.framework.dns.DnsSignal;
import com.cognesis.framework.dns.DnsSignalAnalyzer;
import com.cognesis.framework.trust.TrustEngine;

/**
 * User behaviour: the person requesting the resolution. Users who habitually
 * visit sketchy domains carry a mild risk; users with low trust push the
 * request's risk up slightly. This signal is intentionally weak so it cannot
 * dominate the evidence.
 */
public class UserBehaviourAnalyzer implements DnsSignalAnalyzer {

    private final TrustEngine trustEngine;

    public UserBehaviourAnalyzer(TrustEngine trustEngine) {
        this.trustEngine = trustEngine;
    }

    @Override
    public DnsSignal analyze(DnsResolutionRequest request, DnsFacts facts) {
        String user = request.requestingUser();
        if (user == null || user.isBlank()) {
            return new DnsSignal(EvidenceType.USER_BEHAVIOUR, 0.3, 0.2,
                    "No user identity available for behavioural context",
                    Provenance.TELEMETRY);
        }
        double trust = trustEngine.assess(user, "USER").trust();
        double strength = 0.15 + 0.35 * (1.0 - trust);
        return new DnsSignal(EvidenceType.USER_BEHAVIOUR, strength, 0.5,
                "User trust is " + String.format("%.2f", trust) + "; habitual-behaviour influence is mild",
                Provenance.TELEMETRY);
    }
}
