package com.cognesis.framework.dns.analyzer;

import com.cognesis.framework.common.EvidenceType;
import com.cognesis.framework.common.Provenance;
import com.cognesis.framework.dns.DnsFacts;
import com.cognesis.framework.dns.DnsResolutionRequest;
import com.cognesis.framework.dns.DnsSignal;
import com.cognesis.framework.dns.DnsSignalAnalyzer;
import com.cognesis.framework.trust.TrustEngine;

/**
 * Network behaviour: the source IP making the resolution. Unknown or
 * low-trust origins nudge risk up slightly. Kept mild so network reputation
 * never outweighs domain-level evidence.
 */
public class NetworkBehaviourAnalyzer implements DnsSignalAnalyzer {

    private final TrustEngine trustEngine;

    public NetworkBehaviourAnalyzer(TrustEngine trustEngine) {
        this.trustEngine = trustEngine;
    }

    @Override
    public DnsSignal analyze(DnsResolutionRequest request, DnsFacts facts) {
        String ip = request.sourceIp();
        if (ip == null || ip.isBlank()) {
            return new DnsSignal(EvidenceType.NETWORK_BEHAVIOUR, 0.3, 0.2,
                    "No source IP for network context", Provenance.TELEMETRY);
        }
        double trust = trustEngine.assess(ip, "IP").trust();
        double strength = 0.15 + 0.35 * (1.0 - trust);
        return new DnsSignal(EvidenceType.NETWORK_BEHAVIOUR, strength, 0.45,
                "Source network trust is " + String.format("%.2f", trust),
                Provenance.TELEMETRY);
    }
}
