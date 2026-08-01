package com.cognesis.framework.dns.analyzer;

import com.cognesis.framework.common.EvidenceType;
import com.cognesis.framework.common.Provenance;
import com.cognesis.framework.dns.DnsFacts;
import com.cognesis.framework.dns.DnsResolutionRequest;
import com.cognesis.framework.dns.DnsSignal;
import com.cognesis.framework.dns.DnsSignalAnalyzer;

/**
 * Registrar churn - a domain jumping between registrars - is a classic sign of
 * infrastructure being recycled for abuse. Each registrar move adds signal.
 */
public class RegistrarHistoryAnalyzer implements DnsSignalAnalyzer {

    @Override
    public DnsSignal analyze(DnsResolutionRequest request, DnsFacts facts) {
        int registrars = facts.registrarCount();
        if (registrars <= 1) {
            return new DnsSignal(EvidenceType.DNS_REGISTRAR_HISTORY, 0.5, 0.3,
                    "No registrar churn observed", Provenance.WHOIS);
        }
        double strength = Math.min(1.0, 0.35 * registrars - 0.3);
        return new DnsSignal(EvidenceType.DNS_REGISTRAR_HISTORY, strength, 0.6,
                registrars + " distinct registrars observed - infrastructure being recycled",
                Provenance.WHOIS);
    }
}
