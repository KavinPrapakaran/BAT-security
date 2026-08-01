package com.cognesis.framework.observatory;

import com.cognesis.framework.common.EvidenceType;
import com.cognesis.framework.common.Provenance;
import com.cognesis.framework.dns.DnsFacts;
import com.cognesis.framework.dns.DnsFactsRepository;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * OBSERVATORY adapter for DNS telemetry. Translates raw domain facts into
 * normalized evidence fragments that the decision core consumes. This is the
 * "DNS sense" of the framework - analogous providers will feed Cloud, Identity,
 * Email, API, IoT, Endpoint and Threat Intelligence senses.
 */
public class DnsEvidenceProvider implements EvidenceProvider {

    private final DnsFactsRepository factsRepository;

    public DnsEvidenceProvider(DnsFactsRepository factsRepository) {
        this.factsRepository = factsRepository;
    }

    @Override
    public List<EvidenceFragment> provide(EvidenceRequest request) {
        if (!"DOMAIN".equalsIgnoreCase(request.entityType())) {
            return List.of();
        }
        DnsFacts facts = factsRepository.factsFor(request.entityId());
        List<EvidenceFragment> fragments = new ArrayList<>();

        long ageDays = Math.max(0, facts.ageDays());
        if (ageDays < 30) {
            fragments.add(fragment(request, EvidenceType.DNS_DOMAIN_AGE,
                    Math.min(1.0, 0.9 - 0.015 * ageDays),
                    Math.min(0.8, 0.4 + 0.02 * ageDays),
                    "Domain is only " + ageDays + " days old",
                    Provenance.WHOIS));
        }

        if (!facts.dnssecValid()) {
            fragments.add(fragment(request, EvidenceType.DNS_DNSSEC, 0.25, 0.4,
                    "DNSSEC validation is not in place", Provenance.DNS_RESPONSE));
        }

        double churn = facts.ipRecordChurn();
        if (churn >= 0.5) {
            fragments.add(fragment(request, EvidenceType.DNS_FAST_FLUX, Math.min(1.0, 0.5 + churn * 0.4), 0.7,
                    "A/AAAA record churn of " + String.format("%.0f%%", churn * 100) + " suggests fast flux",
                    Provenance.LIVE_TRAFFIC));
        }

        if (facts.certificateCount() > 0 && !facts.certificateInCtLogs()) {
            fragments.add(fragment(request, EvidenceType.DNS_CERTIFICATE, 0.55, 0.6,
                    "Certificate not visible in public CT logs", Provenance.CERTIFICATE_TRANSPARENCY));
        }
        Instant certIssued = facts.certificateIssuedAt();
        if (certIssued != null && Duration.between(certIssued, Instant.now()).toDays() < 7 && ageDays < 90) {
            fragments.add(fragment(request, EvidenceType.DNS_CERTIFICATE, 0.45, 0.5,
                    "Certificate issued very recently for a young domain", Provenance.CERTIFICATE_TRANSPARENCY));
        }

        if ("enabled".equalsIgnoreCase(facts.whoisPrivacy()) && ageDays < 60) {
            fragments.add(fragment(request, EvidenceType.DNS_WHOIS, 0.5, 0.5,
                    "WHOIS privacy on a young domain", Provenance.WHOIS));
        }

        if (facts.registrarCount() > 2) {
            fragments.add(fragment(request, EvidenceType.DNS_REGISTRAR_HISTORY,
                    Math.min(1.0, 0.35 * facts.registrarCount() - 0.3), 0.6,
                    "Multiple registrars observed for this domain", Provenance.WHOIS));
        }

        if (facts.maliciousFlagCount() > 0) {
            fragments.add(fragment(request, EvidenceType.THREAT_MEMORY,
                    Math.min(1.0, 0.4 + facts.maliciousFlagCount() * 0.25), 0.8,
                    "Previously flagged " + facts.maliciousFlagCount() + " time(s)",
                    Provenance.PAST_DECISION));
        }

        return fragments;
    }

    private EvidenceFragment fragment(EvidenceRequest request, EvidenceType type,
                                      double strength, double confidence,
                                      String explanation, Provenance provenance) {
        return new EvidenceFragment(request.entityId(), request.entityType(), type,
                strength, confidence, explanation, provenance, Instant.now());
    }
}
