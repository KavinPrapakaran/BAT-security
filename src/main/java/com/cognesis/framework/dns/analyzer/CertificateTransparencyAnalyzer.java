package com.cognesis.framework.dns.analyzer;

import com.cognesis.framework.common.EvidenceType;
import com.cognesis.framework.common.Provenance;
import com.cognesis.framework.dns.DnsFacts;
import com.cognesis.framework.dns.DnsResolutionRequest;
import com.cognesis.framework.dns.DnsSignal;
import com.cognesis.framework.dns.DnsSignalAnalyzer;

import java.time.Duration;
import java.time.Instant;

/**
 * Certificate information from Certificate Transparency: absence from CT logs,
 * very recent issuance, or self-signed certificates on a young domain all
 * raise suspicion that the domain is provisioned for abuse rather than
 * legitimate operation.
 */
public class CertificateTransparencyAnalyzer implements DnsSignalAnalyzer {

    @Override
    public DnsSignal analyze(DnsResolutionRequest request, DnsFacts facts) {
        Instant issued = facts.certificateIssuedAt();
        boolean inCt = facts.certificateInCtLogs();
        int count = facts.certificateCount();

        if (count <= 0) {
            return new DnsSignal(EvidenceType.DNS_CERTIFICATE, 0.3, 0.3,
                    "No certificate evidence available", Provenance.CERTIFICATE_TRANSPARENCY);
        }
        if (!inCt) {
            return new DnsSignal(EvidenceType.DNS_CERTIFICATE, 0.6, 0.6,
                    "Certificate not found in public CT logs", Provenance.CERTIFICATE_TRANSPARENCY);
        }
        if (issued != null && Duration.between(issued, Instant.now()).toDays() < 7) {
            return new DnsSignal(EvidenceType.DNS_CERTIFICATE, 0.45, 0.5,
                    "Certificate issued within the last week", Provenance.CERTIFICATE_TRANSPARENCY);
        }
        return new DnsSignal(EvidenceType.DNS_CERTIFICATE, 0.15, 0.6,
                "Certificate history is healthy and CT-logged", Provenance.CERTIFICATE_TRANSPARENCY);
    }
}
