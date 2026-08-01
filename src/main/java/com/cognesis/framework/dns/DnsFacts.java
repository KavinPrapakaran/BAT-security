package com.cognesis.framework.dns;

import java.time.Instant;
import java.util.List;

/**
 * Structured facts about a domain, assembled from WHOIS, DNS responses,
 * certificate transparency, and historical telemetry. Analyzers read these
 * facts and convert them into evidence signals. In production these are fed by
 * live resolvers and feeds; the scaffold ships a sample repository.
 *
 * @param domain              requested domain
 * @param ageDays             domain age in days
 * @param dnssecValid         whether DNSSEC validation passes
 * @param registrarCount      distinct registrars observed
 * @param nameServerChanges   number of nameserver changes observed
 * @param ipRecordChurn       churn of A/AAAA answers in [0,1]
 * @param subdomains          observed subdomains
 * @param whoisPrivacy        "enabled" | "disabled" | "unknown"
 * @param certificateIssuedAt most recent certificate issuance
 * @param certificateCount    certificates seen in CT logs
 * @param certificateInCtLogs whether certs are in public CT logs
 * @param maliciousFlagCount  times this domain was previously flagged
 */
public record DnsFacts(
        String domain,
        long ageDays,
        boolean dnssecValid,
        int registrarCount,
        int nameServerChanges,
        double ipRecordChurn,
        List<String> subdomains,
        String whoisPrivacy,
        Instant certificateIssuedAt,
        int certificateCount,
        boolean certificateInCtLogs,
        int maliciousFlagCount) {

    public DnsFacts {
        ipRecordChurn = Math.max(0.0, Math.min(1.0, ipRecordChurn));
        subdomains = subdomains != null ? List.copyOf(subdomains) : List.of();
    }
}
