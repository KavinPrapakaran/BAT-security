package com.cognesis.framework.dns.analyzer;

import com.cognesis.framework.common.EvidenceType;
import com.cognesis.framework.common.Provenance;
import com.cognesis.framework.dns.DnsFacts;
import com.cognesis.framework.dns.DnsResolutionRequest;
import com.cognesis.framework.dns.DnsSignal;
import com.cognesis.framework.dns.DnsSignalAnalyzer;

import java.util.List;
import java.util.Locale;

/**
 * Typosquatting detection: a domain that is an edit-distance of 1-2 characters
 * away from a protected brand is very likely parked for phishing or credential
 * harvesting. Uses the classic Levenshtein algorithm against a configurable
 * protected-domain list.
 */
public class TyposquattingAnalyzer implements DnsSignalAnalyzer {

    /** Protected brands - extend from configuration/CMDB in production. */
    private static final List<String> PROTECTED_DOMAINS = List.of(
            "google.com", "paypal.com", "apple.com", "microsoft.com",
            "amazon.com", "office365.com", "github.com", "facebook.com",
            "chase.com", "corp.example.com");

    @Override
    public DnsSignal analyze(DnsResolutionRequest request, DnsFacts facts) {
        String domain = request.domain() == null ? "" : request.domain().toLowerCase(Locale.ROOT);
        if (domain.isEmpty()) {
            return new DnsSignal(EvidenceType.DNS_TYPOSQUATTING, 0.2, 0.2, "no domain", Provenance.OSINT);
        }

        double closest = 1.0;
        String closestBrand = null;
        for (String brand : PROTECTED_DOMAINS) {
            if (domain.equals(brand)) {
                return new DnsSignal(EvidenceType.DNS_TYPOSQUATTING, 0.05, 0.9,
                        "Domain is an exact match for protected brand '" + brand + "'", Provenance.OSINT);
            }
            int dist = levenshtein(domain, brand);
            double normalized = (double) dist / Math.max(domain.length(), brand.length());
            if (dist <= 2 && normalized < closest) {
                closest = normalized;
                closestBrand = brand;
            }
        }

        if (closestBrand != null) {
            double strength = Math.max(0.55, 1.0 - closest);
            return new DnsSignal(EvidenceType.DNS_TYPOSQUATTING, strength, 0.8,
                    "Domain is " + (int) (closest * Math.max(domain.length(), closestBrand.length()))
                            + " edit(s) away from protected brand '" + closestBrand + "'",
                    Provenance.OSINT);
        }
        return new DnsSignal(EvidenceType.DNS_TYPOSQUATTING, 0.15, 0.6,
                "No proximity to protected brands", Provenance.OSINT);
    }

    private int levenshtein(String a, String b) {
        int[] prev = new int[b.length() + 1];
        int[] curr = new int[b.length() + 1];
        for (int j = 0; j <= b.length(); j++) {
            prev[j] = j;
        }
        for (int i = 1; i <= a.length(); i++) {
            curr[0] = i;
            for (int j = 1; j <= b.length(); j++) {
                int cost = a.charAt(i - 1) == b.charAt(j - 1) ? 0 : 1;
                curr[j] = Math.min(Math.min(curr[j - 1] + 1, prev[j] + 1), prev[j - 1] + cost);
            }
            int[] tmp = prev;
            prev = curr;
            curr = tmp;
        }
        return prev[b.length()];
    }
}
