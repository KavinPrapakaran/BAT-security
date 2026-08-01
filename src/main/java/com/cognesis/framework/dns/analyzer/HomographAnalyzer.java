package com.cognesis.framework.dns.analyzer;

import com.cognesis.framework.common.EvidenceType;
import com.cognesis.framework.common.Provenance;
import com.cognesis.framework.dns.DnsFacts;
import com.cognesis.framework.dns.DnsResolutionRequest;
import com.cognesis.framework.dns.DnsSignal;
import com.cognesis.framework.dns.DnsSignalAnalyzer;

import java.util.List;

/**
 * Homograph detection: domains that visually impersonate a trusted brand by
 * swapping characters for look-alikes from other scripts (e.g. Cyrillic 'а' in
 * "amazon.com") or by using punycode to hide non-ASCII characters. These are a
 * phishing staple because they defeat human pattern-matching.
 */
public class HomographAnalyzer implements DnsSignalAnalyzer {

    private static final int MAX_BRAND_LENGTH = 16;

    @Override
    public DnsSignal analyze(DnsResolutionRequest request, DnsFacts facts) {
        String domain = request.domain() == null ? "" : request.domain().toLowerCase();
        if (domain.startsWith("xn--")) {
            return new DnsSignal(EvidenceType.DNS_HOMOGRAPH, 0.55, 0.7,
                    "Punycode-encoded domain is likely hiding non-ASCII characters", Provenance.DNS_RESPONSE);
        }

        int nonAscii = 0;
        int total = 0;
        for (int i = 0; i < domain.length(); i++) {
            char c = domain.charAt(i);
            if (c == '.') {
                continue;
            }
            total++;
            if (c > 0x007F) {
                nonAscii++;
            }
        }
        if (total > 0 && nonAscii > 0) {
            double fraction = (double) nonAscii / total;
            double strength = Math.min(1.0, 0.55 + fraction * 0.40);
            return new DnsSignal(EvidenceType.DNS_HOMOGRAPH, strength, 0.75,
                    nonAscii + " non-ASCII characters present - possible visual spoofing",
                    Provenance.DNS_RESPONSE);
        }

        String label = domain.split("\\.", 2)[0];
        if (label.length() > MAX_BRAND_LENGTH && containsUncommonDigits(label)) {
            return new DnsSignal(EvidenceType.DNS_HOMOGRAPH, 0.4, 0.5,
                    "Long label with unusual digit substitutions", Provenance.DNS_RESPONSE);
        }
        return new DnsSignal(EvidenceType.DNS_HOMOGRAPH, 0.15, 0.6,
                "No homograph indicators", Provenance.DNS_RESPONSE);
    }

    private boolean containsUncommonDigits(String s) {
        List<String> patterns = List.of("0", "1", "3", "5", "8");
        return patterns.stream().anyMatch(s::contains);
    }
}
