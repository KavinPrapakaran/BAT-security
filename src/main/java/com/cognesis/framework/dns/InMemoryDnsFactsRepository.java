package com.cognesis.framework.dns;

import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Sample facts repository used by the scaffold and tests. Well-known domains
 * return healthy, long-lived facts; unknown domains return the profile of a
 * brand-new, weakly-validated domain (the common case an analyst faces when a
 * truly new domain is encountered).
 */
public class InMemoryDnsFactsRepository implements DnsFactsRepository {

    private static final DnsFacts UNKNOWN_DOMAIN = new DnsFacts(
            "", 3L, false, 1, 1, 0.45,
            List.of(), "enabled", Instant.now().minusSeconds(86400),
            1, false, 0);

    private final Map<String, DnsFacts> facts = new ConcurrentHashMap<>();

    public InMemoryDnsFactsRepository() {
        Instant now = Instant.now();
        facts.put("google.com", new DnsFacts("google.com", 32000L, true, 1, 0, 0.02,
                List.of("www", "mail", "drive", "maps"), "disabled",
                now.minusSeconds(86400 * 60), 45, true, 0));
        facts.put("corp.example.com", new DnsFacts("corp.example.com", 5200L, true, 1, 0, 0.01,
                List.of("www", "vpn", "mail", "wiki"), "disabled",
                now.minusSeconds(86400 * 300), 12, true, 0));
        facts.put("amazon.com", new DnsFacts("amazon.com", 30000L, true, 1, 0, 0.03,
                List.of("www", "smile", "aws"), "disabled",
                now.minusSeconds(86400 * 90), 80, true, 0));
        facts.put("paypal.com", new DnsFacts("paypal.com", 28000L, true, 1, 0, 0.02,
                List.of("www"), "disabled",
                now.minusSeconds(86400 * 45), 22, true, 0));
        facts.put("paypa1.com", new DnsFacts("paypa1.com", 2L, false, 1, 2, 0.6,
                List.of(), "enabled", now.minusSeconds(3600),
                1, false, 1));
        facts.put("xn--amazon-3hb.com", new DnsFacts("xn--amazon-3hb.com", 1L, false, 1, 1, 0.3,
                List.of(), "enabled", now.minusSeconds(600),
                1, false, 0));
        facts.put("tkqzvbxkadnpqws.example", new DnsFacts("tkqzvbxkadnpqws.example", 1L, false, 1, 3, 0.8,
                List.of(), "enabled", now.minusSeconds(1200),
                1, false, 1));
    }

    @Override
    public DnsFacts factsFor(String domain) {
        String key = normalize(domain);
        DnsFacts known = facts.get(key);
        if (known != null) {
            return known;
        }
        return new DnsFacts(
                key, UNKNOWN_DOMAIN.ageDays(), false, 1, 1, 0.45,
                List.of(), "enabled", Instant.now().minusSeconds(86400),
                1, false, 0);
    }

    /**
     * Marks a domain as previously-flagged (IOC). Used by threat-intel feed
     * ingestion so that live feeds (e.g. abuse.ch) influence future verdicts.
     */
    public void flagMalicious(String domain) {
        String key = normalize(domain);
        if (key.isEmpty()) {
            return;
        }
        facts.compute(key, (k, existing) -> existing == null
                ? new DnsFacts(key, UNKNOWN_DOMAIN.ageDays(), false, 1, 1, 0.6,
                        List.of(), "enabled", Instant.now().minusSeconds(86400),
                        1, false, 1)
                : new DnsFacts(existing.domain(), existing.ageDays(), existing.dnssecValid(),
                        existing.registrarCount(), existing.nameServerChanges(),
                        existing.ipRecordChurn(), existing.subdomains(), existing.whoisPrivacy(),
                        existing.certificateIssuedAt(), existing.certificateCount(),
                        existing.certificateInCtLogs(), existing.maliciousFlagCount() + 1));
    }

    private static String normalize(String domain) {
        return domain == null ? "" : domain.trim().toLowerCase(Locale.ROOT);
    }
}
