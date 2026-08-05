package com.cognesis.framework.dns;

import com.cognesis.framework.persistence.IocStore;

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
 *
 * <p>When a {@link IocStore} is present, threat-intel flags are persisted
 * there and reloaded on every {@link #factsFor} lookup, so live feed
 * indicators survive restarts.
 */
public class InMemoryDnsFactsRepository implements DnsFactsRepository {

    private static final DnsFacts UNKNOWN_DOMAIN = new DnsFacts(
            "", 3L, false, 1, 1, 0.45,
            List.of(), "enabled", Instant.now().minusSeconds(86400),
            1, false, 0, List.of());

    private final Map<String, DnsFacts> facts = new ConcurrentHashMap<>();
    private final IocStore iocStore;

    public InMemoryDnsFactsRepository() {
        this(null);
    }

    public InMemoryDnsFactsRepository(IocStore iocStore) {
        this.iocStore = iocStore;
        Instant now = Instant.now();
        facts.put("google.com", new DnsFacts("google.com", 32000L, true, 1, 0, 0.02,
                List.of("www", "mail", "drive", "maps"), "disabled",
                now.minusSeconds(86400 * 60), 45, true, 0, List.of("142.250.72.14", "142.250.72.14")));
        facts.put("corp.example.com", new DnsFacts("corp.example.com", 5200L, true, 1, 0, 0.01,
                List.of("www", "vpn", "mail", "wiki"), "disabled",
                now.minusSeconds(86400 * 300), 12, true, 0, List.of("10.1.2.3")));
        facts.put("amazon.com", new DnsFacts("amazon.com", 30000L, true, 1, 0, 0.03,
                List.of("www", "smile", "aws"), "disabled",
                now.minusSeconds(86400 * 90), 80, true, 0, List.of("176.32.103.205")));
        facts.put("paypal.com", new DnsFacts("paypal.com", 28000L, true, 1, 0, 0.02,
                List.of("www"), "disabled",
                now.minusSeconds(86400 * 45), 22, true, 0, List.of("151.101.2.109")));
        facts.put("paypa1.com", new DnsFacts("paypa1.com", 2L, false, 1, 2, 0.6,
                List.of(), "enabled", now.minusSeconds(3600),
                1, false, 1, List.of("45.155.205.233")));
        facts.put("xn--amazon-3hb.com", new DnsFacts("xn--amazon-3hb.com", 1L, false, 1, 1, 0.3,
                List.of(), "enabled", now.minusSeconds(600),
                1, false, 0, List.of("185.220.101.4")));
        facts.put("tkqzvbxkadnpqws.example", new DnsFacts("tkqzvbxkadnpqws.example", 1L, false, 1, 3, 0.8,
                List.of(), "enabled", now.minusSeconds(1200),
                1, false, 1, List.of("185.130.5.9")));
    }

    @Override
    public DnsFacts factsFor(String domain) {
        String key = normalize(domain);
        DnsFacts known = facts.get(key);
        int extraFlags = iocStore == null ? 0 : iocStore.flagCount(key);
        if (known != null) {
            return extraFlags > 0 ? withFlags(known, known.maliciousFlagCount() + extraFlags) : known;
        }
        return new DnsFacts(
                key, UNKNOWN_DOMAIN.ageDays(), false, 1, 1, 0.45,
                List.of(), "enabled", Instant.now().minusSeconds(86400),
                1, false, extraFlags, List.of());
    }

    private static DnsFacts withFlags(DnsFacts facts, int flagCount) {
        return new DnsFacts(facts.domain(), facts.ageDays(), facts.dnssecValid(),
                facts.registrarCount(), facts.nameServerChanges(), facts.ipRecordChurn(),
                facts.subdomains(), facts.whoisPrivacy(), facts.certificateIssuedAt(),
                facts.certificateCount(), facts.certificateInCtLogs(), flagCount, facts.resolvedIps());
    }

    /**
     * Marks a domain as previously-flagged (IOC). Used by threat-intel feed
     * ingestion so that live feeds (e.g. abuse.ch) influence future verdicts.
     * With a configured {@link IocStore} the flag is persisted; otherwise it
     * is kept in memory only.
     */
    public void flagMalicious(String domain) {
        String key = normalize(domain);
        if (key.isEmpty()) {
            return;
        }
        if (iocStore != null) {
            iocStore.flag(key);
            return;
        }
        facts.compute(key, (k, existing) -> existing == null
                ? new DnsFacts(key, UNKNOWN_DOMAIN.ageDays(), false, 1, 1, 0.6,
                        List.of(), "enabled", Instant.now().minusSeconds(86400),
                        1, false, 1, List.of())
                : new DnsFacts(existing.domain(), existing.ageDays(), existing.dnssecValid(),
                        existing.registrarCount(), existing.nameServerChanges(),
                        existing.ipRecordChurn(), existing.subdomains(), existing.whoisPrivacy(),
                        existing.certificateIssuedAt(), existing.certificateCount(),
                        existing.certificateInCtLogs(), existing.maliciousFlagCount() + 1,
                        existing.resolvedIps()));
    }

    private static String normalize(String domain) {
        return domain == null ? "" : domain.trim().toLowerCase(Locale.ROOT);
    }
}
