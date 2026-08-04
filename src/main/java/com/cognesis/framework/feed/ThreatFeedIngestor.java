package com.cognesis.framework.feed;

import com.cognesis.framework.dns.InMemoryDnsFactsRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.client.RestClient;

import java.util.List;
import java.util.Locale;

/**
 * Ingests known-bad domains from an external threat-intel feed (abuse.ch
 * ThreatFox/URLhaus style) and flags them in the DNS facts repository so live
 * IOCs influence future COGNESIS verdicts. Disabled unless a feed URL is
 * configured; never blocks startup when offline.
 */
public class ThreatFeedIngestor {

    private static final Logger log = LoggerFactory.getLogger(ThreatFeedIngestor.class);

    private final RestClient restClient;
    private final InMemoryDnsFactsRepository factsRepository;
    private final String feedUrl;

    public ThreatFeedIngestor(RestClient restClient,
                              InMemoryDnsFactsRepository factsRepository,
                              String feedUrl) {
        this.restClient = restClient;
        this.factsRepository = factsRepository;
        this.feedUrl = feedUrl;
    }

    /** Pulls the feed and flags every domain line. Returns count ingested. */
    public int refresh() {
        if (feedUrl == null || feedUrl.isBlank()) {
            log.debug("No threat feed configured; skipping refresh");
            return 0;
        }
        try {
            String body = restClient.get().uri(feedUrl).retrieve().body(String.class);
            if (body == null || body.isBlank()) {
                return 0;
            }
            List<String> domains = body.lines()
                    .map(String::trim)
                    .filter(l -> !l.isEmpty() && !l.startsWith("#"))
                    .map(l -> {
                        String[] parts = l.split("\\s+");
                        if (parts.length > 1 && (parts[0].equals("0.0.0.0") || parts[0].equals("127.0.0.1"))) {
                            return parts[1];
                        }
                        return parts[0];
                    })
                    .map(d -> d.toLowerCase(Locale.ROOT))
                    .filter(d -> d.matches("^[a-z0-9._-]+\\.[a-z]{2,}$"))
                    .distinct()
                    .toList();
            domains.forEach(factsRepository::flagMalicious);
            log.info("Threat feed refresh: {} IOCs ingested from {}", domains.size(), feedUrl);
            return domains.size();
        } catch (Exception e) {
            log.warn("Threat feed refresh failed (feed offline or unreachable): {}", e.getMessage());
            return 0;
        }
    }
}
