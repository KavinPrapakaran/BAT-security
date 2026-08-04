package com.cognesis.framework.feed;

import com.cognesis.framework.config.CognesisProperties;
import com.cognesis.framework.dns.InMemoryDnsFactsRepository;
import com.cognesis.framework.persistence.InMemoryIocStore;
import org.junit.jupiter.api.Test;
import org.springframework.boot.actuate.health.Health;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/**
 * The feed health indicator must surface IOC freshness without flapping: DOWN
 * only when the feed is enabled but stale or never refreshed.
 */
class FeedHealthIndicatorTest {

    private CognesisProperties props(boolean enabled, String url) {
        CognesisProperties props = new CognesisProperties();
        props.getFeed().setEnabled(enabled);
        props.getFeed().setUrl(url);
        props.getFeed().setRefreshMinutes(60);
        return props;
    }

    @Test
    void disabledFeedIsHealthy() {
        FeedHealthIndicator indicator = new FeedHealthIndicator(
                new ThreatFeedIngestor(null, new InMemoryDnsFactsRepository(), ""),
                new InMemoryIocStore(), props(false, ""));
        Health health = indicator.health();
        assertEquals("UP", health.getStatus().getCode());
    }

    @Test
    void enabledButNeverRefreshedIsDown() {
        FeedHealthIndicator indicator = new FeedHealthIndicator(
                new ThreatFeedIngestor(null, new InMemoryDnsFactsRepository(), "http://feed.invalid/x"),
                new InMemoryIocStore(), props(true, "http://feed.invalid/x"));
        Health health = indicator.health();
        assertEquals("DOWN", health.getStatus().getCode());
        assertFalse((Boolean) health.getDetails().get("enabled") == false,
                "a disabled feed detail would be contradictory here");
    }

    @Test
    void freshRefreshIsUpWithIocCount() {
        InMemoryIocStore store = new InMemoryIocStore();
        RestClient.Builder builder = RestClient.builder().baseUrl("http://localhost");
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo("http://localhost/feed.txt"))
                .andRespond(withSuccess("0.0.0.0 evil.example\n", org.springframework.http.MediaType.TEXT_PLAIN));
        ThreatFeedIngestor ingestor = new ThreatFeedIngestor(builder.build(), new InMemoryDnsFactsRepository(store), "http://localhost/feed.txt");
        ingestor.refresh();

        FeedHealthIndicator indicator = new FeedHealthIndicator(ingestor, store, props(true, "http://localhost/feed.txt"));
        Health health = indicator.health();
        assertEquals("UP", health.getStatus().getCode());
        assertEquals(1L, health.getDetails().get("iocs"));
    }
}
