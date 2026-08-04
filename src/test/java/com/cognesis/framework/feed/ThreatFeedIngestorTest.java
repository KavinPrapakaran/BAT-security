package com.cognesis.framework.feed;

import com.cognesis.framework.dns.DnsFacts;
import com.cognesis.framework.dns.InMemoryDnsFactsRepository;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

class ThreatFeedIngestorTest {

    @Test
    void parsesHostFileStyleFeedAndFlagsDomains() {
        String body = """
                # threatfox domains export
                0.0.0.0 evil1.example
                127.0.0.1 evil2.example
                standalone.example
                """;
        var harness = new FeedHarness(body, "/feed.txt");
        assertEquals(3, harness.ingestor.refresh());

        DnsFacts flagged = harness.repo.factsFor("evil1.example");
        assertTrue(flagged.maliciousFlagCount() >= 1, "flagged domain must carry an IOC flag");
        assertEquals(0, harness.repo.factsFor("clean.example").maliciousFlagCount());
    }

    @Test
    void ignoresCommentsAndBlankLines() {
        String body = """
                # header
                0.0.0.0 only.example

                # another comment
                """;
        var harness = new FeedHarness(body, "/feed.txt");
        assertEquals(1, harness.ingestor.refresh());
        assertTrue(harness.repo.factsFor("only.example").maliciousFlagCount() >= 1);
    }

    @Test
    void flagsAccumulateAcrossRefreshes() {
        InMemoryDnsFactsRepository repo = new InMemoryDnsFactsRepository();
        ThreatFeedIngestor ingestor = new ThreatFeedIngestor(null, repo, "");

        repo.flagMalicious("repeat.example");
        repo.flagMalicious("repeat.example");

        assertTrue(repo.factsFor("repeat.example").maliciousFlagCount() >= 2,
                "repeat flags must accumulate");
    }

    @Test
    void disabledFeedSkipsNetworkEntirely() {
        InMemoryDnsFactsRepository repo = new InMemoryDnsFactsRepository();
        ThreatFeedIngestor ingestor = new ThreatFeedIngestor(null, repo, "");
        assertEquals(0, ingestor.refresh());
    }

    @Test
    void unreachableFeedIsSwallowedNotThrown() {
        var harness = new FeedHarness("", "/feed.txt");
        harness.server.expect(requestTo("/feed.txt")).andRespond(withServerError());
        assertEquals(0, harness.ingestor.refresh());
    }

    private static class FeedHarness {
        final InMemoryDnsFactsRepository repo = new InMemoryDnsFactsRepository();
        final MockRestServiceServer server;
        final ThreatFeedIngestor ingestor;

        FeedHarness(String body, String url) {
            RestClient.Builder builder = RestClient.builder().baseUrl("http://localhost");
            server = MockRestServiceServer.bindTo(builder).build();
            server.expect(requestTo("http://localhost" + url)).andRespond(withSuccess(body, org.springframework.http.MediaType.TEXT_PLAIN));
            ingestor = new ThreatFeedIngestor(builder.build(), repo, url);
        }
    }
}
