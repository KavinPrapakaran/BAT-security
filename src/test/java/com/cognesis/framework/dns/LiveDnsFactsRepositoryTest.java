package com.cognesis.framework.dns;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/**
 * LiveDnsFactsRepository is the production facts source: DNS-over-HTTPS, RDAP,
 * and certificate transparency. All HTTP is mocked; these tests lock in the
 * merging, the offline fallback, and the IOC-flag carry-over.
 */
class LiveDnsFactsRepositoryTest {

    private static final String DOH = "http://localhost/dns-query";
    private static final String RDAP = "http://localhost/rdap";
    private static final String CRT = "http://localhost/crt";

    private final InMemoryDnsFactsRepository fallback = new InMemoryDnsFactsRepository();

    private Harness harness() {
        RestClient.Builder builder = RestClient.builder().baseUrl("http://localhost");
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).ignoreExpectOrder(true).build();
        LiveDnsFactsRepository repo = new LiveDnsFactsRepository(builder.build(), new ObjectMapper(), fallback,
                DOH, RDAP, CRT, 3600);
        return new Harness(server, repo);
    }

    @Test
    void assemblesFactsFromAllLiveSources() {
        Harness h = harness();
        String doh = "{\"Status\":0,\"AD\":true,\"Answer\":[{\"name\":\"google.com\",\"type\":1,\"data\":\"1.2.3.4\"}]}";
        String rdap = "{\"events\":[{\"eventAction\":\"registration\",\"eventDate\":\"2010-01-01T00:00:00Z\"}],"
                + "\"secureDNS\":{\"delegationSigned\":true},\"entities\":[{\"roles\":[\"registrar\"]}]}";
        String crt = "[{\"name_value\":\"google.com\\nwww.google.com\",\"not_before\":\"2025-01-01T00:00:00Z\"},"
                + "{\"name_value\":\"google.com\",\"not_before\":\"2024-06-01T00:00:00Z\"}]";
        h.server.expect(requestTo(DOH + "?name=google.com&type=A")).andRespond(withSuccess(doh, org.springframework.http.MediaType.APPLICATION_JSON));
        h.server.expect(requestTo(RDAP + "/google.com")).andRespond(withSuccess(rdap, org.springframework.http.MediaType.APPLICATION_JSON));
        h.server.expect(requestTo(CRT + "/?q=google.com&output=json")).andRespond(withSuccess(crt, org.springframework.http.MediaType.APPLICATION_JSON));

        DnsFacts facts = h.repo.factsFor("google.com");

        assertTrue(facts.dnssecValid(), "AD flag + secureDNS delegation must yield dnssecValid");
        assertTrue(facts.ageDays() > 5000, "registration 2010 must yield a multi-thousand-day age");
        assertEquals(2, facts.certificateCount());
        assertTrue(facts.certificateInCtLogs());
        assertTrue(facts.subdomains().contains("www.google.com"));
    }

    @Test
    void fallsBackWholesaleWhenEverySourceIsOffline() {
        Harness h = harness();
        h.server.expect(requestTo(DOH + "?name=google.com&type=A")).andRespond(withServerError());
        h.server.expect(requestTo(RDAP + "/google.com")).andRespond(withServerError());
        h.server.expect(requestTo(CRT + "/?q=google.com&output=json")).andRespond(withServerError());

        DnsFacts facts = h.repo.factsFor("google.com");

        assertEquals("google.com", facts.domain());
        assertEquals(32000L, facts.ageDays(), "fallback sample age must stand in when offline");
    }

    @Test
    void partialFailureStillUsesTheSourcesThatResponded() {
        Harness h = harness();
        String doh = "{\"Status\":0,\"AD\":false,\"Answer\":[]}";
        String rdap = "{\"events\":[{\"eventAction\":\"registration\",\"eventDate\":\"2020-01-01T00:00:00Z\"}]}";
        h.server.expect(requestTo(DOH + "?name=example.org&type=A")).andRespond(withSuccess(doh, org.springframework.http.MediaType.APPLICATION_JSON));
        h.server.expect(requestTo(RDAP + "/example.org")).andRespond(withSuccess(rdap, org.springframework.http.MediaType.APPLICATION_JSON));
        h.server.expect(requestTo(CRT + "/?q=example.org&output=json")).andRespond(withServerError());

        DnsFacts facts = h.repo.factsFor("example.org");

        assertTrue(facts.ageDays() > 1000, "RDAP still contributed age even though crt.sh was down");
        assertEquals(0, facts.certificateCount());
        assertFalse(facts.certificateInCtLogs());
    }

    @Test
    void feedIocFlagsSurviveTheLiveMerge() {
        fallback.flagMalicious("evil-payload.example");
        Harness h = harness();
        String doh = "{\"Status\":0,\"AD\":true,\"Answer\":[]}";
        String rdap = "{\"events\":[{\"eventAction\":\"registration\",\"eventDate\":\"2015-01-01T00:00:00Z\"}]}";
        String crt = "[{\"name_value\":\"evil-payload.example\",\"not_before\":\"2024-01-01T00:00:00Z\"}]";
        h.server.expect(requestTo(DOH + "?name=evil-payload.example&type=A")).andRespond(withSuccess(doh, org.springframework.http.MediaType.APPLICATION_JSON));
        h.server.expect(requestTo(RDAP + "/evil-payload.example")).andRespond(withSuccess(rdap, org.springframework.http.MediaType.APPLICATION_JSON));
        h.server.expect(requestTo(CRT + "/?q=evil-payload.example&output=json")).andRespond(withSuccess(crt, org.springframework.http.MediaType.APPLICATION_JSON));

        DnsFacts facts = h.repo.factsFor("evil-payload.example");

        assertTrue(facts.maliciousFlagCount() >= 1, "feed flag must survive the live facts merge");
    }

    @Test
    void resultsAreCached() {
        Harness h = harness();
        String doh = "{\"Status\":0,\"AD\":true,\"Answer\":[]}";
        String rdap = "{\"events\":[{\"eventAction\":\"registration\",\"eventDate\":\"2015-01-01T00:00:00Z\"}]}";
        String crt = "[]";
        h.server.expect(requestTo(DOH + "?name=cache.me&type=A")).andRespond(withSuccess(doh, org.springframework.http.MediaType.APPLICATION_JSON));
        h.server.expect(requestTo(RDAP + "/cache.me")).andRespond(withSuccess(rdap, org.springframework.http.MediaType.APPLICATION_JSON));
        h.server.expect(requestTo(CRT + "/?q=cache.me&output=json")).andRespond(withSuccess(crt, org.springframework.http.MediaType.APPLICATION_JSON));

        DnsFacts first = h.repo.factsFor("cache.me");
        DnsFacts second = h.repo.factsFor("cache.me");

        assertEquals(first, second);
        assertEquals("cache.me", second.domain());
        h.server.verify(); // second call must have hit the cache, not the network
    }

    private static class Harness {
        final MockRestServiceServer server;
        final LiveDnsFactsRepository repo;

        Harness(MockRestServiceServer server, LiveDnsFactsRepository repo) {
            this.server = server;
            this.repo = repo;
        }
    }
}
