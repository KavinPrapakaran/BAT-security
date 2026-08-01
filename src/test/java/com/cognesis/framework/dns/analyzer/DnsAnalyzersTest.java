package com.cognesis.framework.dns.analyzer;

import com.cognesis.framework.dns.DnsFacts;
import com.cognesis.framework.dns.DnsResolutionRequest;
import com.cognesis.framework.dns.DnsSignal;
import com.cognesis.framework.memory.MnemonicMemoryEngine;
import com.cognesis.framework.trust.FidesTrustEngine;
import com.cognesis.framework.trust.TrustProperties;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DnsAnalyzersTest {

    private final FidesTrustEngine trustEngine = new FidesTrustEngine(TrustProperties.defaults());
    private final MnemonicMemoryEngine memoryEngine = new MnemonicMemoryEngine(0.02, 20);

    @Test
    void homographAnalyzerFlagsCyrillicSpoof() {
        DnsSignal signal = new HomographAnalyzer().analyze(
                DnsResolutionRequest.of("am\u0430zon.com", "user", "10.0.0.1"), facts("am\u0430zon.com"));
        assertTrue(signal.strength() > 0.5, "cyrillic look-alike should be flagged");
    }

    @Test
    void homographAnalyzerAllowsCleanAscii() {
        DnsSignal signal = new HomographAnalyzer().analyze(
                DnsResolutionRequest.of("amazon.com", "user", "10.0.0.1"), facts("amazon.com"));
        assertTrue(signal.strength() < 0.3, "clean ascii domain should not be flagged");
    }

    @Test
    void dgaAnalyzerFlagsRandomLabel() {
        DnsSignal signal = new DgaAnalyzer().analyze(
                DnsResolutionRequest.of("tkqzvbxkadnpqws.example", "user", "10.0.0.1"),
                facts("tkqzvbxkadnpqws.example"));
        assertTrue(signal.strength() > 0.6, "high-entropy label should look DGA-like");
    }

    @Test
    void dgaAnalyzerAcceptsReadableWord() {
        DnsSignal signal = new DgaAnalyzer().analyze(
                DnsResolutionRequest.of("billing-portal.example", "user", "10.0.0.1"),
                facts("billing-portal.example"));
        assertTrue(signal.strength() < 0.5, "readable label should not look DGA-like");
    }

    @Test
    void typosquattingAnalyzerFlagsCloseBrand() {
        DnsSignal signal = new TyposquattingAnalyzer().analyze(
                DnsResolutionRequest.of("paypa1.com", "user", "10.0.0.1"), facts("paypa1.com"));
        assertTrue(signal.strength() > 0.5, "one-edit variation of paypal should be flagged");
    }

    @Test
    void typosquattingAnalyzerDoesNotFlagExactBrand() {
        DnsSignal signal = new TyposquattingAnalyzer().analyze(
                DnsResolutionRequest.of("paypal.com", "user", "10.0.0.1"), facts("paypal.com"));
        assertTrue(signal.strength() < 0.2, "exact brand should not be a typosquat");
    }

    @Test
    void domainAgeAnalyzerFlagsYoungDomain() {
        DnsSignal signal = new DomainAgeAnalyzer().analyze(
                DnsResolutionRequest.of("fresh.example", "user", "10.0.0.1"),
                factsWithAge("fresh.example", 2));
        assertTrue(signal.strength() > 0.6, "a two-day-old domain should be treated with caution");
    }

    @Test
    void historicalTrustAnalyzerReflectsFides() {
        trustEngine.recordEvent(new com.cognesis.framework.trust.TrustEvent(
                "old.example", com.cognesis.framework.trust.TrustEvent.EventType.POSITIVE, 1.0, "seen"));
        DnsSignal signal = new HistoricalTrustAnalyzer(trustEngine).analyze(
                DnsResolutionRequest.of("old.example", "user", "10.0.0.1"), facts("old.example"));
        assertTrue(signal.strength() < 0.5, "trusted domain should reduce the risk signal");
    }

    private DnsFacts facts(String domain) {
        return new DnsFacts(domain, 300, true, 1, 0, 0.02,
                List.of("www"), "disabled", Instant.now().minusSeconds(86400 * 30),
                3, true, 0);
    }

    private DnsFacts factsWithAge(String domain, long ageDays) {
        return new DnsFacts(domain, ageDays, false, 1, 1, 0.3,
                List.of(), "enabled", Instant.now().minusSeconds(86400),
                1, false, 0);
    }
}
