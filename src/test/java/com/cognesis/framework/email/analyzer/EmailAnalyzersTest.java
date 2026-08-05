package com.cognesis.framework.email.analyzer;

import com.cognesis.framework.email.EmailEvaluationRequest;
import com.cognesis.framework.email.EmailFacts;
import com.cognesis.framework.email.EmailSignal;
import com.cognesis.framework.policy.InMemoryPolicyEvaluator;
import com.cognesis.framework.policy.PolicyEvaluator;
import com.cognesis.framework.policy.PolicyRule;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EmailAnalyzersTest {

    private final EmailEvaluationRequest request = EmailEvaluationRequest.of("msg-x", "alice@corp.example.com");

    @Test
    void authAnalyzerStronglyFlagsDoubleFailure() {
        EmailSignal signal = new EmailAuthAnalyzer().analyze(request,
                new EmailFacts("m", "a@evil.example", "evil.example", 5,
                        "fail", "fail", "none", false, false, 0, 0, false, false, 0));
        assertTrue(signal.strength() >= 0.85, "two failed mechanisms should be near-flagged");
    }

    @Test
    void authAnalyzerPassesAuthenticatedMail() {
        EmailSignal signal = new EmailAuthAnalyzer().analyze(request,
                new EmailFacts("m", "b@paypal.com", "paypal.com", 7000,
                        "pass", "pass", "pass", false, false, 0, 0, false, false, 0));
        assertTrue(signal.strength() < 0.3, "authenticated mail should be a weak signal");
    }

    @Test
    void authAnalyzerSkipsInternalSender() {
        EmailSignal signal = new EmailAuthAnalyzer().analyze(request,
                new EmailFacts("m", "hr@corp.example.com", "corp.example.com", 5000,
                        "fail", "fail", "fail", false, false, 0, 0, false, true, 0));
        assertTrue(signal.strength() < 0.2, "internal mail does not require external authentication");
    }

    @Test
    void senderAgeFlagsBrandNewDomain() {
        EmailSignal signal = new SenderDomainAgeAnalyzer().analyze(request,
                new EmailFacts("m", "a@fresh.example", "fresh.example", 2,
                        "none", "none", "none", false, false, 0, 0, false, false, 0));
        assertTrue(signal.strength() > 0.6, "a two-day-old sender domain should be risky");
    }

    @Test
    void senderAgeAllowsEstablishedDomain() {
        EmailSignal signal = new SenderDomainAgeAnalyzer().analyze(request,
                new EmailFacts("m", "b@paypal.com", "paypal.com", 7000,
                        "pass", "pass", "pass", false, false, 0, 0, false, false, 0));
        assertTrue(signal.strength() < 0.3, "an established sender domain should be low risk");
    }

    @Test
    void spoofingFlagsLookalikeAndReplyToMismatch() {
        EmailSignal signal = new SpoofingAnalyzer().analyze(request,
                new EmailFacts("m", "ceo@paypa1-secure.com", "paypa1-secure.com", 4,
                        "fail", "none", "none", true, true, 0, 0, false, false, 0));
        assertTrue(signal.strength() >= 0.85, "reply-to mismatch plus lookalike should be strong");
    }

    @Test
    void spoofingPassesCleanMail() {
        EmailSignal signal = new SpoofingAnalyzer().analyze(request,
                new EmailFacts("m", "b@paypal.com", "paypal.com", 7000,
                        "pass", "pass", "pass", false, false, 0, 0, false, false, 0));
        assertTrue(signal.strength() < 0.2, "clean mail has no spoofing indicators");
    }

    @Test
    void linkAnalyzerFlagsSuspiciousUrls() {
        EmailSignal signal = new LinkAnalyzer().analyze(request,
                new EmailFacts("m", "a@evil.example", "evil.example", 5,
                        "fail", "fail", "none", false, false, 2, 0, false, false, 0));
        assertTrue(signal.strength() >= 0.6, "suspicious URLs should be flagged");
    }

    @Test
    void attachmentAnalyzerFlagsRareAttachment() {
        EmailSignal signal = new AttachmentAnalyzer().analyze(request,
                new EmailFacts("m", "a@evil.example", "evil.example", 5,
                        "fail", "fail", "none", false, false, 0, 1, true, false, 0));
        assertTrue(signal.strength() >= 0.7, "a never-seen attachment hash should be the strongest payload signal");
    }

    @Test
    void senderReputationScalesWithFlags() {
        EmailSignal first = new SenderReputationAnalyzer().analyze(request,
                new EmailFacts("m", "a@repeat.example", "repeat.example", 60,
                        "fail", "fail", "none", false, false, 0, 0, false, false, 1));
        EmailSignal second = new SenderReputationAnalyzer().analyze(request,
                new EmailFacts("m", "a@repeat.example", "repeat.example", 60,
                        "fail", "fail", "none", false, false, 0, 0, false, false, 3));
        assertTrue(second.strength() > first.strength(), "more prior flags must mean higher risk");
    }

    @Test
    void threatIntelCarriesFeedProvenance() {
        EmailSignal signal = new ThreatIntelEmailAnalyzer().analyze(request,
                new EmailFacts("m", "a@evil.example", "evil.example", 5,
                        "fail", "fail", "none", false, false, 0, 0, false, false, 2));
        assertTrue(signal.strength() >= 0.9, "feed-flagged sender should be near-certain");
        assertEquals(com.cognesis.framework.common.Provenance.THREAT_INTEL_FEED, signal.provenance());
    }

    @Test
    void policyAnalyzerHardBlocksMatchedSender() {
        PolicyEvaluator policy = new InMemoryPolicyEvaluator(List.of(
                new PolicyRule("block", "BLOCK_LIST", "evil.example", "BLOCK", 10)));
        EmailSignal signal = new EmailPolicyAnalyzer(policy).analyze(request,
                new EmailFacts("m", "a@evil.example", "evil.example", 5,
                        "none", "none", "none", false, false, 0, 0, false, false, 0));
        assertEquals(1.0, signal.strength(), 1e-9, "policy block is ground truth");
        assertEquals(1.0, signal.confidence(), 1e-9);
    }
}
