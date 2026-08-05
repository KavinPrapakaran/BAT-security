package com.cognesis.framework.benchmark;

import com.cognesis.framework.acde.AcdeEngine;
import com.cognesis.framework.actg.ActgGraph;
import com.cognesis.framework.actg.SecurityKnowledgeGraph;
import com.cognesis.framework.algorithm.DecisionBandPolicy;
import com.cognesis.framework.algorithm.SynapseEngine;
import com.cognesis.framework.algorithm.SynapseWeights;
import com.cognesis.framework.context.SituationalContextEngine;
import com.cognesis.framework.dns.DnsIntelligenceEngine;
import com.cognesis.framework.dns.DnsIntelligenceEngineImpl;
import com.cognesis.framework.dns.DnsResolutionRequest;
import com.cognesis.framework.dns.DnsSignalAnalyzer;
import com.cognesis.framework.dns.InMemoryDnsFactsRepository;
import com.cognesis.framework.dns.analyzer.ActgAnalyzer;
import com.cognesis.framework.dns.analyzer.CertificateTransparencyAnalyzer;
import com.cognesis.framework.dns.analyzer.DgaAnalyzer;
import com.cognesis.framework.dns.analyzer.DnssecAnalyzer;
import com.cognesis.framework.dns.analyzer.DomainAgeAnalyzer;
import com.cognesis.framework.dns.analyzer.FastFluxAnalyzer;
import com.cognesis.framework.dns.analyzer.HistoricalTrustAnalyzer;
import com.cognesis.framework.dns.analyzer.HomographAnalyzer;
import com.cognesis.framework.dns.analyzer.NetworkBehaviourAnalyzer;
import com.cognesis.framework.dns.analyzer.PolicyAnalyzer;
import com.cognesis.framework.dns.analyzer.RegistrarHistoryAnalyzer;
import com.cognesis.framework.dns.analyzer.SubdomainBehaviourAnalyzer;
import com.cognesis.framework.dns.analyzer.ThreatIntelAnalyzer;
import com.cognesis.framework.dns.analyzer.ThreatMemoryAnalyzer;
import com.cognesis.framework.dns.analyzer.TyposquattingAnalyzer;
import com.cognesis.framework.dns.analyzer.UserBehaviourAnalyzer;
import com.cognesis.framework.dns.analyzer.WhoisAnalyzer;
import com.cognesis.framework.email.EmailEvaluationRequest;
import com.cognesis.framework.email.EmailIntelligenceEngine;
import com.cognesis.framework.email.EmailIntelligenceEngineImpl;
import com.cognesis.framework.email.EmailSignalAnalyzer;
import com.cognesis.framework.email.InMemoryEmailFactsRepository;
import com.cognesis.framework.email.analyzer.AttachmentAnalyzer;
import com.cognesis.framework.email.analyzer.EmailAuthAnalyzer;
import com.cognesis.framework.email.analyzer.EmailPolicyAnalyzer;
import com.cognesis.framework.email.analyzer.LinkAnalyzer;
import com.cognesis.framework.email.analyzer.SenderDomainAgeAnalyzer;
import com.cognesis.framework.email.analyzer.SenderReputationAnalyzer;
import com.cognesis.framework.email.analyzer.SpoofingAnalyzer;
import com.cognesis.framework.email.analyzer.ThreatIntelEmailAnalyzer;
import com.cognesis.framework.impact.InMemoryAssetRegistry;
import com.cognesis.framework.impact.ResolveImpactEngine;
import com.cognesis.framework.intent.MotiveIntentEngine;
import com.cognesis.framework.learning.InMemoryWeightStore;
import com.cognesis.framework.memory.MemoryEngine;
import com.cognesis.framework.memory.MnemonicMemoryEngine;
import com.cognesis.framework.observatory.EvidenceIngestor;
import com.cognesis.framework.persistence.DecisionLogDao;
import com.cognesis.framework.policy.InMemoryPolicyEvaluator;
import com.cognesis.framework.policy.PolicyEvaluator;
import com.cognesis.framework.policy.PolicyRule;
import com.cognesis.framework.prediction.SeerPredictionEngine;
import com.cognesis.framework.recommend.PactRecommendationEngine;
import com.cognesis.framework.trust.FidesTrustEngine;
import com.cognesis.framework.trust.TrustEngine;
import com.cognesis.framework.trust.TrustEvent;
import com.cognesis.framework.trust.TrustProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The calibration benchmark: labeled attack/benign scenarios are scored by both
 * domain engines and the resulting predictions are checked for calibration
 * (Brier score, bin error) and separation against a no-information baseline.
 * This is the proof that the decision core is calibrated, not just plausible.
 */
class DecisionBenchmarkTest {

    private DnsIntelligenceEngine dnsEngine;
    private EmailIntelligenceEngine emailEngine;

    @BeforeEach
    void setUp() {
        TrustEngine trustEngine = new FidesTrustEngine(TrustProperties.defaults());
        MemoryEngine memoryEngine = new MnemonicMemoryEngine(0.02, 20);
        for (String domain : List.of("google.com", "corp.example.com", "amazon.com", "paypal.com",
                "corp.example.com")) {
            for (int i = 0; i < 30; i++) {
                trustEngine.recordEvent(new TrustEvent(domain, TrustEvent.EventType.POSITIVE, 0.9, "steady history"));
            }
        }

        PolicyEvaluator policy = new InMemoryPolicyEvaluator(List.of(
                new PolicyRule("malware blocklist", "BLOCK_LIST", "example-malware.test", "BLOCK", 10)));

        ActgGraph actgGraph = new SecurityKnowledgeGraph();

        AcdeEngine acde = new AcdeEngine(
                List.of(), new EvidenceIngestor(), trustEngine, memoryEngine,
                new SituationalContextEngine(), new SeerPredictionEngine(), new MotiveIntentEngine(),
                new ResolveImpactEngine(new InMemoryAssetRegistry()), new PactRecommendationEngine(),
                new SynapseEngine(DecisionBandPolicy.defaults()),
                new InMemoryWeightStore(SynapseWeights.defaults()),
                new DecisionLogDao() {
                }, policy);

        List<DnsSignalAnalyzer> dnsAnalyzers = List.of(
                new DomainAgeAnalyzer(), new DgaAnalyzer(), new HomographAnalyzer(),
                new TyposquattingAnalyzer(), new FastFluxAnalyzer(), new DnssecAnalyzer(),
                new RegistrarHistoryAnalyzer(), new WhoisAnalyzer(), new CertificateTransparencyAnalyzer(),
                new SubdomainBehaviourAnalyzer(), new HistoricalTrustAnalyzer(trustEngine),
                new PolicyAnalyzer(policy), new ThreatMemoryAnalyzer(memoryEngine),
                new ThreatIntelAnalyzer(), new UserBehaviourAnalyzer(trustEngine),
                new NetworkBehaviourAnalyzer(trustEngine), new ActgAnalyzer(actgGraph));

        dnsEngine = new DnsIntelligenceEngineImpl(new InMemoryDnsFactsRepository(), dnsAnalyzers,
                acde, actgGraph, null);

        List<EmailSignalAnalyzer> emailAnalyzers = List.of(
                new EmailAuthAnalyzer(), new SenderDomainAgeAnalyzer(), new SpoofingAnalyzer(),
                new LinkAnalyzer(), new AttachmentAnalyzer(), new SenderReputationAnalyzer(),
                new ThreatIntelEmailAnalyzer(), new EmailPolicyAnalyzer(policy));

        emailEngine = new EmailIntelligenceEngineImpl(new InMemoryEmailFactsRepository(),
                emailAnalyzers, acde);
    }

    @Test
    void dnsEngineIsCalibratedAndSeparates() {
        Map<String, Double> cases = new LinkedHashMap<>();
        cases.put("google.com", 0.0);
        cases.put("corp.example.com", 0.0);
        cases.put("amazon.com", 0.0);
        cases.put("paypal.com", 0.0);
        cases.put("paypa1.com", 1.0);
        cases.put("xn--amazon-3hb.com", 1.0);
        cases.put("tkqzvbxkadnpqws.example", 1.0);
        cases.put("example-malware.test", 1.0);

        BenchmarkReport report = DecisionBenchmark.run(cases,
                d -> dnsEngine.evaluate(DnsResolutionRequest.of(d, "soc", "10.0.0.1")).outcome());

        assertEquals(8, report.total());
        assertTrue(report.beatsBaseline(), "Brier " + report.brierScore()
                + " must beat base-rate baseline " + report.baselineBrierScore());
        assertTrue(report.separates(), "DNS engine must separate positives from negatives");
        assertTrue(report.brierScore() < 0.20, "DNS Brier score must stay below 0.20");
        assertTrue(report.calibrationError() < 0.30, "DNS bin calibration error must stay bounded");
    }

    @Test
    void emailEngineIsCalibratedAndSeparates() {
        Map<String, Double> cases = new LinkedHashMap<>();
        cases.put("msg-001", 0.0);
        cases.put("msg-003", 0.0);
        cases.put("msg-004", 0.0);
        cases.put("msg-002", 1.0);

        BenchmarkReport report = DecisionBenchmark.run(cases,
                m -> emailEngine.evaluate(EmailEvaluationRequest.of(m, "alice@corp.example.com")).outcome());

        assertEquals(4, report.total());
        assertTrue(report.beatsBaseline(), "Email Brier " + report.brierScore()
                + " must beat base-rate baseline " + report.baselineBrierScore());
        assertTrue(report.separates(), "VOID engine must separate positives from negatives");
        assertTrue(report.brierScore() < 0.20, "VOID Brier score must stay below 0.20");
    }

    @Test
    void bothEnginesScorePositivesAboveNegatives() {
        Map<String, Double> dnsCases = new LinkedHashMap<>();
        dnsCases.put("google.com", 0.0);
        dnsCases.put("paypa1.com", 1.0);
        BenchmarkReport dns = DecisionBenchmark.run(dnsCases,
                d -> dnsEngine.evaluate(DnsResolutionRequest.of(d, "soc", "10.0.0.1")).outcome());

        Map<String, Double> emailCases = new LinkedHashMap<>();
        emailCases.put("msg-001", 0.0);
        emailCases.put("msg-002", 1.0);
        BenchmarkReport email = DecisionBenchmark.run(emailCases,
                m -> emailEngine.evaluate(EmailEvaluationRequest.of(m, "alice@corp.example.com")).outcome());

        assertTrue(dns.meanPredictedPositive() > dns.meanPredictedNegative(),
                "DNS: mean risk for malicious must exceed mean risk for benign");
        assertTrue(email.meanPredictedPositive() > email.meanPredictedNegative(),
                "VOID: mean risk for malicious must exceed mean risk for benign");
    }
}
