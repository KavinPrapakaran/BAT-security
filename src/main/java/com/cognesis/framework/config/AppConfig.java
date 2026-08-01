package com.cognesis.framework.config;

import com.cognesis.framework.algorithm.SynapseEngine;
import com.cognesis.framework.algorithm.SynapseWeights;
import com.cognesis.framework.dns.CognitiveDnsEngine;
import com.cognesis.framework.dns.CognitiveDnsEngineImpl;
import com.cognesis.framework.dns.DnsFactsRepository;
import com.cognesis.framework.dns.DnsSignalAnalyzer;
import com.cognesis.framework.dns.InMemoryDnsFactsRepository;
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
import com.cognesis.framework.dns.analyzer.ThreatMemoryAnalyzer;
import com.cognesis.framework.dns.analyzer.TyposquattingAnalyzer;
import com.cognesis.framework.dns.analyzer.UserBehaviourAnalyzer;
import com.cognesis.framework.dns.analyzer.WhoisAnalyzer;
import com.cognesis.framework.impact.AssetRegistry;
import com.cognesis.framework.impact.ImpactEngine;
import com.cognesis.framework.impact.InMemoryAssetRegistry;
import com.cognesis.framework.impact.ResolveImpactEngine;
import com.cognesis.framework.intent.IntentEngine;
import com.cognesis.framework.intent.MotiveIntentEngine;
import com.cognesis.framework.learning.InMemoryWeightStore;
import com.cognesis.framework.learning.LoreLearningEngine;
import com.cognesis.framework.learning.WeightStore;
import com.cognesis.framework.memory.MemoryEngine;
import com.cognesis.framework.memory.MnemonicMemoryEngine;
import com.cognesis.framework.observatory.DnsEvidenceProvider;
import com.cognesis.framework.observatory.EvidenceIngestor;
import com.cognesis.framework.observatory.EvidenceProvider;
import com.cognesis.framework.orchestrator.DecisionOrchestrator;
import com.cognesis.framework.persistence.DecisionLogDao;
import com.cognesis.framework.persistence.JdbcDecisionLogDao;
import com.cognesis.framework.persistence.JdbcTrustProfileStore;
import com.cognesis.framework.persistence.TrustProfileStore;
import com.cognesis.framework.policy.InMemoryPolicyEvaluator;
import com.cognesis.framework.policy.PolicyEvaluator;
import com.cognesis.framework.policy.PolicyRule;
import com.cognesis.framework.prediction.PredictionEngine;
import com.cognesis.framework.prediction.SeerPredictionEngine;
import com.cognesis.framework.recommend.PactRecommendationEngine;
import com.cognesis.framework.recommend.RecommendationEngine;
import com.cognesis.framework.trust.FidesTrustEngine;
import com.cognesis.framework.trust.TrustEngine;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.util.List;

/**
 * Spring wiring for the COGNESIS scaffold. Every engine is declared here as a
 * bean; production deployments can override individual beans without touching
 * the engine implementations (dependency inversion in action).
 */
@Configuration
@EnableConfigurationProperties(CognesisProperties.class)
public class AppConfig {

    // ------------------------------------------------------------------
    // Core algorithm
    // ------------------------------------------------------------------

    @Bean
    public SynapseEngine synapseEngine(CognesisProperties props) {
        return new SynapseEngine(props.getAlgorithm().toBandPolicy());
    }

    @Bean
    public WeightStore weightStore(CognesisProperties props) {
        return new InMemoryWeightStore(props.getDns().toSynapseWeights());
    }

    // ------------------------------------------------------------------
    // Reasoning engines
    // ------------------------------------------------------------------

    @Bean
    public TrustEngine trustEngine(CognesisProperties props, TrustProfileStore trustProfileStore) {
        return new FidesTrustEngine(props.getTrust().toProperties(), trustProfileStore);
    }

    @Bean
    public MemoryEngine memoryEngine(CognesisProperties props) {
        return new MnemonicMemoryEngine(props.getMemory().getActivationDecay(), props.getMemory().getRecallLimit());
    }

    @Bean
    public PredictionEngine predictionEngine() {
        return new SeerPredictionEngine();
    }

    @Bean
    public IntentEngine intentEngine() {
        return new MotiveIntentEngine();
    }

    @Bean
    public ImpactEngine impactEngine(AssetRegistry assetRegistry) {
        return new ResolveImpactEngine(assetRegistry);
    }

    @Bean
    public RecommendationEngine recommendationEngine() {
        return new PactRecommendationEngine();
    }

    // ------------------------------------------------------------------
    // Policy & assets
    // ------------------------------------------------------------------

    @Bean
    public PolicyEvaluator policyEvaluator() {
        return new InMemoryPolicyEvaluator(List.of(
                new PolicyRule("Block known malware domains", "BLOCK_LIST", "example-malware.test", "BLOCK", 10),
                new PolicyRule("Block phishing category", "DENY_CATEGORY", "phishing", "BLOCK", 20),
                new PolicyRule("Allow corporate zone", "ALLOW_LIST", "corp.example.com", "ALLOW", 5)));
    }

    @Bean
    public AssetRegistry assetRegistry() {
        return new InMemoryAssetRegistry();
    }

    // ------------------------------------------------------------------
    // Observatory
    // ------------------------------------------------------------------

    @Bean
    public DnsFactsRepository dnsFactsRepository() {
        return new InMemoryDnsFactsRepository();
    }

    @Bean
    public EvidenceIngestor evidenceIngestor() {
        return new EvidenceIngestor();
    }

    @Bean
    public EvidenceProvider dnsEvidenceProvider(DnsFactsRepository dnsFactsRepository) {
        return new DnsEvidenceProvider(dnsFactsRepository);
    }

    // ------------------------------------------------------------------
    // Cognitive DNS Engine
    // ------------------------------------------------------------------

    @Bean
    public List<DnsSignalAnalyzer> dnsSignalAnalyzers(TrustEngine trustEngine,
                                                      MemoryEngine memoryEngine,
                                                      PolicyEvaluator policyEvaluator) {
        return List.of(
                new DomainAgeAnalyzer(),
                new DgaAnalyzer(),
                new HomographAnalyzer(),
                new TyposquattingAnalyzer(),
                new FastFluxAnalyzer(),
                new DnssecAnalyzer(),
                new RegistrarHistoryAnalyzer(),
                new WhoisAnalyzer(),
                new CertificateTransparencyAnalyzer(),
                new SubdomainBehaviourAnalyzer(),
                new HistoricalTrustAnalyzer(trustEngine),
                new PolicyAnalyzer(policyEvaluator),
                new ThreatMemoryAnalyzer(memoryEngine),
                new UserBehaviourAnalyzer(trustEngine),
                new NetworkBehaviourAnalyzer(trustEngine));
    }

    @Bean
    public CognitiveDnsEngine cognitiveDnsEngine(DnsFactsRepository dnsFactsRepository,
                                                 List<DnsSignalAnalyzer> dnsSignalAnalyzers,
                                                 TrustEngine trustEngine,
                                                 MemoryEngine memoryEngine,
                                                 PredictionEngine predictionEngine,
                                                 IntentEngine intentEngine,
                                                 ImpactEngine impactEngine,
                                                 RecommendationEngine recommendationEngine,
                                                 SynapseEngine synapseEngine,
                                                 WeightStore weightStore,
                                                 EvidenceIngestor evidenceIngestor,
                                                 DecisionLogDao decisionLogDao,
                                                 PolicyEvaluator policyEvaluator) {
        return new CognitiveDnsEngineImpl(dnsFactsRepository, dnsSignalAnalyzers, trustEngine,
                memoryEngine, predictionEngine, intentEngine, impactEngine, recommendationEngine,
                synapseEngine, weightStore, evidenceIngestor, decisionLogDao, policyEvaluator);
    }

    // ------------------------------------------------------------------
    // Orchestrator
    // ------------------------------------------------------------------

    @Bean
    public DecisionOrchestrator decisionOrchestrator(List<EvidenceProvider> evidenceProviders,
                                                     EvidenceIngestor evidenceIngestor,
                                                     TrustEngine trustEngine,
                                                     MemoryEngine memoryEngine,
                                                     PredictionEngine predictionEngine,
                                                     IntentEngine intentEngine,
                                                     ImpactEngine impactEngine,
                                                     RecommendationEngine recommendationEngine,
                                                     SynapseEngine synapseEngine,
                                                     WeightStore weightStore,
                                                     DecisionLogDao decisionLogDao) {
        return new DecisionOrchestrator(evidenceProviders, evidenceIngestor, trustEngine, memoryEngine,
                predictionEngine, intentEngine, impactEngine, recommendationEngine, synapseEngine,
                weightStore, decisionLogDao);
    }

    @Bean
    public LoreLearningEngine loreLearningEngine(WeightStore weightStore) {
        return new LoreLearningEngine(weightStore);
    }

    // ------------------------------------------------------------------
    // Persistence
    // ------------------------------------------------------------------

    @Bean
    public TrustProfileStore trustProfileStore(JdbcTemplate jdbcTemplate) {
        return new JdbcTrustProfileStore(jdbcTemplate);
    }

    @Bean
    public DecisionLogDao decisionLogDao(NamedParameterJdbcTemplate jdbcTemplate, ObjectMapper objectMapper) {
        return new JdbcDecisionLogDao(jdbcTemplate, objectMapper);
    }
}
