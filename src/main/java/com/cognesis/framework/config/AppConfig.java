package com.cognesis.framework.config;

import com.cognesis.framework.acde.AcdeEngine;
import com.cognesis.framework.actg.ActgGraph;
import com.cognesis.framework.actg.SecurityKnowledgeGraph;
import com.cognesis.framework.algorithm.SynapseEngine;
import com.cognesis.framework.algorithm.SynapseWeights;
import com.cognesis.framework.context.ContextEngine;
import com.cognesis.framework.context.SituationalContextEngine;
import com.cognesis.framework.dns.DnsFactsRepository;
import com.cognesis.framework.dns.DnsIntelligenceEngine;
import com.cognesis.framework.dns.DnsIntelligenceEngineImpl;
import com.cognesis.framework.dns.DnsSignalAnalyzer;
import com.cognesis.framework.dns.InMemoryDnsFactsRepository;
import com.cognesis.framework.dns.LiveDnsFactsRepository;
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
import com.cognesis.framework.feed.ThreatFeedIngestor;
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
import com.cognesis.framework.metrics.CognesisMetrics;
import com.cognesis.framework.observatory.DnsEvidenceProvider;
import com.cognesis.framework.observatory.EvidenceIngestor;
import com.cognesis.framework.observatory.EvidenceProvider;
import com.cognesis.framework.persistence.DecisionLogDao;
import com.cognesis.framework.persistence.IocStore;
import com.cognesis.framework.persistence.JdbcDecisionLogDao;
import com.cognesis.framework.persistence.JdbcIocStore;
import com.cognesis.framework.persistence.JdbcMemoryGraphDao;
import com.cognesis.framework.persistence.JdbcTrustProfileStore;
import com.cognesis.framework.persistence.MemoryGraphDao;
import com.cognesis.framework.persistence.TrustProfileStore;
import com.cognesis.framework.policy.InMemoryPolicyEvaluator;
import com.cognesis.framework.policy.PolicyEvaluator;
import com.cognesis.framework.policy.PolicyRule;
import com.cognesis.framework.prediction.PredictionEngine;
import com.cognesis.framework.prediction.SeerPredictionEngine;
import com.cognesis.framework.profile.ProfileEvaluationEngine;
import com.cognesis.framework.recommend.PactRecommendationEngine;
import com.cognesis.framework.recommend.RecommendationEngine;
import com.cognesis.framework.trust.FidesTrustEngine;
import com.cognesis.framework.trust.TrustEngine;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.web.client.RestClient;

import javax.sql.DataSource;
import java.util.List;

/**
 * Spring wiring for the BAT security scaffold. Every engine is declared here as a
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
    public ContextEngine contextEngine() {
        return new SituationalContextEngine();
    }

    @Bean
    public RecommendationEngine recommendationEngine() {
        return new PactRecommendationEngine();
    }

    @Bean
    public ActgGraph actgGraph() {
        return new SecurityKnowledgeGraph();
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

    @Bean
    public ProfileEvaluationEngine profileEvaluationEngine() {
        return ProfileEvaluationEngine.withDefaults();
    }

    // ------------------------------------------------------------------
    // Observatory
    // ------------------------------------------------------------------

    @Bean
    public IocStore iocStore(NamedParameterJdbcTemplate jdbcTemplate) {
        return new JdbcIocStore(jdbcTemplate);
    }

    @Bean
    public InMemoryDnsFactsRepository inMemoryDnsFactsRepository(IocStore iocStore) {
        return new InMemoryDnsFactsRepository(iocStore);
    }

    /**
     * Primary DNS facts source. In production (and by default) this is the live
     * repository (DNS-over-HTTPS + RDAP + crt.sh) with the in-memory store as an
     * offline fallback; tests disable live lookups via {@code cognesis.dns.live.enabled}.
     */
    @Bean
    public DnsFactsRepository dnsFactsRepository(CognesisProperties props,
                                                 ObjectMapper objectMapper,
                                                 InMemoryDnsFactsRepository fallback,
                                                 CognesisMetrics metrics) {
        CognesisProperties.Dns.Live live = props.getDns().getLive();
        if (!live.isEnabled()) {
            return fallback;
        }
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(java.time.Duration.ofSeconds(live.getTimeoutSeconds()));
        requestFactory.setReadTimeout(java.time.Duration.ofSeconds(live.getTimeoutSeconds()));
        RestClient restClient = RestClient.builder().requestFactory(requestFactory).build();
        return new LiveDnsFactsRepository(restClient, objectMapper, fallback,
                live.getDohUrl(), live.getDohFallbackUrl(), live.getRdapUrl(), live.getCrtUrl(),
                live.getCacheTtlSeconds(), metrics);
    }

    @Bean
    public EvidenceIngestor evidenceIngestor() {
        return new EvidenceIngestor();
    }

    @Bean
    public ThreatFeedIngestor threatFeedIngestor(CognesisProperties props,
                                                 InMemoryDnsFactsRepository inMemoryDnsFactsRepository,
                                                 CognesisMetrics metrics) {
        CognesisProperties.Feed feed = props.getFeed();
        if (!feed.isEnabled() || feed.getUrl().isBlank()) {
            return new ThreatFeedIngestor(null, inMemoryDnsFactsRepository, "", metrics);
        }
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(java.time.Duration.ofSeconds(feed.getTimeoutSeconds()));
        requestFactory.setReadTimeout(java.time.Duration.ofSeconds(feed.getTimeoutSeconds()));
        RestClient restClient = RestClient.builder().requestFactory(requestFactory).build();
        return new ThreatFeedIngestor(restClient, inMemoryDnsFactsRepository, feed.getUrl(), metrics);
    }

    /**
     * When a feed is configured, refresh it once at startup so live IOCs are
     * available immediately. Guarded by the ingestor itself; never blocks boot.
     */
    @Bean
    public ApplicationRunner threatFeedStartupRefresh(CognesisProperties props,
                                                      ThreatFeedIngestor threatFeedIngestor) {
        return args -> {
            if (props.getFeed().isEnabled() && !props.getFeed().getUrl().isBlank()) {
                threatFeedIngestor.refresh();
            }
        };
    }

    @Bean
    public EvidenceProvider dnsEvidenceProvider(DnsFactsRepository dnsFactsRepository) {
        return new DnsEvidenceProvider(dnsFactsRepository);
    }

    // ------------------------------------------------------------------
    // DNS Intelligence Engine
    // ------------------------------------------------------------------

    @Bean
    public List<DnsSignalAnalyzer> dnsSignalAnalyzers(TrustEngine trustEngine,
                                                      MemoryEngine memoryEngine,
                                                      PolicyEvaluator policyEvaluator,
                                                      ActgGraph actgGraph) {
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
                new ThreatIntelAnalyzer(),
                new UserBehaviourAnalyzer(trustEngine),
                new NetworkBehaviourAnalyzer(trustEngine),
                new ActgAnalyzer(actgGraph));
    }

    @Bean
    public DnsIntelligenceEngine dnsIntelligenceEngine(DnsFactsRepository dnsFactsRepository,
                                                       List<DnsSignalAnalyzer> dnsSignalAnalyzers,
                                                       AcdeEngine acdeEngine,
                                                       ActgGraph actgGraph,
                                                       CognesisMetrics metrics) {
        return new DnsIntelligenceEngineImpl(dnsFactsRepository, dnsSignalAnalyzers, acdeEngine,
                actgGraph, metrics);
    }

    // ------------------------------------------------------------------
    // ACDE - the single decision-maker
    // ------------------------------------------------------------------

    @Bean
    public AcdeEngine acdeEngine(List<EvidenceProvider> evidenceProviders,
                                 EvidenceIngestor evidenceIngestor,
                                 TrustEngine trustEngine,
                                 MemoryEngine memoryEngine,
                                 ContextEngine contextEngine,
                                 PredictionEngine predictionEngine,
                                 IntentEngine intentEngine,
                                 ImpactEngine impactEngine,
                                 RecommendationEngine recommendationEngine,
                                 SynapseEngine synapseEngine,
                                 WeightStore weightStore,
                                 DecisionLogDao decisionLogDao,
                                 PolicyEvaluator policyEvaluator,
                                 ProfileEvaluationEngine profileEvaluationEngine) {
        return new AcdeEngine(evidenceProviders, evidenceIngestor, trustEngine, memoryEngine,
                contextEngine, predictionEngine, intentEngine, impactEngine, recommendationEngine,
                synapseEngine, weightStore, decisionLogDao, policyEvaluator, profileEvaluationEngine);
    }

    @Bean
    public LoreLearningEngine loreLearningEngine(WeightStore weightStore) {
        return new LoreLearningEngine(weightStore);
    }

    // ------------------------------------------------------------------
    // Persistence
    // ------------------------------------------------------------------

    @Bean
    public DataSource dataSource() {
        DriverManagerDataSource ds = new DriverManagerDataSource();
        ds.setUrl("jdbc:h2:mem:cognesis;DB_CLOSE_DELAY=-1;MODE=PostgreSQL");
        ds.setUsername("sa");
        ds.setPassword("");
        ds.setDriverClassName("org.h2.Driver");
        ResourceDatabasePopulator populator = new ResourceDatabasePopulator();
        populator.addScript(new ClassPathResource("db/schema-h2.sql"));
        populator.execute(ds);
        return ds;
    }

    @Bean
    public JdbcTemplate jdbcTemplate(DataSource dataSource) {
        return new JdbcTemplate(dataSource);
    }

    @Bean
    public NamedParameterJdbcTemplate namedParameterJdbcTemplate(DataSource dataSource) {
        return new NamedParameterJdbcTemplate(dataSource);
    }

    @Bean
    public TrustProfileStore trustProfileStore(JdbcTemplate jdbcTemplate) {
        return new JdbcTrustProfileStore(jdbcTemplate);
    }

    @Bean
    public DecisionLogDao decisionLogDao(NamedParameterJdbcTemplate jdbcTemplate, ObjectMapper objectMapper) {
        return new JdbcDecisionLogDao(jdbcTemplate, objectMapper);
    }

    @Bean
    public MemoryGraphDao memoryGraphDao(JdbcTemplate jdbcTemplate, ObjectMapper objectMapper) {
        return new JdbcMemoryGraphDao(jdbcTemplate, objectMapper);
    }
}
