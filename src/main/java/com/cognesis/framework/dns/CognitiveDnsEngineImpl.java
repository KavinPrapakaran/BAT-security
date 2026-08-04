package com.cognesis.framework.dns;

import com.cognesis.framework.acde.AcdeEngine;
import com.cognesis.framework.acde.DecisionRequest;
import com.cognesis.framework.common.DecisionResult;
import com.cognesis.framework.common.ReasoningStep;
import com.cognesis.framework.observatory.EvidenceFragment;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * CODE - Cognitive DNS Engine. This is a DNS evidence module: it runs the DNS
 * senses (the 15 analyzers), converts them into normalized evidence fragments,
 * and delegates the actual decision to the ACDE. CODE no longer decides - it
 * sees, the ACDE decides.
 */
public class CognitiveDnsEngineImpl implements CognitiveDnsEngine {

    private static final Logger log = LoggerFactory.getLogger(CognitiveDnsEngineImpl.class);

    private final DnsFactsRepository factsRepository;
    private final List<DnsSignalAnalyzer> analyzers;
    private final AcdeEngine acde;

    public CognitiveDnsEngineImpl(DnsFactsRepository factsRepository,
                                  List<DnsSignalAnalyzer> analyzers,
                                  AcdeEngine acde) {
        this.factsRepository = factsRepository;
        this.analyzers = analyzers != null ? List.copyOf(analyzers) : List.of();
        this.acde = acde;
    }

    @Override
    public DnsDecision evaluate(DnsResolutionRequest request) {
        long start = System.nanoTime();

        DnsFacts facts = factsRepository.factsFor(request.domain());

        // 1. Senses: every analyzer emits one signal, converted to evidence.
        List<DnsSignal> signals = analyzers.stream()
                .map(a -> a.analyze(request, facts))
                .toList();
        List<EvidenceFragment> fragments = signals.stream()
                .map(s -> new EvidenceFragment(request.domain(), "DOMAIN", s.type(),
                        s.strength(), s.confidence(), s.explanation(), s.provenance(), Instant.now()))
                .toList();
        List<ReasoningStep> dnsSteps = signals.stream()
                .map(s -> new ReasoningStep("CODE:" + s.type().name(), s.explanation(),
                        s.strength(), s.confidence(), s.explanation()))
                .toList();

        // 2. Delegate the decision to the ACDE (the single decision-maker).
        Map<String, Object> context = new HashMap<>();
        context.put("sourceIp", request.sourceIp());
        context.put("deviation.feature", "subdomain_count");
        context.put("deviation.observed", facts.subdomains().size());

        DecisionRequest decisionRequest = new DecisionRequest(
                request.domain(), "DOMAIN", request.requestingUser(),
                List.of(), "dns-resolution", context);

        DecisionResult result = acde.evaluate(decisionRequest, fragments, dnsSteps);

        long elapsedMs = (System.nanoTime() - start) / 1_000_000;
        log.info("CODE verdict for {}: {} in {}ms (risk={})",
                request.domain(), result.decision(), elapsedMs,
                String.format("%.2f", result.riskScore()));
        return DnsDecision.from(result);
    }
}
