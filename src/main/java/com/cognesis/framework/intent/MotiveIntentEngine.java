package com.cognesis.framework.intent;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Default MOTIVE implementation. Maps observed evidence families to intent
 * categories with base probabilities, then combines them as independent
 * hypotheses:
 * <pre>
 *   P(any adversarial intent) = 1 - prod(1 - p_i)
 * </pre>
 * The primary intent is the category with the highest fused probability.
 * The mappings below are curated for the DNS engine scaffold and are meant to
 * be extended per evidence family (Cloud, Identity, Email, ...) via the same
 * contract.
 */
public class MotiveIntentEngine implements IntentEngine {

    private final Map<String, Map<String, Double>> evidenceToIntent;

    public MotiveIntentEngine() {
        evidenceToIntent = new LinkedHashMap<>();
        evidenceToIntent.put("DNS_DGA", Map.of("MALWARE_COMMS", 0.70, "EVASION", 0.30));
        evidenceToIntent.put("DNS_FAST_FLUX", Map.of("C2", 0.80, "ABUSE", 0.20));
        evidenceToIntent.put("DNS_TYPOSQUATTING", Map.of("PHISHING", 0.85, "MALWARE_COMMS", 0.15));
        evidenceToIntent.put("DNS_HOMOGRAPH", Map.of("PHISHING", 0.85, "MALWARE_COMMS", 0.15));
        evidenceToIntent.put("DNS_CERTIFICATE", Map.of("C2", 0.40, "ABUSE", 0.40, "MALWARE_COMMS", 0.20));
        evidenceToIntent.put("THREAT_MEMORY", Map.of("RECON", 0.25, "C2", 0.45, "ABUSE", 0.30));
        evidenceToIntent.put("DNS_SUBDOMAIN_BEHAVIOUR", Map.of("EVASION", 0.60, "MALWARE_COMMS", 0.40));
        evidenceToIntent.put("USER_BEHAVIOUR", Map.of("PHISHING", 0.40, "RECON", 0.60));
        evidenceToIntent.put("NETWORK_BEHAVIOUR", Map.of("RECON", 0.50, "SCANNING", 0.50));
    }

    @Override
    public IntentAssessment assess(IntentContext context) {
        Map<String, Double> fused = new LinkedHashMap<>();
        for (String evidence : context.evidenceTypes()) {
            Map<String, Double> contribution = evidenceToIntent.getOrDefault(evidence, Map.of());
            for (Map.Entry<String, Double> e : contribution.entrySet()) {
                fused.merge(e.getKey(), e.getValue(), MotiveIntentEngine::independentOr);
            }
        }
        double any = 1.0;
        for (double p : fused.values()) {
            any *= (1.0 - Math.max(0.0, Math.min(1.0, p)));
        }
        double intentProbability = Math.max(0.0, Math.min(1.0, 1.0 - any));

        String primary = fused.entrySet().stream()
                .max(Map.Entry.comparingByValue())
                .map(Map.Entry::getKey)
                .orElse("UNKNOWN");

        return new IntentAssessment(intentProbability, primary, fused);
    }

    /** p OR q = 1 - (1-p)(1-q). */
    private static double independentOr(double a, double b) {
        return 1.0 - (1.0 - a) * (1.0 - b);
    }
}
