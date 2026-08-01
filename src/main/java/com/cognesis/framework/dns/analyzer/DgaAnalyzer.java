package com.cognesis.framework.dns.analyzer;

import com.cognesis.framework.common.EvidenceType;
import com.cognesis.framework.common.Provenance;
import com.cognesis.framework.dns.DnsFacts;
import com.cognesis.framework.dns.DnsResolutionRequest;
import com.cognesis.framework.dns.DnsSignal;
import com.cognesis.framework.dns.DnsSignalAnalyzer;

import java.util.Locale;
import java.util.Map;

/**
 * Domain Generation Algorithm (DGA) detection. Malware frequently talks to
 * domains it generates algorithmically; those labels have no meaning, high
 * character entropy, unusual length, low vowel density and unnatural
 * consonant clusters.
 *
 * <pre>
 *   entropy      = Shannon entropy over characters (bits per char)
 *   consRun      = longest run of consecutive consonants (pronounceability proxy)
 *   score = 0.15 * sigmoid((len-12)/4)
 *         + 0.20 * clamp(entropy / 4.5)
 *         + 0.40 * clamp(consRun / 8)
 *         + 0.25 * (1 - clamp(vowelRatio / 0.5))
 * </pre>
 * Consonant-clustering carries the most weight because it best separates
 * machine-generated labels from real words.
 */
public class DgaAnalyzer implements DnsSignalAnalyzer {

    @Override
    public DnsSignal analyze(DnsResolutionRequest request, DnsFacts facts) {
        String label = label(request.domain());
        if (label.isEmpty()) {
            return neutral();
        }

        double entropy = shannonEntropy(label);
        double vowelRatio = vowelRatio(label);
        int length = label.length();
        int consRun = longestConsonantRun(label);

        double score = 0.15 * sigmoid((length - 12.0) / 4.0)
                + 0.20 * Math.min(1.0, entropy / 4.5)
                + 0.40 * Math.min(1.0, consRun / 8.0)
                + 0.25 * (1.0 - Math.min(1.0, vowelRatio / 0.5));

        double confidence = 0.5 + 0.3 * Math.min(1.0, (length - 6.0) / 10.0);
        String explanation = String.format(
                "label '%s': length %d, char entropy %.2f, longest consonant run %d, vowel ratio %.2f -> DGA-like %.2f",
                label, length, entropy, consRun, vowelRatio, score);

        return new DnsSignal(EvidenceType.DNS_DGA, Math.min(1.0, score), confidence,
                explanation, Provenance.DNS_RESPONSE);
    }

    private DnsSignal neutral() {
        return new DnsSignal(EvidenceType.DNS_DGA, 0.2, 0.2, "no resolvable label", Provenance.DNS_RESPONSE);
    }

    private String label(String domain) {
        if (domain == null) {
            return "";
        }
        String d = domain.trim().toLowerCase(Locale.ROOT);
        if (d.startsWith("www.")) {
            d = d.substring(4);
        }
        int dot = d.indexOf('.');
        return dot > 0 ? d.substring(0, dot) : d;
    }

    private double shannonEntropy(String s) {
        Map<Character, Integer> counts = new java.util.HashMap<>();
        for (char c : s.toCharArray()) {
            counts.merge(c, 1, Integer::sum);
        }
        double entropy = 0.0;
        for (int count : counts.values()) {
            double p = (double) count / s.length();
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        return entropy;
    }

    private double vowelRatio(String s) {
        long vowels = s.chars().filter(c -> "aeiouy".indexOf(c) >= 0).count();
        return s.isEmpty() ? 0 : (double) vowels / s.length();
    }

    private int longestConsonantRun(String s) {
        int best = 0;
        int current = 0;
        for (char c : s.toCharArray()) {
            if (Character.isLetter(c) && "aeiouy".indexOf(c) < 0) {
                current++;
                best = Math.max(best, current);
            } else {
                current = 0;
            }
        }
        return best;
    }

    private static double sigmoid(double x) {
        return 1.0 / (1.0 + Math.exp(-x));
    }
}
