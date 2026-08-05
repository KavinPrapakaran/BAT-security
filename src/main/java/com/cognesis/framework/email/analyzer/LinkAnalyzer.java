package com.cognesis.framework.email.analyzer;

import com.cognesis.framework.common.EvidenceType;
import com.cognesis.framework.common.Provenance;
import com.cognesis.framework.email.EmailEvaluationRequest;
import com.cognesis.framework.email.EmailFacts;
import com.cognesis.framework.email.EmailSignal;
import com.cognesis.framework.email.EmailSignalAnalyzer;

/**
 * Link sense: URLs in the body that failed URL reputation checks are the
 * payload delivery mechanism of phishing and malware campaigns. A single
 * suspicious link is enough to flag; strength grows with the count.
 */
public class LinkAnalyzer implements EmailSignalAnalyzer {

    @Override
    public EmailSignal analyze(EmailEvaluationRequest request, EmailFacts facts) {
        int suspicious = facts.suspiciousLinkCount();
        if (suspicious > 0) {
            double strength = Math.min(1.0, 0.6 + (suspicious - 1) * 0.15);
            return new EmailSignal(EvidenceType.EMAIL_LINKS, strength, 0.8,
                    suspicious + " suspicious link(s) in message body", Provenance.EMAIL_GATEWAY);
        }
        return new EmailSignal(EvidenceType.EMAIL_LINKS, 0.1, 0.9,
                "No suspicious links in message body", Provenance.EMAIL_GATEWAY);
    }
}
