package com.cognesis.framework.email.analyzer;

import com.cognesis.framework.common.EvidenceType;
import com.cognesis.framework.common.Provenance;
import com.cognesis.framework.email.EmailEvaluationRequest;
import com.cognesis.framework.email.EmailFacts;
import com.cognesis.framework.email.EmailSignal;
import com.cognesis.framework.email.EmailSignalAnalyzer;

/**
 * Sender-domain age sense: legitimate brands age their domains for years, so a
 * brand-new sender domain carrying authentication failures is the classic
 * phishing signature. Mirrors the DNS DomainAge analyzer with a 30-day cutoff.
 */
public class SenderDomainAgeAnalyzer implements EmailSignalAnalyzer {

    private static final long YOUNG_THRESHOLD_DAYS = 30;

    @Override
    public EmailSignal analyze(EmailEvaluationRequest request, EmailFacts facts) {
        long age = facts.senderDomainAgeDays();
        if (age < YOUNG_THRESHOLD_DAYS) {
            double strength = Math.min(1.0, 0.5 + (YOUNG_THRESHOLD_DAYS - age) / 60.0);
            return new EmailSignal(EvidenceType.EMAIL_SENDER_AGE, strength, 0.8,
                    "Sender domain registered " + age + " days ago (young)", Provenance.EMAIL_GATEWAY);
        }
        if (age < 90) {
            return new EmailSignal(EvidenceType.EMAIL_SENDER_AGE, 0.3, 0.7,
                    "Sender domain registered " + age + " days ago (recent)", Provenance.EMAIL_GATEWAY);
        }
        return new EmailSignal(EvidenceType.EMAIL_SENDER_AGE, 0.1, 0.9,
                "Sender domain age " + age + " days (established)", Provenance.EMAIL_GATEWAY);
    }
}
