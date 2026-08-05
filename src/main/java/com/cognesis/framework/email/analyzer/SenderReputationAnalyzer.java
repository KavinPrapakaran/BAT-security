package com.cognesis.framework.email.analyzer;

import com.cognesis.framework.common.EvidenceType;
import com.cognesis.framework.common.Provenance;
import com.cognesis.framework.email.EmailEvaluationRequest;
import com.cognesis.framework.email.EmailFacts;
import com.cognesis.framework.email.EmailSignal;
import com.cognesis.framework.email.EmailSignalAnalyzer;

/**
 * Sender-reputation sense: how many times this sender domain was previously
 * flagged by the framework. Escalates geometrically with repeat offence,
 * carrying over threat memory into the email decision.
 */
public class SenderReputationAnalyzer implements EmailSignalAnalyzer {

    @Override
    public EmailSignal analyze(EmailEvaluationRequest request, EmailFacts facts) {
        int flags = facts.maliciousFlagCount();
        if (flags > 0) {
            double strength = Math.min(1.0, 0.35 + flags * 0.2);
            return new EmailSignal(EvidenceType.EMAIL_SENDER_REP, strength, 0.75,
                    "Sender domain previously flagged " + flags + " time(s)", Provenance.EMAIL_GATEWAY);
        }
        return new EmailSignal(EvidenceType.EMAIL_SENDER_REP, 0.1, 0.8,
                "Sender domain has no prior flags", Provenance.EMAIL_GATEWAY);
    }
}
