package com.cognesis.framework.email.analyzer;

import com.cognesis.framework.common.EvidenceType;
import com.cognesis.framework.common.Provenance;
import com.cognesis.framework.email.EmailEvaluationRequest;
import com.cognesis.framework.email.EmailFacts;
import com.cognesis.framework.email.EmailSignal;
import com.cognesis.framework.email.EmailSignalAnalyzer;

/**
 * Threat-intel sense: a sender domain previously flagged by a live IOC feed
 * (abuse.ch URLhaus / ThreatFox) is treated as high-risk. Carries the feed
 * provenance so the email decision trail points back to the external source.
 */
public class ThreatIntelEmailAnalyzer implements EmailSignalAnalyzer {

    @Override
    public EmailSignal analyze(EmailEvaluationRequest request, EmailFacts facts) {
        if (facts.maliciousFlagCount() > 0) {
            double strength = Math.min(1.0, 0.55 + facts.maliciousFlagCount() * 0.2);
            return new EmailSignal(EvidenceType.THREAT_INTEL, strength, 0.85,
                    "Sender domain flagged " + facts.maliciousFlagCount() + " time(s) by threat-intel feed",
                    Provenance.THREAT_INTEL_FEED);
        }
        return new EmailSignal(EvidenceType.THREAT_INTEL, 0.1, 0.9,
                "No threat-intel flags for this sender domain",
                Provenance.THREAT_INTEL_FEED);
    }
}
