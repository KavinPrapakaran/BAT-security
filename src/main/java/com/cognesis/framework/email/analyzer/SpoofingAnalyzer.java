package com.cognesis.framework.email.analyzer;

import com.cognesis.framework.common.EvidenceType;
import com.cognesis.framework.common.Provenance;
import com.cognesis.framework.email.EmailEvaluationRequest;
import com.cognesis.framework.email.EmailFacts;
import com.cognesis.framework.email.EmailSignal;
import com.cognesis.framework.email.EmailSignalAnalyzer;

/**
 * Spoofing sense: a reply-to that does not match the sender and a sender domain
 * that visually resembles a trusted brand are deliberate social-engineering
 * signals. Either one flags immediately (mirrors the DNS homograph 0.55 floor).
 */
public class SpoofingAnalyzer implements EmailSignalAnalyzer {

    @Override
    public EmailSignal analyze(EmailEvaluationRequest request, EmailFacts facts) {
        double strength = 0.1;
        StringBuilder why = new StringBuilder();
        if (facts.replyToMismatch()) {
            strength += 0.55;
            why.append("reply-to does not match sender; ");
        }
        if (facts.lookalikeDomain()) {
            strength += 0.35;
            why.append("sender domain resembles a trusted brand; ");
        }
        if (why.length() == 0) {
            return new EmailSignal(EvidenceType.EMAIL_SPOOF, 0.1, 0.9,
                    "No spoofing indicators observed", Provenance.EMAIL_GATEWAY);
        }
        return new EmailSignal(EvidenceType.EMAIL_SPOOF, Math.min(1.0, strength), 0.85,
                why.toString().trim(), Provenance.EMAIL_GATEWAY);
    }
}
