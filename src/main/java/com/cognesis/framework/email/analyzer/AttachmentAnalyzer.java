package com.cognesis.framework.email.analyzer;

import com.cognesis.framework.common.EvidenceType;
import com.cognesis.framework.common.Provenance;
import com.cognesis.framework.email.EmailEvaluationRequest;
import com.cognesis.framework.email.EmailFacts;
import com.cognesis.framework.email.EmailSignal;
import com.cognesis.framework.email.EmailSignalAnalyzer;

/**
 * Attachment sense: an attachment hash never seen on this tenant before is the
 * strongest single payload indicator (unknown = unsandboxed = risky). Volume of
 * attachments adds a weaker signal.
 */
public class AttachmentAnalyzer implements EmailSignalAnalyzer {

    @Override
    public EmailSignal analyze(EmailEvaluationRequest request, EmailFacts facts) {
        double strength = 0.1;
        StringBuilder why = new StringBuilder();
        if (facts.rareAttachment()) {
            strength = 0.75;
            why.append("attachment hash not seen before on this tenant; ");
        } else if (facts.attachmentCount() > 3) {
            strength = 0.45;
            why.append(facts.attachmentCount() + " attachments in a single message; ");
        }
        if (why.length() == 0) {
            return new EmailSignal(EvidenceType.EMAIL_ATTACHMENTS, 0.1, 0.9,
                    "No attachment risk indicators", Provenance.EMAIL_GATEWAY);
        }
        return new EmailSignal(EvidenceType.EMAIL_ATTACHMENTS, strength, 0.8,
                why.toString().trim(), Provenance.EMAIL_GATEWAY);
    }
}
