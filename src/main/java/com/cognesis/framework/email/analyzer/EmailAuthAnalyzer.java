package com.cognesis.framework.email.analyzer;

import com.cognesis.framework.common.EvidenceType;
import com.cognesis.framework.common.Provenance;
import com.cognesis.framework.email.EmailEvaluationRequest;
import com.cognesis.framework.email.EmailFacts;
import com.cognesis.framework.email.EmailSignal;
import com.cognesis.framework.email.EmailSignalAnalyzer;

/**
 * Email authentication sense: SPF, DKIM and DMARC are the sender-identity
 * proof that a message is not spoofed. Each failed or missing check adds risk;
 * a message that passes all three is treated as authenticated.
 */
public class EmailAuthAnalyzer implements EmailSignalAnalyzer {

    @Override
    public EmailSignal analyze(EmailEvaluationRequest request, EmailFacts facts) {
        if (facts.internalSender()) {
            return new EmailSignal(EvidenceType.EMAIL_AUTH, 0.1, 0.9,
                    "Internal sender; SPF/DKIM/DMARC not required", Provenance.EMAIL_GATEWAY);
        }
        int failures = 0;
        int checked = 0;
        for (String result : new String[]{facts.spfResult(), facts.dkimResult(), facts.dmarcResult()}) {
            if (result == null) {
                continue;
            }
            checked++;
            if ("fail".equalsIgnoreCase(result) || "quarantine".equalsIgnoreCase(result)) {
                failures++;
            }
        }
        double strength;
        String explanation;
        if (failures >= 2) {
            strength = 0.9;
            explanation = "SPF/DKIM/DMARC failed on " + failures + " of " + checked + " checks";
        } else if (failures == 1) {
            strength = 0.65;
            explanation = "SPF/DKIM/DMARC failed on 1 of " + checked + " checks";
        } else if (checked > 0 && "pass".equalsIgnoreCase(facts.spfResult())
                && "pass".equalsIgnoreCase(facts.dkimResult())
                && "pass".equalsIgnoreCase(facts.dmarcResult())) {
            strength = 0.1;
            explanation = "SPF, DKIM and DMARC all pass";
        } else {
            strength = 0.35;
            explanation = "Email authentication absent or incomplete (checked " + checked + " mechanisms)";
        }
        return new EmailSignal(EvidenceType.EMAIL_AUTH, strength, 0.85, explanation, Provenance.EMAIL_GATEWAY);
    }
}
