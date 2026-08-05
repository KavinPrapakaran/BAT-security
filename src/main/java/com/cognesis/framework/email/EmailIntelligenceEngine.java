package com.cognesis.framework.email;

/**
 * VOID - the email intelligence engine. It does not simply scan mail; it
 * reasons about every inbound message, fusing email-specific senses (SPF/DKIM/
 * DMARC, sender age, spoofing, links, attachments, reputation) through the
 * SYNAPSE decision algorithm and returning an explainable verdict. It is the
 * second domain engine: proof that the decision core is drop-in replaceable
 * across domains.
 */
public interface EmailIntelligenceEngine {

    /** Evaluate one inbound message and return an explainable decision. */
    EmailDecision evaluate(EmailEvaluationRequest request);
}
