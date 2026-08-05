package com.cognesis.framework.email;

import java.util.List;

/**
 * Structured facts about one inbound message, assembled from the email gateway
 * (SPF/DKIM/DMARC headers), sender history and attachment/link heuristics.
 * Analyzers read these facts and convert them into evidence signals. In
 * production these are fed by an email-security gateway; the scaffold ships a
 * sample repository.
 *
 * @param messageId          gateway message identifier
 * @param senderAddress      full sender address (name &lt;addr&gt;)
 * @param senderDomain       sender mail domain
 * @param senderDomainAgeDays age of the sender domain in days
 * @param spfResult          "pass" | "fail" | "softfail" | "neutral" | "none"
 * @param dkimResult         "pass" | "fail" | "none"
 * @param dmarcResult        "pass" | "fail" | "quarantine" | "none"
 * @param replyToMismatch    reply-to header does not match the sender
 * @param lookalikeDomain    sender domain visually spoofs a known brand
 * @param suspiciousLinkCount links that failed URL reputation checks
 * @param attachmentCount    number of attachments
 * @param rareAttachment     an attachment hash never seen on this tenant before
 * @param internalSender     sender is inside the trusted organization domain
 * @param maliciousFlagCount times this sender domain was previously flagged
 */
public record EmailFacts(
        String messageId,
        String senderAddress,
        String senderDomain,
        long senderDomainAgeDays,
        String spfResult,
        String dkimResult,
        String dmarcResult,
        boolean replyToMismatch,
        boolean lookalikeDomain,
        int suspiciousLinkCount,
        int attachmentCount,
        boolean rareAttachment,
        boolean internalSender,
        int maliciousFlagCount) {

    public EmailFacts {
        spfResult = spfResult != null ? spfResult : "none";
        dkimResult = dkimResult != null ? dkimResult : "none";
        dmarcResult = dmarcResult != null ? dmarcResult : "none";
        suspiciousLinkCount = Math.max(0, suspiciousLinkCount);
        attachmentCount = Math.max(0, attachmentCount);
    }
}
