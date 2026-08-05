package com.cognesis.framework.email;

import java.time.Instant;
import java.util.Map;

/**
 * An inbound email that triggers a cognitive decision.
 *
 * @param messageId     message identifier to look up in the facts repository
 * @param recipient     destination address (the entity being protected)
 * @param clientIp      network origin of the delivery
 * @param context       free-form situational context (mailbox, geolocation, ...)
 */
public record EmailEvaluationRequest(
        String messageId,
        String recipient,
        String clientIp,
        Map<String, String> context) {

    public EmailEvaluationRequest {
        context = context != null ? Map.copyOf(context) : Map.of();
    }

    public static EmailEvaluationRequest of(String messageId, String recipient) {
        return new EmailEvaluationRequest(messageId, recipient, "unknown", Map.of());
    }
}
