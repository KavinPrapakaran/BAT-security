package com.cognesis.framework.email;

/**
 * Supplies structured facts about an inbound message to the VOID email engine.
 * The scaffold ships a deterministic in-memory repository; production
 * deployments back this interface with an email-security gateway (SPF/DKIM/
 * DMARC verdicts, URL reputation, attachment sandboxing).
 */
public interface EmailFactsRepository {

    /** Facts for the message identified by {@code messageId}. */
    EmailFacts factsFor(String messageId);
}
