package com.cognesis.framework.email;

import java.util.HashMap;
import java.util.Map;

/**
 * Deterministic seed facts for tests and offline development. Mirrors the DNS
 * in-memory repository: a small, stable corpus covering clean mail, phishing,
 * spoofing, attachment-borne payloads and aged-sender lookalikes.
 */
public class InMemoryEmailFactsRepository implements EmailFactsRepository {

    private final Map<String, EmailFacts> facts = new HashMap<>();

    public InMemoryEmailFactsRepository() {
        facts.put("msg-001", new EmailFacts(
                "msg-001", "billing@paypal.com", "paypal.com", 7000,
                "pass", "pass", "pass",
                false, false, 0, 1, false, false, 0));

        facts.put("msg-002", new EmailFacts(
                "msg-002", "urgent@paypa1-secure.com", "paypa1-secure.com", 4,
                "fail", "none", "none",
                true, true, 3, 1, true, false, 2));

        facts.put("msg-003", new EmailFacts(
                "msg-003", "exec-board@corp.example.com", "corp.example.com", 5000,
                "pass", "pass", "pass",
                false, false, 0, 1, false, true, 0));

        facts.put("msg-004", new EmailFacts(
                "msg-004", "invoice@green-supplies.example", "green-supplies.example", 12,
                "neutral", "none", "none",
                false, false, 1, 0, false, false, 0));
    }

    @Override
    public EmailFacts factsFor(String messageId) {
        return facts.getOrDefault(messageId,
                new EmailFacts(messageId, "unknown@unknown.example", "unknown.example", 0,
                        "none", "none", "none",
                        false, false, 0, 0, false, false, 0));
    }
}
