package com.cognesis.framework.dns;

/**
 * Supplies structured facts about a domain to the DNS Intelligence Engine (DIE).
 * Backed by live resolution pipelines in production; the scaffold uses a
 * sample in-memory repository.
 */
public interface DnsFactsRepository {

    DnsFacts factsFor(String domain);
}
