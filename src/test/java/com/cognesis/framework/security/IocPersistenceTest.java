package com.cognesis.framework.security;

import com.cognesis.framework.dns.DnsFacts;
import com.cognesis.framework.dns.InMemoryDnsFactsRepository;
import com.cognesis.framework.persistence.InMemoryIocStore;
import com.cognesis.framework.persistence.IocStore;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The in-memory facts repository must surface persisted IOC flags, so a live
 * feed survives repository replacement (restart-equivalent).
 */
class IocPersistenceTest {

    @Test
    void feedFlagsSurfaceThroughAFreshFactsRepository() {
        IocStore store = new InMemoryIocStore();
        InMemoryDnsFactsRepository first = new InMemoryDnsFactsRepository(store);
        first.flagMalicious("persisted.example");

        InMemoryDnsFactsRepository second = new InMemoryDnsFactsRepository(store);

        DnsFacts facts = second.factsFor("persisted.example");
        assertTrue(facts.maliciousFlagCount() >= 1,
                "IOC flag recorded through one repository must be visible to a fresh one");
    }

    @Test
    void unknownDomainWithoutFlagsIsClean() {
        InMemoryDnsFactsRepository repo = new InMemoryDnsFactsRepository(new InMemoryIocStore());
        assertEquals(0, repo.factsFor("clean.example").maliciousFlagCount());
    }
}
