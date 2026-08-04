package com.cognesis.framework.persistence;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory {@link IocStore} for tests and non-persistent deployments.
 */
public class InMemoryIocStore implements IocStore {

    private record Entry(int count, Instant firstSeen) {
    }

    private final Map<String, Entry> flags = new ConcurrentHashMap<>();

    @Override
    public void flag(String domain) {
        flags.compute(domain, (k, existing) -> existing == null
                ? new Entry(1, Instant.now())
                : new Entry(existing.count() + 1, existing.firstSeen()));
    }

    @Override
    public int flagCount(String domain) {
        Entry e = flags.get(domain);
        return e == null ? 0 : e.count();
    }

    @Override
    public int total() {
        return flags.size();
    }

    @Override
    public Optional<Instant> firstSeen(String domain) {
        Entry e = flags.get(domain);
        return e == null ? Optional.empty() : Optional.of(e.firstSeen());
    }
}
