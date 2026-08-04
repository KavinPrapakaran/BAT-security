package com.cognesis.framework.persistence;

import java.util.Optional;

/**
 * Persistent store for threat-intel IOC flags. Feed ingestion writes here so
 * flagged domains survive restarts and every facts lookup sees them.
 */
public interface IocStore {

    /** Records (or re-confirms) that a domain was flagged by a threat feed. */
    void flag(String domain);

    /** Number of distinct flagging events for a domain, 0 if never flagged. */
    int flagCount(String domain);

    /** Total number of distinct flagged domains. */
    int total();

    /** When the domain was first flagged, if it was. */
    Optional<java.time.Instant> firstSeen(String domain);
}
