package com.cognesis.framework.persistence;

import java.util.Optional;

/**
 * Persistence abstraction for trust profiles. The default implementation is a
 * no-op so the framework runs fully in-memory; a JDBC/Redis store can be
 * injected for production.
 */
public interface TrustProfileStore {

    default void save(TrustProfile profile) {
    }

    default Optional<TrustProfile> load(String entityId) {
        return Optional.empty();
    }
}
