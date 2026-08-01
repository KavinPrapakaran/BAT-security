package com.cognesis.framework.persistence;

import com.cognesis.framework.common.DecisionResult;

/**
 * Persistence abstraction for decision logs. Every COGNESIS verdict is written
 * here for audit, trend analysis, and LORE learning. The default implementation
 * is a no-op so the framework runs in-memory; production injects the JDBC store.
 */
public interface DecisionLogDao {

    default void save(DecisionResult result) {
    }
}
