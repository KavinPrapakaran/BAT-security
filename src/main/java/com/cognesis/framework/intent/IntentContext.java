package com.cognesis.framework.intent;

import java.util.List;

/**
 * Input to the MOTIVE intent engine: which evidence families fired, plus the
 * entity type under evaluation. The engine infers what the actor is probably
 * trying to do.
 */
public record IntentContext(
        List<String> evidenceTypes,
        String entityType) {

    public IntentContext {
        evidenceTypes = evidenceTypes != null ? List.copyOf(evidenceTypes) : List.of();
    }
}
