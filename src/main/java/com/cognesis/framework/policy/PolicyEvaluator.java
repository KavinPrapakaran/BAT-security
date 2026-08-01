package com.cognesis.framework.policy;

/**
 * Evaluates an entity against declarative policy rules. The DNS engine uses
 * this so hard policy (blocklists, allowlists, categories) always takes
 * precedence over statistical inference - the same way an analyst never
 * questions a signed blocklist entry.
 */
public interface PolicyEvaluator {

    PolicyVerdict evaluate(String entityId, String entityType);
}
