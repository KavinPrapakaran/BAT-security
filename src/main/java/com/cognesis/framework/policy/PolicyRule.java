package com.cognesis.framework.policy;

/**
 * A declarative business policy rule consumed by the policy evaluator.
 *
 * @param ruleName    human-readable name
 * @param ruleType    BLOCK_LIST | DENY_CATEGORY | ALLOW_LIST | RISK_OVERRIDE
 * @param matchTarget domain/suffix/category to match
 * @param action      resulting decision when matched
 * @param priority    lower number wins
 */
public record PolicyRule(String ruleName, String ruleType, String matchTarget, String action, int priority) {
}
