package com.cognesis.framework.policy;

import com.cognesis.framework.common.Decision;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

/**
 * Deterministic policy evaluation over an ordered rule set. Highest-priority
 * matching rule wins. The scaffold is seeded from the policy_rule table; a
 * JDBC-backed evaluator can swap in without interface changes.
 */
public class InMemoryPolicyEvaluator implements PolicyEvaluator {

    private final List<PolicyRule> rules;

    public InMemoryPolicyEvaluator(List<PolicyRule> rules) {
        this.rules = new ArrayList<>(rules);
        this.rules.sort(Comparator.comparingInt(PolicyRule::priority));
    }

    @Override
    public PolicyVerdict evaluate(String entityId, String entityType) {
        String target = entityId == null ? "" : entityId.toLowerCase(Locale.ROOT);
        List<String> matched = new ArrayList<>();
        for (PolicyRule rule : rules) {
            String matchTarget = rule.matchTarget() == null ? "" : rule.matchTarget().toLowerCase(Locale.ROOT);
            boolean hit = switch (rule.ruleType()) {
                case "BLOCK_LIST", "ALLOW_LIST" -> target.equals(matchTarget) || target.endsWith("." + matchTarget);
                case "DENY_CATEGORY" -> target.contains(matchTarget);
                default -> false;
            };
            if (hit) {
                matched.add(rule.ruleName());
                return new PolicyVerdict(Decision.valueOf(rule.action()), matched);
            }
        }
        return new PolicyVerdict(Decision.ALLOW, List.of());
    }
}
