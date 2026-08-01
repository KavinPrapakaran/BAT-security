package com.cognesis.framework.policy;

import com.cognesis.framework.common.Decision;

import java.util.List;

/**
 * Outcome of evaluating an entity against the policy rule set.
 */
public record PolicyVerdict(
        Decision decision,
        List<String> matchedRules) {

    public PolicyVerdict {
        matchedRules = matchedRules != null ? List.copyOf(matchedRules) : List.of();
    }

    public boolean isMatch() {
        return !matchedRules.isEmpty() && decision != Decision.ALLOW;
    }
}
