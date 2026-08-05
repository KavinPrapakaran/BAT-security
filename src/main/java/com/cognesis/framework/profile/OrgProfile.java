package com.cognesis.framework.profile;

import com.cognesis.framework.policy.PolicyRule;

import java.util.List;

/**
 * A security posture profile for an organization. The risk tolerance scales
 * the decision bands (below 1.0 is stricter, above 1.0 more permissive) and
 * {@code rules} scopes declarative policies to this organization only.
 *
 * @param organizationId unique identifier of the organization
 * @param name           human-readable name
 * @param riskTolerance  in (0, 2]; 1.0 keeps the framework's defaults
 * @param rules          org-scoped policy rules (evaluated in priority order)
 */
public record OrgProfile(String organizationId, String name,
                         double riskTolerance, List<PolicyRule> rules) {

    public OrgProfile {
        riskTolerance = Math.max(0.05, Math.min(2.0, riskTolerance));
        rules = rules != null ? List.copyOf(rules) : List.of();
    }
}
