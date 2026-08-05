package com.cognesis.framework.profile;

import com.cognesis.framework.algorithm.DecisionBandPolicy;
import com.cognesis.framework.common.Decision;
import com.cognesis.framework.policy.PolicyRule;
import com.cognesis.framework.policy.PolicyVerdict;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Resolves which {@link OrgProfile} applies to a request and applies it to the
 * decision path. Two levers:
 *
 * <ul>
 *   <li><b>Tolerance</b> - the profile's risk tolerance rescales the
 *       {@link DecisionBandPolicy} bands, so a hospital blocks what a
 *       university merely monitors for the same risk score.</li>
 *   <li><b>Org-scoped rules</b> - policies that exist only for one
 *       organization (e.g. a bank blocking all new TLDs) without affecting
 *       global evaluation.</li>
 * </ul>
 */
public class ProfileEvaluationEngine {

    public static final String DEFAULT_ORG = "default";

    private final Map<String, OrgProfile> profiles;

    public ProfileEvaluationEngine(List<OrgProfile> profiles) {
        Map<String, OrgProfile> byId = new LinkedHashMap<>();
        if (profiles != null) {
            for (OrgProfile profile : profiles) {
                byId.put(normalize(profile.organizationId()), profile);
            }
        }
        byId.putIfAbsent(DEFAULT_ORG, new OrgProfile(DEFAULT_ORG, "Default", 1.0, List.of()));
        this.profiles = Map.copyOf(byId);
    }

    /** Convenience factory seeding realistic defaults for regulated sectors. */
    public static ProfileEvaluationEngine withDefaults() {
        return new ProfileEvaluationEngine(List.of(
                new OrgProfile("hospital", "Regional Hospital",
                        0.70,
                        List.of(new PolicyRule("No patient-data exfil TLDs", "BLOCK_LIST", "example.tld", "BLOCK", 10))),
                new OrgProfile("bank", "First National Bank",
                        0.80,
                        List.of(new PolicyRule("Block brand-squatting domains", "BLOCK_LIST", "bank-verify.example", "BLOCK", 10),
                                new PolicyRule("Block newly-registered TLDs", "DENY_CATEGORY", "phishing", "BLOCK", 20))),
                new OrgProfile("university", "State University",
                        1.20,
                        List.of(new PolicyRule("Allow research sandboxes", "ALLOW_LIST", "research.example", "ALLOW", 5)))));
    }

    public OrgProfile profileFor(String organizationId) {
        return profiles.getOrDefault(normalize(organizationId), profiles.get(DEFAULT_ORG));
    }

    public double toleranceFor(String organizationId) {
        return profileFor(organizationId).riskTolerance();
    }

    public Set<String> organizationIds() {
        return profiles.keySet();
    }

    /**
     * Scales a base band policy by the organization's tolerance while
     * preserving the base thresholds, so stricter orgs land on a higher
     * severity decision for the same risk score.
     */
    public DecisionBandPolicy scaledBandPolicy(String organizationId, DecisionBandPolicy base) {
        double tolerance = toleranceFor(organizationId);
        return new DecisionBandPolicy(
                base.monitor(), base.warn(), base.challenge(), base.escalate(),
                base.isolate(), base.block(),
                base.tolerance() * tolerance,
                base.lowConfidenceThreshold(), base.escalateWhenUncertain());
    }

    /**
     * Evaluates org-scoped rules only. Unknown organizations get the neutral
     * default profile, which carries no rules.
     */
    public PolicyVerdict evaluate(String organizationId, String entityId, String entityType) {
        OrgProfile profile = profileFor(organizationId);
        List<PolicyRule> rules = new ArrayList<>(profile.rules());
        rules.sort(Comparator.comparingInt(PolicyRule::priority));
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

    private static String normalize(String organizationId) {
        return organizationId == null || organizationId.isBlank()
                ? DEFAULT_ORG
                : organizationId.trim().toLowerCase(Locale.ROOT);
    }
}
