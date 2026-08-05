package com.cognesis.framework.profile;

import com.cognesis.framework.algorithm.DecisionBandPolicy;
import com.cognesis.framework.common.Decision;
import com.cognesis.framework.policy.PolicyVerdict;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ProfileEvaluationEngineTest {

    private final ProfileEvaluationEngine engine = ProfileEvaluationEngine.withDefaults();

    @Test
    void stricterOrgEscalatesWhatPermissiveOrgMonitors() {
        DecisionBandPolicy base = DecisionBandPolicy.defaults();
        double risk = 0.5;

        Decision hospital = engine.scaledBandPolicy("hospital", base).mapRisk(risk, 0.9);
        Decision university = engine.scaledBandPolicy("university", base).mapRisk(risk, 0.9);

        assertTrue(severity(hospital) > severity(university),
                "for the same risk score a hospital must get a stricter decision than a university: "
                        + hospital + " vs " + university);
    }

    @Test
    void defaultToleranceLeavesBandsUnchanged() {
        DecisionBandPolicy base = DecisionBandPolicy.defaults();
        DecisionBandPolicy scaled = engine.scaledBandPolicy("unknown-org", base);
        assertEquals(base.tolerance(), scaled.tolerance(), 1e-9,
                "unknown organizations must use the neutral default profile");
    }

    @Test
    void orgScopedRuleOnlyBlocksItsOrganization() {
        PolicyVerdict bank = engine.evaluate("bank", "bank-verify.example", "DOMAIN");
        assertEquals(Decision.BLOCK, bank.decision(), "the bank's org-scoped rule must block the domain");
        assertTrue(bank.matchedRules().stream().anyMatch(r -> r.contains("brand-squatting")));

        PolicyVerdict university = engine.evaluate("university", "bank-verify.example", "DOMAIN");
        assertEquals(Decision.ALLOW, university.decision(),
                "another organization must not inherit the bank's scoped rule");
    }

    @Test
    void defaultProfileCarriesNoRules() {
        PolicyVerdict verdict = engine.evaluate(ProfileEvaluationEngine.DEFAULT_ORG, "anything.example", "DOMAIN");
        assertEquals(Decision.ALLOW, verdict.decision());
        assertTrue(verdict.matchedRules().isEmpty());
    }

    @Test
    void allDefaultOrganizationsResolve() {
        for (String org : engine.organizationIds()) {
            assertTrue(engine.profileFor(org).riskTolerance() > 0.0, org + " must resolve to a real profile");
        }
    }

    private static int severity(Decision d) {
        return switch (d) {
            case ALLOW -> 0;
            case MONITOR -> 1;
            case WARN -> 2;
            case CHALLENGE -> 3;
            case ESCALATE -> 4;
            case ISOLATE -> 5;
            case BLOCK -> 6;
        };
    }
}
