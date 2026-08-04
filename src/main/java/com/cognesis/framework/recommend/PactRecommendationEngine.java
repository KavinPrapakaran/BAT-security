package com.cognesis.framework.recommend;

import com.cognesis.framework.common.Decision;
import com.cognesis.framework.common.RecommendedAction;

/**
 * Default PACT implementation. Verdicts map to actuators across the seven-band
 * ladder:
 * <ul>
 *   <li>ALLOW      -&gt; ALLOW (or ALERT_ONLY when impact is high)</li>
 *   <li>MONITOR    -&gt; MONITOR_ONGOING (+ RATE_LIMIT when risk climbs)</li>
 *   <li>WARN       -&gt; WARN_NOTIFY (notify the owner/operator)</li>
 *   <li>CHALLENGE  -&gt; CHALLENGE_VERIFY / REQUIRE_MFA (step-up verification)</li>
 *   <li>ESCALATE   -&gt; ESCALATE_TO_ANALYST (+ ENRICH when confidence is low)</li>
 *   <li>ISOLATE    -&gt; entity-type-specific quarantine</li>
 *   <li>BLOCK      -&gt; entity-type-specific block, escalated to ISOLATE_ASSET
 *                     for high-impact decisions</li>
 * </ul>
 */
public class PactRecommendationEngine implements RecommendationEngine {

    @Override
    public Recommendation recommend(Decision decision, double riskScore, double businessImpact,
                                    String entityId, String entityType) {
        String type = entityType == null ? "" : entityType.toUpperCase();
        return switch (decision) {
            case ALLOW -> businessImpact >= 0.7
                    ? new Recommendation(RecommendedAction.ALERT_ONLY, entityId,
                            "Allowed, but the asset is high-impact; keeping an alert trail.")
                    : new Recommendation(RecommendedAction.ALLOW, entityId, "No adversarial signal worth acting on.");
            case MONITOR -> new Recommendation(riskScore >= 0.4
                    ? RecommendedAction.RATE_LIMIT
                    : RecommendedAction.MONITOR_ONGOING, entityId,
                    "Noteworthy; keep passive watch and telemetry.");
            case WARN -> new Recommendation(RecommendedAction.WARN_NOTIFY, entityId,
                    "Present a warning: notify the asset owner and record for review.");
            case CHALLENGE -> new Recommendation(RecommendedAction.REQUIRE_MFA, entityId,
                    "Require additional verification before the action proceeds.");
            case ESCALATE -> new Recommendation(riskScore >= 0.6
                    ? RecommendedAction.ENRICH_INTELLIGENCE
                    : RecommendedAction.ESCALATE_TO_ANALYST, entityId,
                    "Hand to a human analyst and enrich with intelligence.");
            case ISOLATE -> {
                RecommendedAction action = switch (type) {
                    case "DOMAIN" -> RecommendedAction.QUARANTINE_DOMAIN;
                    case "IP" -> RecommendedAction.QUARANTINE_IP;
                    case "USER", "ACCOUNT" -> RecommendedAction.SUSPEND_ACCOUNT;
                    case "ENDPOINT", "DEVICE" -> RecommendedAction.QUARANTINE_ENDPOINT;
                    case "CERTIFICATE" -> RecommendedAction.REVOKE_CERTIFICATE;
                    default -> RecommendedAction.ISOLATE_ASSET;
                };
                yield new Recommendation(action, entityId,
                        "Contain the entity while keeping it observable for analysis.");
            }
            case BLOCK -> {
                RecommendedAction action = switch (type) {
                    case "DOMAIN" -> RecommendedAction.BLOCK_DOMAIN;
                    case "IP" -> RecommendedAction.BLOCK_IP;
                    case "USER" -> RecommendedAction.BLOCK_USER;
                    case "ENDPOINT", "DEVICE" -> RecommendedAction.QUARANTINE_ENDPOINT;
                    case "CERTIFICATE" -> RecommendedAction.REVOKE_CERTIFICATE;
                    default -> RecommendedAction.BLOCK_DOMAIN;
                };
                if (businessImpact >= 0.8) {
                    yield new Recommendation(RecommendedAction.ISOLATE_ASSET, entityId,
                            "High impact block - isolate the asset and confirm scope with the response team.");
                }
                yield new Recommendation(action, entityId, "Strong fused evidence; blocking to protect the business.");
            }
        };
    }
}
