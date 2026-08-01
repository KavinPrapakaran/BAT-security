package com.cognesis.framework.recommend;

import com.cognesis.framework.common.Decision;
import com.cognesis.framework.common.RecommendedAction;

/**
 * Default PACT implementation. Verdicts map to actuators as follows:
 * <ul>
 *   <li>ALLOW    -&gt; ALLOW (or ALERT_ONLY when impact is high)</li>
 *   <li>WARN     -&gt; ESCALATE_TO_ANALYST</li>
 *   <li>MONITOR  -&gt; INCREASE_MONITORING (+ ENRICH when confidence is low)</li>
 *   <li>BLOCK    -&gt; entity-type-specific block/quarantine, escalated to
 *                    ISOLATE_ASSET for high-impact decisions</li>
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
            case WARN -> new Recommendation(RecommendedAction.ESCALATE_TO_ANALYST, entityId,
                    "Weak but present signals; a human should sanity-check before trust is granted.");
            case MONITOR -> new Recommendation(riskScore >= 0.5
                    ? RecommendedAction.ENRICH_INTELLIGENCE
                    : RecommendedAction.INCREASE_MONITORING, entityId,
                    "Uncertain or moderately risky; observe closely and enrich with intelligence.");
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
