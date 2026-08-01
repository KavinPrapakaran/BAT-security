package com.cognesis.framework.recommend;

import com.cognesis.framework.common.Decision;
import com.cognesis.framework.common.RecommendedAction;

/**
 * PACT - Policy &amp; Action Control Tower. Translates a SYNAPSE verdict into
 * an operational action on the security stack, guided by entity type and the
 * business impact of the decision.
 */
public interface RecommendationEngine {

    Recommendation recommend(Decision decision, double riskScore, double businessImpact,
                            String entityId, String entityType);
}
