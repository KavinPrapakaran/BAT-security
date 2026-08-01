package com.cognesis.framework.impact;

import java.util.Comparator;
import java.util.List;

/**
 * Default RESOLVE implementation. The business impact B is the maximum
 * criticality-and-sensitivity weighted score over the affected assets:
 * <pre>
 *   B(asset) = criticality * 0.6 + sensitivity * 0.4
 *   B        = max over affected assets, or a neutral default when none given
 * </pre>
 * An activity modifier nudges the score up for destructive/costly activities.
 */
public class ResolveImpactEngine implements ImpactEngine {

    private static final double NEUTRAL_IMPACT = 0.55;

    private final AssetRegistry registry;

    public ResolveImpactEngine(AssetRegistry registry) {
        this.registry = registry;
    }

    @Override
    public ImpactAssessment assess(ImpactContext context) {
        List<Asset> assets = registry.allAssets();
        if (assets.isEmpty()) {
            return new ImpactAssessment(NEUTRAL_IMPACT, null, "no assets registered; neutral impact assumed");
        }

        double maxImpact = -1.0;
        String topAsset = null;
        for (Asset asset : assets) {
            boolean affected = context.affectedAssetIds().isEmpty() || context.affectedAssetIds().contains(asset.assetId());
            if (!affected) {
                continue;
            }
            double impact = asset.criticality() * 0.6 + asset.sensitivity() * 0.4;
            if (impact > maxImpact) {
                maxImpact = impact;
                topAsset = asset.assetId();
            }
        }

        double impact = maxImpact >= 0 ? maxImpact : NEUTRAL_IMPACT;
        String rationale = maxImpact >= 0
                ? "highest impact asset '%s' drives the score".formatted(topAsset)
                : "no affected asset specified; neutral impact assumed";

        String activity = context.activity() == null ? "" : context.activity().toLowerCase();
        if (activity.contains("exfil") || activity.contains("destroy") || activity.contains("ransom")) {
            impact = Math.min(1.0, impact * 1.25);
            rationale = rationale + "; destructive activity modifier applied";
        }
        return new ImpactAssessment(impact, topAsset, rationale);
    }
}
