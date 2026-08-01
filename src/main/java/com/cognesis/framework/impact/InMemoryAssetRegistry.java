package com.cognesis.framework.impact;

import java.util.ArrayList;
import java.util.List;

/**
 * Scaffold asset registry, mirroring the asset table seed. In production this
 * is backed by a CMDB sync.
 */
public class InMemoryAssetRegistry implements AssetRegistry {

    private final List<Asset> assets = new ArrayList<>();

    public InMemoryAssetRegistry() {
        assets.add(new Asset("asset-billing", "Billing Portal", "WEB", 0.95, 0.90));
        assets.add(new Asset("asset-mail", "Corporate Mail", "API", 0.85, 0.80));
        assets.add(new Asset("asset-build", "CI Build Farm", "SERVICE", 0.60, 0.30));
    }

    @Override
    public List<Asset> allAssets() {
        return List.copyOf(assets);
    }
}
