package com.cognesis.framework.impact;

import java.util.List;

/**
 * Registry of business assets used by RESOLVE to score business impact.
 */
public interface AssetRegistry {

    List<Asset> allAssets();
}
