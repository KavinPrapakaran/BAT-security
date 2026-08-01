package com.cognesis.framework.impact;

/**
 * A business asset that could be affected by an adversary action.
 *
 * @param assetId      stable identifier
 * @param name         display name
 * @param assetType    WEB | API | DB | ENDPOINT | SERVICE | CLOUD
 * @param criticality  business criticality in [0,1]
 * @param sensitivity  data sensitivity in [0,1]
 */
public record Asset(String assetId, String name, String assetType, double criticality, double sensitivity) {
}
