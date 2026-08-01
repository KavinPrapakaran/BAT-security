package com.cognesis.framework.impact;

/**
 * RESOLVE - the business impact engine. Maps an action to the assets it could
 * harm and produces the value-at-risk used by SYNAPSE. Business impact is never
 * conflated with likelihood of compromise; the two are blended explicitly by
 * the decision algorithm.
 */
public interface ImpactEngine {

    ImpactAssessment assess(ImpactContext context);
}
