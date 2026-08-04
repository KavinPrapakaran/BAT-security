package com.cognesis.framework.detection;

import com.cognesis.framework.common.DecisionResult;

/**
 * One generated detection artifact (Sigma YAML, YARA, …) plus its format tag.
 */
public record DetectionRule(String format, String content, String filename) {

    public static DetectionRule sigma(DecisionResult result) {
        return new DetectionRule("sigma",
                DetectionRuleGenerator.sigmaRule(result),
                "cognesis_" + result.decisionId() + ".yml");
    }

    public static DetectionRule yara(DecisionResult result) {
        return new DetectionRule("yara",
                DetectionRuleGenerator.yaraRule(result),
                "cognesis_" + result.decisionId() + ".yar");
    }
}
