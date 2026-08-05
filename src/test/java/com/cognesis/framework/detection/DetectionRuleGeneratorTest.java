package com.cognesis.framework.detection;

import com.cognesis.framework.common.Decision;
import com.cognesis.framework.common.DecisionResult;
import com.cognesis.framework.common.ReasoningStep;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DetectionRuleGeneratorTest {

    private final DecisionResult result = new DecisionResult(
            UUID.fromString("00000000-0000-0000-0000-000000000001"),
            "evil-payload.example",
            "DNS_RESOLUTION",
            Decision.BLOCK,
            null,
            0.95,
            0.1,
            0.9,
            0.8,
            "Domain matched a known malware distribution pattern",
            List.of(
                    new ReasoningStep("DIE", "malware distribution", 0.9, 0.85, "feed flag", Instant.now()),
                    new ReasoningStep("FIDES", "low trust", 0.8, 0.7, "no history", Instant.now())),
            Instant.now());

    @Test
    void sigmaRuleIsWellFormedYaml() {
        String sigma = DetectionRuleGenerator.sigmaRule(result);
        assertNotNull(sigma);
        assertTrue(sigma.contains("title: BAT security - BLOCK"));
        assertTrue(sigma.contains("level: critical"), "BLOCK must map to critical");
        assertTrue(sigma.contains("category: dns_query"));
        assertTrue(sigma.contains("query|cstartswith: evil-payload.example"));
        assertTrue(sigma.contains("malware distribution"), "reasoning chain claims must be embedded");
    }

    @Test
    void sigmaLevelsMapToSeverity() {
        String allow = DetectionRuleGenerator.sigmaRule(sampleWith(Decision.ALLOW));
        String warn = DetectionRuleGenerator.sigmaRule(sampleWith(Decision.WARN));
        String isolate = DetectionRuleGenerator.sigmaRule(sampleWith(Decision.ISOLATE));
        assertTrue(allow.contains("level: informational"));
        assertTrue(warn.contains("level: medium"));
        assertTrue(isolate.contains("level: critical"));
    }

    @Test
    void yaraRuleIsWellFormed() {
        String yara = DetectionRuleGenerator.yaraRule(result);
        assertNotNull(yara);
        assertTrue(yara.startsWith("rule batsec_high_risk_block {"));
        assertTrue(yara.contains("$a = \"evil-payload.example\" ascii wide nocase"));
        assertTrue(yara.contains("risk_score = \"0.95\""));
        assertTrue(yara.contains("condition:"));
        assertTrue(yara.endsWith("}\n"));
    }

    @Test
    void detectionRuleBundleExposesBothFormats() {
        DetectionRule sigma = DetectionRule.sigma(result);
        DetectionRule yara = DetectionRule.yara(result);
        assertTrue(sigma.format().equals("sigma"));
        assertTrue(sigma.filename().endsWith(".yml"));
        assertTrue(yara.format().equals("yara"));
        assertTrue(yara.filename().endsWith(".yar"));
    }

    private DecisionResult sampleWith(Decision d) {
        return new DecisionResult(UUID.randomUUID(), "test.example", "DNS_RESOLUTION", d,
                null, 0.5, 0.5, 0.5, 0.5, "rationale", List.of(), Instant.now());
    }
}
