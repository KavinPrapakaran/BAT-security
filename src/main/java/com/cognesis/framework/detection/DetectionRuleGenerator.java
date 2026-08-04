package com.cognesis.framework.detection;

import com.cognesis.framework.common.Decision;
import com.cognesis.framework.common.DecisionResult;
import com.cognesis.framework.common.ReasoningStep;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.UUID;

/**
 * Converts a COGNESIS verdict into industry-standard detection content so the
 * decision can be consumed by any SIEM (Sigma) or endpoint scanner (YARA).
 * This bridges the framework to real security tooling.
 */
public final class DetectionRuleGenerator {

    private static final DateTimeFormatter ISO = DateTimeFormatter.ISO_INSTANT;

    private DetectionRuleGenerator() {
    }

    /** Emit a Sigma detection rule (YAML) describing the decision. */
    public static String sigmaRule(DecisionResult result) {
        Decision d = result.decision();
        String level = sigmaLevel(d);
        StringBuilder sb = new StringBuilder();
        sb.append("title: COGNESIS - ").append(d).append(" on ").append(sanitizeYaml(result.entityId())).append('\n');
        sb.append("id: ").append(result.decisionId()).append('\n');
        sb.append("status: experimental\n");
        sb.append("description: \"").append(escapeYaml(result.rationale())).append("\"\n");
        sb.append("author: COGNESIS\n");
        sb.append("date: ").append(Instant.now().atZone(ZoneOffset.UTC).toLocalDate()).append('\n');
        sb.append("tags:\n  - attack.discovery\n");
        sb.append("logsource:\n  category: dns_query\n");
        sb.append("detection:\n");
        sb.append("  selection:\n");
        sb.append("    query|cstartswith: ").append(sanitizeYaml(result.entityId())).append('\n');
        sb.append("    query|contains:\n");
        for (ReasoningStep step : result.reasoningChain()) {
            if (step.claim() != null && !step.claim().isBlank()) {
                sb.append("      - \"").append(escapeYaml(step.claim())).append("\"\n");
            }
        }
        sb.append("  condition: selection\n");
        sb.append("level: ").append(level).append('\n');
        sb.append("falsepositives:\n  - Legitimate new registrations under monitoring\n");
        sb.append("fields:\n  - query\n  - src_ip\n  - user\n");
        return sb.toString();
    }

    /** Emit a YARA rule (from the domain and decision metadata). */
    public static String yaraRule(DecisionResult result) {
        Decision d = result.decision();
        String domain = result.entityId();
        StringBuilder sb = new StringBuilder();
        sb.append("rule cogensis_high_risk_").append(d.name().toLowerCase(Locale.ROOT)).append(" {\n");
        sb.append("    meta:\n");
        sb.append("        description = \"").append(escapeYara(result.rationale())).append("\"\n");
        sb.append("        author = \"COGNESIS\"\n");
        sb.append("        reference = \"decision ").append(result.decisionId()).append("\"\n");
        sb.append("        risk_score = \"").append(String.format(Locale.ROOT, "%.2f", result.riskScore())).append("\"\n");
        sb.append("        date = \"").append(ISO.format(result.decidedAt())).append("\"\n");
        sb.append("    strings:\n");
        sb.append("        $a = \"").append(escapeYara(domain)).append("\" ascii wide nocase\n");
        int i = 0;
        for (ReasoningStep step : result.reasoningChain()) {
            if (i >= 8) {
                break;
            }
            if (step.claim() != null && !step.claim().isBlank()) {
                sb.append("        $s").append(i).append(" = \"").append(escapeYara(step.claim())).append("\" ascii wide nocase\n");
                i++;
            }
        }
        sb.append("    condition:\n");
        sb.append("        $a and (").append(i == 0 ? "1 of them" : "any of ($s0..$s" + (i - 1) + ")").append(")\n");
        sb.append("}\n");
        return sb.toString();
    }

    private static String sigmaLevel(Decision d) {
        return switch (d) {
            case ALLOW -> "informational";
            case MONITOR -> "low";
            case WARN, CHALLENGE -> "medium";
            case ESCALATE -> "high";
            case ISOLATE, BLOCK -> "critical";
        };
    }

    private static String sanitizeYaml(String value) {
        if (value == null) {
            return "";
        }
        return value.replaceAll("[\\r\\n]", " ").replaceAll("^[-?]", "'").trim();
    }

    private static String escapeYaml(String value) {
        return value == null ? "" : value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static String escapeYara(String value) {
        return value == null ? "" : value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
