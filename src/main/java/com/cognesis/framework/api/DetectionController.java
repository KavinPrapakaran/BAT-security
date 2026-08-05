package com.cognesis.framework.api;

import com.cognesis.framework.detection.DetectionRule;
import com.cognesis.framework.dns.DnsDecision;
import com.cognesis.framework.dns.DnsIntelligenceEngine;
import com.cognesis.framework.dns.DnsResolutionRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Evaluates a DNS resolution and exports the verdict as SIEM-ready detection
 * content (Sigma + YARA). Lets the framework hand its decisions to real
 * tooling instead of only returning JSON.
 */
@RestController
@RequestMapping("/api/v1/detections")
public class DetectionController {

    private final DnsIntelligenceEngine engine;

    public DetectionController(DnsIntelligenceEngine engine) {
        this.engine = engine;
    }

    @PostMapping("/dns")
    public ResponseEntity<List<DetectionRule>> detect(@Valid @RequestBody DnsResolutionRequest request) {
        DnsDecision decision = engine.evaluate(request);
        return ResponseEntity.ok(List.of(
                DetectionRule.sigma(decision.outcome()),
                DetectionRule.yara(decision.outcome())));
    }
}
