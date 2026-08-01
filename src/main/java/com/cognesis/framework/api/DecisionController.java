package com.cognesis.framework.api;

import com.cognesis.framework.common.DecisionResult;
import com.cognesis.framework.orchestrator.DecisionOrchestrator;
import com.cognesis.framework.orchestrator.DecisionRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * General-purpose decision endpoint. Evaluates any entity (DOMAIN, IP, USER,
 * API, EMAIL, ...) for which evidence providers exist and returns a fully
 * explainable decision.
 */
@RestController
@RequestMapping("/api/v1/decisions")
public class DecisionController {

    private final DecisionOrchestrator orchestrator;

    public DecisionController(DecisionOrchestrator orchestrator) {
        this.orchestrator = orchestrator;
    }

    @PostMapping("/evaluate")
    public ResponseEntity<DecisionResult> evaluate(@Valid @RequestBody DecisionRequest request) {
        DecisionResult result = orchestrator.evaluate(request);
        return ResponseEntity.ok(result);
    }
}
