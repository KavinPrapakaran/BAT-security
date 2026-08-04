package com.cognesis.framework.api;

import com.cognesis.framework.acde.AcdeEngine;
import com.cognesis.framework.acde.DecisionRequest;
import com.cognesis.framework.common.DecisionResult;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * General-purpose decision endpoint. Evaluates any entity (DOMAIN, IP, USER,
 * API, EMAIL, ...) through the ACDE - the single decision-maker - and returns
 * a fully explainable decision.
 */
@RestController
@RequestMapping("/api/v1/decisions")
public class DecisionController {

    private final AcdeEngine acde;

    public DecisionController(AcdeEngine acde) {
        this.acde = acde;
    }

    @PostMapping("/evaluate")
    public ResponseEntity<DecisionResult> evaluate(@Valid @RequestBody DecisionRequest request) {
        DecisionResult result = acde.evaluate(request);
        return ResponseEntity.ok(result);
    }
}
