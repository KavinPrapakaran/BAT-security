package com.cognesis.framework.api;

import com.cognesis.framework.email.EmailDecision;
import com.cognesis.framework.email.EmailEvaluationRequest;
import com.cognesis.framework.email.EmailIntelligenceEngine;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * VOID email intelligence engine evaluation endpoint. Meant to be called by an
 * email-security gateway before a message is allowed into a mailbox.
 */
@RestController
@RequestMapping("/api/v1/email")
public class EmailController {

    private final EmailIntelligenceEngine engine;

    public EmailController(EmailIntelligenceEngine engine) {
        this.engine = engine;
    }

    @PostMapping("/evaluate")
    public ResponseEntity<EmailDecision> evaluate(@Valid @RequestBody EmailEvaluationRequest request) {
        return ResponseEntity.ok(engine.evaluate(request));
    }
}
