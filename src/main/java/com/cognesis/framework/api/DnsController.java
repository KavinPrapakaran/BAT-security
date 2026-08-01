package com.cognesis.framework.api;

import com.cognesis.framework.dns.CognitiveDnsEngine;
import com.cognesis.framework.dns.DnsDecision;
import com.cognesis.framework.dns.DnsResolutionRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Cognitive DNS evaluation endpoint. Meant to be called by a DNS proxy or
 * forwarder before a resolution is allowed to complete.
 */
@RestController
@RequestMapping("/api/v1/dns")
public class DnsController {

    private final CognitiveDnsEngine engine;

    public DnsController(CognitiveDnsEngine engine) {
        this.engine = engine;
    }

    @PostMapping("/evaluate")
    public ResponseEntity<DnsDecision> evaluate(@Valid @RequestBody DnsResolutionRequest request) {
        return ResponseEntity.ok(engine.evaluate(request));
    }
}
