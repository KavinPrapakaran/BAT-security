package com.cognesis.framework.api;

import com.cognesis.framework.trust.TrustAssessment;
import com.cognesis.framework.trust.TrustEngine;
import com.cognesis.framework.trust.TrustEvent;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Trust management endpoints. Query or evolve an entity's dynamic trust.
 */
@RestController
@RequestMapping("/api/v1/trust")
public class TrustController {

    private final TrustEngine trustEngine;

    public TrustController(TrustEngine trustEngine) {
        this.trustEngine = trustEngine;
    }

    @GetMapping("/{entityType}/{entityId}")
    public ResponseEntity<TrustAssessment> assess(@PathVariable String entityType,
                                                  @PathVariable String entityId) {
        return ResponseEntity.ok(trustEngine.assess(entityId, entityType));
    }

    @PostMapping("/events")
    public ResponseEntity<TrustAssessment> recordEvent(@RequestBody TrustEvent event) {
        return ResponseEntity.ok(trustEngine.recordEvent(event));
    }
}
