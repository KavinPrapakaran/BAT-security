package com.cognesis.framework.api;

import com.cognesis.framework.observatory.EvidenceFragment;
import com.cognesis.framework.observatory.EvidenceIngestor;
import com.cognesis.framework.observatory.AggregatedEvidence;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Evidence ingestion endpoint: external systems can push raw evidence and
 * immediately see how the framework would aggregate it into an evidence
 * strength and confidence factors.
 */
@RestController
@RequestMapping("/api/v1/evidence")
public class EvidenceController {

    private final EvidenceIngestor ingestor;

    public EvidenceController(EvidenceIngestor ingestor) {
        this.ingestor = ingestor;
    }

    @PostMapping("/aggregate")
    public ResponseEntity<AggregatedEvidence> aggregate(@RequestBody List<EvidenceFragment> fragments) {
        return ResponseEntity.ok(ingestor.aggregate(fragments));
    }
}
