package com.cognesis.framework.api;

import com.cognesis.framework.feed.ThreatFeedIngestor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Admin endpoint to trigger a threat-intel feed refresh (abuse.ch etc.).
 * Requires a configured feed URL; returns the number of IOCs ingested.
 */
@RestController
@RequestMapping("/api/v1/feeds")
public class FeedController {

    private final ThreatFeedIngestor ingestor;

    public FeedController(ThreatFeedIngestor ingestor) {
        this.ingestor = ingestor;
    }

    @PostMapping("/refresh")
    public ResponseEntity<Map<String, Object>> refresh() {
        int ingested = ingestor.refresh();
        return ResponseEntity.accepted().body(Map.of(
                "status", "accepted",
                "iocsIngested", ingested));
    }
}
