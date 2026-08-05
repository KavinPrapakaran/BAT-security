package com.cognesis.framework.api;

import com.cognesis.framework.memory.MemoryEngine;
import com.cognesis.framework.memory.MemoryIncident;
import com.cognesis.framework.memory.MemoryQuery;
import com.cognesis.framework.memory.MemoryRecall;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Memory endpoints: recall what BAT security remembers about an entity and feed it
 * new incidents to learn from.
 */
@RestController
@RequestMapping("/api/v1/memory")
public class MemoryController {

    private final MemoryEngine memoryEngine;

    public MemoryController(MemoryEngine memoryEngine) {
        this.memoryEngine = memoryEngine;
    }

    @GetMapping("/recall")
    public ResponseEntity<MemoryRecall> recall(@RequestParam String entityId,
                                               @RequestParam(defaultValue = "ENTITY") String entityType) {
        return ResponseEntity.ok(memoryEngine.recall(new MemoryQuery(entityId, entityType)));
    }

    @PostMapping("/incidents")
    public ResponseEntity<Void> memorize(@RequestBody MemoryIncident incident) {
        memoryEngine.memorize(incident);
        return ResponseEntity.accepted().build();
    }
}
