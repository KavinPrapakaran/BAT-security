package com.cognesis.framework.feed;

import com.cognesis.framework.config.CognesisProperties;
import com.cognesis.framework.persistence.IocStore;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;

/**
 * Surfaces threat-intel feed freshness on the actuator health endpoint. The
 * feed is "down" only when it is enabled but has not been refreshed for more
 * than twice the configured interval — so operators get a visible signal when
 * IOC coverage goes stale without the health check flapping on a single miss.
 */
@Component
public class FeedHealthIndicator implements HealthIndicator {

    private final ThreatFeedIngestor ingestor;
    private final IocStore iocStore;
    private final CognesisProperties props;

    public FeedHealthIndicator(ThreatFeedIngestor ingestor, IocStore iocStore, CognesisProperties props) {
        this.ingestor = ingestor;
        this.iocStore = iocStore;
        this.props = props;
    }

    @Override
    public Health health() {
        if (!props.getFeed().isEnabled() || props.getFeed().getUrl().isBlank()) {
            return Health.up().withDetail("enabled", false).build();
        }
        Instant last = ingestor.lastRefreshAt();
        long iocCount = iocStore.total();
        if (last == null) {
            return Health.down()
                    .withDetail("enabled", true)
                    .withDetail("iocs", iocCount)
                    .withDetail("detail", "feed never refreshed")
                    .build();
        }
        Duration age = Duration.between(last, Instant.now());
        long refreshMinutes = props.getFeed().getRefreshMinutes();
        boolean stale = age.toMinutes() > 2 * Math.max(1, refreshMinutes);
        Health.Builder h = stale ? Health.down() : Health.up();
        return h
                .withDetail("enabled", true)
                .withDetail("iocs", iocCount)
                .withDetail("lastRefreshSecondsAgo", age.getSeconds())
                .withDetail("lastIngested", ingestor.lastIngested())
                .build();
    }
}
