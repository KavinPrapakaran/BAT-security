package com.cognesis.framework.feed;

import com.cognesis.framework.config.CognesisProperties;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Periodically refreshes the threat-intel feed so IOC coverage stays current
 * between on-demand refreshes. No-op when the feed is disabled; refresh runs
 * are guarded and time-boxed by the ingestor itself.
 */
@Component
public class FeedScheduler {

    private final ThreatFeedIngestor ingestor;
    private final CognesisProperties props;

    public FeedScheduler(ThreatFeedIngestor ingestor, CognesisProperties props) {
        this.ingestor = ingestor;
        this.props = props;
    }

    @Scheduled(fixedDelayString = "${cognesis.feed.refresh-minutes:60}m")
    public void refreshFeed() {
        if (!props.getFeed().isEnabled() || props.getFeed().getUrl().isBlank()) {
            return;
        }
        ingestor.refresh();
    }
}
