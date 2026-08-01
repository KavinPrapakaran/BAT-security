package com.cognesis.framework.dns;

import java.time.Instant;
import java.util.Map;

/**
 * A DNS resolution request that triggers a cognitive decision.
 *
 * @param domain         fully qualified domain to resolve
 * @param requestingUser principal requesting resolution
 * @param sourceIp       network origin of the request
 * @param clientApp      application that issued the request
 * @param context        free-form situational context (device, geolocation, ...)
 */
public record DnsResolutionRequest(
        String domain,
        String requestingUser,
        String sourceIp,
        String clientApp,
        Map<String, String> context) {

    public DnsResolutionRequest {
        context = context != null ? Map.copyOf(context) : Map.of();
    }

    public static DnsResolutionRequest of(String domain, String user, String ip) {
        return new DnsResolutionRequest(domain, user, ip, "browser", Map.of());
    }
}
