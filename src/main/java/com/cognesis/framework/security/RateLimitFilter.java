package com.cognesis.framework.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Simple, dependency-free fixed-window rate limiter keyed by client IP and
 * authenticated API key. Protects the decision endpoints from abuse while the
 * framework is embedded in front of DNS proxies or SIEMs.
 */
public class RateLimitFilter extends OncePerRequestFilter {

    private static final long WINDOW_MS = 60_000L;

    private final boolean enabled;
    private final int maxPerWindow;
    private final ConcurrentHashMap<String, Window> windows = new ConcurrentHashMap<>();

    public RateLimitFilter(boolean enabled, int maxPerWindow) {
        this.enabled = enabled;
        this.maxPerWindow = maxPerWindow;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        if (enabled && !shouldNotRateLimit(request)) {
            String key = clientKey(request);
            if (isRateLimited(key)) {
                response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                response.setHeader("Retry-After", "60");
                response.setContentType("application/json");
                response.getWriter().write("{\"error\":\"rate_limit_exceeded\"}");
                return;
            }
        }
        filterChain.doFilter(request, response);
    }

    private String clientKey(HttpServletRequest request) {
        String apiKey = request.getHeader("X-API-Key");
        if (apiKey == null || apiKey.isBlank()) {
            String auth = request.getHeader("Authorization");
            if (auth != null && auth.startsWith("Bearer ")) {
                apiKey = auth.substring(7).trim();
            }
        }
        String ip = request.getRemoteAddr();
        return (apiKey == null || apiKey.isBlank()) ? "ip:" + ip : "key:" + apiKey;
    }

    private boolean isRateLimited(String key) {
        Window window = windows.computeIfAbsent(key, k -> new Window());
        return window.acquire() > maxPerWindow;
    }

    private boolean shouldNotRateLimit(HttpServletRequest request) {
        String path = request.getRequestURI();
        return "/actuator/health".equals(path) || "/actuator/info".equals(path);
    }

    /** Sliding one-minute window: each call records a timestamp and drops old ones. */
    private static final class Window {
        private final ConcurrentLinkedQueue<Long> stamps = new ConcurrentLinkedQueue<>();

        int acquire() {
            long now = System.currentTimeMillis();
            stamps.add(now);
            Long oldest;
            while ((oldest = stamps.peek()) != null && now - oldest > WINDOW_MS) {
                stamps.poll();
            }
            return stamps.size();
        }
    }
}
