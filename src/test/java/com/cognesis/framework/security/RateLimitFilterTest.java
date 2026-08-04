package com.cognesis.framework.security;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * The rate limiter protects decision endpoints from abuse. Locked by a sliding
 * one-minute window per API key / IP.
 */
class RateLimitFilterTest {

    @Test
    void allowsRequestsWithinTheWindow() throws Exception {
        RateLimitFilter filter = new RateLimitFilter(true, 3);
        for (int i = 0; i < 3; i++) {
            MockHttpServletResponse response = call(filter, "key-1");
            assertEquals(200, response.getStatus(), "requests within the limit must pass");
        }
    }

    @Test
    void rejectsRequestsBeyondTheWindow() throws Exception {
        RateLimitFilter filter = new RateLimitFilter(true, 3);
        for (int i = 0; i < 3; i++) {
            call(filter, "key-1");
        }
        MockHttpServletResponse fourth = call(filter, "key-1");
        assertEquals(429, fourth.getStatus(), "the fourth request in a window must be rate limited");
        assertEquals("60", fourth.getHeader("Retry-After"));
    }

    @Test
    void clientsAreLimitedIndependently() throws Exception {
        RateLimitFilter filter = new RateLimitFilter(true, 2);
        call(filter, "client-a");
        call(filter, "client-a");
        assertEquals(429, call(filter, "client-a").getStatus());
        assertEquals(200, call(filter, "client-b").getStatus(), "a different client must be unaffected");
    }

    @Test
    void disabledFilterNeverLimits() throws Exception {
        RateLimitFilter filter = new RateLimitFilter(false, 2);
        for (int i = 0; i < 5; i++) {
            assertEquals(200, call(filter, "whatever").getStatus());
        }
    }

    @Test
    void healthEndpointIsNeverLimited() throws Exception {
        RateLimitFilter filter = new RateLimitFilter(true, 1);
        for (int i = 0; i < 3; i++) {
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/actuator/health");
            MockHttpServletResponse response = new MockHttpServletResponse();
            filter.doFilter(request, response, new MockFilterChain());
            assertEquals(200, response.getStatus());
        }
    }

    private MockHttpServletResponse call(RateLimitFilter filter, String apiKey) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/dns/evaluate");
        request.addHeader("X-API-Key", apiKey);
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, new MockFilterChain());
        return response;
    }
}
