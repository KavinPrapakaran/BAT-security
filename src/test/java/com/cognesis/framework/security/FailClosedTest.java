package com.cognesis.framework.security;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * With no API keys configured the service must fail CLOSED: every protected
 * endpoint rejects even the default posture requests. This guards against a
 * misconfigured deployment silently opening the API.
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = "cognesis.security.api-keys=")
class FailClosedTest {

    @Autowired
    MockMvc mockMvc;

    @Test
    void apiEndpointIsLockedWithoutConfiguredKeys() throws Exception {
        mockMvc.perform(get("/api/v1/dashboard"))
                .andExpect(status().isForbidden());
    }

    @Test
    void anyPresentedKeyIsRejectedWhenNoneAreConfigured() throws Exception {
        mockMvc.perform(get("/api/v1/dashboard")
                        .header("X-API-Key", "anything-at-all"))
                .andExpect(status().isForbidden());
    }

    @Test
    void actuatorProtectedEndpointIsLockedToo() throws Exception {
        mockMvc.perform(get("/actuator/metrics"))
                .andExpect(status().isForbidden());
    }
}
