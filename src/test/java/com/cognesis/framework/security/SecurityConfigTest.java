package com.cognesis.framework.security;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class SecurityConfigTest {

    @Autowired
    MockMvc mockMvc;

    @Test
    void healthEndpointIsOpen() throws Exception {
        mockMvc.perform(get("/actuator/health"))
                .andExpect(status().isOk());
    }

    @Test
    void apiEndpointWithoutKeyReturns403() throws Exception {
        mockMvc.perform(get("/api/v1/dashboard"))
                .andExpect(status().isForbidden());
    }

    @Test
    void apiEndpointWithInvalidKeyReturns403() throws Exception {
        mockMvc.perform(get("/api/v1/dashboard")
                        .header("Authorization", "Bearer wrong-key"))
                .andExpect(status().isForbidden());
    }

    @Test
    void apiEndpointWithValidKeyReturns200() throws Exception {
        mockMvc.perform(get("/api/v1/dashboard")
                        .header("Authorization", "Bearer cognesis-test-key-1"))
                .andExpect(status().isOk());
    }

    @Test
    void apiEndpointWithXApiKeyHeaderReturns200() throws Exception {
        mockMvc.perform(get("/api/v1/dashboard")
                        .header("X-API-Key", "cognesis-test-key-1"))
                .andExpect(status().isOk());
    }

    @Test
    void actuatorHealthRequiresNoAuth() throws Exception {
        mockMvc.perform(get("/actuator/health"))
                .andExpect(status().isOk());
    }

    @Test
    void actuatorProtectedEndpointRequiresAuth() throws Exception {
        mockMvc.perform(get("/actuator/metrics"))
                .andExpect(status().isForbidden());
    }

    @Test
    void unauthenticatedPathIsOpen() throws Exception {
        mockMvc.perform(get("/nonexistent"))
                .andExpect(status().isNotFound());
    }
}
