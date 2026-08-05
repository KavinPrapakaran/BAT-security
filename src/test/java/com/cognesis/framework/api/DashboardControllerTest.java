package com.cognesis.framework.api;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class DashboardControllerTest {

    @Autowired
    MockMvc mockMvc;

    @Test
    void dashboardReturnsStatusAndWeights() throws Exception {
        mockMvc.perform(get("/api/v1/dashboard")
                        .header("Authorization", "Bearer cognesis-test-key-1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.version").value("1.2.0"))
                .andExpect(jsonPath("$.status").value("RUNNING"))
                .andExpect(jsonPath("$.synapseWeights.evidence").isNumber())
                .andExpect(jsonPath("$.synapseWeights.trust").isNumber())
                .andExpect(jsonPath("$.system.heapUsedMB").isNumber())
                .andExpect(jsonPath("$.system.threadCount").isNumber());
    }
}
