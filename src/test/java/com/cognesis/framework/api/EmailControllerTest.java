package com.cognesis.framework.api;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class EmailControllerTest {

    @Autowired
    MockMvc mockMvc;

    @Test
    void emailEvaluateBlocksPhishingPayload() throws Exception {
        mockMvc.perform(post("/api/v1/email/evaluate")
                        .header("Authorization", "Bearer cognesis-test-key-1")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "messageId": "msg-002",
                                  "recipient": "alice@corp.example.com",
                                  "clientIp": "203.0.113.9"
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.decision").value("BLOCK"))
                .andExpect(jsonPath("$.outcome.riskScore").isNumber())
                .andExpect(jsonPath("$.outcome.decisionId").isNotEmpty());
    }

    @Test
    void emailEvaluateAllowsAuthenticatedMail() throws Exception {
        mockMvc.perform(post("/api/v1/email/evaluate")
                        .header("Authorization", "Bearer cognesis-test-key-1")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "messageId": "msg-001",
                                  "recipient": "alice@corp.example.com",
                                  "clientIp": "198.51.100.10"
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.decision").exists());
    }
}
