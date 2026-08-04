package com.cognesis.framework.api;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class LoreFeedbackControllerTest {

    @Autowired
    MockMvc mockMvc;

    @Test
    void submitFeedbackAccepted() throws Exception {
        String body = """
                {
                    "decisionId": "%s",
                    "realizedRisk": 0.85,
                    "wasCorrect": true,
                    "notes": "confirmed malicious"
                }
                """.formatted(UUID.randomUUID());

        mockMvc.perform(post("/api/v1/feedback")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.status").value("accepted"))
                .andExpect(jsonPath("$.realizedRisk").value(0.85))
                .andExpect(jsonPath("$.wasCorrect").value(true));
    }

    @Test
    void submitFeedbackClampsRisk() throws Exception {
        String body = """
                {
                    "decisionId": "%s",
                    "realizedRisk": 1.5,
                    "wasCorrect": false,
                    "notes": "false positive"
                }
                """.formatted(UUID.randomUUID());

        mockMvc.perform(post("/api/v1/feedback")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.realizedRisk").value(1.0));
    }
}
