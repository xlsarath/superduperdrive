package io.github.xlsarath.superduperdrive.web;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;

@SpringBootTest(properties = "sdd.login.max-attempts-per-ip=3")
@AutoConfigureMockMvc
@ActiveProfiles("test")
class LoginRateLimitTest {

    @Autowired
    MockMvc mvc;

    @Test
    void throttlesGuessingPerClientAddress() throws Exception {
        for (int i = 0; i < 3; i++) {
            mvc.perform(post("/login").with(csrf()).with(from("203.0.113.7"))
                            .param("username", "nobody").param("password", "guess-" + i))
                    .andExpect(redirectedUrl("/login?error"));
        }
        mvc.perform(post("/login").with(csrf()).with(from("203.0.113.7"))
                        .param("username", "nobody").param("password", "guess"))
                .andExpect(redirectedUrl("/login?throttled"))
                .andExpect(header().exists("Retry-After"));
        mvc.perform(post("/recover").with(csrf()).with(from("203.0.113.7")).param("username", "nobody"))
                .andExpect(redirectedUrl("/recover?throttled"));
        mvc.perform(post("/login").with(csrf()).with(from("198.51.100.1"))
                        .param("username", "nobody").param("password", "guess"))
                .andExpect(redirectedUrl("/login?error"));
    }

    private static org.springframework.test.web.servlet.request.RequestPostProcessor from(String address) {
        return request -> {
            request.setRemoteAddr(address);
            return request;
        };
    }
}
