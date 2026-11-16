package io.github.xlsarath.superduperdrive.web;

import io.github.xlsarath.superduperdrive.crypto.suite.HybridAesGcmSuiteV1;
import io.github.xlsarath.superduperdrive.crypto.suite.LegacyAesEcbCredentialSuite;
import io.github.xlsarath.superduperdrive.domain.Credential;
import io.github.xlsarath.superduperdrive.domain.UserAccount;
import io.github.xlsarath.superduperdrive.repository.CredentialRepository;
import io.github.xlsarath.superduperdrive.repository.NoteRepository;
import io.github.xlsarath.superduperdrive.repository.UserAccountRepository;
import io.github.xlsarath.superduperdrive.security.DriveUserDetails;
import io.github.xlsarath.superduperdrive.security.KeyUnlockingSuccessHandler;
import io.github.xlsarath.superduperdrive.support.TestUsers;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.flash;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Security configuration, login with key unlocking, legacy upgrade and HTTP-level protections. */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class WebSecurityTest {

    @Autowired
    MockMvc mvc;
    @Autowired
    TestUsers testUsers;
    @Autowired
    UserAccountRepository users;
    @Autowired
    CredentialRepository credentials;
    @Autowired
    NoteRepository notes;

    @Test
    void anonymousUsersOnlyReachPublicPages() throws Exception {
        for (String path : List.of("/files", "/notes", "/credentials", "/security", "/")) {
            mvc.perform(get(path)).andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrlPattern("**/login"));
        }
        mvc.perform(get("/login")).andExpect(status().isOk());
        mvc.perform(get("/signup")).andExpect(status().isOk());
        mvc.perform(get("/recover")).andExpect(status().isOk());
        mvc.perform(get("/actuator/health")).andExpect(status().isOk());
    }

    @Test
    void responsesCarryStrictSecurityHeaders() throws Exception {
        mvc.perform(get("/login"))
                .andExpect(header().string("Content-Security-Policy", containsString("default-src 'self'")))
                .andExpect(header().string("Content-Security-Policy", containsString("frame-ancestors 'none'")))
                .andExpect(header().string("Content-Security-Policy", containsString("script-src 'self'")))
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("Referrer-Policy", "no-referrer"))
                .andExpect(header().string("Cross-Origin-Opener-Policy", "same-origin"))
                .andExpect(header().string("Cache-Control", containsString("no-store")));
    }

    @Test
    void hstsIsSentOverHttps() throws Exception {
        mvc.perform(get("/login").secure(true))
                .andExpect(header().string("Strict-Transport-Security", containsString("max-age=31536000")));
    }

    @Test
    void stateChangingRequestsRequireCsrfTokens() throws Exception {
        // Without a session, a missing token is handled as an expired session (Spring Security's
        // InvalidSessionAccessDeniedHandler): the request is refused and nothing is created.
        mvc.perform(post("/signup").param("firstName", "Mallory").param("lastName", "X")
                        .param("username", "mallory").param("password", TestUsers.PASSWORD)
                        .param("confirmPassword", TestUsers.PASSWORD))
                .andExpect(redirectedUrl("/login?expired"));
        assertThat(users.existsByUsername("mallory")).isFalse();
        String username = registerUser();
        MockHttpSession session = login(username);
        // Missing token: treated as an expired session; a forged token: 403. Nothing is stored either way.
        mvc.perform(post("/notes").session(session).param("title", "x").param("body", "y"))
                .andExpect(redirectedUrl("/login?expired"));
        mvc.perform(post("/notes").session(session).with(csrf().useInvalidToken())
                        .param("title", "x").param("body", "y"))
                .andExpect(status().isForbidden());
        assertThat(notes.countByOwnerId(users.findByUsername(username).orElseThrow().getId())).isZero();
    }

    @Test
    void signupShowsTheRecoveryKeyOnceAndValidatesInput() throws Exception {
        String username = TestUsers.uniqueUsername();
        mvc.perform(post("/signup").with(csrf())
                        .param("firstName", "Ada").param("lastName", "Lovelace").param("username", username)
                        .param("password", TestUsers.PASSWORD).param("confirmPassword", TestUsers.PASSWORD))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("id=\"recovery-key\"")));
        mvc.perform(post("/signup").with(csrf())
                        .param("firstName", "Ada").param("lastName", "Lovelace").param("username", username)
                        .param("password", "short").param("confirmPassword", "other"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("12 to 128 characters")))
                .andExpect(content().string(containsString("do not match")));
    }

    @Test
    void loginUnlocksKeysAndLogoutWipesThem() throws Exception {
        String username = registerUser();
        MvcResult result = mvc.perform(post("/login").with(csrf())
                        .param("username", username).param("password", TestUsers.PASSWORD))
                .andExpect(redirectedUrl("/files")).andReturn();
        MockHttpSession session = (MockHttpSession) result.getRequest().getSession();
        mvc.perform(get("/files").session(session)).andExpect(status().isOk());

        mvc.perform(post("/logout").with(csrf()).session(session)).andExpect(redirectedUrl("/login?logout"));
        assertThat(session.isInvalid()).isTrue();
    }

    @Test
    void authenticatedSessionWithoutKeysIsSentBackToLogin() throws Exception {
        UserAccount account = users.findByUsername(registerUser()).orElseThrow();
        DriveUserDetails principal = new DriveUserDetails(account.getId(), account.getUsername(), null, true);
        mvc.perform(get("/files").with(authentication(
                        UsernamePasswordAuthenticationToken.authenticated(principal, null, principal.getAuthorities()))))
                .andExpect(redirectedUrl("/login?expired"));
    }

    @Test
    void repeatedFailuresLockTheAccountWithoutRevealingIt() throws Exception {
        String username = registerUser();
        for (int i = 0; i < 5; i++) {
            mvc.perform(post("/login").with(csrf()).param("username", username).param("password", "wrong-" + i))
                    .andExpect(redirectedUrl("/login?error"));
        }
        // Even the right password is refused while locked, with the same generic message.
        mvc.perform(post("/login").with(csrf()).param("username", username).param("password", TestUsers.PASSWORD))
                .andExpect(redirectedUrl("/login?error"));
        assertThat(users.findByUsername(username).orElseThrow().isLockedAt(java.time.Instant.now())).isTrue();
    }

    @Test
    void legacyAccountsAreUpgradedAtFirstLogin() throws Exception {
        String username = "legacy" + System.nanoTime() % 100_000;
        UserAccount legacy = users.saveAndFlush(new UserAccount(UUID.randomUUID(), username,
                "{legacy-pbkdf2-sha1}3JtJsoXJ9Q94vScIO8l2Gw==$0f0aJ9fyQzEQU4ORvcxztg==", "Grace", "Hopper"));
        Credential ecb = credentials.saveAndFlush(Credential.legacy(UUID.randomUUID(), legacy.getId(),
                LegacyAesEcbCredentialSuite.ID, "https://example.org", "grace", "kh1dzoGmM40lvT8+GnvE8Q==",
                "HUQHSPSbVLk92JyMNQgCF/7zIYsyJpm8erP3jnK2P9E="));

        MvcResult result = mvc.perform(post("/login").with(csrf())
                        .param("username", username).param("password", "grace-hopper-1906"))
                .andExpect(redirectedUrl("/account/recovery-key")).andReturn();
        MockHttpSession session = (MockHttpSession) result.getRequest().getSession();
        assertThat(session.getAttribute(KeyUnlockingSuccessHandler.PENDING_RECOVERY_KEY)).isNotNull();

        UserAccount upgraded = users.findById(legacy.getId()).orElseThrow();
        assertThat(upgraded.getPasswordHash()).startsWith("{argon2}");
        assertThat(upgraded.hasKeys()).isTrue();
        Credential migrated = credentials.findById(ecb.getId()).orElseThrow();
        assertThat(migrated.getSuiteId()).isEqualTo(HybridAesGcmSuiteV1.ID);
        assertThat(migrated.getMigratedFromSuite()).contains(LegacyAesEcbCredentialSuite.ID);

        mvc.perform(get("/account/recovery-key").session(session))
                .andExpect(status().isOk()).andExpect(content().string(containsString("id=\"recovery-key\"")));
        // Shown once only.
        mvc.perform(get("/account/recovery-key").session(session)).andExpect(redirectedUrl("/files"));
        mvc.perform(post("/credentials/{id}/reveal", ecb.getId()).with(csrf()).session(session))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", containsString("no-store")))
                .andExpect(jsonPath("$.password").value("cobol-forever-1959"));
    }

    @Test
    void downloadsAreForcedAttachmentsAndForeignOrMalformedIdsAre404() throws Exception {
        MockHttpSession ada = login(registerUser());
        MockHttpSession grace = login(registerUser());
        mvc.perform(multipart("/files").file(new MockMultipartFile("file", "page.html", "text/html",
                        "<script>alert(1)</script>".getBytes())).with(csrf()).session(ada))
                .andExpect(redirectedUrl("/files")).andExpect(flash().attributeExists("flashSuccess"));
        String html = mvc.perform(get("/files").session(ada)).andReturn().getResponse().getContentAsString();
        assertThat(html).contains("Verified · ML-DSA-65");
        String id = html.replaceAll("(?s).*?/files/([0-9a-f-]{36})/download.*", "$1");

        mvc.perform(get("/files/{id}/download", id).session(ada))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/octet-stream"))
                .andExpect(header().string("Content-Disposition", containsString("attachment")))
                .andExpect(header().string("Content-Security-Policy", containsString("sandbox")));
        mvc.perform(get("/files/{id}/download", id).session(grace)).andExpect(status().isNotFound());
        mvc.perform(get("/files/not-a-uuid/download").session(ada)).andExpect(status().isNotFound());
        mvc.perform(post("/notes/{id}/delete", UUID.randomUUID()).with(csrf()).session(ada))
                .andExpect(status().isNotFound());
    }

    @Test
    void invalidFormsAreRejectedWithMessages() throws Exception {
        MockHttpSession session = login(registerUser());
        mvc.perform(post("/notes").with(csrf()).session(session).param("title", "").param("body", "x"))
                .andExpect(redirectedUrl("/notes"))
                .andExpect(flash().attribute("flashError", containsString("needs a title")));
        mvc.perform(post("/credentials").with(csrf()).session(session)
                        .param("url", "example.com").param("username", "ada").param("password", ""))
                .andExpect(flash().attribute("flashError", containsString("Enter a password")));
        mvc.perform(multipart("/files").file(new MockMultipartFile("file", "empty.txt", "text/plain", new byte[0]))
                        .with(csrf()).session(session))
                .andExpect(flash().attribute("flashError", containsString("non-empty")));
    }

    private String registerUser() {
        String username = TestUsers.uniqueUsername();
        testUsers.register(username);
        return username;
    }

    private MockHttpSession login(String username) throws Exception {
        MvcResult result = mvc.perform(post("/login").with(csrf())
                .param("username", username).param("password", TestUsers.PASSWORD)).andReturn();
        return (MockHttpSession) result.getRequest().getSession();
    }
}
