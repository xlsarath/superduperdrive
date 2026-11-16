package io.github.xlsarath.superduperdrive.e2e;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.io.TempDir;
import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.ActiveProfiles;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The user journey in a real headless Chrome against the real server: signup with recovery key,
 * login, files (encrypted, signed, verified, downloaded), notes, credentials, the Security page,
 * logout and account recovery. Fake data only.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class DriveE2EIT {

    private static final String USERNAME = "ada";
    private static final String PASSWORD = "ada-lovelace-1815";
    private static final String NEW_PASSWORD = "difference-engine-1822";

    @TempDir
    static Path downloads;
    static Browser browser;
    static String recoveryKey;

    @LocalServerPort
    int port;

    @AfterAll
    static void stopBrowser() {
        if (browser != null) {
            browser.close();
        }
    }

    /** Created on first use: the random server port is only known per test instance. */
    private Browser browser() {
        if (browser == null) {
            browser = new Browser("http://localhost:" + port, downloads);
        }
        return browser;
    }

    @Test
    @Order(1)
    void unauthenticatedVisitorsAreSentToLogin() {
        browser().open("/files");
        browser().waitForPath("/login");
        browser().open("/notes");
        browser().waitForPath("/login");
    }

    @Test
    @Order(2)
    void signupShowsAOneTimeRecoveryKeyAndLogsIn() {
        recoveryKey = browser().signUp("Ada", "Lovelace", USERNAME, PASSWORD);
        assertThat(recoveryKey).matches("([A-Z2-7]{4}-){13}[A-Z2-7]{4}");
        browser().click(By.id("continue-link"));
        browser().waitForPath("/login");

        // Login resumes the page last requested while signed out (/notes in the previous test).
        browser().logIn(USERNAME, PASSWORD);
        browser().waitForPath("/notes");
        assertThat(browser().visible(By.id("current-user")).getText()).contains("ada");
    }

    @Test
    @Order(3)
    void uploadedFilesAreVerifiedAndDownloadIntact() throws IOException, InterruptedException {
        Path file = Files.createTempFile("engine-", ".txt");
        Files.writeString(file, "The Analytical Engine weaves algebraic patterns.");
        browser().open("/files");
        browser().visible(By.id("fileUpload")).sendKeys(file.toString());
        browser().submit(By.id("upload-button"));
        browser().visible(By.id("flash-success"));

        WebElement row = browser().visible(By.cssSelector("#fileTable tbody tr"));
        assertThat(row.getText()).contains(file.getFileName().toString());
        assertThat(row.findElement(By.className("verified-badge")).getText()).contains("Verified");

        // Duplicate names are rejected with a message, not an error page.
        browser().visible(By.id("fileUpload")).sendKeys(file.toString());
        browser().submit(By.id("upload-button"));
        assertThat(browser().visible(By.id("flash-error")).getText()).contains("already");

        browser().click(By.cssSelector("#fileTable a[href$='/download']"));
        Path downloaded = downloads.resolve(file.getFileName().toString());
        for (int i = 0; i < 100 && !Files.exists(downloaded); i++) {
            Thread.sleep(100);
        }
        assertThat(downloaded).hasContent("The Analytical Engine weaves algebraic patterns.");
        Files.delete(file);
    }

    @Test
    @Order(4)
    void notesCanBeCreatedEditedAndDeleted() {
        browser().open("/notes");
        browser().click(By.id("add-note-button"));
        browser().type(By.id("note-title"), "Note G");
        browser().type(By.id("note-description"), "An algorithm for Bernoulli numbers.");
        browser().submit(By.id("note-save"));
        browser().visible(By.id("flash-success"));
        assertThat(browser().visible(By.cssSelector("#noteTable .note-title")).getText()).isEqualTo("Note G");

        browser().click(By.cssSelector("#noteTable .edit-note"));
        browser().waitUntil(d -> "Note G".equals(d.findElement(By.id("note-title")).getDomProperty("value")));
        browser().type(By.id("note-title"), "Note G (revised)");
        browser().submit(By.id("note-save"));
        browser().visible(By.id("flash-success"));
        assertThat(browser().visible(By.cssSelector("#noteTable .note-title")).getText()).isEqualTo("Note G (revised)");

        browser().submitConfirmed(By.cssSelector("#noteTable .delete-note"));
        browser().visible(By.id("flash-success"));
        assertThat(browser().driver.findElements(By.cssSelector("#noteTable .note-title"))).isEmpty();
    }

    @Test
    @Order(5)
    void credentialsShowCiphertextUntilRevealed() {
        browser().open("/credentials");
        browser().click(By.id("add-credential-button"));
        browser().type(By.id("credential-url"), "https://example.com");
        browser().type(By.id("credential-username"), "ada");
        browser().type(By.id("credential-password"), "poetical-science");
        browser().submit(By.id("credential-save"));
        browser().visible(By.id("flash-success"));

        WebElement cipher = browser().visible(By.cssSelector("#credentialTable .credential-password"));
        assertThat(cipher.getText()).isNotBlank().doesNotContain("poetical-science");
        browser().click(By.cssSelector("#credentialTable .reveal-credential"));
        browser().waitUntil(d -> "poetical-science".equals(
                d.findElement(By.cssSelector("#credentialTable .credential-revealed")).getText()));
    }

    @Test
    @Order(6)
    void securityPageShowsQuantumSafeSuitesAndReKeys() {
        browser().open("/security");
        List<WebElement> rows = browser().driver.findElements(By.cssSelector("#securityTable tbody tr"));
        assertThat(rows).hasSize(2);
        assertThat(browser().visible(By.id("suiteTable")).getText()).contains("HYB-X25519-MLKEM768-AES256GCM-v1");

        browser().submit(By.cssSelector("#securityTable .rekey-button"));
        assertThat(browser().visible(By.id("flash-success")).getText()).containsIgnoringCase("re-keyed");
    }

    @Test
    @Order(7)
    void logoutEndsTheSession() {
        browser().logOut();
        browser().open("/files");
        browser().waitForPath("/login");
    }

    @Test
    @Order(8)
    void recoveryKeyResetsThePasswordWithoutLosingData() {
        browser().open("/recover");
        browser().type(By.name("username"), USERNAME);
        browser().type(By.name("recoveryKey"), recoveryKey.toLowerCase());
        browser().type(By.name("newPassword"), NEW_PASSWORD);
        browser().type(By.name("confirmPassword"), NEW_PASSWORD);
        browser().submit(By.id("buttonRecover"));
        String rotated = browser().visible(By.id("recovery-key")).getText().trim();
        assertThat(rotated).isNotEqualTo(recoveryKey);

        browser().logIn(USERNAME, PASSWORD);
        browser().visible(By.id("error-msg"));
        browser().logIn(USERNAME, NEW_PASSWORD);
        browser().waitForPath("/files");
        assertThat(browser().visible(By.cssSelector("#fileTable .verified-badge")).isDisplayed()).isTrue();
        browser().open("/credentials");
        browser().click(By.cssSelector("#credentialTable .reveal-credential"));
        browser().waitUntil(d -> "poetical-science".equals(
                d.findElement(By.cssSelector("#credentialTable .credential-revealed")).getText()));
    }
}
