package io.github.xlsarath.superduperdrive.e2e;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.openqa.selenium.By;
import org.openqa.selenium.OutputType;
import org.openqa.selenium.TakesScreenshot;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

/**
 * Captures the README screenshots from a running instance seeded with fake data. Opt-in only:
 *
 * <pre>
 * ./mvnw spring-boot:run -Dspring-boot.run.profiles=demo        # terminal 1
 * ./mvnw test-compile failsafe:integration-test -Dit.test=ScreenshotTourIT \
 *     -Dsdd.screenshots.baseUrl=http://localhost:8085            # terminal 2 (fresh ./data)
 * </pre>
 */
@EnabledIfSystemProperty(named = "sdd.screenshots.baseUrl", matches = "https?://.+")
class ScreenshotTourIT {

    private static final Path OUT = Path.of("docs", "screenshots");
    private static final String USERNAME = "ada";
    private static final String PASSWORD = "ada-lovelace-1815";

    @Test
    void captureTour() throws Exception {
        Files.createDirectories(OUT);
        Path samples = Files.createTempDirectory("sdd-samples");
        try (Browser browser = new Browser(System.getProperty("sdd.screenshots.baseUrl"), null)) {
            browser.open("/login");
            browser.visible(By.id("inputUsername"));
            shot(browser, "01-login");

            browser.open("/signup");
            browser.type(By.id("inputFirstName"), "Ada");
            browser.type(By.id("inputLastName"), "Lovelace");
            browser.type(By.id("inputUsername"), USERNAME);
            browser.type(By.id("inputPassword"), PASSWORD);
            browser.type(By.id("inputConfirmPassword"), PASSWORD);
            shot(browser, "02-signup");
            browser.submit(By.id("buttonSignUp"));
            browser.visible(By.id("recovery-key"));
            shot(browser, "03-recovery-key");

            browser.logIn(USERNAME, PASSWORD);
            browser.waitForPath("/files");
            for (Map.Entry<String, String> sample : sampleFiles().entrySet()) {
                Path file = samples.resolve(sample.getKey());
                Files.writeString(file, sample.getValue());
                browser.visible(By.id("fileUpload")).sendKeys(file.toAbsolutePath().toString());
                browser.submit(By.id("upload-button"));
            }
            browser.open("/files");
            browser.visible(By.cssSelector("#fileTable .verified-badge"));
            shot(browser, "04-files-verified");

            browser.open("/notes");
            addNote(browser, "Note G", "Diagram for the computation of Bernoulli numbers by the Analytical Engine.");
            addNote(browser, "Reading list", "Menabrea's memoir (1842), translated with notes A to G.");
            browser.open("/notes");
            shot(browser, "05-notes");

            browser.open("/credentials");
            browser.click(By.id("add-credential-button"));
            browser.type(By.id("credential-url"), "https://example.com/login");
            browser.type(By.id("credential-username"), "ada");
            browser.type(By.id("credential-password"), "poetical-science-1843");
            browser.submit(By.id("credential-save"));
            browser.click(By.id("add-credential-button"));
            browser.type(By.id("credential-url"), "https://mail.example.com");
            browser.type(By.id("credential-username"), "ada.lovelace");
            browser.type(By.id("credential-password"), "enchantress-of-numbers");
            browser.submit(By.id("credential-save"));
            browser.open("/credentials");
            browser.visible(By.cssSelector("#credentialTable .credential-password"));
            shot(browser, "06-credentials-encrypted");
            browser.click(By.cssSelector("#credentialTable .reveal-credential"));
            browser.waitUntil(d -> !d.findElement(By.cssSelector("#credentialTable .credential-revealed")).getText().isBlank());
            shot(browser, "07-credentials-revealed");

            browser.open("/security");
            browser.visible(By.id("suiteTable"));
            shot(browser, "08-security");
            browser.logOut();

            // The seeded 2020-era account (demo profile): migrated from AES-ECB at this login.
            browser.logIn("grace", "grace-hopper-1906");
            browser.waitForPath("/account/recovery-key");
            browser.click(By.id("continue-link"));
            browser.open("/security");
            browser.visible(By.id("securityTable"));
            shot(browser, "09-security-migrated");
            browser.logOut();

            Path report = writeTestReport(samples.resolve("test-report.html"));
            browser.driver.get(report.toUri().toString());
            browser.visible(By.id("summary"));
            shot(browser, "10-test-results");
        } finally {
            try (Stream<Path> files = Files.walk(samples)) {
                files.sorted(java.util.Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
            }
        }
    }

    private static void addNote(Browser browser, String title, String body) {
        browser.click(By.id("add-note-button"));
        browser.type(By.id("note-title"), title);
        browser.type(By.id("note-description"), body);
        browser.submit(By.id("note-save"));
    }

    private static Map<String, String> sampleFiles() {
        Map<String, String> files = new java.util.LinkedHashMap<>();
        files.put("analytical-engine-notes.md", "# Notes\n\nThe engine weaves algebraic patterns.\n");
        files.put("bernoulli-numbers.csv", "n,B_n\n0,1\n1,-1/2\n2,1/6\n4,-1/30\n");
        files.put("difference-engine-plan.txt", "Columns: 7. Digits per column: 31.\n");
        return files;
    }

    private static void shot(Browser browser, String name) throws IOException {
        byte[] png = ((TakesScreenshot) browser.driver).getScreenshotAs(OutputType.BYTES);
        Files.write(OUT.resolve(name + ".png"), png);
    }

    /** Renders the surefire and failsafe XML reports of the last build as a small HTML summary. */
    private static Path writeTestReport(Path target) throws Exception {
        record Suite(String name, int tests, int failures, int skipped, double seconds) {
        }
        List<Suite> suites = new ArrayList<>();
        for (String dir : List.of("target/surefire-reports", "target/failsafe-reports")) {
            Path reports = Path.of(dir);
            if (!Files.isDirectory(reports)) {
                continue;
            }
            try (Stream<Path> xml = Files.list(reports)) {
                for (Path file : xml.filter(p -> p.getFileName().toString().matches("TEST-.*\\.xml")).sorted().toList()) {
                    Element suite = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(file.toFile())
                            .getDocumentElement();
                    String name = suite.getAttribute("name").replace("io.github.xlsarath.superduperdrive.", "");
                    if (name.endsWith("ScreenshotTourIT")) {
                        continue;
                    }
                    suites.add(new Suite(name, Integer.parseInt(suite.getAttribute("tests")),
                            Integer.parseInt(suite.getAttribute("failures")) + Integer.parseInt(suite.getAttribute("errors")),
                            Integer.parseInt(suite.getAttribute("skipped")), Double.parseDouble(suite.getAttribute("time"))));
                }
            }
        }
        int total = suites.stream().mapToInt(Suite::tests).sum();
        int failed = suites.stream().mapToInt(Suite::failures).sum();
        StringBuilder rows = new StringBuilder();
        for (Suite s : suites) {
            rows.append("<tr><td>").append(s.name()).append("</td><td>").append(s.tests()).append("</td><td>")
                    .append(s.failures() == 0 ? "<span class=ok>passed</span>" : "<span class=bad>" + s.failures() + " failed</span>")
                    .append("</td><td>").append(String.format("%.2f s", s.seconds())).append("</td></tr>");
        }
        String html = """
                <!doctype html><html><head><meta charset="utf-8"><title>Test results</title><style>
                body{font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif;margin:32px 48px;color:#1f2933;background:#f7f8fa}
                h1{font-size:22px;margin:0 0 4px} p{margin:0 0 16px;color:#52606d}
                #summary{display:inline-block;padding:6px 12px;border-radius:6px;background:#e3f9e5;color:#0e5e2b;font-weight:600}
                table{border-collapse:collapse;width:100%%;background:#fff;border:1px solid #e4e7eb;border-radius:8px;margin-top:16px}
                th,td{text-align:left;padding:5px 12px;border-bottom:1px solid #eef0f2;font-size:13px}
                th{background:#f0f4f8;font-weight:600} .ok{color:#0e7c3a;font-weight:600} .bad{color:#b42318;font-weight:600}
                </style></head><body><h1>SuperDuperDrive &middot; ./mvnw verify</h1>
                <p>JUnit 5 unit, slice and integration tests, plus Selenium 4 end-to-end tests in headless Chrome.</p>
                <div id="summary">%d tests &middot; %d failed &middot; %d suites</div>
                <table><thead><tr><th>Suite</th><th>Tests</th><th>Result</th><th>Time</th></tr></thead><tbody>%s</tbody></table>
                </body></html>""".formatted(total, failed, suites.size(), rows);
        Files.writeString(target, html, StandardCharsets.UTF_8);
        return target;
    }
}
