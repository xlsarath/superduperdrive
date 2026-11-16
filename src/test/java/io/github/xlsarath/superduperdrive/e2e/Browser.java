package io.github.xlsarath.superduperdrive.e2e;

import org.openqa.selenium.By;
import org.openqa.selenium.Dimension;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;

import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;

/**
 * Thin page-driver around a headless Chrome. Selenium Manager resolves the matching driver
 * (and, on CI, a Chrome for Testing build) automatically.
 */
final class Browser implements AutoCloseable {

    final WebDriver driver;
    private final WebDriverWait wait;
    private final String baseUrl;

    Browser(String baseUrl, Path downloadDirectory) {
        ChromeOptions options = new ChromeOptions();
        options.addArguments("--headless=new", "--window-size=1440,900", "--force-device-scale-factor=1",
                "--disable-gpu", "--no-sandbox", "--disable-dev-shm-usage", "--blink-settings=preferredColorScheme=1",
                "--lang=en-US");
        if (downloadDirectory != null) {
            options.setExperimentalOption("prefs", Map.of(
                    "download.default_directory", downloadDirectory.toAbsolutePath().toString(),
                    "download.prompt_for_download", false));
        }
        this.driver = new ChromeDriver(options);
        sizeViewport(1440, 900);
        this.wait = new WebDriverWait(driver, Duration.ofSeconds(15));
        this.baseUrl = baseUrl;
    }

    /** Grows the window so that the page viewport (not the window) has exactly this size. */
    private void sizeViewport(int width, int height) {
        driver.get("about:blank");
        JavascriptExecutor js = (JavascriptExecutor) driver;
        long extraWidth = ((Number) js.executeScript("return window.outerWidth - window.innerWidth")).longValue();
        long extraHeight = ((Number) js.executeScript("return window.outerHeight - window.innerHeight")).longValue();
        driver.manage().window().setSize(new Dimension(width + (int) extraWidth, height + (int) extraHeight));
    }

    void open(String path) {
        driver.get(baseUrl + path);
    }

    WebElement visible(By by) {
        return wait.until(ExpectedConditions.visibilityOfElementLocated(by));
    }

    WebElement clickable(By by) {
        return wait.until(ExpectedConditions.elementToBeClickable(by));
    }

    void type(By by, String text) {
        WebElement field = visible(by);
        field.clear();
        field.sendKeys(text);
    }

    void click(By by) {
        clickable(by).click();
    }

    /** Clicks something that submits a form, then waits until the next page has replaced this one. */
    void submit(By by) {
        WebElement page = driver.findElement(By.tagName("html"));
        clickable(by).click();
        wait.until(ExpectedConditions.stalenessOf(page));
    }

    void waitForPath(String path) {
        wait.until(ExpectedConditions.urlMatches(java.util.regex.Pattern.quote(baseUrl + path) + "([?#].*)?$"));
    }

    void waitUntil(java.util.function.Function<WebDriver, Boolean> condition) {
        wait.until(condition::apply);
    }

    /** Fills and submits the signup form; returns the recovery key shown once afterwards. */
    String signUp(String first, String last, String username, String password) {
        open("/signup");
        type(By.id("inputFirstName"), first);
        type(By.id("inputLastName"), last);
        type(By.id("inputUsername"), username);
        type(By.id("inputPassword"), password);
        type(By.id("inputConfirmPassword"), password);
        submit(By.id("buttonSignUp"));
        return visible(By.id("recovery-key")).getText().trim();
    }

    void logIn(String username, String password) {
        open("/login");
        type(By.id("inputUsername"), username);
        type(By.id("inputPassword"), password);
        submit(By.id("submit-button"));
    }

    void logOut() {
        submit(By.id("logout-button"));
        waitForPath("/login");
    }

    /** Clicks a control guarded by a confirm() dialog, accepts it and waits for the next page. */
    void submitConfirmed(By by) {
        WebElement page = driver.findElement(By.tagName("html"));
        clickable(by).click();
        wait.until(ExpectedConditions.alertIsPresent()).accept();
        wait.until(ExpectedConditions.stalenessOf(page));
    }

    @Override
    public void close() {
        driver.quit();
    }
}
