package com.udacity.jwdnd.course1.cloudstorage;

import io.github.bonigarcia.wdm.WebDriverManager;
import org.junit.jupiter.api.*;
import org.openqa.selenium.By;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class CloudStorageApplicationTests {

	@LocalServerPort
	private int port;
	private WebDriver driver;

	@BeforeAll
	static void beforeAll() {
		WebDriverManager.chromedriver().setup();

	}

	@BeforeEach
	public void beforeEach() {
		this.driver = new ChromeDriver();
	}

	@AfterEach
	public void afterEach() {
		if (this.driver != null) {
			driver.quit();
		}
	}

	@Test
	@Order(1)
	public void getLoginPage() {
		driver.get("http://localhost:" + this.port + "/login");
		Assertions.assertEquals("Login", driver.getTitle());
	}

	@Test
	@Order(2)
	public void testSignUp(){
		driver.get("http://localhost:" + this.port + "/");
		driver.manage().window().maximize();
		JavascriptExecutor jse = (JavascriptExecutor) driver;
		WebElement signup = driver.findElement(By.id("signup-link"));
		signup.click();
		Assertions.assertEquals("Sign Up", driver.getTitle());
	}

	@Test
	@Order(3)
	public void signinAttempt(){
		driver.get("http://localhost:" + this.port + "/");
		driver.manage().window().maximize();
		JavascriptExecutor jse = (JavascriptExecutor) driver;
		WebElement signup = driver.findElement(By.id("signup-link"));
		signup.click();
		Assertions.assertEquals("Sign Up", driver.getTitle());

		WebDriverWait holdOnTime = new WebDriverWait (driver, 40);
		WebElement inputFirstName = driver.findElement(By.id("inputFirstName"));
		holdOnTime.until(ExpectedConditions.elementToBeClickable(inputFirstName)).click();
		inputFirstName.sendKeys("Sarath");

		WebElement inputLastName= driver.findElement(By.id("inputLastName"));
		holdOnTime.until(ExpectedConditions.elementToBeClickable(inputLastName)).click();
		inputLastName.sendKeys("chandra");

		WebElement inputUsername= driver.findElement(By.id("inputUsername"));
		holdOnTime.until(ExpectedConditions.elementToBeClickable(inputUsername)).click();
		inputUsername.sendKeys("testuser");

		WebElement inputPassword= driver.findElement(By.id("inputPassword"));
		holdOnTime.until(ExpectedConditions.elementToBeClickable(inputPassword)).click();
		inputPassword.sendKeys("testpassword");

		WebElement signupButton= driver.findElement(By.id("buttonSignUp"));
		holdOnTime.until(ExpectedConditions.elementToBeClickable(signupButton)).click();

		WebElement divSuccess = holdOnTime.until(ExpectedConditions.visibilityOfElementLocated(By.id("success-msg")));
		driver.get(String.format("http://localhost:%s/login", this.port));

		WebElement username = driver.findElement(By.id("inputUsername"));
		holdOnTime.until(ExpectedConditions.elementToBeClickable(username)).click();

		WebElement password = driver.findElement(By.id("inputPassword"));
		holdOnTime.until(ExpectedConditions.elementToBeClickable(password)).click();

		username.sendKeys("testuser");
		password.sendKeys("testpassword");

		WebElement login = driver.findElement(By.id("login-button"));
		login.click();

		Assertions.assertEquals("Home", driver.getTitle());

	}

	@Test
	@Order(4)
	public void generalSignInpostSignupTest(){
		driver.get("http://localhost:" + this.port + "/");
		driver.manage().window().maximize();
		JavascriptExecutor jse =(JavascriptExecutor) driver;
		WebElement username = driver.findElement(By.id("inputUsername"));
		WebElement password = driver.findElement(By.id("inputPassword"));
		username.sendKeys("testuser");
		password.sendKeys("testpassword");
		WebElement login = driver.findElement(By.id("login-button"));
		login.click();
		Assertions.assertEquals("Home", driver.getTitle());
	}

	@Test
	@Order(5)
	public void unauthorizedHomePage() {
		driver.get("http://localhost:" + this.port + "/home.html");
		Assertions.assertEquals("Login", driver.getTitle());
	}

	@Test
	@Order(6)
	public void validLoginAndNoteCreationTest() {
		WebDriverWait wait = new WebDriverWait (driver, 30);
		driver.get("http://localhost:" + this.port + "/");
		driver.manage().window().maximize();
		JavascriptExecutor jse =(JavascriptExecutor) driver;
		WebElement username = driver.findElement(By.id("inputUsername"));
		WebElement password = driver.findElement(By.id("inputPassword"));
		username.sendKeys("testuser");
		password.sendKeys("testpassword");
		WebElement login = driver.findElement(By.id("login-button"));
		login.click();

		WebElement notes = wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("nav-notes-tab")));
		jse.executeScript("arguments[0].click()", notes);

		WebElement addNoteButton = wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("buttonAddNote")));
		addNoteButton.click();

		wait.until(ExpectedConditions.elementToBeClickable(By.id("note-title"))).sendKeys("new-title");;
		WebElement noteDescription = driver.findElement(By.id("note-description"));
		noteDescription.click();
		noteDescription.sendKeys("adding-description");
		WebElement noteSubmit = wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("saveNoteButton")));
		noteSubmit.click();
		Assertions.assertEquals("Result", driver.getTitle());
		driver.get("http://localhost:" + this.port + "/home");
		Assertions.assertEquals("Home", driver.getTitle());
		notes = wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("nav-notes-tab")));
		jse.executeScript("arguments[0].click()", notes);
		System.out.println(notes.getText());
		Assertions.assertTrue(notes.getText().contains("new-title"));
		Assertions.assertTrue(notes.getText().contains("adding-description"));
	}

}
