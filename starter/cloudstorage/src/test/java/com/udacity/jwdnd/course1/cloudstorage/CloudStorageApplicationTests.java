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

import java.util.List;

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
		driver.get("http://localhost:" + this.port + "/");
		Assertions.assertEquals("Home", driver.getTitle());
		notes = wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("nav-notes-tab")));
		jse.executeScript("arguments[0].click()", notes);
		WebElement table = wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("userTable")));
		Assertions.assertTrue(table.getText().contains("new-title"));
		Assertions.assertTrue(table.getText().contains("adding-description"));
	}

	@Test
	@Order(7)
	public void updateExistingNotesTest(){
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
		List<WebElement> edit = wait.until(ExpectedConditions.visibilityOfAllElementsLocatedBy(By.className("edit-note-button")));

		if (edit.size() > 0) {
			edit.get(0).click();
			WebElement titleip = wait.until(ExpectedConditions.elementToBeClickable(By.id("note-title")));
			titleip.click();
			titleip.clear();
			titleip.sendKeys("new-title-update");
			WebElement noteDescription = driver.findElement(By.id("note-description"));
			noteDescription.click();
			noteDescription.clear();
			noteDescription.sendKeys("adding-description-update");
			WebElement noteSubmit = wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("saveNoteButton")));
			noteSubmit.click();
			Assertions.assertEquals("Result", driver.getTitle());
			driver.get("http://localhost:" + this.port + "/");
			Assertions.assertEquals("Home", driver.getTitle());
			notes = wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("nav-notes-tab")));
			jse.executeScript("arguments[0].click()", notes);
			WebElement table = wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("userTable")));
			Assertions.assertTrue(table.getText().contains("new-title-update"));
			Assertions.assertTrue(table.getText().contains("adding-description-update"));
		}
	}


	@Test
	@Order(8)
	public void deleteExistingNotesTest(){
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
		List<WebElement> edit = wait.until(ExpectedConditions.visibilityOfAllElementsLocatedBy(By.className("delete-note-button")));

		if (edit.size() > 0) {
			edit.get(0).click();
			Assertions.assertEquals("Result", driver.getTitle());
			driver.get("http://localhost:" + this.port + "/");
			Assertions.assertEquals("Home", driver.getTitle());
			notes = wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("nav-notes-tab")));
			jse.executeScript("arguments[0].click()", notes);
			WebElement table = wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("userTable")));
			Assertions.assertFalse(table.getText().contains("new-title-update"));
		}
	}

	@Test
	@Order(9)
	public void createCredentailTest(){
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

		WebElement notes = wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("nav-credentials-tab")));
		jse.executeScript("arguments[0].click()", notes);
		WebElement addNoteButton = wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("buttonAddNewCredential")));
		addNoteButton.click();
		wait.until(ExpectedConditions.elementToBeClickable(By.id("credential-url"))).sendKeys("www.testurl.com");;
		WebElement noteDescription = driver.findElement(By.id("credential-username"));
		noteDescription.click();
		noteDescription.sendKeys("testuser");
		WebElement credentialPass = driver.findElement(By.id("credential-password"));
		credentialPass.click();
		credentialPass.sendKeys("testpassword");
		WebElement noteSubmit = wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("saveCredentialButton")));
		noteSubmit.click();
		Assertions.assertEquals("Result", driver.getTitle());
		driver.get("http://localhost:" + this.port + "/");
		Assertions.assertEquals("Home", driver.getTitle());
		notes = wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("nav-credentials-tab")));
		jse.executeScript("arguments[0].click()", notes);
		WebElement table = wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("credentialTable")));
		Assertions.assertTrue(table.getText().contains("www.testurl.com"));
		Assertions.assertTrue(table.getText().contains("testuser"));

	}

	@Test
	@Order(10)
	public void updateExistingCredentialsTest(){
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

		WebElement notes = wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("nav-credentials-tab")));
		jse.executeScript("arguments[0].click()", notes);
		List<WebElement> edit = wait.until(ExpectedConditions.visibilityOfAllElementsLocatedBy(By.className("edit-credential-button")));

		if (edit.size() > 0) {
			edit.get(0).click();
			WebElement url = wait.until(ExpectedConditions.elementToBeClickable(By.id("credential-url")));
			url.clear();
			url.sendKeys("www.testurlupdate.com");
			WebElement noteDescription = driver.findElement(By.id("credential-username"));
			noteDescription.click();
			noteDescription.sendKeys("testuserupdate");
			WebElement credentialPass = driver.findElement(By.id("credential-password"));
			credentialPass.clear();
			credentialPass.click();
			credentialPass.sendKeys("testpasswordupdate");
			WebElement noteSubmit = wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("saveCredentialButton")));
			noteSubmit.click();
			Assertions.assertEquals("Result", driver.getTitle());
			driver.get("http://localhost:" + this.port + "/");
			Assertions.assertEquals("Home", driver.getTitle());
			notes = wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("nav-credentials-tab")));
			jse.executeScript("arguments[0].click()", notes);
			WebElement table = wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("credentialTable")));
			Assertions.assertTrue(table.getText().contains("www.testurlupdate.com"));
			Assertions.assertTrue(table.getText().contains("testuserupdate"));
		}
	}


	@Test
	@Order(11)
	public void deleteExistingCredentailsTest(){
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

		WebElement notes = wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("nav-credentials-tab")));
		jse.executeScript("arguments[0].click()", notes);
		List<WebElement> edit = wait.until(ExpectedConditions.visibilityOfAllElementsLocatedBy(By.className("delete-credential-button")));

		if (edit.size() > 0) {
			edit.get(0).click();
			Assertions.assertEquals("Result", driver.getTitle());
			driver.get("http://localhost:" + this.port + "/");
			Assertions.assertEquals("Home", driver.getTitle());
			notes = wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("nav-credentials-tab")));
			jse.executeScript("arguments[0].click()", notes);
			WebElement table = wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("credentialTable")));
			Assertions.assertFalse(table.getText().contains("www.testuserupdate.com"));
		}
	}


}
