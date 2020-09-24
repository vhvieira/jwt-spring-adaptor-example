package br.com.alphatecti.security.jwt.example.util;

import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.openqa.selenium.By;
import org.openqa.selenium.Cookie;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;

import lombok.extern.slf4j.Slf4j;

/**
 * Automation for getting External JWT token from Breeze platform. 
 * NOTE: To make this external unit test working, please download chrome driver from:
 * https://chromedriver.storage.googleapis.com/index.html?path=84.0.4147.30/
 */
@Slf4j
public class ExternalTokenAutomation {

    /**
     * The page in this example has the both fields here to perform login:
     * <input class="login-input" type="text" id="username" name="username" autocomplete="off" placeholder="Username">
     * <input class="login-input" type="password" id="password" name="password" autocomplete="off" placeholder="Password">
     * <button type="submit" id="login-button">SIGN IN</button>
     */
    public String retrieveWorkspacesToken(String externalLoginPage, String username, String password) {
        WebDriver driver = null;
        try {
            // setting the driver executable
            System.setProperty("webdriver.chrome.driver", ".\\driver\\chromedriver.exe");

            // Driver configuration
            ChromeOptions chromeOptions = new ChromeOptions();
            chromeOptions.addArguments("ignore-certificate-errors");
            chromeOptions.addArguments("--test-type");

            // Initiating your chromedriver
            driver = new ChromeDriver(chromeOptions);
            // open browser with desried URL
            driver.get(externalLoginPage);

            // Applied wait time
            driver.manage().timeouts().pageLoadTimeout(10, TimeUnit.SECONDS);
            WebElement usernameInput = driver.findElement(By.id("email"));
            WebElement passwordInput = driver.findElement(By.id("password"));
            WebElement loginButton = driver.findElement(By.xpath("@type='submit'"));
            usernameInput.sendKeys(username);
            passwordInput.sendKeys(password);
            loginButton.click();
            driver.manage().timeouts().pageLoadTimeout(10, TimeUnit.SECONDS);
            Set<Cookie> cookies = driver.manage().getCookies();
            String jwtToken = getJWTTokenFromCookies(cookies);
            log.info("JWT external token retrieved: " + jwtToken);
            
            return jwtToken;
            
        } catch (Exception ex) {
            log.error("Error retrieving JWT external token, pls check configuration");
            log.error("Exception details", ex);
            return null;
        } finally {
            // closing the browser
            if (driver != null) {
                driver.close();
            }
        }

    }

    /**
     * Finds JWT value inside the cookie
     */
    private String getJWTTokenFromCookies(Set<Cookie> cookies) {
        for (Cookie cookie : cookies) {
            if (cookie.getName().equals("ssm_au_c")) {
                return cookie.getValue().substring("Bearer".length()).trim();
            }
        }

        // not found
        return null;
    }
}