package br.com.alphatecti.security.jwt.example;

import java.util.Collections;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;

import br.com.alphatecti.security.base.util.ReflectionUtils;
import br.com.alphatecti.security.jwt.example.config.MultipleAuthProviderSecurityConfig;
import br.com.alphatecti.security.jwt.example.util.ExternalTokenAutomation;
import br.com.alphatecti.security.jwt.parser.JWTInternalTokenParser;
import br.com.alphatecti.security.jwt.util.JWTTokenGenerator;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public abstract class BaseSecurityTests {

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    protected MultipleAuthProviderSecurityConfig authConfig;

    protected static final String VALID_USER = "memuser";

    protected static final String VALID_PASSWORD = "pass";

    protected static final String INVALID_USER = "nouser";

    protected static final String INVALID_PASSWORD = "bad_password";

    protected static final long EXPIRATION_TIME = 860_000_000;

    protected static final long CACHE_EXPIRATION_TIME = 30;

    protected static final long EXPIRATED_TIME = -1000;

    protected static final String SECRET = "MySecret";

    protected static final String WRONG_SECRET = "WrongKey";

    protected static final String TOKEN_PREFIX = "Bearer";

    protected static final String HEADER_STRING = "Authorization";

    // EXTERNAL TOKENS, SHOULD BE READ BY AUTOMATION
    protected static boolean wasExternalTokenRead = false;
    protected static String externalValidToken;
    protected static final String EXTERNAL_URL = "https://www.instagram.com/direct/inbox/";
    protected static final String EXTERNAL_LOGIN_URL = "https://www.instagram.com/";
    protected static final String EXTERNAL_LOGIN_USERNAME = "externaljwt";
    protected static final String EXTERNAL_LOGIN_PASSWORD = "Instagram123";
    protected static final String EXTERNAL_INVALID_TOKEN = "invalid.eyJzdWIiOiJJVmRRRkdiaVF2ZXN3OFo0bHBnckpnIiwiaXNzIjoiSVZkUUZHYmlRdmVzdzhaNGxwZ3JKZyIsImlhdCI6MTU5NjEzNTQxNiwianRpIjoiNGQ0ZWMwN2MtY2QxMi00ODMxLWJkYmMtMmUzYTJiZTM3NDMwIn0.L0WMLmVQalolPXBdZDS40LwOYQp4jxyJdnyKl5weGjvmMfAN2ouAUewNbFENmyRg6iv0EqpKf0dbwOlMqHsOJAuD0TXf47rPbv5YJeYKKMfibmwKsVVIEcryUWgbeWhQBwVtCremGYFY1KFMJj1MefHfTmHJ3k5uPzP5K1zT1jz8DqNltTip2v7j5E9BMK9zMmxWBt4a5EZ2HQb3lR_Sx7qZQS-TTpUO2j2EcdMOBcAlrIB572Kc5fkWf0duRMsxzlHJQj7F8ecvoQbWWO2UWFhdA5FY5V8E7vKVi9DkTTggxioTymqQWwfUlO9LS7yXUeG54o5w60NQnRtQ86e-sg";

    /**
     * Method required to be called by all tests for external token scenarios
     */
    protected static void prepareValidJWTExternalToken() {
        ExternalTokenAutomation externalTokenAutomation = new ExternalTokenAutomation();
        String externalToken = externalTokenAutomation.retrieveWorkspacesToken(EXTERNAL_LOGIN_URL, EXTERNAL_LOGIN_USERNAME, EXTERNAL_LOGIN_PASSWORD);
        if (externalToken != null) {
            wasExternalTokenRead = true;
            log.debug("External token got:" + wasExternalTokenRead);
            externalValidToken = externalToken;
        }
    }

    /**
     * Method to kill the spring container in order to start a new configuration in next test
     */
    protected static void killsSpringApplicationContext() {
        try {
            System.out.println("***AFTER ALL ---> KILLING SPRING CONTEXT ***");
            ConfigurableApplicationContext ctx = new SpringApplicationBuilder(SecurityPocApplication.class).web(WebApplicationType.NONE).run();
            SpringApplication.exit(ctx, () -> 0);
        } catch (Exception e) {
            // ignore exception
            log.error("Error killing spring context application", e);
        }
    }

    protected ResponseEntity<String> makeRestCallWithUser(String endpoint, String username, String password) {
        return getRestTemplate().withBasicAuth(username, password).getForEntity(endpoint, String.class, Collections.emptyMap());
    }

    protected ResponseEntity<String> makeRestCall(String endpoint) {
        return getRestTemplate().getForEntity(endpoint, String.class, Collections.emptyMap());
    }

    protected ResponseEntity<String> makeRestCallWithHeaders(String endpoint, HttpHeaders headers) {
        HttpEntity<String> entity = new HttpEntity<String>("parameters", headers);
        ResponseEntity<String> response = getRestTemplate().exchange(endpoint, HttpMethod.GET, entity, String.class);
        return response;
    }

    protected HttpHeaders getHeaderWithValidJWTInternalToken(String subject) {
        String jwtToken = JWTTokenGenerator.getJWTToken(SECRET, EXPIRATION_TIME, subject);
        return createHeaderWithToken(jwtToken);
    }

    protected HttpHeaders getHeaderWithExpiredJWTInternalToken(String subject) {
        String jwtToken = JWTTokenGenerator.getJWTToken(SECRET, EXPIRATED_TIME, subject);
        return createHeaderWithToken(jwtToken);
    }

    protected HttpHeaders getHeaderWithValidJWTExternalToken() {
        return createHeaderWithToken(externalValidToken);
    }

    protected HttpHeaders getHeaderWithInvalidJWTExternalToken() {
        return createHeaderWithToken(EXTERNAL_INVALID_TOKEN);
    }

    /**
     * Generates a token with an invalid key
     */
    protected HttpHeaders getHeaderWithWrongKeyJWTInternalToken(String subject) throws ReflectiveOperationException {
        // force to reload the wrong key
        ReflectionUtils.setFinalStaticField(JWTInternalTokenParser.class, "secretKey", null);
        String jwtToken = JWTTokenGenerator.getJWTToken(WRONG_SECRET, EXPIRATED_TIME, subject);
        // force jwt to use right key
        ReflectionUtils.setFinalStaticField(JWTInternalTokenParser.class, "secretKey", null);
        // create a new token with the right key just to initialize it
        JWTTokenGenerator.getJWTToken(SECRET, EXPIRATED_TIME, subject);
        // return token generated with the wrong key
        return createHeaderWithToken(jwtToken);
    }

    /**
     * Internal method to create a http header
     */
    private HttpHeaders createHeaderWithToken(String jwtToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.add(HEADER_STRING, TOKEN_PREFIX + " " + jwtToken);
        return headers;
    }

    /**
     * Get rest template to be used for testing Usefull if want to put special config on it
     */
    private TestRestTemplate getRestTemplate() {
        return restTemplate;
    }
}
