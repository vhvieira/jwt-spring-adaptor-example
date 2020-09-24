package br.com.alphatecti.security.jwt.example;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;

import br.com.alphatecti.security.base.util.ReflectionUtils;
import br.com.alphatecti.security.jwt.example.config.MultipleAuthProviderSecurityConfig;
import lombok.extern.log4j.Log4j2;

/**
 * Testing with first configuration: --> Memory user enable (isDevelopment = true) --> URLs for external and internal JWT filters are different
 */
@SpringBootTest(webEnvironment = WebEnvironment.DEFINED_PORT)
@Log4j2
public class MultipleAuthProviderSecurityConfigiration01Tests extends BaseSecurityTests {

    private static final String EXTERNAL_JWT_ENDPOINT = "/widget/ping";

    private static final String INTERNAL_JWT_ENDPOINT = "/api/ping";

    private static final String BASIC_AUTH_ENDPOINT = "/login";

    private static final String LOGIN_JWT_ENDPOINT = "/login";
    
    private static final String VALID_LDAP_USER = "mike";

    private static final String VALID_LDAP_PASSWORD = "mike";


    /*
     * Update security configuration
     */
    @BeforeAll
    static void setup() throws ReflectiveOperationException {
        BaseSecurityTests.prepareValidJWTExternalToken();
        ReflectionUtils.setFinalStaticField(MultipleAuthProviderSecurityConfig.class, "isDevelopment", Boolean.TRUE);
        ReflectionUtils.setFinalStaticField(MultipleAuthProviderSecurityConfig.class, "isLDAP", Boolean.TRUE);
        ReflectionUtils.setFinalStaticField(MultipleAuthProviderSecurityConfig.class, "INTERNAL_URL_FILTER", "/api");
        ReflectionUtils.setFinalStaticField(MultipleAuthProviderSecurityConfig.class, "EXTERNAL_FILTER_URL", "/widget");
    }

    @AfterAll
    static void afterAll() {
        BaseSecurityTests.killsSpringApplicationContext();
    }

    /*
     * NON JWT SCENARIOS
     */

    @Test
    public void testBasicUsingWrongUserAndPass_then401() {
        ResponseEntity<String> result = makeRestCallWithUser(BASIC_AUTH_ENDPOINT, INVALID_USER, INVALID_PASSWORD);

        assertThat(result.getStatusCodeValue()).isEqualTo(401);
    }

    @Test
    public void testBasicUsingValidUserAndWrongPass_then401() {
        ResponseEntity<String> result = makeRestCallWithUser(BASIC_AUTH_ENDPOINT, VALID_USER, INVALID_PASSWORD);

        assertThat(result.getStatusCodeValue()).isEqualTo(401);
    }

    @Test
    public void testBasicUsingNoUserAndPass_then401() {
        ResponseEntity<String> result = makeRestCall(BASIC_AUTH_ENDPOINT);

        assertThat(result.getStatusCodeValue()).isEqualTo(401);
    }

    @Test
    public void testBasicUsingValidUserAndPass_then200() {
        ResponseEntity<String> result = makeRestCallWithUser(BASIC_AUTH_ENDPOINT, VALID_USER, VALID_PASSWORD);

        assertThat(result.getStatusCodeValue()).isEqualTo(200);
    }
    
    @Test
    public void testBasicUsingValidLDAPUserAndPass_then200() {
        ResponseEntity<String> result = makeRestCallWithUser(BASIC_AUTH_ENDPOINT, VALID_LDAP_USER, VALID_LDAP_PASSWORD);

        assertThat(result.getStatusCodeValue()).isEqualTo(200);
    }
    
    @Test
    public void testBasicUsingValidLDAPUserAndWrongPass_then401() {
        ResponseEntity<String> result = makeRestCallWithUser(BASIC_AUTH_ENDPOINT, VALID_LDAP_USER, INVALID_PASSWORD);

        assertThat(result.getStatusCodeValue()).isEqualTo(401);
    }

    /*
     * INTERNAL JWT LOGIN SCENARIOS
     */

    @Test
    public void testJWTUsingNoCredentials_then401() {
        ResponseEntity<String> result = makeRestCall(INTERNAL_JWT_ENDPOINT);
        assertEquals(401, result.getStatusCodeValue());
    }

    @Test
    public void testJWTUsingOnlyBasicValidUserAndPass_then401() {
        ResponseEntity<String> result = makeRestCallWithUser(INTERNAL_JWT_ENDPOINT, VALID_USER, VALID_PASSWORD);
        assertEquals(401, result.getStatusCodeValue());
    }

    @Test
    public void testJWTUsingInvalidBasicValidUserAndInvalidPass_then401() {
        ResponseEntity<String> result = makeRestCallWithUser(LOGIN_JWT_ENDPOINT, VALID_USER, INVALID_PASSWORD);
        assertEquals(401, result.getStatusCodeValue());
        HttpHeaders headers = result.getHeaders();

        ResponseEntity<String> resultPing = makeRestCallWithHeaders(INTERNAL_JWT_ENDPOINT, headers);
        assertThat(resultPing.getStatusCodeValue()).isEqualTo(401);
    }

    @Test
    public void testJWTUsingValidBasicAndToken_then200() {
        ResponseEntity<String> result = makeRestCallWithUser(LOGIN_JWT_ENDPOINT, VALID_USER, VALID_PASSWORD);
        assertEquals(200, result.getStatusCodeValue());
        HttpHeaders headers = result.getHeaders();

        ResponseEntity<String> resultPing = makeRestCallWithHeaders(INTERNAL_JWT_ENDPOINT, headers);
        assertThat(resultPing.getStatusCodeValue()).isEqualTo(200);
    }
    
    @Test
    public void testJWTUsingValidLDAPBasicAndToken_then200() {
        ResponseEntity<String> result = makeRestCallWithUser(LOGIN_JWT_ENDPOINT, VALID_LDAP_USER, VALID_LDAP_PASSWORD);
        assertEquals(200, result.getStatusCodeValue());
        HttpHeaders headers = result.getHeaders();

        ResponseEntity<String> resultPing = makeRestCallWithHeaders(INTERNAL_JWT_ENDPOINT, headers);
        assertThat(resultPing.getStatusCodeValue()).isEqualTo(200);
    }

    @Test
    public void testInternalJWTUsingManualJWTToken_then200() {
        HttpHeaders headers = super.getHeaderWithValidJWTInternalToken(VALID_USER);
        ResponseEntity<String> resultPing = makeRestCallWithHeaders(INTERNAL_JWT_ENDPOINT, headers);
        assertThat(resultPing.getStatusCodeValue()).isEqualTo(200);
    }

    @Test
    @Order(10)
    public void testInternalJWTUsingJWTWrongKeyToken_then401() throws ReflectiveOperationException {
        HttpHeaders headers = super.getHeaderWithWrongKeyJWTInternalToken(VALID_USER);
        ResponseEntity<String> resultPing = makeRestCallWithHeaders(INTERNAL_JWT_ENDPOINT, headers);
        assertThat(resultPing.getStatusCodeValue()).isEqualTo(401);
    }

    @Test
    public void testInternalJWTUsingJWTExpiredToken_then401() {
        HttpHeaders headers = super.getHeaderWithExpiredJWTInternalToken(VALID_USER);
        ResponseEntity<String> resultPing = makeRestCallWithHeaders(INTERNAL_JWT_ENDPOINT, headers);
        assertThat(resultPing.getStatusCodeValue()).isEqualTo(401);
    }

    /*
     * EXTERNAL JWT LOGIN SCENARIOS
     */

    @Test
    public void testExternalJWTUsingNoCredentials_then401() {
        if (wasExternalTokenRead) {
            ResponseEntity<String> result = makeRestCall(EXTERNAL_JWT_ENDPOINT);
            assertEquals(401, result.getStatusCodeValue());
        } else {
            log.warn("External valid token testing scenario skkiped");
        }
    }

    @Test
    public void testExternalJWTUsingOnlyBasicValidUserAndPass_then401() {
        if (wasExternalTokenRead) {
            ResponseEntity<String> result = makeRestCallWithUser(EXTERNAL_JWT_ENDPOINT, VALID_USER, VALID_PASSWORD);
            assertEquals(401, result.getStatusCodeValue());
        } else {
            log.warn("External valid token testing scenario skkiped");
        }
    }

    @Test
    public void testExternalJWTUsingInvalidBasicValidUserAndInvalidPass_then401() {
        if (wasExternalTokenRead) {
            ResponseEntity<String> result = makeRestCallWithUser(EXTERNAL_JWT_ENDPOINT, VALID_USER, INVALID_PASSWORD);
            assertEquals(401, result.getStatusCodeValue());
            HttpHeaders headers = result.getHeaders();

            ResponseEntity<String> resultPing = makeRestCallWithHeaders(EXTERNAL_JWT_ENDPOINT, headers);
            assertThat(resultPing.getStatusCodeValue()).isEqualTo(401);
        } else {
            log.warn("External valid token testing scenario skkiped");
        }
    }

    @Test
    public void testExternalJWTUsingInternalJWTToken_then405() {
        if (wasExternalTokenRead) {
            ResponseEntity<String> result = makeRestCallWithUser(LOGIN_JWT_ENDPOINT, VALID_USER, VALID_PASSWORD);
            assertEquals(200, result.getStatusCodeValue());
            HttpHeaders headers = result.getHeaders();

            ResponseEntity<String> resultPing = makeRestCallWithHeaders(EXTERNAL_JWT_ENDPOINT, headers);
            assertThat(resultPing.getStatusCodeValue()).isEqualTo(405);
        } else {
            log.warn("External valid token testing scenario skkiped");
        }
    }

    @Test
    public void testExternalJWTUsingValidJWTToken_then200() {
        if (wasExternalTokenRead) {
            HttpHeaders headers = super.getHeaderWithValidJWTExternalToken();
            ResponseEntity<String> resultPing = makeRestCallWithHeaders(EXTERNAL_JWT_ENDPOINT, headers);
            assertThat(resultPing.getStatusCodeValue()).isEqualTo(200);
        } else {
            log.warn("External valid token testing scenario skkiped");
        }
    }

    @Test
    public void testExternalJWTUsingInvalidToken_then401() {
        HttpHeaders headers = super.getHeaderWithInvalidJWTExternalToken();
        ResponseEntity<String> resultPing = makeRestCallWithHeaders(EXTERNAL_JWT_ENDPOINT, headers);
        assertThat(resultPing.getStatusCodeValue()).isEqualTo(401);
    }

}
