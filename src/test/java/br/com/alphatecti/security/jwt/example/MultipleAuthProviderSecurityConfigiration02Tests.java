package br.com.alphatecti.security.jwt.example;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.event.annotation.AfterTestClass;

import br.com.alphatecti.security.base.util.ReflectionUtils;
import br.com.alphatecti.security.jwt.example.config.MultipleAuthProviderSecurityConfig;
import lombok.extern.slf4j.Slf4j;

/**
 * Testing with second configuration: --> Memory user enable (isDevelopment = true) --> URLs for external and internal JWT filters are the same
 */
@SpringBootTest(webEnvironment = WebEnvironment.DEFINED_PORT)
@Slf4j
public class MultipleAuthProviderSecurityConfigiration02Tests extends BaseSecurityTests {

    private static final String EXTERNAL_JWT_ENDPOINT = "/api/ping";

    private static final String INTERNAL_JWT_ENDPOINT = "/api/ping";

    private static final String BASIC_AUTH_ENDPOINT = "/login";

    private static final String LOGIN_JWT_ENDPOINT = "/login";
    
    private static final String VALID_LDAP_USER = "john";

    private static final String VALID_LDAP_PASSWORD = "john";


    /*
     * Update security configuration
     */
    @BeforeAll
    static void beforeAll() throws ReflectiveOperationException {
        BaseSecurityTests.prepareValidJWTExternalToken();
        ReflectionUtils.setFinalStaticField(MultipleAuthProviderSecurityConfig.class, "isDevelopment", Boolean.TRUE);
        ReflectionUtils.setFinalStaticField(MultipleAuthProviderSecurityConfig.class, "isLDAP", Boolean.TRUE);
        ReflectionUtils.setFinalStaticField(MultipleAuthProviderSecurityConfig.class, "INTERNAL_URL_FILTER", "/api/");
        ReflectionUtils.setFinalStaticField(MultipleAuthProviderSecurityConfig.class, "EXTERNAL_FILTER_URL", "/api/");
    }

    @AfterTestClass
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
        assertThat(result.getBody()).isEqualTo("OK");
    }
    
    @Test
    public void testBasicUsingValidLDAPUserAndPass_then200() {
        ResponseEntity<String> result = makeRestCallWithUser(BASIC_AUTH_ENDPOINT, VALID_LDAP_USER, VALID_LDAP_PASSWORD);

        assertThat(result.getStatusCodeValue()).isEqualTo(200);
        assertThat(result.getBody()).isEqualTo("OK");
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
    public void testJWTUsingNoCredentials_then403() {
        ResponseEntity<String> result = makeRestCall(INTERNAL_JWT_ENDPOINT);
        assertEquals(403, result.getStatusCodeValue());
    }

    @Test
    public void testJWTUsingOnlyBasicValidUserAndPass_then403() {
        ResponseEntity<String> result = makeRestCallWithUser(INTERNAL_JWT_ENDPOINT, VALID_USER, VALID_PASSWORD);
        assertEquals(403, result.getStatusCodeValue());
    }

    @Test
    public void testJWTUsingInvalidBasicValidUserAndInvalidPass_then400() {
        ResponseEntity<String> result = makeRestCallWithUser(LOGIN_JWT_ENDPOINT, VALID_USER, INVALID_PASSWORD);
        assertEquals(401, result.getStatusCodeValue());
        HttpHeaders headers = result.getHeaders();

        ResponseEntity<String> resultPing = makeRestCallWithHeaders(INTERNAL_JWT_ENDPOINT, headers);
        assertThat(resultPing.getStatusCodeValue()).isEqualTo(403);
    }

    @Test
    public void testJWTUsingValidBasicAndToken_then200() {
        ResponseEntity<String> result = makeRestCallWithUser(LOGIN_JWT_ENDPOINT, VALID_USER, VALID_PASSWORD);
        assertEquals(200, result.getStatusCodeValue());
        HttpHeaders headers = result.getHeaders();

        ResponseEntity<String> resultPing = makeRestCallWithHeaders(INTERNAL_JWT_ENDPOINT, headers);
        assertThat(resultPing.getStatusCodeValue()).isEqualTo(200);
        assertThat(result.getBody()).isEqualTo("OK");
    }
    
    @Test
    public void testJWTUsingValidLDAPBasicAndToken_then200() {
        ResponseEntity<String> result = makeRestCallWithUser(LOGIN_JWT_ENDPOINT, VALID_LDAP_USER, VALID_LDAP_PASSWORD);
        assertEquals(200, result.getStatusCodeValue());
        HttpHeaders headers = result.getHeaders();

        ResponseEntity<String> resultPing = makeRestCallWithHeaders(INTERNAL_JWT_ENDPOINT, headers);
        assertThat(resultPing.getStatusCodeValue()).isEqualTo(200);
        assertThat(result.getBody()).isEqualTo("OK");
    }

    @Test
    public void testInternalJWTUsingManualJWTToken_then200() {
        HttpHeaders headers = super.getHeaderWithValidJWTInternalToken(VALID_USER);
        ResponseEntity<String> resultPing = makeRestCallWithHeaders(INTERNAL_JWT_ENDPOINT, headers);
        assertThat(resultPing.getStatusCodeValue()).isEqualTo(200);
        assertThat(resultPing.getBody()).isEqualTo("OK");
    }

    @Test
    public void testInternalJWTUsingJWTWrongKeyToken_then403() throws ReflectiveOperationException {
        HttpHeaders headers = super.getHeaderWithWrongKeyJWTInternalToken(VALID_USER);
        ResponseEntity<String> resultPing = makeRestCallWithHeaders(INTERNAL_JWT_ENDPOINT, headers);
        assertThat(resultPing.getStatusCodeValue()).isEqualTo(403);
    }

    @Test
    public void testInternalJWTUsingJWTExpiredToken_then403() {
        HttpHeaders headers = super.getHeaderWithExpiredJWTInternalToken(VALID_USER);
        ResponseEntity<String> resultPing = makeRestCallWithHeaders(INTERNAL_JWT_ENDPOINT, headers);
        assertThat(resultPing.getStatusCodeValue()).isEqualTo(403);
    }

    /*
     * EXTERNAL JWT LOGIN SCENARIOS
     */

    @Test
    public void testExternalJWTUsingNoCredentials_then403() {
        if (wasExternalTokenRead) {
            ResponseEntity<String> result = makeRestCall(EXTERNAL_JWT_ENDPOINT);
            assertEquals(403, result.getStatusCodeValue());
        } else {
            log.warn("External valid token testing scenario skkiped");
        }
    }

    @Test
    public void testExternalJWTUsingOnlyBasicValidUserAndPass_then403() {
        if (wasExternalTokenRead) {
            ResponseEntity<String> result = makeRestCallWithUser(EXTERNAL_JWT_ENDPOINT, VALID_USER, VALID_PASSWORD);
            assertEquals(403, result.getStatusCodeValue());
        } else {
            log.warn("External valid token testing scenario skkiped");
        }
    }

    @Test
    public void testExternalJWTUsingInvalidBasicValidUserAndInvalidPass_then403() {
        if (wasExternalTokenRead) {
            ResponseEntity<String> result = makeRestCallWithUser(EXTERNAL_JWT_ENDPOINT, VALID_USER, INVALID_PASSWORD);
            assertEquals(403, result.getStatusCodeValue());
            HttpHeaders headers = result.getHeaders();

            ResponseEntity<String> resultPing = makeRestCallWithHeaders(EXTERNAL_JWT_ENDPOINT, headers);
            assertThat(resultPing.getStatusCodeValue()).isEqualTo(403);
        } else {
            log.warn("External valid token testing scenario skkiped");
        }
    }

    @Test
    public void testExternalJWTUsingInternalJWTToken_then200() {
        ResponseEntity<String> result = makeRestCallWithUser(LOGIN_JWT_ENDPOINT, VALID_USER, VALID_PASSWORD);
        assertEquals(200, result.getStatusCodeValue());
        HttpHeaders headers = result.getHeaders();

        ResponseEntity<String> resultPing = makeRestCallWithHeaders(EXTERNAL_JWT_ENDPOINT, headers);
        assertThat(resultPing.getStatusCodeValue()).isEqualTo(200);
        assertThat(resultPing.getBody()).isEqualTo("OK");
    }

    @Test
    public void testExternalJWTUsingValidJWTToken_then200() {
        if (wasExternalTokenRead) {
            HttpHeaders headers = super.getHeaderWithValidJWTExternalToken();
            ResponseEntity<String> resultPing = makeRestCallWithHeaders(EXTERNAL_JWT_ENDPOINT, headers);
            assertThat(resultPing.getStatusCodeValue()).isEqualTo(200);
            assertThat(resultPing.getBody()).isEqualTo("OK");
        } else {
            log.warn("External valid token testing scenario skkiped");
        }
    }

    @Test
    @Disabled("This test doesn't run on mvn clean install because security conf is not reload correct")
    public void testExternalJWTUsingInvalidToken_then403() {
        if (wasExternalTokenRead) {
            HttpHeaders headers = super.getHeaderWithInvalidJWTExternalToken();
            ResponseEntity<String> resultPing = makeRestCallWithHeaders(EXTERNAL_JWT_ENDPOINT, headers);
            assertThat(resultPing.getStatusCodeValue()).isEqualTo(403);
        }
    }

}
