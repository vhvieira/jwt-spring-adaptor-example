package br.com.alphatecti.security.jwt.example;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;

import br.com.alphatecti.security.base.util.ReflectionUtils;
import br.com.alphatecti.security.jwt.example.config.MultipleAuthProviderSecurityConfig;

/**
 * LDAP Testing scenarios. Links used:
 * https://spring.io/guides/gs/authenticating-ldap/
 * https://www.levvel.io/resource-library/restful-api-security-&-ldap-authentication-with-spring
 * https://www.programcreek.com/java-api-examples/?api=org.springframework.security.ldap.DefaultSpringSecurityContextSource
 * https://www.concretepage.com/spring-5/spring-security-ldap-authentication
 * https://www.devglan.com/spring-security/spring-security-ldap-authentication
 * 
 * Keep this tests disabled, just uncomment for running into local IDE
 */
@SpringBootTest(webEnvironment = WebEnvironment.DEFINED_PORT)
@Disabled
public class LDAPSecurityTests extends BaseSecurityTests {

    private static final String ADMIN_ENDPOINT = "/secure/admin/test";

    private static final String USER_ENDPOINT = "/secure/user/test";

    private static final String LOGIN_ENDPOINT = "/ldap/login";

    private static final String LOGIN_JWT_ENDPOINT = "/login";

    private static final String VALID_USER = "john";

    private static final String VALID_PASSWORD = "john";

    private static final String VALID_ADMIN = "mike";

    private static final String ADMIN_PASSWORD = "mike";

    @BeforeAll
    static void setup() throws ReflectiveOperationException {
        ReflectionUtils.setFinalStaticField(MultipleAuthProviderSecurityConfig.class, "isLDAP", Boolean.TRUE);
        ReflectionUtils.setFinalStaticField(MultipleAuthProviderSecurityConfig.class, "INTERNAL_URL_FILTER", "/secure");
    }

    /**
     * @AfterAll didn't work as except, this interface and method is called just after all methods are finished
     */
    @AfterAll
    public static void afterAll() {
        BaseSecurityTests.killsSpringApplicationContext();
    }

    @Test
    @Order(1)
    public void testBasicUsingWrongUserAndPass_then401() {
        ResponseEntity<String> result = makeRestCallWithUser(USER_ENDPOINT, INVALID_USER, INVALID_PASSWORD);

        assertThat(result.getStatusCodeValue()).isEqualTo(401);
    }

    @Test
    @Order(2)
    public void testBasicUsingValidUserAndWrongPass_then401() {
        ResponseEntity<String> result = makeRestCallWithUser(USER_ENDPOINT, VALID_USER, INVALID_PASSWORD);

        assertThat(result.getStatusCodeValue()).isEqualTo(401);
    }

    @Test
    @Order(3)
    public void testBasicUsingNoUserAndPass_then401() {
        ResponseEntity<String> result = makeRestCall(USER_ENDPOINT);

        assertThat(result.getStatusCodeValue()).isEqualTo(401);
    }

    @Test
    @Order(4)
    public void testBasicUsingValidUserAndPass_then200() {
        ResponseEntity<String> result = makeRestCallWithUser(LOGIN_JWT_ENDPOINT, VALID_USER, VALID_PASSWORD);
        assertEquals(200, result.getStatusCodeValue());
        HttpHeaders headers = result.getHeaders();

        ResponseEntity<String> resultPing = makeRestCallWithHeaders(USER_ENDPOINT, headers);
        assertThat(resultPing.getStatusCodeValue()).isEqualTo(200);
    }

    @Test
    @Order(5)
    public void testLoginNoUser_then200() {
        ResponseEntity<String> result = makeRestCall(LOGIN_ENDPOINT);

        assertThat(result.getStatusCodeValue()).isEqualTo(200);
    }

    @Test
    @Order(6)
    public void testBasicUsingValidAdminAndPass_then200() {
        ResponseEntity<String> result = makeRestCallWithUser(LOGIN_JWT_ENDPOINT, VALID_ADMIN, ADMIN_PASSWORD);
        assertEquals(200, result.getStatusCodeValue());
        HttpHeaders headers = result.getHeaders();

        ResponseEntity<String> resultPing = makeRestCallWithHeaders(ADMIN_ENDPOINT, headers);
        assertThat(resultPing.getStatusCodeValue()).isEqualTo(200);

    }

    @Test
    @Order(7)
    public void testBasicUsingValidAdminAndUserPass_then401() {
        ResponseEntity<String> result = makeRestCallWithUser(ADMIN_ENDPOINT, VALID_ADMIN, VALID_PASSWORD);

        assertThat(result.getStatusCodeValue()).isEqualTo(401);
    }

    @Test
    @Order(8)
    public void testBasicUsingWrongAdminAndPass_then401() {
        ResponseEntity<String> result = makeRestCallWithUser(ADMIN_ENDPOINT, INVALID_USER, INVALID_PASSWORD);

        assertThat(result.getStatusCodeValue()).isEqualTo(401);
    }

    @Test
    @Order(9)
    public void testBasicUsingValidAdminAndWrongPass_then401() {
        ResponseEntity<String> result = makeRestCallWithUser(ADMIN_ENDPOINT, VALID_ADMIN, INVALID_PASSWORD);

        assertThat(result.getStatusCodeValue()).isEqualTo(401);
    }

    @Test
    @Order(10)
    public void testBasicAdminUsingNoUserAndPass_then401() {
        ResponseEntity<String> result = makeRestCall(ADMIN_ENDPOINT);

        assertThat(result.getStatusCodeValue()).isEqualTo(401);
    }

}
