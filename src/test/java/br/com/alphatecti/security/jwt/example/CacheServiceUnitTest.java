package br.com.alphatecti.security.jwt.example;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;

import br.com.alphatecti.security.base.config.ExternalJWTConfiguration;
import br.com.alphatecti.security.base.util.ReflectionUtils;
import br.com.alphatecti.security.jwt.example.config.MultipleAuthProviderSecurityConfig;
import br.com.alphatecti.security.jwt.filter.JWTExternalAuthenticationFilter;
import br.com.alphatecti.security.jwt.filter.JWTInternalAuthenticationFilter;
import br.com.alphatecti.security.jwt.parser.JWTInternalTokenParser;
import br.com.alphatecti.security.jwt.parser.JWTTokenParser;

/**
 * Internal class to test the JWT cache TO RUN THIS TEST: 
 * 1) Go to JWTInternalAuthenticationFilter and make field configuration static; 
 * 2) Go to JWTExternalAuthenticationFilter and make field configuration static; 
 * 3) Remove the disabled annotation
 * 4) Run as JUnit test 
 * 5) Don't forget to rollback all steps before commit
 */
@SpringBootTest(webEnvironment = WebEnvironment.DEFINED_PORT)
@Disabled
public class CacheServiceUnitTest extends BaseSecurityTests {

    private static final String EXTERNAL_JWT_ENDPOINT = "/api/ping";

    private static final String INTERNAL_JWT_ENDPOINT = "/api/ping";

    private static List<String> EXTERNAL_DEFAULT_PERMISSIONS = new ArrayList<String>();

    private static String NON_BREEZE_PRIV_URL = "https://dialogflow.cloud.google.com/cx/projects";

    private static JWTTokenParser alwaysFailParser;

    private static JWTTokenParser defaultParser;

    private static ExternalJWTConfiguration defaultConfiguration;

    private static ExternalJWTConfiguration wrongConfiguration;

    @BeforeAll
    static void beforeAll() throws ReflectiveOperationException {
        BaseSecurityTests.prepareValidJWTExternalToken();
        ReflectionUtils.setFinalStaticField(MultipleAuthProviderSecurityConfig.class, "isDevelopment", Boolean.TRUE);
        ReflectionUtils.setFinalStaticField(MultipleAuthProviderSecurityConfig.class, "INTERNAL_URL_FILTER", "/api/");
        ReflectionUtils.setFinalStaticField(MultipleAuthProviderSecurityConfig.class, "EXTERNAL_FILTER_URL", "/api/");
    }

    @AfterAll
    static void afterAll() {
        BaseSecurityTests.killsSpringApplicationContext();
    }

    @BeforeEach
    public void before() throws ReflectiveOperationException {
        // back to default values
        ReflectionUtils.setFinalStaticField(JWTInternalAuthenticationFilter.class, "tokenParser", getDefaultTokenParser());
        ReflectionUtils.setFinalStaticField(JWTExternalAuthenticationFilter.class, "configuration", getDefaultExternalJWTConfiguration());
    }

    @Test
    public void testInternalJWTCache_SameToken_then200() throws ReflectiveOperationException {
        HttpHeaders headers = super.getHeaderWithValidJWTInternalToken(VALID_USER);
        ResponseEntity<String> resultPing = makeRestCallWithHeaders(INTERNAL_JWT_ENDPOINT, headers);
        assertThat(resultPing.getStatusCodeValue()).isEqualTo(200);

        // inner parser to make sure cache is working
        ReflectionUtils.setFinalStaticField(JWTInternalAuthenticationFilter.class, "tokenParser", getAlwaysFailParser());

        resultPing = makeRestCallWithHeaders(INTERNAL_JWT_ENDPOINT, headers);
        assertThat(resultPing.getStatusCodeValue()).isEqualTo(200);

    }

    @Test
    public void testExternalJWTCache_SameToken_then200() throws ReflectiveOperationException {
        HttpHeaders headers = super.getHeaderWithValidJWTExternalToken();
        ResponseEntity<String> resultPing = makeRestCallWithHeaders(EXTERNAL_JWT_ENDPOINT, headers);
        assertThat(resultPing.getStatusCodeValue()).isEqualTo(200);

        // inner parser to make sure cache is working
        ReflectionUtils.setFinalStaticField(JWTExternalAuthenticationFilter.class, "configuration", getInvalidExternalJWTConfiguration());

        resultPing = makeRestCallWithHeaders(EXTERNAL_JWT_ENDPOINT, headers);
        assertThat(resultPing.getStatusCodeValue()).isEqualTo(200);

    }

    @Test
    public void testInternalJWTCache_NoPreviousCache_then401() throws ReflectiveOperationException {
        HttpHeaders headers = super.getHeaderWithValidJWTInternalToken(VALID_USER);
        // inner parser to make sure cache is working
        ReflectionUtils.setFinalStaticField(JWTInternalAuthenticationFilter.class, "tokenParser", getAlwaysFailParser());

        headers = super.getHeaderWithValidJWTInternalToken(VALID_USER); // NEW JWT
        ResponseEntity<String> resultPing = makeRestCallWithHeaders(INTERNAL_JWT_ENDPOINT, headers);
        assertThat(resultPing.getStatusCodeValue()).isEqualTo(401);

    }

    @Test
    public void testExternalJWTCache_NoPreviousCache_then401() throws ReflectiveOperationException {
        HttpHeaders headers = super.getHeaderWithValidJWTExternalToken();

        // inner parser to make sure cache is working
        ReflectionUtils.setFinalStaticField(JWTExternalAuthenticationFilter.class, "configuration", getInvalidExternalJWTConfiguration());

        ResponseEntity<String> resultPing = makeRestCallWithHeaders(EXTERNAL_JWT_ENDPOINT, headers);
        assertThat(resultPing.getStatusCodeValue()).isEqualTo(401);

    }

    private JWTTokenParser getAlwaysFailParser() {
        if (alwaysFailParser == null) {
            alwaysFailParser = new JWTTokenParser() {
                @Override
                public String createJWTToken(String subject) {
                    throw new BadCredentialsException("Cache is not working");
                }

                @Override
                public String parseJWTToken(String token) {
                    throw new BadCredentialsException("Cache is not working");
                }

            };
        }

        return alwaysFailParser;
    }

    private JWTTokenParser getDefaultTokenParser() {
        if (defaultParser == null) {
            defaultParser = new JWTInternalTokenParser(SECRET, EXPIRATION_TIME);
        }

        return defaultParser;
    }

    private ExternalJWTConfiguration getDefaultExternalJWTConfiguration() {
        if (defaultConfiguration == null) {
            defaultConfiguration = ExternalJWTConfiguration.builder().urlFilter(EXTERNAL_JWT_ENDPOINT).externalURL(EXTERNAL_LOGIN_URL)
                    .tokenSubject(VALID_USER).cacheExpirationTime(CACHE_EXPIRATION_TIME).defaultPermissions(EXTERNAL_DEFAULT_PERMISSIONS).build();
        }
        return defaultConfiguration;
    }

    private ExternalJWTConfiguration getInvalidExternalJWTConfiguration() {
        if (wrongConfiguration == null) {
            wrongConfiguration = ExternalJWTConfiguration.builder().urlFilter(EXTERNAL_JWT_ENDPOINT).externalURL(NON_BREEZE_PRIV_URL)
                    .tokenSubject(VALID_USER).cacheExpirationTime(CACHE_EXPIRATION_TIME).defaultPermissions(EXTERNAL_DEFAULT_PERMISSIONS).build();
        }
        return wrongConfiguration;
    }

}
