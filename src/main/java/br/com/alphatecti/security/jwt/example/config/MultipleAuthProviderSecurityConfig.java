package br.com.alphatecti.security.jwt.example.config;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import br.com.alphatecti.security.base.AccountCredentials;
import br.com.alphatecti.security.base.config.BaseBasicAuthToInternalJWTConfig;
import br.com.alphatecti.security.base.config.BaseExternalJWTConfig;
import br.com.alphatecti.security.base.config.BaseInternalJWTConfig;
import br.com.alphatecti.security.base.config.BasicAuthToInternalJWTConfiguration;
import br.com.alphatecti.security.base.config.ExternalJWTConfiguration;
import br.com.alphatecti.security.base.config.InternalJWTConfiguration;
import br.com.alphatecti.security.base.config.LDAPConfiguration;

@EnableWebSecurity
@Configuration
public class MultipleAuthProviderSecurityConfig extends WebSecurityConfigurerAdapter {

    /**
     * Configuration used for testing scenarios
     */
    private static boolean isDevelopment;
    private static boolean isLDAP;

    /**
     * Basic auth config
     */
    private static String INMEMORY_USER = "memuser";
    private static String LOGIN_URL_PATTERN = "/login";
    private static String INMEMORY_CRYPTO_PASS = "$2a$10$XkojTnfRmJ2bJAMmn.dP2uZWkk3MAFigh97yfD.1Ph7swGr2lzuHO";
    private static String[] INMEMORY_USER_ROLES = new String[] { "USER" };
    private static List<AuthenticationProvider> AUTH_PROVIDERS = new ArrayList<AuthenticationProvider>();

    /**
     * JWT internal config
     */
    /*
     * Configuration
     */
    private static String INTERNAL_URL_FILTER = "/api";
    private static String INTERNAL_TOKEN_SECRET = "mySecret";
    private static long INTERNAL_EXP_TIME_MS = 30 * 1000; // 30 minutes
    private static List<String> INTERNAL_DEFAULT_PERMISSIONS = new ArrayList<String>();
    private static long INTERNAL_CACHE_EXP_TIME = 30; // 30 minutes

    /**
     * JWT external config
     */
    public static String EXTERNAL_AUTH_URL = "https://www.instagram.com/direct/inbox/";
    public static String EXTERNAL_FILTER_URL = "/widget";
    public static String EXTERNAL_TOKEN_SUBJECT = "username";
    // Note: If you want to use @PreAuthorize("hasAuthority('External')") or hasRole(“ADMIN”)
    private static List<String> EXTERNAL_DEFAULT_PERMISSIONS = Arrays.asList(new String[] { "USER" });
    private static long EXTERNAL_CACHE_EXP_TIME = 60; // 1 hour

    @Configuration
    @Order(1)
    public class BasicAuthSecurityAdapter extends BaseBasicAuthToInternalJWTConfig {
        /**
         * Adding configuration for basic authentication
         */
        public BasicAuthSecurityAdapter() {

            super(BasicAuthToInternalJWTConfiguration.builder().urlFilter(LOGIN_URL_PATTERN).tokenSecret(INTERNAL_TOKEN_SECRET)
                    .expirationInMiliseconds(INTERNAL_EXP_TIME_MS).customProviders(AUTH_PROVIDERS).ldapConfig(getLDAPConfig()).build());
            if (isDevelopment) {
                super.addInMemoryCredentialsForTesting(
                        AccountCredentials.builder().username(INMEMORY_USER).password(INMEMORY_CRYPTO_PASS).roles(INMEMORY_USER_ROLES).build());
            }
        }

    }

    @Configuration
    @Order(2)
    public class InternalJWTSecurityAdapter extends BaseInternalJWTConfig {

        /**
         * Adding configuration for internal JWT
         */
        public InternalJWTSecurityAdapter() {
            super(InternalJWTConfiguration.builder().urlFilter(INTERNAL_URL_FILTER).tokenSecret(INTERNAL_TOKEN_SECRET)
                    .expirationTimeInMiliseconds(INTERNAL_EXP_TIME_MS).cacheExpirationTime(INTERNAL_CACHE_EXP_TIME)
                    .defaultPermissions(INTERNAL_DEFAULT_PERMISSIONS).build());
        }

    }

    @Configuration
    @Order(3)
    public class ExternalJWTSecurityAdapter extends BaseExternalJWTConfig {
        /**
         * Adding configuration for external JWT
         */
        public ExternalJWTSecurityAdapter() {
            super(ExternalJWTConfiguration.builder().urlFilter(EXTERNAL_FILTER_URL).externalURL(EXTERNAL_AUTH_URL)
                    .tokenSubject(EXTERNAL_TOKEN_SUBJECT).cacheExpirationTime(EXTERNAL_CACHE_EXP_TIME)
                    .defaultPermissions(EXTERNAL_DEFAULT_PERMISSIONS).build());
        }
    }

    /**
     * Return LDAP configuration for unboundid-ldapsdk (local LDAP)
     */
    private static LDAPConfiguration getLDAPConfig() {
        
        LDAPConfiguration ldapConfig = null;
        if(isLDAP) {
            ldapConfig = new LDAPConfiguration();
            ldapConfig.setUserDnPatterns("uid={0},ou=people");
            ldapConfig.getUserSearchFilter();
            ldapConfig.setGroupSearchBase("ou=groups");
            ldapConfig.setUrl("ldap://localhost:8389/dc=devglan,dc=com");
            ldapConfig.setUserPasswordAttribute("userPassword");
        }
        
        return ldapConfig;
    }

}
