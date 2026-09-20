package com.frog.common.uaa.config;

import com.frog.common.web.domain.SecurityUser;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Value;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.web.filter.ForwardedHeaderFilter;

import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.UUID;

/**
 *
 *
 * @author Deng
 * createData 2025/10/24 14:23
 * @version 1.0
 */
@Configuration
@RequiredArgsConstructor
@Slf4j
public class AuthorizationServerConfig {
    @Value("${security.oauth2.authorizationserver.issuer:http://localhost:8090}")
    private String issuer;

    // Optional keystore-based JWK configuration (fallback to generated if missing)
    @Value("${security.oauth2.authorizationserver.jwk.keystore-location:}")
    private String keystoreLocation;
    @Value("${security.oauth2.authorizationserver.jwk.keystore-password:}")
    private String keystorePassword;
    @Value("${security.oauth2.authorizationserver.jwk.key-alias:}")
    private String keyAlias;
    @Value("${security.oauth2.authorizationserver.jwk.key-password:}")
    private String keyPassword;

    /**
     * OAuth2授权服务器安全过滤链
     */
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) {
		OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();

		// 仅匹配授权服务器端点；精确忽略 CSRF
		http
				.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
				.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
				.csrf(csrf -> csrf.ignoringRequestMatchers(authorizationServerConfigurer.getEndpointsMatcher()))
				.exceptionHandling(exceptions -> exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")))
				.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));

		// 启用 OIDC 支持
		authorizationServerConfigurer.oidc(Customizer.withDefaults());
		http.with(authorizationServerConfigurer, Customizer.withDefaults());

		return http.build();
    }

    /**
     * 默认安全过滤链
     */
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/actuator/**", "/login", "/error").permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin(Customizer.withDefaults())
                .csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }

    /**
     * 注册客户端
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        // Web 客户端
        RegisteredClient webClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("nearsync-web")
                .clientSecret(passwordEncoder().encode("web-secret-2024"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("http://localhost:3000/callback")
                .redirectUri("http://localhost:3000/authorized")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope("user.read")
                .scope("user.write")
                .scope("system.admin")
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofHours(2))
                        .refreshTokenTimeToLive(Duration.ofDays(7))
                        .reuseRefreshTokens(false)
                        .build())
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false)
                        .requireProofKey(false)
                        .build())
                .build();

        // 移动客户端（使用PKCE）
        RegisteredClient mobileClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("nearsync-mobile")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE) // 公开客户端
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("nearsync://callback")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope("user.read")
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofHours(1))
                        .refreshTokenTimeToLive(Duration.ofDays(30))
                        .build())
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(true)
                        .requireProofKey(true) // 强制 PKCE
                        .build())
                .build();

        // 服务间调用客户端
        RegisteredClient serviceClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("internal-service")
                .clientSecret(passwordEncoder().encode("service-secret-2024"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("service.internal")
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(30))
                        .build())
                .build();

        return new InMemoryRegisteredClientRepository(webClient, mobileClient, serviceClient);
    }

    /**
     * JWT 解码器
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    /**
     * JWK源（使用RSA密钥对）
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        // 优先从 keystore 加载；失败则回退到启动时生成
        RSAKey rsaKey = loadRsaFromKeystore();
        if (rsaKey == null) {
            log.warn("No JWK keystore configured - generating ephemeral RSA key pair. "
                    + "Tokens will be INVALID after restart or across instances. "
                    + "Configure security.oauth2.authorizationserver.jwk.keystore-location for production.");
            KeyPair keyPair = generateRsaKey();
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
            rsaKey = new RSAKey.Builder(publicKey)
                    .privateKey(privateKey)
                    .keyID(UUID.randomUUID().toString())
                    .build();
        }

        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    /**
     * 生成 RSA密钥对
     */
    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    /**
     * 授权服务器设置
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer(issuer)
                .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return context -> {
            if (!"access_token".equals(context.getTokenType().getValue())) {
                return;
            }

            AuthorizationGrantType grantType = context.getAuthorizationGrantType();
            boolean userGrant = AuthorizationGrantType.AUTHORIZATION_CODE.equals(grantType)
                    || AuthorizationGrantType.REFRESH_TOKEN.equals(grantType)
                    || new AuthorizationGrantType("password").equals(grantType);

            if (!userGrant) {
                return;
            }

            Authentication principal = context.getPrincipal();
            if (principal != null && principal.getPrincipal() instanceof SecurityUser user) {
                context.getClaims().claims(claims -> {
                    // 原 JwtUtils 全部 claim 字段
                    claims.put("userId", String.valueOf(user.getUserId()));
                    claims.put("deptId", String.valueOf(user.getDeptId()));
                    claims.put("roles", user.getRoles());
                    claims.put("permissions", user.getPermissions());
                    claims.put("deviceId", user.getDeviceId());
                    claims.put("ipAddress", user.getIpAddress());
                    claims.put("amr", user.getAmr());
                });
            }
        };
    }

    @Bean
    public ForwardedHeaderFilter forwardedHeaderFilter() {
        return new ForwardedHeaderFilter();
    }

    private RSAKey loadRsaFromKeystore() {
        if (!hasText(keystoreLocation) || !hasText(keyAlias)) {
            return null;
        }
        try {
            var resource = new DefaultResourceLoader().getResource(keystoreLocation);
            if (!resource.exists()) {
                return null;
            }
            try (InputStream is = resource.getInputStream()) {
                KeyStore keyStore = KeyStore.getInstance("JKS");
                char[] ksPass = hasText(keystorePassword) ? keystorePassword.toCharArray() : null;
                keyStore.load(is, ksPass);

                char[] keyPass = hasText(keyPassword) ? keyPassword.toCharArray() : null;
                Key key = keyStore.getKey(keyAlias, keyPass);
                if (key instanceof RSAPrivateKey privateKey) {
                    var cert = keyStore.getCertificate(keyAlias);
                    RSAPublicKey publicKey = (RSAPublicKey) cert.getPublicKey();
                    return new RSAKey.Builder(publicKey)
                            .privateKey(privateKey)
                            .keyID(UUID.randomUUID().toString())
                            .build();
                }
            }
        } catch (Exception ignored) {
            // ignore and fallback
        }
        return null;
    }

    private static boolean hasText(String s) {
        return s != null && !s.trim().isEmpty();
    }
}
