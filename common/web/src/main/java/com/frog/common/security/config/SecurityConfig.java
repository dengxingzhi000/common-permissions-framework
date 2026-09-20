package com.frog.common.security.config;

import com.frog.common.security.decision.DecisionRecorderProperties;
import com.frog.common.security.filter.IdentityTokenVerificationFilter;
import com.frog.common.security.filter.JwtAuthenticationFilter;
import com.frog.common.security.filter.SqlInjectionFilter;
import com.frog.common.security.handler.JwtAccessDeniedHandler;
import com.frog.common.security.handler.JwtAuthenticationEntryPoint;
import com.frog.common.security.identity.IdentityTokenProperties;
import com.frog.common.security.stepup.StepUpFilter;
import com.frog.common.tenant.TenantContextFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.config.Customizer;
import org.springframework.util.StringUtils;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

/**
 * SpringSecurity 配置类
 *
 * @author Deng
 * createData 2025/10/11 10:37
 * @version 1.0
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(
        securedEnabled = true,
        jsr250Enabled = true
)
@EnableConfigurationProperties({IdentityTokenProperties.class, DecisionRecorderProperties.class})
@RequiredArgsConstructor
public class SecurityConfig {
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final SqlInjectionFilter sqlInjectionFilter;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;
    private final StepUpFilter stepUpFilter;
    private final SecurityHeadersProperties securityHeadersProperties;
    private final IdentityTokenVerificationFilter identityTokenVerificationFilter;
    private final TenantContextFilter tenantContextFilter;

    /**
     * Spring Security 主过滤器链
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   AuthenticationManager authenticationManager) {
        http
                // 1️⃣ 禁用 CSRF（使用 JWT）
                .csrf(AbstractHttpConfigurer::disable)

                // 2️⃣ CORS 配置
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                // 3️⃣ 无状态 Session 管理
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                        .maximumSessions(1)
                        .maxSessionsPreventsLogin(true))

                // 4️⃣ 异常处理（认证与授权）
                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                        .accessDeniedHandler(jwtAccessDeniedHandler))

                // 5️⃣ 安全头配置
                // 安全头配置
                .headers(headers -> {
                    if (!securityHeadersProperties.isEnabled()) {
                        return;
                    }
                    if (securityHeadersProperties.isHstsEnabled()) {
                        headers.httpStrictTransportSecurity(hsts -> hsts
                                .includeSubDomains(securityHeadersProperties.isHstsIncludeSubdomains())
                                .maxAgeInSeconds(securityHeadersProperties.getHstsMaxAgeSeconds()));
                    } else {
                        headers.httpStrictTransportSecurity(HeadersConfigurer.HstsConfig::disable);
                    }

                    if (securityHeadersProperties.isFrameOptionsEnabled()) {
                        headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::deny);
                    } else {
                        headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable);
                    }

                    if (securityHeadersProperties.isContentTypeOptionsEnabled()) {
                        headers.contentTypeOptions(Customizer.withDefaults());
                    } else {
                        headers.contentTypeOptions(HeadersConfigurer.ContentTypeOptionsConfig::disable);
                    }

                    headers.xssProtection(HeadersConfigurer.XXssConfig::disable);

                    headers.contentSecurityPolicy(csp -> csp
                            .policyDirectives("default-src 'self'; " +
                                    "script-src 'self' https://cdn.jsdelivr.net; " +
                                    "style-src 'self' 'unsafe-inline'; " +
                                    "img-src 'self' data: https:; " +
                                    "frame-ancestors 'none'"));

                    if (securityHeadersProperties.isReferrerPolicyEnabled()) {
                        headers.referrerPolicy(referrer -> referrer.policy(
                                resolveReferrerPolicy(securityHeadersProperties.getReferrerPolicy())));
                    }
                })

                // 6️⃣ 授权规则
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/v1/api/auth/login",
                                "/v1/api/auth/register",
                                "/v1/api/auth/refresh",
                                "/v1/api/auth/logout",
                                "/api/auth/login",
                                "/api/auth/register",
                                "/api/auth/refresh",
                                "/api/auth/logout",
                                "/api/public/**"
                        ).permitAll()
                        .requestMatchers(
                                "/swagger-ui/**",
                                "/v3/api-docs/**",
                                "/swagger-resources/**",
                                "/webjars/**",
                                "/doc.html"
                        ).permitAll()
                        .requestMatchers("/actuator/health", "/actuator/info").permitAll()
                        .anyRequest().authenticated())

                // 7️⃣ 指定认证管理器（替代 DaoAuthenticationProvider）
                .authenticationManager(authenticationManager)

                // 8️⃣ 添加自定义过滤器
                .addFilterBefore(identityTokenVerificationFilter, LogoutFilter.class)
                .addFilterBefore(sqlInjectionFilter, LogoutFilter.class)
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(stepUpFilter, JwtAuthenticationFilter.class)
                // TenantContext 在 JwtAuthenticationFilter 之后:这样 Phase 1.5+ 时可以
                // 从 JWT claim 拿到 tenantId(目前 Phase 1.3 仅从 X-Tenant-Id header 读)
                .addFilterAfter(tenantContextFilter, JwtAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOriginPatterns(Arrays.asList(
                "https://*.bank.com",
                "https://*.nearsync.com",
                "http://localhost:*"
        ));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setExposedHeaders(Arrays.asList(
                "Authorization",
                "X-Total-Count",
                "X-Request-ID",
                "X-StepUp-Required"
        ));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }

    private ReferrerPolicyHeaderWriter.ReferrerPolicy resolveReferrerPolicy(String configured) {
        ReferrerPolicyHeaderWriter.ReferrerPolicy defaultPolicy =
                ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN;
        if (!StringUtils.hasText(configured)) {
            return defaultPolicy;
        }
        String normalized = configured.trim().toUpperCase().replace('-', '_');
        try {
            return ReferrerPolicyHeaderWriter.ReferrerPolicy.valueOf(normalized);
        } catch (IllegalArgumentException ex) {
            return defaultPolicy;
        }
    }
}
