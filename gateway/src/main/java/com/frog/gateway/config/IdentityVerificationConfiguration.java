package com.frog.gateway.config;

import com.frog.common.security.identity.IdentityTokenProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

/**
 * Wires the identity-token verifier into the gateway context.
 *
 * <p>The verification filter ({@link com.frog.gateway.security.IdentityTokenVerificationWebFilter})
 * is auto-registered via {@code @Component}; this configuration makes its dependencies
 * available: {@link IdentityTokenProperties} (via {@code @EnableConfigurationProperties})
 * and {@link com.frog.common.security.identity.IdentityTokenVerifier} (via the targeted
 * {@code @ComponentScan} since the gateway's main scan only covers {@code com.frog.gateway}).
 */
@Configuration
@EnableConfigurationProperties(IdentityTokenProperties.class)
@ComponentScan(basePackages = "com.frog.common.security.identity")
public class IdentityVerificationConfiguration {
}
