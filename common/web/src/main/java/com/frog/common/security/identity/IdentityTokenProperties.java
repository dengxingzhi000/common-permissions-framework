package com.frog.common.security.identity;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration for {@link IdentityTokenVerifier}.
 *
 * <p>Bound from {@code security.identity-propagation.*} in {@code application.yml}:
 * <pre>
 * security:
 *   identity-propagation:
 *     enabled: true
 *     shared-secret: ${IDENTITY_TOKEN_SECRET}
 *     max-skew-seconds: 30
 *     failure-mode: strict        # strict | log-and-pass
 * </pre>
 *
 * <p>{@code sharedSecret} must be at least 32 bytes (256 bits) to match the strength
 * of the HMAC-SHA256 signature scheme; longer secrets are recommended for rotation.
 *
 * <p>{@code failureMode} is reserved for a follow-up (planned in Task 2.3 / Wave 2):
 * {@code strict} (default) rejects any verification failure with HTTP 401,
 * {@code log-and-pass} accepts and only logs (intended for staged rollout).
 */
@Data
@ConfigurationProperties(prefix = "security.identity-propagation")
public class IdentityTokenProperties {
    private boolean enabled = true;
    private String sharedSecret;
    private int maxSkewSeconds = 30;
    private String failureMode = "strict"; // strict | log-and-pass
}