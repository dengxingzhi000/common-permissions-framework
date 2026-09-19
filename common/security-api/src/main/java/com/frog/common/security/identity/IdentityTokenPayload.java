package com.frog.common.security.identity;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Decoded payload of the gateway-to-backend {@code X-Identity-Token} header.
 *
 * <p>Used to propagate a caller identity across the internal network without re-issuing
 * an OAuth2 access token. The on-the-wire form is produced by
 * {@link IdentityTokenPayloadCodec#encode(IdentityTokenPayload)} and signed by an
 * HMAC-SHA256 shared secret (see {@code IdentityTokenVerifier}).
 *
 * <p>Fields:
 * <ul>
 *   <li>{@code userId} – UUID of the authenticated user</li>
 *   <li>{@code username} – human-readable username</li>
 *   <li>{@code deviceId} – originating device identifier</li>
 *   <li>{@code authorities} – list of authority codes propagated for this request</li>
 *   <li>{@code issuedAt} – epoch-seconds when the token was minted by the gateway</li>
 *   <li>{@code jti} – unique token ID (UUID string) for replay-protection</li>
 * </ul>
 *
 * <p>Lives in the security-api module so it can be referenced by both
 * {@code common/web} (verifier) and the gateway (signer) without forcing either
 * to depend on the other.
 *
 * @param userId      UUID of the authenticated user
 * @param username    human-readable username
 * @param deviceId    originating device identifier
 * @param authorities list of authority codes propagated for this request
 * @param issuedAt    epoch-seconds when the token was minted by the gateway
 * @param jti         unique token ID (UUID string) for replay protection
 */
public record IdentityTokenPayload(
        UUID userId,
        String username,
        String deviceId,
        List<String> authorities,
        long issuedAt,
        String jti
) {}