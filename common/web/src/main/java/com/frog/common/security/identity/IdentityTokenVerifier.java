package com.frog.common.security.identity;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;

/**
 * Verifies the {@code X-Identity-Token} header propagated by the gateway.
 *
 * <p>Wire format: {@code base64url(jsonPayload) + "." + hexHmacSha256(secret, base64url(jsonPayload))}.
 *
 * <p>Verification order (fail-closed):
 * <ol>
 *   <li>Property toggle — if {@code security.identity-propagation.enabled=false}, returns
 *       {@link VerifyResult#ok() ok}=true with reason {@code DISABLED} (used for staged rollout).</li>
 *   <li>Format — non-null, non-blank token, exactly one {@code "."} separator.</li>
 *   <li>Signature — HMAC-SHA256 constant-time comparison via
 *       {@link MessageDigest#isEqual(byte[], byte[])} (prevents timing attacks).</li>
 *   <li>Decode — payload round-tripped via {@link IdentityTokenPayloadCodec}.</li>
 *   <li>Freshness — {@code |now - payload.issuedAt|} ≤ {@code maxSkewSeconds}.</li>
 *   <li>Binding — optional claimed user id matches the payload's {@code userId}.</li>
 * </ol>
 *
 * <p>Companion to the gateway-side signer (Task 2.5) which produces tokens of the same shape.
 *
 * <p>The {@code claimedRoles} parameter is accepted to mirror the gateway contract and
 * reserved for a follow-up Wave where role-level checks are added.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class IdentityTokenVerifier {

    /**
     * Result of a {@link #verify} call. {@code ok}=true means the token is trusted and
     * {@code payload} carries the propagated identity; {@code ok}=false means the caller
     * must reject the request and {@code reason} is a stable machine-readable code
     * suitable for logging and response headers.
     */
    public record VerifyResult(boolean ok, IdentityTokenPayload payload, String reason) {}

    private final IdentityTokenProperties properties;

    public VerifyResult verify(String token, String claimedUserId, String claimedRoles) {
        if (!properties.isEnabled()) return new VerifyResult(true, null, "DISABLED");
        if (token == null || token.isBlank())
            return new VerifyResult(false, null, "MISSING");
        int dot = token.lastIndexOf('.');
        if (dot < 0) return new VerifyResult(false, null, "MALFORMED");
        String payload = token.substring(0, dot);
        String sig = token.substring(dot + 1);
        String expectedSig = hmacHex(payload);
        if (!MessageDigest.isEqual(sig.getBytes(StandardCharsets.UTF_8),
                                   expectedSig.getBytes(StandardCharsets.UTF_8))) {
            return new VerifyResult(false, null, "INVALID");
        }
        IdentityTokenPayload p;
        try {
            p = IdentityTokenPayloadCodec.decode(payload);
        } catch (Exception e) {
            return new VerifyResult(false, null, "DECODE_FAILED: " + e.getMessage());
        }
        long now = Instant.now().getEpochSecond();
        if (Math.abs(now - p.issuedAt()) > properties.getMaxSkewSeconds())
            return new VerifyResult(false, p, "EXPIRED");
        if (claimedUserId != null && !claimedUserId.equals(p.userId().toString()))
            return new VerifyResult(false, p, "USERID_MISMATCH");
        return new VerifyResult(true, p, "OK");
    }

    private String hmacHex(String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(properties.getSharedSecret().getBytes(StandardCharsets.UTF_8),
                                       "HmacSHA256"));
            return HexFormat.of().formatHex(mac.doFinal(data.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("HMAC failure", e);
        }
    }
}