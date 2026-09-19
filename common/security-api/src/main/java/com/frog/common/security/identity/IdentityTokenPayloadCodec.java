package com.frog.common.security.identity;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Encodes and decodes {@link IdentityTokenPayload} values to/from the URL-safe
 * Base64 wire form used inside the {@code X-Identity-Token} header.
 *
 * <p>Wire format: {@code base64url(json)} (no padding). Jackson is used to (de)serialize
 * the record fields. This codec does <strong>not</strong> sign the payload – signing
 * and verification are handled separately by the gateway's signer and
 * {@code IdentityTokenVerifier} using HMAC-SHA256.
 *
 * <p>Used by:
 * <ul>
 *   <li>gateway – encodes the payload before signing</li>
 *   <li>{@code common/web} verifier – decodes after signature validation</li>
 *   <li>integration tests – round-trip the payload for assertions</li>
 * </ul>
 */
public final class IdentityTokenPayloadCodec {
    private static final ObjectMapper MAPPER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    private IdentityTokenPayloadCodec() {}

    public static String encode(IdentityTokenPayload p) {
        try {
            byte[] json = MAPPER.writeValueAsBytes(p);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(json);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to encode identity payload", e);
        }
    }

    public static IdentityTokenPayload decode(String wire) {
        try {
            byte[] json = Base64.getUrlDecoder().decode(wire.getBytes(StandardCharsets.UTF_8));
            return MAPPER.readValue(json, IdentityTokenPayload.class);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid identity token payload: " + e.getMessage(), e);
        }
    }
}