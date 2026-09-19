package com.frog.common.security.identity;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class IdentityTokenVerifierTest {

    private static final String SECRET = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private IdentityTokenVerifier verifier;

    @BeforeEach
    void setup() {
        IdentityTokenProperties props = new IdentityTokenProperties();
        props.setEnabled(true);
        props.setSharedSecret(SECRET);
        props.setMaxSkewSeconds(30);
        verifier = new IdentityTokenVerifier(props);
    }

    @Test
    void verify_validToken_ok() {
        UUID userId = UUID.randomUUID();
        IdentityTokenPayload p = new IdentityTokenPayload(
                userId, "alice", "dev", List.of("user.read"),
                Instant.now().getEpochSecond(), UUID.randomUUID().toString());
        String token = signToken(p);
        IdentityTokenVerifier.VerifyResult r = verifier.verify(token, userId.toString(), "user.read");
        assertThat(r.ok()).isTrue();
    }

    @Test
    void verify_tamperedSignature_fails() {
        UUID userId = UUID.randomUUID();
        IdentityTokenPayload p = new IdentityTokenPayload(
                userId, "alice", "dev", List.of("user.read"),
                Instant.now().getEpochSecond(), UUID.randomUUID().toString());
        String token = signToken(p);
        String tampered = token.substring(0, token.length() - 4) + "0000";
        IdentityTokenVerifier.VerifyResult r = verifier.verify(tampered, userId.toString(), "user.read");
        assertThat(r.ok()).isFalse();
        assertThat(r.reason()).contains("INVALID");
    }

    @Test
    void verify_expiredToken_fails() {
        UUID userId = UUID.randomUUID();
        IdentityTokenPayload p = new IdentityTokenPayload(
                userId, "alice", "dev", List.of("user.read"),
                Instant.now().getEpochSecond() - 600, UUID.randomUUID().toString());
        String token = signToken(p);
        IdentityTokenVerifier.VerifyResult r = verifier.verify(token, userId.toString(), "user.read");
        assertThat(r.ok()).isFalse();
        assertThat(r.reason()).contains("EXPIRED");
    }

    @Test
    void verify_userIdMismatch_fails() {
        UUID realUser = UUID.randomUUID();
        UUID claimedUser = UUID.randomUUID();
        IdentityTokenPayload p = new IdentityTokenPayload(
                realUser, "alice", "dev", List.of("user.read"),
                Instant.now().getEpochSecond(), UUID.randomUUID().toString());
        String token = signToken(p);
        IdentityTokenVerifier.VerifyResult r = verifier.verify(token, claimedUser.toString(), "user.read");
        assertThat(r.ok()).isFalse();
    }

    private String signToken(IdentityTokenPayload p) {
        String payload = IdentityTokenPayloadCodec.encode(p);
        String sig = hmacHex(payload);
        return payload + "." + sig;
    }

    private String hmacHex(String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(SECRET.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return HexFormat.of().formatHex(mac.doFinal(data.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}