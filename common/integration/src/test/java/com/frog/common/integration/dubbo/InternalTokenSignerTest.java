package com.frog.common.integration.dubbo;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class InternalTokenSignerTest {

    private static final String SECRET = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    InternalTokenSigner signer;

    @BeforeEach
    void setup() {
        InternalTokenProperties props = new InternalTokenProperties();
        props.setSharedSecret(SECRET);
        props.setTtlSeconds(60);
        signer = new InternalTokenSigner(props);
    }

    @Test
    void signVerify_roundTrip_ok() {
        String token = signer.sign("auth-service", "user-uuid-here");
        InternalTokenSigner.VerifyResult r = signer.verify(token, "auth-service");
        assertThat(r.ok()).isTrue();
        assertThat(r.userId()).isEqualTo("user-uuid-here");
    }

    @Test
    void verify_wrongCaller_rejected() {
        String token = signer.sign("auth-service", "user-uuid");
        InternalTokenSigner.VerifyResult r = signer.verify(token, "gateway-service");
        assertThat(r.ok()).isFalse();
    }

    @Test
    void verify_tampered_rejected() {
        String token = signer.sign("auth-service", "user-uuid");
        String tampered = token.substring(0, token.length() - 4) + "0000";
        InternalTokenSigner.VerifyResult r = signer.verify(tampered, "auth-service");
        assertThat(r.ok()).isFalse();
    }
}
