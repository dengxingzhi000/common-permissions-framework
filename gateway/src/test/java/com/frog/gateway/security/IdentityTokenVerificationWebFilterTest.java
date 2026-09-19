package com.frog.gateway.security;

import com.frog.common.security.identity.IdentityTokenPayload;
import com.frog.common.security.identity.IdentityTokenPayloadCodec;
import com.frog.common.security.identity.IdentityTokenProperties;
import com.frog.common.security.identity.IdentityTokenVerifier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;

class IdentityTokenVerificationWebFilterTest {

    private static final String SECRET =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    private IdentityTokenVerificationWebFilter filter;

    @BeforeEach
    void setup() {
        IdentityTokenProperties props = new IdentityTokenProperties();
        props.setEnabled(true);
        props.setSharedSecret(SECRET);
        props.setMaxSkewSeconds(30);
        IdentityTokenVerifier verifier = new IdentityTokenVerifier(props);
        filter = new IdentityTokenVerificationWebFilter(verifier, props);
    }

    @Test
    void filter_whitelistedAuthPath_passesThrough() {
        MockServerHttpRequest request = MockServerHttpRequest.post("/api/auth/login").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        AtomicBoolean proceeded = new AtomicBoolean(false);

        StepVerifier.create(filter.filter(exchange, e -> {
            proceeded.set(true);
            return Mono.empty();
        })).verifyComplete();

        assertThat(proceeded).isTrue();
        assertThat(exchange.getResponse().getStatusCode()).isNull();
    }

    @Test
    void filter_whitelistedPublicPath_passesThrough() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/public/health").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        AtomicBoolean proceeded = new AtomicBoolean(false);

        StepVerifier.create(filter.filter(exchange, e -> {
            proceeded.set(true);
            return Mono.empty();
        })).verifyComplete();

        assertThat(proceeded).isTrue();
    }

    @Test
    void filter_whitelistedActuatorPath_passesThrough() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/actuator/health").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        AtomicBoolean proceeded = new AtomicBoolean(false);

        StepVerifier.create(filter.filter(exchange, e -> {
            proceeded.set(true);
            return Mono.empty();
        })).verifyComplete();

        assertThat(proceeded).isTrue();
    }

    @Test
    void filter_missingTokenOnProtectedPath_rejects401() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/system/users").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        StepVerifier.create(filter.filter(exchange, e -> Mono.empty()))
                .verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        String body = exchange.getResponse().getBodyAsString().block();
        assertThat(body).contains("IDENTITY_TOKEN_MISSING");
    }

    @Test
    void filter_validToken_passesThrough() {
        UUID userId = UUID.randomUUID();
        String token = signedTokenFor(userId, Instant.now().getEpochSecond());

        MockServerHttpRequest request = MockServerHttpRequest.get("/api/system/users")
                .header("X-Identity-Token", token)
                .header("X-User-Id", userId.toString())
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        AtomicBoolean proceeded = new AtomicBoolean(false);

        StepVerifier.create(filter.filter(exchange, e -> {
            proceeded.set(true);
            return Mono.empty();
        })).verifyComplete();

        assertThat(proceeded).isTrue();
        assertThat(exchange.getResponse().getStatusCode()).isNull();
    }

    @Test
    void filter_tamperedToken_rejects401() {
        UUID userId = UUID.randomUUID();
        String token = signedTokenFor(userId, Instant.now().getEpochSecond());
        String tampered = token.substring(0, token.length() - 4) + "0000";

        MockServerHttpRequest request = MockServerHttpRequest.get("/api/system/users")
                .header("X-Identity-Token", tampered)
                .header("X-User-Id", userId.toString())
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        StepVerifier.create(filter.filter(exchange, e -> Mono.empty()))
                .verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        String body = exchange.getResponse().getBodyAsString().block();
        assertThat(body).contains("IDENTITY_TOKEN_INVALID");
    }

    @Test
    void filter_disabled_passesThroughEvenWithoutToken() {
        IdentityTokenProperties disabledProps = new IdentityTokenProperties();
        disabledProps.setEnabled(false);
        disabledProps.setSharedSecret(SECRET);
        IdentityTokenVerifier verifier = new IdentityTokenVerifier(disabledProps);
        IdentityTokenVerificationWebFilter disabled =
                new IdentityTokenVerificationWebFilter(verifier, disabledProps);

        MockServerHttpRequest request = MockServerHttpRequest.get("/api/system/users").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        AtomicBoolean proceeded = new AtomicBoolean(false);

        StepVerifier.create(disabled.filter(exchange, e -> {
            proceeded.set(true);
            return Mono.empty();
        })).verifyComplete();

        assertThat(proceeded).isTrue();
    }

    private String signedTokenFor(UUID userId, long issuedAt) {
        IdentityTokenPayload p = new IdentityTokenPayload(
                userId, "alice", "dev", List.of("user.read"),
                issuedAt, UUID.randomUUID().toString());
        String payload = IdentityTokenPayloadCodec.encode(p);
        return payload + "." + hmacHex(payload);
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
