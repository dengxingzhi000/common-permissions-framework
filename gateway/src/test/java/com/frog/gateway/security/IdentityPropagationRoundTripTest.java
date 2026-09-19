package com.frog.gateway.security;

import com.alibaba.fastjson2.JSON;
import com.frog.common.security.identity.IdentityTokenProperties;
import com.frog.common.security.identity.IdentityTokenVerifier;
import com.frog.gateway.properties.IdentityPropagationProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class IdentityPropagationRoundTripTest {

    private static final String SECRET =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    private IdentityPropagationWebFilter filter;
    private IdentityPropagationProperties props;
    private IdentityTokenProperties verifierProps;

    @BeforeEach
    void setup() {
        props = new IdentityPropagationProperties();
        props.setEnabled(true);
        props.setSignatureSecret(SECRET);

        verifierProps = new IdentityTokenProperties();
        verifierProps.setEnabled(true);
        verifierProps.setSharedSecret(SECRET);
        verifierProps.setMaxSkewSeconds(30);

        IdentityTokenEncoder encoder = new IdentityTokenEncoder(SECRET);
        filter = new IdentityPropagationWebFilter(props, encoder);
    }

    @Test
    void propagation_includesJtiInSignedPayload() {
        AtomicReference<ServerWebExchange> downstreamExchange = new AtomicReference<>();
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/test").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        String userId = UUID.randomUUID().toString();
        JwtAuthenticationToken auth = jwtAuth(userId, "alice", "dev-1",
                List.of("ROLE_user.read"));

        StepVerifier.create(
                        filter.filter(exchange, ex -> {
                                    downstreamExchange.set(ex);
                                    return Mono.empty();
                                })
                                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth))
                )
                .verifyComplete();

        ServerWebExchange mutated = downstreamExchange.get();
        assertThat(mutated).as("filter must mutate and forward downstream exchange").isNotNull();

        String token = mutated.getRequest().getHeaders().getFirst("X-Identity-Token");
        assertThat(token).as("X-Identity-Token must be set on mutated exchange").isNotBlank();
        assertThat(token).contains(".");

        Map<String, Object> payload = decodePayload(token);
        assertThat(payload).containsKey("jti");
        assertThat(payload.get("jti")).isInstanceOf(String.class);
        assertThat((String) payload.get("jti")).isNotBlank();
        assertThat(payload.get("userId")).isEqualTo(userId);
        assertThat(payload.get("username")).isEqualTo("alice");
        assertThat(payload.get("deviceId")).isEqualTo("dev-1");
    }

    @Test
    void propagation_jtiIsUniquePerRequest() {
        List<String> tokens = new ArrayList<>();
        String userId = UUID.randomUUID().toString();
        for (int i = 0; i < 3; i++) {
            AtomicReference<ServerWebExchange> downstream = new AtomicReference<>();
            MockServerHttpRequest req = MockServerHttpRequest.get("/api/test").build();
            MockServerWebExchange exchange = MockServerWebExchange.from(req);
            JwtAuthenticationToken auth = jwtAuth(userId, "alice", "dev-1",
                    List.of("ROLE_user.read"));

            StepVerifier.create(
                            filter.filter(exchange, ex -> {
                                        downstream.set(ex);
                                        return Mono.empty();
                                    })
                                    .contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth))
                    )
                    .verifyComplete();
            tokens.add(downstream.get().getRequest().getHeaders().getFirst("X-Identity-Token"));
        }

        String jti0 = decodePayload(tokens.get(0)).get("jti").toString();
        String jti1 = decodePayload(tokens.get(1)).get("jti").toString();
        String jti2 = decodePayload(tokens.get(2)).get("jti").toString();

        assertThat(jti0).isNotEqualTo(jti1);
        assertThat(jti1).isNotEqualTo(jti2);
        assertThat(jti0).isNotEqualTo(jti2);
    }

    @Test
    void roundTrip_gatewayTokenIsAcceptedByVerifier() {
        AtomicReference<ServerWebExchange> downstream = new AtomicReference<>();
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/test").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        String userId = UUID.randomUUID().toString();
        JwtAuthenticationToken auth = jwtAuth(userId, "bob", "dev-9",
                List.of("ROLE_user.read"));

        StepVerifier.create(
                        filter.filter(exchange, ex -> {
                                    downstream.set(ex);
                                    return Mono.empty();
                                })
                                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth))
                )
                .verifyComplete();

        String token = downstream.get().getRequest().getHeaders().getFirst("X-Identity-Token");
        assertThat(token).isNotBlank();

        IdentityTokenVerifier verifier = new IdentityTokenVerifier(verifierProps);
        IdentityTokenVerifier.VerifyResult verifyResult =
                verifier.verify(token, userId, "ROLE_user.read");

        assertThat(verifyResult.ok())
                .as("verifier must accept gateway-signed token: %s", verifyResult.reason())
                .isTrue();
    }

    private JwtAuthenticationToken jwtAuth(String userId, String username, String deviceId,
                                           List<String> roles) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", userId);
        claims.put("userId", userId);
        claims.put("username", username);
        claims.put("deviceId", deviceId);
        Instant issuedAt = Instant.now();
        Jwt jwt = new Jwt(
                "fake-token",
                issuedAt,
                issuedAt.plusSeconds(60),
                Map.of("alg", "RS256"),
                claims);
        var authorities = roles.stream()
                .map(r -> (org.springframework.security.core.GrantedAuthority)
                        new org.springframework.security.core.authority.SimpleGrantedAuthority(r))
                .toList();
        return new JwtAuthenticationToken(jwt, authorities, userId);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> decodePayload(String token) {
        String payloadB64 = token.substring(0, token.lastIndexOf('.'));
        byte[] json = Base64.getUrlDecoder().decode(payloadB64);
        return JSON.parseObject(new String(json), Map.class);
    }
}
