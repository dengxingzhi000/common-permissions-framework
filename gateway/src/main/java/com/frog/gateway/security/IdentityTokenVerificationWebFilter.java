package com.frog.gateway.security;

import com.frog.common.security.identity.IdentityTokenProperties;
import com.frog.common.security.identity.IdentityTokenVerifier;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Verifies the {@code X-Identity-Token} header on inbound requests at the gateway.
 *
 * <p>The gateway has already authenticated the user via OAuth2 JWT in
 * {@link com.frog.gateway.config.GatewaySecurityConfig}. This filter provides a
 * defense-in-depth check: it confirms that a properly signed identity token is
 * present before forwarding the request to downstream services. This catches
 * cases where:
 * <ul>
 *   <li>A request reaches the gateway bypassing OAuth2 authentication (e.g.
 *       direct internal calls from misconfigured clients).</li>
 *   <li>The token was tampered with in transit.</li>
 *   <li>The token has expired or is otherwise malformed.</li>
 * </ul>
 *
 * <p>Public endpoints aligned with {@code GatewaySecurityConfig.permitAll} are
 * bypassed — they have no identity to verify.
 *
 * <p>Ordering: positioned just before authentication so the check happens before
 * downstream identity propagation in {@link IdentityPropagationWebFilter}.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class IdentityTokenVerificationWebFilter implements WebFilter, Ordered {

    private static final AntPathMatcher MATCHER = new AntPathMatcher();

    private static final List<String> WHITELIST = List.of(
            "/api/auth/**",
            "/oauth2/**",
            "/api/public/**",
            "/actuator/health",
            "/actuator/info"
    );

    private static final String TOKEN_HEADER = "X-Identity-Token";
    private static final String USER_ID_HEADER = "X-User-Id";

    private final IdentityTokenVerifier verifier;
    private final IdentityTokenProperties properties;

    @Override
    public int getOrder() {
        return SecurityWebFiltersOrder.AUTHENTICATION.getOrder() - 1;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        if (!properties.isEnabled()) {
            return chain.filter(exchange);
        }

        String path = exchange.getRequest().getPath().value();
        if (WHITELIST.stream().anyMatch(p -> MATCHER.match(p, path))) {
            return chain.filter(exchange);
        }

        String token = exchange.getRequest().getHeaders().getFirst(TOKEN_HEADER);
        String claimedUserId = exchange.getRequest().getHeaders().getFirst(USER_ID_HEADER);

        IdentityTokenVerifier.VerifyResult result = verifier.verify(token, claimedUserId, null);

        if (!result.ok()) {
            String reasonCode = result.reason() == null
                    ? "UNKNOWN"
                    : result.reason().split(":", 2)[0];
            log.warn("Gateway identity-token rejected path={} reason={}", path, result.reason());
            return reject(exchange, reasonCode);
        }

        return chain.filter(exchange);
    }

    private Mono<Void> reject(ServerWebExchange exchange, String reasonCode) {
        ServerHttpResponse resp = exchange.getResponse();
        resp.setStatusCode(HttpStatus.UNAUTHORIZED);
        resp.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        DataBufferFactory bf = resp.bufferFactory();
        String body = "{\"error\":\"IDENTITY_TOKEN_" + reasonCode + "\","
                + "\"reason\":\"" + reasonCode + "\"}";
        DataBuffer buf = bf.wrap(body.getBytes(StandardCharsets.UTF_8));
        return resp.writeWith(Mono.just(buf));
    }
}
