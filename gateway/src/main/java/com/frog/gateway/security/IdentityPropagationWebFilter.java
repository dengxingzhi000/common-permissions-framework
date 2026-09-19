package com.frog.gateway.security;

import com.frog.common.util.UUIDv7Util;
import com.frog.gateway.properties.IdentityPropagationProperties;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Adds signed identity headers to downstream requests once authentication succeeds.
 */
@Component
@RequiredArgsConstructor
public class IdentityPropagationWebFilter implements WebFilter, Ordered {
    private final IdentityPropagationProperties properties;
    private final IdentityTokenEncoder tokenEncoder;

    @Override
    public int getOrder() {
        return SecurityWebFiltersOrder.AUTHORIZATION.getOrder() + 1;
    }

    @Override
    @NonNull
    public Mono<Void> filter(@NonNull ServerWebExchange exchange, @NonNull WebFilterChain chain) {
        if (!properties.isEnabled()) {
            return chain.filter(exchange);
        }

        return ReactiveSecurityContextHolder.getContext()
                .mapNotNull(SecurityContext::getAuthentication)
                .filter(Authentication::isAuthenticated)
                .filter(auth -> auth instanceof JwtAuthenticationToken)
                .flatMap(auth ->
                        propagate(exchange, chain, (JwtAuthenticationToken) auth).thenReturn(true))
                .switchIfEmpty(Mono.just(false))
                .flatMap(propagated -> propagated ? Mono.empty() : chain.filter(exchange));
    }

    private Mono<Void> propagate(ServerWebExchange exchange,
                                 WebFilterChain chain,
                                 JwtAuthenticationToken authentication) {
        Jwt token = authentication.getToken();
        String userId = getClaim(token, properties.getUserIdClaim());
        if (!StringUtils.hasText(userId)) {
            return chain.filter(exchange);
        }

        String username = getClaim(token, properties.getUsernameClaim());
        String deviceId = getClaim(token, properties.getDeviceIdClaim());
        List<String> authorities = extractAuthorities(authentication);

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("sub", token.getSubject());
        payload.put("userId", userId);
        payload.put("username", username);
        payload.put("deviceId", deviceId);
        payload.put("authorities", authorities);
        payload.put("issuedAt", Instant.now().getEpochSecond());
        payload.put("jti", UUIDv7Util.generate().toString());

        String identityToken = tokenEncoder.encode(payload);

        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                .headers(headers -> {
                    headers.set(properties.getIdentityTokenHeader(), identityToken);
                    headers.set(properties.getUserIdHeader(), userId);
                    if (StringUtils.hasText(username)) {
                        headers.set(properties.getUsernameHeader(), username);
                    }
                    if (StringUtils.hasText(deviceId)) {
                        headers.set(properties.getDeviceIdHeader(), deviceId);
                    }
                    if (!authorities.isEmpty()) {
                        headers.set(properties.getRolesHeader(), String.join(",", authorities));
                    }
                })
                .build();

        return chain.filter(exchange.mutate().request(mutatedRequest).build());
    }

    private List<String> extractAuthorities(Authentication authentication) {
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .filter(StringUtils::hasText)
                .collect(Collectors.toList());
    }

    private String getClaim(Jwt token, String claimName) {
        if (!StringUtils.hasText(claimName)) {
            return null;
        }
        Object value = token.getClaims().get(claimName);
        return value != null ? value.toString() : null;
    }
}
