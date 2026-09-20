package com.frog.common.tenant;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

/**
 * WebFlux 过滤器 — Gateway 端的 tenantId 解析。
 *
 * <p>逻辑与 servlet 版 {@link TenantContextFilter} 一致,但作用于响应式上下文。
 * 通过 Reactor Context 在 chain 中传递 tenantId,末端从 Context 中取出写入
 * {@link TenantContext} ThreadLocal,然后在 Mono {@code doFinally} 中清理。
 *
 * <p>注册位置(gateway):在 {@code IdentityTokenVerificationWebFilter} 之后。
 *
 * @author Deng
 * @since 2026-09-22
 */
@Slf4j
@RequiredArgsConstructor
public class TenantContextWebFilter implements WebFilter, Ordered {

    /**
     * Reactor Context key — 在 chain 中传递解析后的 tenantId。
     */
    public static final String CTX_TENANT_ID = "tenant.id";

    private final TenantProperties properties;

    @Override
    public int getOrder() {
        // 在身份验证之后,业务处理之前。IdentityTokenVerificationWebFilter 的
        // order = SecurityWebFiltersOrder.AUTHENTICATION.getOrder() - 1,本过滤器
        // 取其 +10,确保身份验证先完成。
        return -1000 + 10;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        if (!properties.isEnabled()) {
            return chain.filter(exchange).doFinally(s -> TenantContext.clear());
        }

        UUID tenantId = resolveTenantId(exchange);
        if (tenantId == null && properties.isStrictMode()) {
            return reject(exchange);
        }

        if (tenantId != null) {
            // 写入 Reactor Context,让下游 Mono 可以拿到
            return chain.filter(exchange)
                    .contextWrite(reactor.util.context.Context.of(CTX_TENANT_ID, tenantId))
                    .doFirst(() -> TenantContext.set(tenantId))
                    .doFinally(s -> TenantContext.clear());
        }
        return chain.filter(exchange).doFinally(s -> TenantContext.clear());
    }

    UUID resolveTenantId(ServerWebExchange exchange) {
        String header = exchange.getRequest().getHeaders().getFirst(properties.getHeaderName());
        if (header == null || header.isBlank()) {
            return null;
        }
        try {
            return UUID.fromString(header.trim());
        } catch (IllegalArgumentException ex) {
            log.debug("WebFlux tenant reference '{}' is not a UUID; Phase 1.3 no-op", header);
            return null;
        }
    }

    private Mono<Void> reject(ServerWebExchange exchange) {
        org.springframework.http.server.reactive.ServerHttpResponse resp = exchange.getResponse();
        resp.setStatusCode(org.springframework.http.HttpStatus.BAD_REQUEST);
        resp.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        HttpHeaders headers = resp.getHeaders();
        if (headers.getFirst("Content-Type") == null) {
            headers.set("Content-Type", "application/json;charset=UTF-8");
        }
        byte[] body = ("{\"code\":\"BAD_REQUEST\","
                + "\"message\":\"Missing tenant context (X-Tenant-Id required)\"}")
                .getBytes(StandardCharsets.UTF_8);
        return resp.writeWith(Mono.just(resp.bufferFactory().wrap(body)));
    }
}
