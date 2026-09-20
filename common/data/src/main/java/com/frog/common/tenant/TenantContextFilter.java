package com.frog.common.tenant;

import com.frog.common.response.ResultCode;
import jakarta.annotation.Nonnull;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;

/**
 * Servlet 过滤器 — 解析请求中的 tenantId 并写入 {@link TenantContext}。
 *
 * <p>解析顺序(Phase 1.3):
 * <ol>
 *   <li>HTTP header {@code X-Tenant-Id}(默认,可配置):支持 UUID 或 tenantCode</li>
 * </ol>
 *
 * <p>Phase 1.5+ 还会尝试从 JWT 的 {@code tenant_id} claim 中读取。
 *
 * <p>完成 chain 后必须 {@link TenantContext#clear()}。
 *
 * <p>注册位置:在 {@code JwtAuthenticationFilter} 之后,以便后续 Phase 能拿到 JWT claim。
 * 但作为兜底,即使 JWT 不带 tenant_id,也会从 header 读取。
 *
 * <p>失败语义:strictMode 下未携带任何 tenant 信息的请求直接 400 拒绝;
 * 非 strict 模式下继续请求,Service 层需自行处理 tenantId 缺失的情况。
 *
 * @author Deng
 * @since 2026-09-22
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class TenantContextFilter extends OncePerRequestFilter {

    /**
     * HTTP header 名:从中读取 tenantId 或 tenantCode(默认 {@code X-Tenant-Id})。
     */
    public static final String DEFAULT_HEADER_NAME = "X-Tenant-Id";

    /**
     * JWT 中 tenant_id claim 名称 — Phase 1.5 启用。
     */
    public static final String JWT_TENANT_CLAIM = "tenant_id";

    private final TenantProperties properties;

    @Override
    protected void doFilterInternal(@Nonnull HttpServletRequest request,
                                    @Nonnull HttpServletResponse response,
                                    @Nonnull FilterChain chain) throws ServletException, IOException {
        if (!properties.isEnabled()) {
            try {
                chain.doFilter(request, response);
            } finally {
                TenantContext.clear();
            }
            return;
        }

        UUID tenantId = null;
        try {
            tenantId = resolveTenantId(request);
        } catch (Exception ex) {
            log.warn("Failed to resolve tenantId on path={}: {}",
                    request.getRequestURI(), ex.getMessage());
        }

        if (tenantId == null && properties.isStrictMode()) {
            log.warn("Strict tenant mode: rejecting request without tenantId, path={}",
                    request.getRequestURI());
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write(
                    "{\"code\":\"" + ResultCode.BAD_REQUEST.getCode() + "\","
                            + "\"message\":\"Missing tenant context (X-Tenant-Id header required)\"}");
            return;
        }

        if (tenantId != null) {
            TenantContext.set(tenantId);
            log.debug("Tenant context set: path={}, tenantId={}",
                    request.getRequestURI(), tenantId);
        }

        try {
            chain.doFilter(request, response);
        } finally {
            TenantContext.clear();
        }
    }

    /**
     * 解析 tenantId:header 优先,再尝试 JWT claim(Phase 1.5+ 生效)。
     */
    UUID resolveTenantId(HttpServletRequest request) {
        String header = request.getHeader(properties.getHeaderName());
        if (StringUtils.hasText(header)) {
            return parseTenantReference(header.trim());
        }
        // Phase 1.5+: extract from JWT claim (预留,Phase 1.3 不启用)
        return null;
    }

    /**
     * 支持两种写法:
     * <ul>
     *   <li>{@code <UUID>} — 直接返回</li>
     *   <li>{@code <tenantCode>} — 视为租户编码;Phase 1.3 返回 null,
     *       由 Service 层调 TenantService 自行解析(避免此处耦合 Mapper)</li>
     * </ul>
     */
    UUID parseTenantReference(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException ex) {
            log.debug("Tenant reference '{}' is not a UUID; treating as tenantCode (Phase 1.3 no-op)",
                    value);
            return null;
        }
    }
}
