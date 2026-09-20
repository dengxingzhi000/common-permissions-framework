package com.frog.common.security.stepup;

import com.alibaba.csp.sentinel.Entry;
import com.alibaba.csp.sentinel.SphU;
import com.alibaba.csp.sentinel.slots.block.BlockException;
import com.frog.common.log.service.ISysAuditLogService;
import com.frog.common.security.decision.DecisionEvent;
import com.frog.common.security.decision.DecisionRecorder;
import com.frog.common.security.metrics.SecurityMetrics;
import com.frog.common.security.util.FilterBypassHelper;
import com.frog.common.security.util.HttpServletRequestUtils;
import com.frog.common.security.util.JwtUtils;
import com.frog.common.security.util.SecurityErrorResponseWriter;
import com.frog.common.web.domain.SecurityUser;
import com.frog.common.web.util.SecurityUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.UUID;

/**
 * Step-Up 认证过滤器：基于 Sentinel 熔断保护的敏感操作二次认证校验
 *
 * <p>使用 Sentinel 进行熔断降级保护，替代原有的 SimpleCircuitBreaker
 *
 * <p>Sentinel Resource: "step-up:evaluate"
 *
 * @author Deng
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class StepUpFilter extends OncePerRequestFilter {
    private final StepUpEvaluator evaluator;
    private final ISysAuditLogService auditLogService;
    private final JwtUtils jwtUtils;
    private final HttpServletRequestUtils requestUtils;
    private final SecurityMetrics securityMetrics;
    private final StepUpProperties properties;
    private final DecisionRecorder decisionRecorder;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        if (!properties.isEnabled()) {
            filterChain.doFilter(request, response);
            return;
        }

        String uri = request.getRequestURI();
        if (FilterBypassHelper.matchesAny(uri, properties.getWhitelistPaths())) {
            filterChain.doFilter(request, response);
            return;
        }

        SecurityUser user = SecurityUtils.getCurrentUser();
        if (shouldBypass(uri, user)) {
            response.setHeader("X-StepUp-Bypass", "config");
            securityMetrics.increment("security.stepup.bypass.config");
            filterChain.doFilter(request, response);
            return;
        }

        // Sentinel resource protection for step-up evaluation
        StepUpRequirement requirement;
        try(Entry entry = SphU.entry("step-up:evaluate")) {
            requirement = evaluator.evaluate(request, user);

        } catch (BlockException ex) {
            // Sentinel circuit is open or rate limited
            if (properties.getCircuitBreaker().isBypassOnOpen()) {
                log.warn("Step-up evaluation BLOCKED by Sentinel, bypassing: uri={}", uri, ex);
                response.setHeader("X-StepUp-Bypass", "sentinel-circuit");
                securityMetrics.increment("security.stepup.bypass.circuit");
                filterChain.doFilter(request, response);
                return;
            } else {
                log.error("Step-up evaluation BLOCKED by Sentinel, denying access: uri={}", uri, ex);
                throw new ServletException("Step-up evaluation blocked by circuit breaker", ex);
            }

        } catch (Exception ex) {
            // Evaluation logic failed
            if (properties.getCircuitBreaker().isBypassOnOpen()) {
                log.error("Step-up evaluation failed, bypassing: {}", ex.getMessage(), ex);
                response.setHeader("X-StepUp-Bypass", "error");
                securityMetrics.increment("security.stepup.bypass.error");
                filterChain.doFilter(request, response);
                return;
            }
            throw new ServletException("Step-up evaluation failed", ex);

        }

        if (requirement != StepUpRequirement.NONE) {
            String token = requestUtils.getTokenFromRequest(request);
            java.util.Set<String> amr = token != null ? jwtUtils.getAmrFromToken(token) : Collections.emptySet();
            if ((requirement == StepUpRequirement.MFA && amr.contains("mfa"))
                    || (requirement == StepUpRequirement.WEBAUTHN && amr.contains("webauthn"))) {
                filterChain.doFilter(request, response);
                return;
            }
        }
        if (requirement != StepUpRequirement.NONE) {
            String require = requirement == StepUpRequirement.MFA ? "mfa" : "webauthn";
            response.setHeader("X-StepUp-Required", require);
            SecurityErrorResponseWriter.write(request, response,
                    HttpServletResponse.SC_UNAUTHORIZED,
                    "STEP_UP_REQUIRED",
                    "Step-up required: " + require);
            securityMetrics.increment("security.stepup.required");

            UUID userIdForDecision = user != null ? user.getUserId() : null;
            decisionRecorder.record(new DecisionEvent(
                    UUID.randomUUID(), "user", userIdForDecision, "auth.stepup",
                    null, null, Map.of("required", require),
                    "deny", "STEP_UP_REQUIRED",
                    null, request.getHeader("X-Request-ID"),
                    0L, "common-web", Instant.now()));

            if (user != null) {
                UUID userId = user.getUserId();
                auditLogService.recordSecurityEvent(
                        "STEP_UP_REQUIRED", 2,
                        userId,
                        user.getUsername(),
                        request.getRemoteAddr(),
                        request.getRequestURI(),
                        false,
                        "Step-up required: " + require
                );
            }
            UUID userIdLog = user != null ? user.getUserId() : null;
            log.info("Step-up required: traceId={} userId={} method={} uri={} -> {}",
                    request.getHeader("X-Request-ID"), userIdLog, request.getMethod(), request.getRequestURI(), require);
            return;
        }

        filterChain.doFilter(request, response);
    }

    private boolean shouldBypass(String uri, SecurityUser user) {
        return FilterBypassHelper.shouldBypass(uri, user,
                properties.getBypassPaths(),
                properties.getBypassUsers(),
                properties.getBypassRoles(),
                properties.getBypassPermissions());
    }
}
