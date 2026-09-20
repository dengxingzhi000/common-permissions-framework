package com.frog.auth.controller;

import com.frog.auth.service.IOAuth2LogoutService;
import com.frog.common.log.annotation.AuditLog;
import com.frog.common.response.ApiResults;
import com.frog.common.security.util.HttpServletRequestUtils;
import com.frog.common.web.domain.SecurityUser;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.util.StringUtils;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

/**
 * OAuth2 登出控制器
 *
 * <p>两个职责分离的端点:</p>
 * <ul>
 *   <li>{@code POST /oauth2/logout} - 单客户端撤销,需已登录</li>
 *   <li>{@code POST /oauth2/logout/all} - 全局撤销,需 {@code oauth2:logout:global} 权限</li>
 * </ul>
 *
 * @since 2025-11-10 (refactored 2026-09-19)
 */
@Slf4j
@Validated
@RestController
@RequestMapping("/oauth2")
@RequiredArgsConstructor
@Tag(name = "OAuth2 登出", description = "OAuth2 授权撤销管理")
public class OAuth2LogoutController {

    private final IOAuth2LogoutService oauth2LogoutService;
    private final HttpServletRequestUtils httpServletRequestUtils;

    @PostMapping("/logout")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "OAuth2 单客户端撤销", description = "撤销当前用户在该客户端的 OAuth2 授权")
    public ApiResults<Void> revokeByClient(
            HttpServletRequest request,
            @RequestParam("clientId") @NotBlank(message = "clientId 不能为空") String clientId,
            @AuthenticationPrincipal SecurityUser caller) {

        String accessToken = httpServletRequestUtils.getTokenFromRequest(request);
        if (!StringUtils.hasText(accessToken)) {
            return ApiResults.fail(400, "Authorization 头格式无效");
        }

        oauth2LogoutService.revokeByClient(accessToken, clientId, caller.getUserId());
        return ApiResults.success();
    }

    @PostMapping("/logout/all")
    @PreAuthorize("hasAuthority('oauth2:logout:global')")
    @AuditLog(operation = "OAuth2 全局登出", businessType = "USER", riskLevel = 3)
    @Operation(summary = "OAuth2 全局登出", description = "撤销指定用户的所有 OAuth2 授权(需 oauth2:logout:global 权限)")
    public ApiResults<Integer> revokeGlobal(
            @RequestParam("userId") UUID userId,
            @RequestParam("reason") @NotBlank(message = "reason 不能为空") String reason,
            @AuthenticationPrincipal SecurityUser caller) {

        int removed = oauth2LogoutService.revokeGlobal(userId, reason, caller.getUsername());
        return ApiResults.success(removed);
    }
}
