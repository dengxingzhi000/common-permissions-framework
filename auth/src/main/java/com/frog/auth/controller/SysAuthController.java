package com.frog.auth.controller;

import com.alibaba.csp.sentinel.annotation.SentinelResource;
import com.frog.auth.service.ISysAuthService;
import com.frog.common.dto.user.LoginRequest;
import com.frog.common.dto.user.LoginResponse;
import com.frog.common.dto.user.RefreshTokenRequest;
import com.frog.common.dto.user.UserInfo;
import com.frog.common.feign.client.SysUserServiceClient;
import com.frog.common.log.annotation.AuditLog;
import com.frog.common.response.ApiResults;
import com.frog.common.security.util.HttpServletRequestUtils;
import com.frog.common.security.util.IpUtils;
import com.frog.common.sentinel.annotation.RateLimit;
import com.frog.common.util.UUIDv7Util;
import com.frog.common.web.util.SecurityUtils;
import org.apache.dubbo.config.annotation.DubboReference;
import com.frog.system.api.UserDubboService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.util.StringUtils;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * 系统认证控制器
 * 提供用户登录、登出、Token刷新等相关接口
 * <p>
 * WebAuthn 相关接口请参考 {@link WebAuthnCredentialController}
 *
 * @author Deng
 * @version 1.0
 * @since 2025-10-14
 */
@Slf4j
@Validated
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Tag(
        name = "系统认证",
        description = "用户登录、登出、Token 管理"
)
public class SysAuthController {
    private final ISysAuthService authService;
    private final SysUserServiceClient userServiceClient;
    private final HttpServletRequestUtils httpServletRequestUtils;
    @DubboReference(version = "1.0.0", check = true, timeout = 3000)
    private final UserDubboService userDubboService;

    /**
     * 用户登录接口
     *
     * @param request 登录请求参数
     * @param httpRequest HTTP 请求对象
     * @return 登录响应结果
     */
    @PostMapping("/login")
    @SentinelResource(value = "auth_login")
    @RateLimit()
    @Operation(
            summary = "用户登录",
            description = "使用用户名密码进行登录认证"
    )
    public ApiResults<LoginResponse> login(
            @RequestBody @Valid LoginRequest request,
            HttpServletRequest httpRequest) {
        String ipAddress = IpUtils.getClientIp(httpRequest);
        String deviceId = httpServletRequestUtils.getDeviceId(httpRequest);
        String traceId = traceId(httpRequest);

        LoginResponse response = authService.login(request, ipAddress, deviceId);
        log.info("login success traceId={} user={} ip={} device={}", traceId, request.getUsername(), ipAddress, deviceId);

        return ApiResults.success(response);
    }

    /**
     * 用户登出接口
     *
     * @param request HTTP 请求对象
     * @return 操作结果
     */
    @PostMapping("/logout")
    @PreAuthorize("isAuthenticated()")
    @Operation(
            summary = "用户登出",
            description = "撤销当前用户的访问令牌"
    )
    public ApiResults<Void> logout(HttpServletRequest request) {
        String token = httpServletRequestUtils.getTokenFromRequest(request);
        if (!StringUtils.hasText(token)) {
            return ApiResults.fail(400, "Missing token");
        }
        UUID userId = SecurityUtils.getCurrentUserUuid().orElse(null);
        String traceId = traceId(request);

        authService.logout(token, userId, "用户主动登出");
        log.info("logout traceId={} userId={}", traceId, userId);

        return ApiResults.success();
    }

    /**
     * 刷新 Token 接口
     *
     * @param request 刷新 Token 请求
     * @param httpRequest HTTP 请求对象
     * @return 登录响应结果
     */
    @PostMapping("/refresh")
    @RateLimit()
    @Operation(
            summary = "刷新 Token",
            description = "使用 Refresh Token 获取新的访问令牌"
    )
    public ApiResults<LoginResponse> refreshToken(
            @RequestBody @Valid RefreshTokenRequest request,
            HttpServletRequest httpRequest) {
        if (!StringUtils.hasText(request.getRefreshToken())) {
            return ApiResults.fail(400, "Missing refresh token");
        }
        String ipAddress = IpUtils.getClientIp(httpRequest);

        String deviceId = httpServletRequestUtils.getDeviceId(httpRequest);
        if (StringUtils.hasText(request.getDeviceId())) {
            deviceId = request.getDeviceId();
        }

        LoginResponse response = authService.refreshToken(
                request.getRefreshToken(),
                deviceId,
                ipAddress);

        return ApiResults.success(response);
    }

    /**
     * 获取当前用户信息接口
     *
     * @param request HTTP 请求对象
     * @return 用户信息
     */
    @GetMapping("/userinfo")
    @PreAuthorize("isAuthenticated()")
    @Operation(
            summary = "获取用户信息",
            description = "获取当前登录用户的详细信息"
    )
    public ApiResults<UserInfo> getUserInfo(HttpServletRequest request) {
        UUID userId = SecurityUtils.getCurrentUserUuid().orElse(null);
        if (userId == null) {
            return ApiResults.fail(401, "Unauthorized");
        }

        // 优先使用 Dubbo，失败回退到 Feign
        UserInfo userInfo;
        try {
            userInfo = userDubboService.getUserInfo(userId);
        } catch (Exception ex) {
            try {
                userInfo = userServiceClient.getUserInfo(userId).data();
            } catch (Exception ex2) {
                String traceId = traceId(request);
                log.error("getUserInfo failed traceId={} userId={} dubboErr={} feignErr={}",
                        traceId, userId, ex.getMessage(), ex2.getMessage());
                return ApiResults.fail(503, "User info unavailable");
            }
        }

        return ApiResults.success(userInfo);
    }

    /**
     * 强制用户登出接口
     *
     * @param userId 用户 ID
     * @param reason 登出原因
     * @return 操作结果
     */
    @PostMapping("/force-logout/{userId}")
    @PreAuthorize("hasAuthority('system:user:edit')")
    @AuditLog(
            operation = "强制下线",
            businessType = "USER",
            riskLevel = 3
    )
    @Operation(
            summary = "强制登出",
            description = "管理员强制指定用户下线"
    )
    public ApiResults<Void> forceLogout(
            @Parameter(description = "用户 ID", required = true)
            @PathVariable UUID userId,
            @Parameter(description = "登出原因", required = true)
            @RequestParam @NotBlank(message = "登出原因不能为空") String reason) {

        authService.forceLogout(userId, reason);
        log.info("force logout userId={} reason={}", userId, reason);

        return ApiResults.success();
    }

    private String traceId(HttpServletRequest request) {
        String id = request.getHeader("X-Request-ID");
        if (!StringUtils.hasText(id)) {
            id = request.getHeader("traceparent");
        }
        return StringUtils.hasText(id) ? id : UUIDv7Util.generate().toString();
    }
}
