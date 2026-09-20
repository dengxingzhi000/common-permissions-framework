package com.frog.system.evaluator;

import com.frog.common.security.decision.DecisionEvent;
import com.frog.common.security.decision.DecisionRecorder;
import com.frog.common.web.domain.SecurityUser;
import com.frog.system.service.ISysPermissionService;
import com.frog.system.service.ISysUserPermissionService;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/**
 * 自定义权限评估器
 *
 * @author Deng
 * createData 2025/10/14 14:59
 * @version 1.0
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class CustomPermissionEvaluator implements PermissionEvaluator {
    private final ISysPermissionService permissionService;
    private final ISysUserPermissionService userPermissionService;
    private final DecisionRecorder decisionRecorder;

    /**
     * 判断用户是否有指定权限。
     * 检查两条路径：(1) 角色继承的权限；(2) 直接授予的权限 (sys_user_permission,审批 type=2)。
     */
    @Override
    public boolean hasPermission(@NonNull Authentication authentication, @NonNull Object targetDomainObject,
                                 @NonNull Object permission) {
        if (!(authentication.getPrincipal() instanceof SecurityUser user)) {
            return false;
        }

        String permissionCode = permission.toString();
        long start = System.currentTimeMillis();
        boolean viaRole = permissionService.hasPermission(user.getUserId(), permissionCode);
        boolean viaDirect = userPermissionService.findEffectiveCodes(user.getUserId())
                .contains(permissionCode);
        boolean allowed = viaRole || viaDirect;
        long latencyMs = System.currentTimeMillis() - start;

        log.debug("Permission check - User: {}, Permission: {}, viaRole={}, viaDirect={}",
                user.getUsername(), permissionCode, viaRole, viaDirect);

        decisionRecorder.record(new DecisionEvent(
                UUID.randomUUID(), "user", user.getUserId(), permissionCode,
                null, null, Map.of("viaRole", viaRole, "viaDirect", viaDirect),
                allowed ? "allow" : "deny", null, null, null,
                latencyMs, "system-service", Instant.now()));

        return allowed;
    }

    /**
     * 判断用户是否有指定资源的权限（基于资源ID）
     */
    @Override
    public boolean hasPermission(@NonNull Authentication authentication, @NonNull Serializable targetId,
                                 @NonNull String targetType, @NonNull Object permission) {
        if (!(authentication.getPrincipal() instanceof SecurityUser user)) {
            return false;
        }

        // 可以实现更复杂的资源级权限控制
        // 例如：检查用户是否可以访问特定ID的资源
        boolean hasPermission = permissionService.hasResourcePermission(
                user.getUserId(), targetType, targetId, permission.toString());

        log.debug("Resource permission check - User: {}, TargetType: {}, TargetId: {}, Permission: {}, Result: {}",
                user.getUsername(), targetType, targetId, permission, hasPermission);

        return hasPermission;
    }
}
