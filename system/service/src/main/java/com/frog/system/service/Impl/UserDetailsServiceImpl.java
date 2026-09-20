package com.frog.system.service.Impl;

import com.frog.common.web.domain.SecurityUser;
import com.frog.system.domain.entity.SysApplication;
import com.frog.system.mapper.SysUserMapper;
import com.frog.system.mapper.SysUserRoleMapper;
import com.frog.system.service.ISysApplicationService;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.UUID;

/**
 * UserDetailsService 实现
 *
 * @author Deng
 * createData 2025/10/14 14:54
 * @version 2.1 (Phase 1.5: tenantId + appId)
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class UserDetailsServiceImpl implements UserDetailsService {
    private final SysUserMapper sysUserMapper;
    private final SysUserRoleMapper sysUserRoleMapper;
    private final ISysApplicationService applicationService;

    @Override
    @Cacheable(
            value = "userDetails",
            key = "#username",
            unless = "#result == null"
    )
    @NonNull
    public UserDetails loadUserByUsername(@NonNull String username) throws UsernameNotFoundException {
        // 1. 从 db_user 库查询用户基本信息
        var user = sysUserMapper.findByUsername(username);
        if (user == null || user.getDeleted()) {
            log.warn("User not found: {}", username);
            throw new UsernameNotFoundException("用户不存在或已删除: " + username);
        }

        // 2. 从 db_permission 库查询用户角色（跨库查询）
        Set<String> roles = sysUserRoleMapper.findRoleCodesByUserId(user.getId());

        // 3. 从 db_permission 库查询用户权限（跨库查询）
        Set<String> permissions = sysUserRoleMapper.findPermissionCodesByUserId(user.getId());

        // 4. Phase 1.5 — 解析 tenantId / appId
        UUID tenantId = user.getTenantId();
        UUID appId = resolveDefaultAppId(tenantId);

        SecurityUser securityUser = SecurityUser.builder()
                .userId(user.getId())
                .username(user.getUsername())
                .password(user.getPassword())
                .realName(user.getRealName())
                .deptId(user.getDeptId())
                .tenantId(tenantId)
                .appId(appId)
                .status(user.getStatus())
                .accountType(user.getAccountType())
                .userLevel(user.getUserLevel())
                .roles(roles)
                .permissions(permissions)
                .twoFactorEnabled(user.getTwoFactorEnabled())
                .passwordExpireTime(user.getPasswordExpireTime())
                .forceChangePassword(user.getForceChangePassword())
                .build();

        log.info("User loaded: {}, Roles: {}, Permissions count: {}, tenantId={}, appId={}",
                username, roles, permissions.size(), tenantId, appId);

        return securityUser;
    }

    /**
     * Phase 1.5 — 解析租户的默认 appId。
     */
    private UUID resolveDefaultAppId(UUID tenantId) {
        if (tenantId == null) {
            return null;
        }
        try {
            SysApplication app = applicationService.getByTenantAndCode(tenantId, "default");
            return app != null ? app.getId() : null;
        } catch (Exception ex) {
            log.debug("resolveDefaultAppId: no default app for tenant={}: {}",
                    tenantId, ex.getMessage());
            return null;
        }
    }
}
