package com.frog.system.service;

import java.util.Set;
import java.util.UUID;

public interface ISysUserPermissionService {

    /**
     * 查询用户在有效期内被直接授予的权限编码集合 (含永久与时间窗口内)。
     */
    Set<String> findEffectiveCodes(UUID userId);

    /**
     * 直接授予用户权限(审批 type=2 落地)。
     * 已存在 (user_id, permission_id) 的记录会被跳过 — 唯一约束保护。
     */
    void grant(UUID userId, Set<UUID> permissionIds, UUID grantedBy, String reason);

    /**
     * 撤销直接授权。
     */
    void revoke(UUID userId, Set<UUID> permissionIds);
}
