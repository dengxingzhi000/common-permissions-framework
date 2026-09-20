package com.frog.system.service.Impl;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.frog.system.domain.entity.SysUserPermission;
import com.frog.system.mapper.SysUserPermissionMapper;
import com.frog.system.service.ISysUserPermissionService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class SysUserPermissionServiceImpl implements ISysUserPermissionService {

    private final SysUserPermissionMapper mapper;

    @Override
    public Set<String> findEffectiveCodes(UUID userId) {
        return mapper.findPermissionCodesByUserId(userId);
    }

    @Override
    @Transactional
    @CacheEvict(value = "userPermissionCodes", key = "#userId")
    @CacheEvict(value = "userPermissions", allEntries = true)
    public void grant(UUID userId, Set<UUID> permissionIds, UUID grantedBy, String reason) {
        if (permissionIds == null || permissionIds.isEmpty()) {
            return;
        }
        for (UUID pid : permissionIds) {
            SysUserPermission entity = new SysUserPermission();
            entity.setUserId(userId);
            entity.setPermissionId(pid);
            entity.setGrantedBy(grantedBy);
            entity.setGrantReason(reason);
            mapper.insert(entity);
        }
        log.info("Direct permissions granted: userId={}, permIds={}, grantedBy={}, reason={}",
                userId, permissionIds, grantedBy, reason);
    }

    @Override
    @Transactional
    @CacheEvict(value = "userPermissionCodes", key = "#userId")
    @CacheEvict(value = "userPermissions", allEntries = true)
    public void revoke(UUID userId, Set<UUID> permissionIds) {
        if (permissionIds == null || permissionIds.isEmpty()) {
            return;
        }
        for (UUID pid : permissionIds) {
            mapper.delete(new QueryWrapper<SysUserPermission>()
                    .eq("user_id", userId)
                    .eq("permission_id", pid));
        }
        log.info("Direct permissions revoked: userId={}, permIds={}", userId, permissionIds);
    }
}
