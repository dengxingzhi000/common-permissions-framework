package com.frog.system.service.Impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.frog.common.exception.BusinessException;
import com.frog.common.util.UUIDv7Util;
import com.frog.system.domain.entity.SysGrant;
import com.frog.system.mapper.SysGrantMapper;
import com.frog.system.service.ISysGrantService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

/**
 * 授权服务实现 — sys_grant(Phase 1.8a)。
 *
 * @author Deng
 * @since 2026-09-24
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class SysGrantServiceImpl extends ServiceImpl<SysGrantMapper, SysGrant>
        implements ISysGrantService {

    private final SysGrantMapper grantMapper;

    @Override
    public List<SysGrant> listActiveBySubject(String subjectType, UUID subjectId,
                                              UUID tenantId, UUID appId) {
        if (subjectType == null || subjectId == null || tenantId == null) {
            return List.of();
        }
        return grantMapper.findActiveBySubject(
                subjectType, subjectId, tenantId, appId, LocalDateTime.now());
    }

    @Override
    public List<SysGrant> listByTarget(String targetType, UUID targetId) {
        if (targetType == null || targetId == null) {
            return List.of();
        }
        return grantMapper.findByTarget(targetType, targetId);
    }

    @Override
    @Transactional(rollbackFor = Exception.class)
    @CacheEvict(value = "grant", allEntries = true)
    public SysGrant addGrant(SysGrant grant) {
        validateGrant(grant);
        if (grant.getId() == null) {
            grant.setId(UUIDv7Util.generate());
        }
        if (grant.getEffect() == null) {
            grant.setEffect(SysGrant.Effect.ALLOW);
        }
        if (grant.getPriority() == null) {
            grant.setPriority(100);
        }
        if (grant.getEffectiveTime() == null) {
            grant.setEffectiveTime(LocalDateTime.now());
        }
        grantMapper.insert(grant);
        log.info("Grant created: id={}, subject={}/{}, target={}/{}, effect={}, priority={}",
                grant.getId(), grant.getSubjectType(), grant.getSubjectId(),
                grant.getTargetType(), grant.getTargetId(),
                grant.getEffect(), grant.getPriority());
        return grant;
    }

    @Override
    @Transactional(rollbackFor = Exception.class)
    @CacheEvict(value = "grant", allEntries = true)
    public void revokeGrant(UUID id) {
        SysGrant grant = grantMapper.selectById(id);
        if (grant == null) {
            throw new BusinessException("授权不存在: " + id);
        }
        grantMapper.deleteById(id);
        log.info("Grant revoked: id={}", id);
    }

    private void validateGrant(SysGrant grant) {
        if (grant == null) {
            throw new BusinessException("授权不能为空");
        }
        if (grant.getTenantId() == null) {
            throw new BusinessException("租户ID不能为空");
        }
        if (grant.getSubjectType() == null || grant.getSubjectType().isBlank()) {
            throw new BusinessException("主体类型不能为空");
        }
        if (grant.getSubjectId() == null) {
            throw new BusinessException("主体ID不能为空");
        }
        if (grant.getTargetType() == null || grant.getTargetType().isBlank()) {
            throw new BusinessException("目标类型不能为空");
        }
        if (grant.getTargetId() == null) {
            throw new BusinessException("目标ID不能为空");
        }
        String effect = grant.getEffect();
        if (effect != null
                && !SysGrant.Effect.ALLOW.equals(effect)
                && !SysGrant.Effect.DENY.equals(effect)) {
            throw new BusinessException("效果必须为 allow 或 deny");
        }
        if (grant.getEffectiveTime() != null
                && grant.getExpireTime() != null
                && !grant.getExpireTime().isAfter(grant.getEffectiveTime())) {
            throw new BusinessException("过期时间必须晚于生效时间");
        }
    }
}