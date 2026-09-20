package com.frog.system.service.Impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.frog.common.exception.BusinessException;
import com.frog.common.util.UUIDv7Util;
import com.frog.system.domain.entity.SysPolicyVersion;
import com.frog.system.mapper.SysPolicyVersionMapper;
import com.frog.system.service.ISysPolicyVersionService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

/**
 * 策略版本服务实现 — sys_policy_version(Phase 1.8b)。
 *
 * @author Deng
 * @since 2026-09-24
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class SysPolicyVersionServiceImpl extends ServiceImpl<SysPolicyVersionMapper, SysPolicyVersion>
        implements ISysPolicyVersionService {

    private final SysPolicyVersionMapper policyVersionMapper;

    @Override
    public SysPolicyVersion getActive(UUID tenantId, UUID appId) {
        return policyVersionMapper.findActive(tenantId, appId);
    }

    @Override
    public List<SysPolicyVersion> listHistory(UUID tenantId) {
        return policyVersionMapper.findHistoryByTenant(tenantId);
    }

    @Override
    public SysPolicyVersion publish(SysPolicyVersion version) {
        if (version.getVersion() == null || version.getVersion().isBlank()) {
            throw new BusinessException("版本标签不能为空");
        }
        if (policyVersionMapper.findByVersion(version.getVersion()) != null) {
            throw new BusinessException("版本标签已存在: " + version.getVersion());
        }
        if (version.getId() == null) {
            version.setId(UUIDv7Util.generate());
        }
        if (version.getStatus() == null) {
            version.setStatus(SysPolicyVersion.Status.ACTIVE);
        }
        if (version.getActivatedAt() == null) {
            version.setActivatedAt(LocalDateTime.now());
        }
        policyVersionMapper.insert(version);
        log.info("Policy version published: version={}, tenant={}, app={}",
                version.getVersion(), version.getTenantId(), version.getAppId());
        return version;
    }
}