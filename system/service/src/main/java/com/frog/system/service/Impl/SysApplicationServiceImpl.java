package com.frog.system.service.Impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.frog.common.exception.BusinessException;
import com.frog.common.util.UUIDv7Util;
import com.frog.system.domain.entity.SysApplication;
import com.frog.system.mapper.SysApplicationMapper;
import com.frog.system.service.ISysApplicationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

/**
 * 应用服务实现 — sys_application。
 *
 * @author Deng
 * @since 2026-09-22
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class SysApplicationServiceImpl extends ServiceImpl<SysApplicationMapper, SysApplication>
        implements ISysApplicationService {

    private final SysApplicationMapper applicationMapper;

    @Override
    public List<SysApplication> listByTenantId(UUID tenantId) {
        return applicationMapper.findByTenantId(tenantId);
    }

    @Override
    public SysApplication getByTenantAndCode(UUID tenantId, String appCode) {
        SysApplication app = applicationMapper.findByTenantAndCode(tenantId, appCode);
        if (app == null) {
            throw new BusinessException("应用不存在: tenantId=" + tenantId + ", appCode=" + appCode);
        }
        return app;
    }

    @Override
    @Transactional(rollbackFor = Exception.class)
    @CacheEvict(value = "application", allEntries = true)
    public SysApplication addApplication(SysApplication application) {
        if (application.getTenantId() == null) {
            throw new BusinessException("租户ID不能为空");
        }
        if (application.getAppCode() == null || application.getAppCode().isBlank()) {
            throw new BusinessException("应用编码不能为空");
        }
        if (applicationMapper.existsByTenantAndCode(
                application.getTenantId(), application.getAppCode())) {
            throw new BusinessException("应用编码已存在: " + application.getAppCode());
        }
        if (application.getId() == null) {
            application.setId(UUIDv7Util.generate());
        }
        if (application.getStatus() == null) {
            application.setStatus(1);
        }
        if (application.getAppType() == null) {
            application.setAppType(SysApplication.Type.WEB);
        }

        applicationMapper.insert(application);
        log.info("Application created: tenantId={}, code={}, id={}",
                application.getTenantId(), application.getAppCode(), application.getId());
        return application;
    }

    @Override
    @Transactional(rollbackFor = Exception.class)
    @CacheEvict(value = "application", allEntries = true)
    public SysApplication updateApplication(SysApplication application) {
        SysApplication existing = applicationMapper.selectById(application.getId());
        if (existing == null) {
            throw new BusinessException("应用不存在: " + application.getId());
        }
        // 不可修改 (tenantId, appCode)
        application.setTenantId(null);
        application.setAppCode(null);
        applicationMapper.updateById(application);
        log.info("Application updated: id={}", application.getId());
        return applicationMapper.selectById(application.getId());
    }

    @Override
    @Transactional(rollbackFor = Exception.class)
    @CacheEvict(value = "application", allEntries = true)
    public void deleteApplication(UUID id) {
        SysApplication app = applicationMapper.selectById(id);
        if (app == null) {
            throw new BusinessException("应用不存在: " + id);
        }
        applicationMapper.deleteById(id);
        log.info("Application deleted: id={}", id);
    }
}
