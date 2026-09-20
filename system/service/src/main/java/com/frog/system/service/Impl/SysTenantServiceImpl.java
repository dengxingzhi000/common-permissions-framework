package com.frog.system.service.Impl;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.frog.common.exception.BusinessException;
import com.frog.common.util.UUIDv7Util;
import com.frog.system.domain.entity.SysTenant;
import com.frog.system.mapper.SysTenantMapper;
import com.frog.system.service.ISysTenantService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

/**
 * 租户服务实现 — sys_tenant。
 *
 * @author Deng
 * @since 2026-09-22
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class SysTenantServiceImpl extends ServiceImpl<SysTenantMapper, SysTenant> implements ISysTenantService {

    private final SysTenantMapper tenantMapper;

    @Override
    public Page<SysTenant> listTenants(Integer pageNum, Integer pageSize,
                                       String tenantCode, Integer status) {
        Page<SysTenant> page = new Page<>(pageNum, pageSize);

        LambdaQueryWrapper<SysTenant> wrapper = new LambdaQueryWrapper<>();
        wrapper.like(tenantCode != null && !tenantCode.isEmpty(), SysTenant::getTenantCode, tenantCode)
                .eq(status != null, SysTenant::getStatus, status)
                .orderByDesc(SysTenant::getCreateTime);

        return tenantMapper.selectPage(page, wrapper);
    }

    @Override
    public SysTenant getByTenantCode(String tenantCode) {
        SysTenant tenant = tenantMapper.findByTenantCode(tenantCode);
        if (tenant == null) {
            throw new BusinessException("租户不存在: " + tenantCode);
        }
        return tenant;
    }

    @Override
    @Transactional(rollbackFor = Exception.class)
    @CacheEvict(value = "tenant", allEntries = true)
    public SysTenant addTenant(SysTenant tenant) {
        if (tenant.getTenantCode() == null || tenant.getTenantCode().isBlank()) {
            throw new BusinessException("租户编码不能为空");
        }
        if (tenantMapper.existsByTenantCode(tenant.getTenantCode())) {
            throw new BusinessException("租户编码已存在: " + tenant.getTenantCode());
        }
        if (tenant.getId() == null) {
            tenant.setId(UUIDv7Util.generate());
        }
        if (tenant.getStatus() == null) {
            tenant.setStatus(1);
        }
        if (tenant.getIsolationLevel() == null) {
            tenant.setIsolationLevel(SysTenant.Isolation.SHARED);
        }

        tenantMapper.insert(tenant);
        log.info("Tenant created: code={}, id={}", tenant.getTenantCode(), tenant.getId());
        return tenant;
    }

    @Override
    @Transactional(rollbackFor = Exception.class)
    @CacheEvict(value = "tenant", allEntries = true)
    public SysTenant updateTenant(SysTenant tenant) {
        SysTenant existing = tenantMapper.selectById(tenant.getId());
        if (existing == null) {
            throw new BusinessException("租户不存在: " + tenant.getId());
        }
        // 不可修改 tenantCode(避免破坏外键引用)
        tenant.setTenantCode(null);
        tenantMapper.updateById(tenant);
        log.info("Tenant updated: id={}", tenant.getId());
        return tenantMapper.selectById(tenant.getId());
    }

    @Override
    @Transactional(rollbackFor = Exception.class)
    @CacheEvict(value = "tenant", allEntries = true)
    public void disableTenant(UUID id) {
        SysTenant tenant = tenantMapper.selectById(id);
        if (tenant == null) {
            throw new BusinessException("租户不存在: " + id);
        }
        tenant.setStatus(0);
        tenantMapper.updateById(tenant);
        log.info("Tenant disabled: id={}", id);
    }

    @Override
    @Transactional(rollbackFor = Exception.class)
    @CacheEvict(value = "tenant", allEntries = true)
    public void enableTenant(UUID id) {
        SysTenant tenant = tenantMapper.selectById(id);
        if (tenant == null) {
            throw new BusinessException("租户不存在: " + id);
        }
        tenant.setStatus(1);
        tenantMapper.updateById(tenant);
        log.info("Tenant enabled: id={}", id);
    }

    @Override
    @Transactional(rollbackFor = Exception.class)
    @CacheEvict(value = "tenant", allEntries = true)
    public void deleteTenant(UUID id) {
        SysTenant tenant = tenantMapper.selectById(id);
        if (tenant == null) {
            throw new BusinessException("租户不存在: " + id);
        }
        tenantMapper.deleteById(id);
        log.info("Tenant deleted: id={}", id);
    }
}
