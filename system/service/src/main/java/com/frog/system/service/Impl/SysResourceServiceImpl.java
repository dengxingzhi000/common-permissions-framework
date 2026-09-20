package com.frog.system.service.Impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.frog.common.exception.BusinessException;
import com.frog.common.util.UUIDv7Util;
import com.frog.system.domain.entity.SysResource;
import com.frog.system.mapper.SysResourceMapper;
import com.frog.system.service.ISysResourceService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

/**
 * 资源目录服务实现 — sys_resource(Phase 1.7)。
 *
 * @author Deng
 * @since 2026-09-24
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class SysResourceServiceImpl extends ServiceImpl<SysResourceMapper, SysResource>
        implements ISysResourceService {

    private final SysResourceMapper resourceMapper;

    @Override
    public List<SysResource> listByTenantAndApp(UUID tenantId, UUID appId) {
        if (tenantId == null || appId == null) {
            return List.of();
        }
        return resourceMapper.findByTenantAndApp(tenantId, appId);
    }

    @Override
    public List<SysResource> listByTenantAppType(UUID tenantId, UUID appId, String resourceType) {
        if (tenantId == null || appId == null || resourceType == null || resourceType.isBlank()) {
            return List.of();
        }
        return resourceMapper.findByTenantAppType(tenantId, appId, resourceType);
    }

    @Override
    public SysResource getByTenantAppCode(UUID tenantId, UUID appId, String resourceCode) {
        return resourceMapper.findByTenantAppCode(tenantId, appId, resourceCode);
    }

    @Override
    public List<SysResource> listByParentId(UUID parentId) {
        return resourceMapper.findByParentId(parentId);
    }

    @Override
    @Transactional(rollbackFor = Exception.class)
    @CacheEvict(value = "resource", allEntries = true)
    public SysResource addResource(SysResource resource) {
        if (resource.getTenantId() == null) {
            throw new BusinessException("租户ID不能为空");
        }
        if (resource.getAppId() == null) {
            throw new BusinessException("应用ID不能为空");
        }
        if (resource.getResourceCode() == null || resource.getResourceCode().isBlank()) {
            throw new BusinessException("资源编码不能为空");
        }
        if (resource.getResourceName() == null || resource.getResourceName().isBlank()) {
            throw new BusinessException("资源名称不能为空");
        }
        if (resource.getResourceType() == null || resource.getResourceType().isBlank()) {
            throw new BusinessException("资源类型不能为空");
        }
        if (resourceMapper.existsByTenantAppCode(
                resource.getTenantId(),
                resource.getAppId(),
                resource.getResourceCode())) {
            throw new BusinessException("资源编码已存在: " + resource.getResourceCode());
        }
        if (resource.getId() == null) {
            resource.setId(UUIDv7Util.generate());
        }
        if (resource.getStatus() == null) {
            resource.setStatus(1);
        }
        resourceMapper.insert(resource);
        log.info("Resource created: tenant={}, app={}, code={}, id={}",
                resource.getTenantId(), resource.getAppId(),
                resource.getResourceCode(), resource.getId());
        return resource;
    }

    @Override
    @Transactional(rollbackFor = Exception.class)
    @CacheEvict(value = "resource", allEntries = true)
    public SysResource updateResource(SysResource resource) {
        SysResource existing = resourceMapper.selectById(resource.getId());
        if (existing == null) {
            throw new BusinessException("资源不存在: " + resource.getId());
        }
        // 不可修改的标识字段
        resource.setTenantId(null);
        resource.setAppId(null);
        resource.setResourceCode(null);
        resource.setResourceType(null);
        resourceMapper.updateById(resource);
        log.info("Resource updated: id={}", resource.getId());
        return resourceMapper.selectById(resource.getId());
    }

    @Override
    @Transactional(rollbackFor = Exception.class)
    @CacheEvict(value = "resource", allEntries = true)
    public void deleteResource(UUID id) {
        SysResource resource = resourceMapper.selectById(id);
        if (resource == null) {
            throw new BusinessException("资源不存在: " + id);
        }
        resourceMapper.deleteById(id);
        log.info("Resource soft-deleted: id={}", id);
    }
}