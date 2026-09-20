package com.frog.system.service;

import com.baomidou.mybatisplus.extension.service.IService;
import com.frog.system.domain.entity.SysResource;

import java.util.List;
import java.util.UUID;

/**
 * 资源目录服务 — sys_resource(Phase 1.7)。
 *
 * <p>取代之前 stringly-typed 的 {@code resource_type VARCHAR(50)},
 * 提供类型化的资源注册与查询。
 *
 * @author Deng
 * @since 2026-09-24
 */
public interface ISysResourceService extends IService<SysResource> {

    /**
     * 查询租户+应用下所有资源
     */
    List<SysResource> listByTenantAndApp(UUID tenantId, UUID appId);

    /**
     * 按资源类型查询
     */
    List<SysResource> listByTenantAppType(UUID tenantId, UUID appId, String resourceType);

    /**
     * 按 (tenant, app, code) 唯一查询
     */
    SysResource getByTenantAppCode(UUID tenantId, UUID appId, String resourceCode);

    /**
     * 查询子资源
     */
    List<SysResource> listByParentId(UUID parentId);

    /**
     * 新增资源
     */
    SysResource addResource(SysResource resource);

    /**
     * 修改资源
     */
    SysResource updateResource(SysResource resource);

    /**
     * 软删除资源
     */
    void deleteResource(UUID id);
}