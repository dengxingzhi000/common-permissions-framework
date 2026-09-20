package com.frog.system.mapper;

import com.baomidou.dynamic.datasource.annotation.DS;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.frog.system.domain.entity.SysResource;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

import java.util.List;
import java.util.UUID;

/**
 * 资源目录 Mapper — sys_resource(Phase 1.7)。
 *
 * @author Deng
 * @since 2026-09-24
 */
@Mapper
@DS("permission")
public interface SysResourceMapper extends BaseMapper<SysResource> {

    /**
     * 按租户 + 应用查询资源列表
     */
    @Select("""
            SELECT * FROM sys_resource
            WHERE tenant_id = #{tenantId}
              AND app_id = #{appId}
              AND NOT deleted
            ORDER BY resource_type, resource_code
            """)
    List<SysResource> findByTenantAndApp(@Param("tenantId") UUID tenantId,
                                         @Param("appId") UUID appId);

    /**
     * 按租户 + 应用 + 资源类型查询
     */
    @Select("""
            SELECT * FROM sys_resource
            WHERE tenant_id = #{tenantId}
              AND app_id = #{appId}
              AND resource_type = #{resourceType}
              AND NOT deleted
            ORDER BY resource_code
            """)
    List<SysResource> findByTenantAppType(@Param("tenantId") UUID tenantId,
                                          @Param("appId") UUID appId,
                                          @Param("resourceType") String resourceType);

    /**
     * 按租户 + 应用 + 资源编码查询
     */
    @Select("""
            SELECT * FROM sys_resource
            WHERE tenant_id = #{tenantId}
              AND app_id = #{appId}
              AND resource_code = #{resourceCode}
              AND NOT deleted
            """)
    SysResource findByTenantAppCode(@Param("tenantId") UUID tenantId,
                                    @Param("appId") UUID appId,
                                    @Param("resourceCode") String resourceCode);

    /**
     * 检查 (tenant, app, code) 是否已存在
     */
    @Select("""
            SELECT COUNT(*) > 0 FROM sys_resource
            WHERE tenant_id = #{tenantId}
              AND app_id = #{appId}
              AND resource_code = #{resourceCode}
              AND NOT deleted
            """)
    boolean existsByTenantAppCode(@Param("tenantId") UUID tenantId,
                                  @Param("appId") UUID appId,
                                  @Param("resourceCode") String resourceCode);

    /**
     * 查询某资源的所有子资源
     */
    @Select("""
            SELECT * FROM sys_resource
            WHERE parent_id = #{parentId}
              AND NOT deleted
            ORDER BY resource_code
            """)
    List<SysResource> findByParentId(@Param("parentId") UUID parentId);
}