package com.frog.system.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.frog.system.domain.entity.SysApplication;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

import java.util.List;
import java.util.UUID;

/**
 * 应用 Mapper — sys_application。
 *
 * @author Deng
 * @since 2026-09-22
 */
@Mapper
public interface SysApplicationMapper extends BaseMapper<SysApplication> {

    /**
     * 根据租户 ID 查询应用列表
     */
    @Select("""
            SELECT * FROM sys_application
            WHERE tenant_id = #{tenantId} AND NOT deleted
            ORDER BY create_time DESC
            """)
    List<SysApplication> findByTenantId(@Param("tenantId") UUID tenantId);

    /**
     * 根据租户 + 应用编码查询
     */
    @Select("""
            SELECT * FROM sys_application
            WHERE tenant_id = #{tenantId}
              AND app_code = #{appCode}
              AND NOT deleted
            """)
    SysApplication findByTenantAndCode(@Param("tenantId") UUID tenantId,
                                       @Param("appCode") String appCode);

    /**
     * 检查 (tenantId, appCode) 是否存在
     */
    @Select("""
            SELECT COUNT(*) > 0 FROM sys_application
            WHERE tenant_id = #{tenantId}
              AND app_code = #{appCode}
              AND NOT deleted
            """)
    boolean existsByTenantAndCode(@Param("tenantId") UUID tenantId,
                                  @Param("appCode") String appCode);
}
