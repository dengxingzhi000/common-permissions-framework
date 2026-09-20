package com.frog.system.mapper;

import com.baomidou.dynamic.datasource.annotation.DS;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.frog.system.domain.entity.SysPolicyVersion;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

import java.util.List;
import java.util.UUID;

/**
 * 策略版本 Mapper — sys_policy_version(Phase 1.8b)。
 *
 * @author Deng
 * @since 2026-09-24
 */
@Mapper
@DS("permission")
public interface SysPolicyVersionMapper extends BaseMapper<SysPolicyVersion> {

    /**
     * 查询当前激活的策略版本(按租户+应用过滤)
     *
     * <p>返回按 activated_at DESC 排序的最新一条 active 记录。
     */
    @Select("""
            SELECT * FROM sys_policy_version
            WHERE status = 'active'
              AND (tenant_id = #{tenantId} OR tenant_id IS NULL)
              AND (app_id = #{appId} OR app_id IS NULL)
            ORDER BY activated_at DESC
            LIMIT 1
            """)
    SysPolicyVersion findActive(@Param("tenantId") UUID tenantId,
                                @Param("appId") UUID appId);

    /**
     * 按租户查询策略版本历史
     */
    @Select("""
            SELECT * FROM sys_policy_version
            WHERE tenant_id = #{tenantId}
            ORDER BY activated_at DESC
            """)
    List<SysPolicyVersion> findHistoryByTenant(@Param("tenantId") UUID tenantId);

    /**
     * 按版本号查询(全局唯一)
     */
    @Select("""
            SELECT * FROM sys_policy_version WHERE version = #{version}
            """)
    SysPolicyVersion findByVersion(@Param("version") String version);
}