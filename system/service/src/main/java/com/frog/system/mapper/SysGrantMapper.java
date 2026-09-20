package com.frog.system.mapper;

import com.baomidou.dynamic.datasource.annotation.DS;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.frog.system.domain.entity.SysGrant;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

/**
 * 授权 Mapper — sys_grant(Phase 1.8a)。
 *
 * @author Deng
 * @since 2026-09-24
 */
@Mapper
@DS("permission")
public interface SysGrantMapper extends BaseMapper<SysGrant> {

    /**
     * 查询主体当前所有有效授权。
     *
     * <p>判定条件:
     * <ul>
     *   <li>subject_type / subject_id 匹配</li>
     *   <li>tenant_id 匹配(请求上下文)</li>
     *   <li>app_id 匹配或为 NULL(跨应用共享)</li>
     *   <li>effective_time IS NULL OR effective_time <= now</li>
     *   <li>expire_time IS NULL OR expire_time > now</li>
     *   <li>NOT deleted</li>
     * </ul>
     */
    @Select("""
            SELECT * FROM sys_grant
            WHERE subject_type = #{subjectType}
              AND subject_id = #{subjectId}
              AND tenant_id = #{tenantId}
              AND (app_id = #{appId} OR app_id IS NULL)
              AND (effective_time IS NULL OR effective_time <= #{now})
              AND (expire_time IS NULL OR expire_time > #{now})
              AND NOT deleted
            ORDER BY priority DESC, create_time DESC
            """)
    List<SysGrant> findActiveBySubject(@Param("subjectType") String subjectType,
                                       @Param("subjectId") UUID subjectId,
                                       @Param("tenantId") UUID tenantId,
                                       @Param("appId") UUID appId,
                                       @Param("now") LocalDateTime now);

    /**
     * 查询目标的所有授权(反向查询: 谁拥有此目标的授权?)
     */
    @Select("""
            SELECT * FROM sys_grant
            WHERE target_type = #{targetType}
              AND target_id = #{targetId}
              AND NOT deleted
            ORDER BY priority DESC
            """)
    List<SysGrant> findByTarget(@Param("targetType") String targetType,
                                @Param("targetId") UUID targetId);
}