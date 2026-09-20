package com.frog.system.service;

import com.baomidou.mybatisplus.extension.service.IService;
import com.frog.system.domain.entity.SysGrant;

import java.util.List;
import java.util.UUID;

/**
 * 授权服务 — sys_grant(Phase 1.8a)。
 *
 * <p>提供授权的 CRUD 与按主体/目标的查询接口。运行时决策由
 * {@link com.frog.system.decision.DecisionService} 调用。
 *
 * @author Deng
 * @since 2026-09-24
 */
public interface ISysGrantService extends IService<SysGrant> {

    /**
     * 查询主体在指定 (tenant, app) 上下文下当前所有有效授权
     */
    List<SysGrant> listActiveBySubject(String subjectType, UUID subjectId,
                                       UUID tenantId, UUID appId);

    /**
     * 查询目标的所有授权
     */
    List<SysGrant> listByTarget(String targetType, UUID targetId);

    /**
     * 新增授权
     */
    SysGrant addGrant(SysGrant grant);

    /**
     * 撤销授权(软删除)
     */
    void revokeGrant(UUID id);
}