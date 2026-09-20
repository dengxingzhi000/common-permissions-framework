package com.frog.system.service;

import com.baomidou.mybatisplus.extension.service.IService;
import com.frog.system.domain.entity.SysPolicyVersion;

import java.util.List;
import java.util.UUID;

/**
 * 策略版本服务 — sys_policy_version(Phase 1.8b)。
 *
 * <p>记录授权策略的版本化快照,供决策评估时引用。
 *
 * @author Deng
 * @since 2026-09-24
 */
public interface ISysPolicyVersionService extends IService<SysPolicyVersion> {

    /**
     * 查询当前激活的策略版本
     */
    SysPolicyVersion getActive(UUID tenantId, UUID appId);

    /**
     * 按租户查询策略历史
     */
    List<SysPolicyVersion> listHistory(UUID tenantId);

    /**
     * 发布新策略版本
     */
    SysPolicyVersion publish(SysPolicyVersion version);
}