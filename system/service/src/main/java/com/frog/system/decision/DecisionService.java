package com.frog.system.decision;

import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * 授权决策服务 — Phase 1.8c 平台数据平面入口。
 *
 * <p>这是平台对外暴露的"我能做这件事吗?"问题的统一入口,聚合 RBAC(角色授权)
 * 与显式 Grant(直接授权)的评估,产出 allow/deny 决策与可追溯的决策原因。
 *
 * <p>详见架构评审 §7.3、§23:
 * <ul>
 *   <li>{@link #check(CheckRequest)} — 单次决策</li>
 *   <li>{@link #batchCheck(List)} — 批量决策,减少网络开销</li>
 *   <li>{@link #getEffectivePermissions(UUID, String)} — SDK 水合用的全量有效权限集合</li>
 * </ul>
 *
 * @author Deng
 * @since 2026-09-24
 */
public interface DecisionService {

    /**
     * 单次授权决策
     *
     * @param req 决策请求
     * @return 决策结果(effect / reason / policyVersion / decisionId)
     */
    Decision check(CheckRequest req);

    /**
     * 批量授权决策
     *
     * @param reqs 决策请求列表
     * @return 决策结果列表,与入参顺序一一对应
     */
    List<Decision> batchCheck(List<CheckRequest> reqs);

    /**
     * 获取主体的有效权限集合(SDK 水合 / 离线缓存)
     *
     * @param subjectId   主体ID
     * @param subjectType 主体类型(user | service_account)
     * @return 该主体当前所有有效权限编码
     */
    Set<String> getEffectivePermissions(UUID subjectId, String subjectType);
}