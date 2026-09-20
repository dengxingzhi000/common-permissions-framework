package com.frog.system.decision;

import com.frog.common.security.decision.DecisionEvent;
import com.frog.common.security.decision.DecisionRecorder;
import com.frog.common.tenant.TenantContext;
import com.frog.common.util.UUIDv7Util;
import com.frog.system.domain.entity.SysGrant;
import com.frog.system.domain.entity.SysPermission;
import com.frog.system.domain.entity.SysPolicyVersion;
import com.frog.system.mapper.SysPermissionMapper;
import com.frog.system.service.ISysGrantService;
import com.frog.system.service.ISysPolicyVersionService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * DecisionService 实现 — deny-overrides 评估算法(Phase 1.8c)。
 *
 * <p>评估流程:
 * <ol>
 *   <li>收集主体当前所有有效授权({@link ISysGrantService#listActiveBySubject})</li>
 *   <li>对 target_type='role' 的授权,展开为角色的所有 permission_code</li>
 *   <li>按 scope / action / resource 约束过滤</li>
 *   <li>优先级数值高者胜出;同优先级时 deny 压倒 allow</li>
 *   <li>读取当前激活的 {@link SysPolicyVersion} 作为 {@code policyVersion}</li>
 *   <li>通过 {@link DecisionRecorder} 记录到决策日志(Phase 0 引入)</li>
 * </ol>
 *
 * @author Deng
 * @since 2026-09-24
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class DecisionServiceImpl implements DecisionService {

    private static final String SOURCE_MODULE = "system-decision-service";

    private final ISysGrantService grantService;
    private final SysPermissionMapper permissionMapper;
    private final ISysPolicyVersionService policyVersionService;
    private final DecisionRecorder decisionRecorder;

    @Override
    public Decision check(CheckRequest req) {
        if (req == null || req.getSubjectId() == null || req.getSubjectType() == null) {
            return denyDecision("missing required fields", null, 0L);
        }

        long start = System.currentTimeMillis();
        UUID tenantId = resolveTenantId(req);
        UUID appId = resolveAppId(req);

        List<SysGrant> grants = grantService.listActiveBySubject(
                req.getSubjectType(), req.getSubjectId(), tenantId, appId);

        Evaluation eval = evaluateGrants(req, grants);
        long latency = System.currentTimeMillis() - start;

        SysPolicyVersion activePolicy = policyVersionService.getActive(tenantId, appId);
        String policyVersion = activePolicy != null ? activePolicy.getVersion() : null;

        UUID decisionId = UUIDv7Util.generate();
        Decision decision = Decision.builder()
                .effect(eval.effect)
                .reason(eval.reason)
                .policyVersion(policyVersion)
                .decisionId(decisionId)
                .latencyMs(latency)
                .build();

        decisionRecorder.record(new DecisionEvent(
                decisionId,
                req.getSubjectType(),
                req.getSubjectId(),
                req.getAction(),
                req.getResourceType(),
                req.getResourceId(),
                req.getContext() == null ? Collections.emptyMap() : req.getContext(),
                eval.effect,
                eval.reason,
                policyVersion,
                null,
                latency,
                SOURCE_MODULE,
                Instant.now()
        ));
        return decision;
    }

    @Override
    public List<Decision> batchCheck(List<CheckRequest> reqs) {
        if (reqs == null || reqs.isEmpty()) {
            return Collections.emptyList();
        }
        List<Decision> out = new ArrayList<>(reqs.size());
        for (CheckRequest r : reqs) {
            out.add(check(r));
        }
        return out;
    }

    @Override
    public Set<String> getEffectivePermissions(UUID subjectId, String subjectType) {
        if (subjectId == null || subjectType == null) {
            return Collections.emptySet();
        }
        UUID tenantId = resolveTenantId(null);
        // appId 留空: 查询跨应用生效的授权;调用方可在需要时按 app 过滤
        List<SysGrant> grants = grantService.listActiveBySubject(
                subjectType, subjectId, tenantId, null);

        Set<String> permissions = new HashSet<>();
        for (SysGrant grant : grants) {
            switch (grant.getTargetType()) {
                case SysGrant.Target.ROLE -> {
                    List<SysPermission> rolePerms =
                            permissionMapper.findPermissionsByRoleId(grant.getTargetId());
                    for (SysPermission p : rolePerms) {
                        if (matchesAction(p.getPermissionCode(), grant.getAction())) {
                            permissions.add(p.getPermissionCode());
                        }
                    }
                }
                case SysGrant.Target.PERMISSION -> {
                    SysPermission perm = permissionMapper.selectById(grant.getTargetId());
                    if (perm != null && matchesAction(perm.getPermissionCode(), grant.getAction())
                            && SysGrant.Effect.ALLOW.equals(grant.getEffect())) {
                        permissions.add(perm.getPermissionCode());
                    }
                }
                default -> {
                    // resource-target grants do not directly contribute to permission set
                }
            }
        }
        return permissions;
    }

    // ---------------------------------------------------------------------
    // Evaluation internals
    // ---------------------------------------------------------------------

    private Evaluation evaluateGrants(CheckRequest req, List<SysGrant> grants) {
        Evaluation current = new Evaluation(SysGrant.Effect.DENY, "no grants match", Integer.MIN_VALUE);

        for (SysGrant grant : grants) {
            if (!scopeMatches(req, grant)) {
                continue;
            }
            if (!actionMatches(req, grant)) {
                continue;
            }
            if (!resourceMatches(req, grant)) {
                continue;
            }
            int priority = grant.getPriority() == null ? 100 : grant.getPriority();
            String effect = grant.getEffect() == null ? SysGrant.Effect.ALLOW : grant.getEffect();

            if (!current.decided || priority > current.priority) {
                current = new Evaluation(effect, describeGrant(grant), priority);
                current.decided = true;
            } else if (priority == current.priority
                    && SysGrant.Effect.DENY.equals(effect)
                    && SysGrant.Effect.ALLOW.equals(current.effect)) {
                current.effect = SysGrant.Effect.DENY;
                current.reason = describeGrant(grant);
            }
        }
        return current;
    }

    private boolean scopeMatches(CheckRequest req, SysGrant grant) {
        if (grant.getScopeOrgId() == null) {
            return true;
        }
        Map<String, Object> ctx = req.getContext();
        if (ctx == null) {
            return false;
        }
        Object dept = ctx.get("deptId");
        if (dept == null) {
            return false;
        }
        try {
            return grant.getScopeOrgId().equals(UUID.fromString(dept.toString()));
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }

    private boolean actionMatches(CheckRequest req, SysGrant grant) {
        // role-target: action filtering happens post-expansion via matchesAction()
        // resource-target: action may be present and must equal request action if set
        if (SysGrant.Target.RESOURCE.equals(grant.getTargetType())) {
            return matchesAction(req.getAction(), grant.getAction());
        }
        return true;
    }

    private boolean resourceMatches(CheckRequest req, SysGrant grant) {
        if (!SysGrant.Target.RESOURCE.equals(grant.getTargetType())) {
            return true;
        }
        if (grant.getResourceTypeFilter() != null
                && req.getResourceType() != null
                && !grant.getResourceTypeFilter().equals(req.getResourceType())) {
            return false;
        }
        if (grant.getScopeResourceId() != null
                && req.getResourceId() != null
                && !grant.getScopeResourceId().equals(req.getResourceId())) {
            return false;
        }
        return true;
    }

    private boolean matchesAction(String requestAction, String grantAction) {
        if (grantAction == null || grantAction.isBlank()) {
            return true;
        }
        return grantAction.equals(requestAction);
    }

    private String describeGrant(SysGrant grant) {
        return "grant " + grant.getEffect()
                + " target=" + grant.getTargetType() + "/" + grant.getTargetId()
                + (grant.getAction() == null ? "" : " action=" + grant.getAction())
                + " priority=" + (grant.getPriority() == null ? 100 : grant.getPriority());
    }

    private UUID resolveTenantId(CheckRequest req) {
        UUID tenantId = TenantContext.get();
        if (tenantId != null) {
            return tenantId;
        }
        Map<String, Object> ctx = req == null ? null : req.getContext();
        if (ctx != null && ctx.get("tenantId") != null) {
            try {
                return UUID.fromString(ctx.get("tenantId").toString());
            } catch (IllegalArgumentException ignored) {
            }
        }
        return null;
    }

    private UUID resolveAppId(CheckRequest req) {
        Map<String, Object> ctx = req == null ? null : req.getContext();
        if (ctx == null || ctx.get("appId") == null) {
            return null;
        }
        try {
            return UUID.fromString(ctx.get("appId").toString());
        } catch (IllegalArgumentException ex) {
            return null;
        }
    }

    private Decision denyDecision(String reason, String policyVersion, long latencyMs) {
        return Decision.builder()
                .effect(SysGrant.Effect.DENY)
                .reason(reason)
                .policyVersion(policyVersion)
                .decisionId(UUIDv7Util.generate())
                .latencyMs(latencyMs)
                .build();
    }

    private static final class Evaluation {
        String effect;
        String reason;
        int priority;
        boolean decided;

        Evaluation(String effect, String reason, int priority) {
            this.effect = effect;
            this.reason = reason;
            this.priority = priority;
            this.decided = false;
        }
    }
}