package com.frog.system.decision;

import com.frog.common.security.decision.DecisionEvent;
import com.frog.common.security.decision.DecisionRecorder;
import com.frog.common.security.decision.DecisionRecorderProperties;
import com.frog.common.tenant.TenantContext;
import com.frog.system.domain.entity.SysGrant;
import com.frog.system.domain.entity.SysPermission;
import com.frog.system.domain.entity.SysPolicyVersion;
import com.frog.system.mapper.SysPermissionMapper;
import com.frog.system.service.ISysGrantService;
import com.frog.system.service.ISysPolicyVersionService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * DecisionServiceImpl unit tests — Phase 1.8c.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("DecisionServiceImpl Tests")
class DecisionServiceImplTest {

    @Mock
    private ISysGrantService grantService;

    @Mock
    private SysPermissionMapper permissionMapper;

    @Mock
    private ISysPolicyVersionService policyVersionService;

    private DecisionRecorder decisionRecorder;

    private DecisionServiceImpl service;

    private UUID subjectId;
    private UUID tenantId;
    private UUID appId;
    private UUID roleId;
    private UUID permissionId;
    private UUID resourceId;

    @BeforeEach
    void setUp() {
        subjectId = UUID.randomUUID();
        tenantId = UUID.randomUUID();
        appId = UUID.randomUUID();
        roleId = UUID.randomUUID();
        permissionId = UUID.randomUUID();
        resourceId = UUID.randomUUID();

        DecisionRecorderProperties props = new DecisionRecorderProperties();
        props.setEnabled(true);
        props.setBatchSize(1000); // suppress auto-flush within tests
        decisionRecorder = new DecisionRecorder(props);

        service = new DecisionServiceImpl(
                grantService, permissionMapper, policyVersionService, decisionRecorder);

        TenantContext.set(tenantId);
    }

    @AfterEach
    void tearDown() {
        TenantContext.clear();
    }

    private CheckRequest baseRequest() {
        return CheckRequest.builder()
                .subjectType("user")
                .subjectId(subjectId)
                .action("project.read")
                .resourceType("PROJECT")
                .resourceId(resourceId.toString())
                .context(Map.of("appId", appId.toString()))
                .build();
    }

    private SysGrant baseGrant(String effect, String targetType, UUID targetId, Integer priority) {
        SysGrant g = new SysGrant();
        g.setId(UUID.randomUUID());
        g.setTenantId(tenantId);
        g.setAppId(appId);
        g.setSubjectType("user");
        g.setSubjectId(subjectId);
        g.setTargetType(targetType);
        g.setTargetId(targetId);
        g.setEffect(effect);
        g.setPriority(priority);
        g.setEffectiveTime(LocalDateTime.now().minusMinutes(1));
        g.setExpireTime(LocalDateTime.now().plusHours(1));
        return g;
    }

    @Test
    @DisplayName("check — no grants → deny with 'no grants match'")
    void check_noGrants_returnsDeny() {
        when(grantService.listActiveBySubject("user", subjectId, tenantId, appId))
                .thenReturn(List.of());
        when(policyVersionService.getActive(tenantId, appId)).thenReturn(null);

        Decision d = service.check(baseRequest());

        assertThat(d.getEffect()).isEqualTo("deny");
        assertThat(d.getReason()).contains("no grants match");
        assertThat(d.getDecisionId()).isNotNull();
        assertThat(d.getPolicyVersion()).isNull();
        assertThat(d.getLatencyMs()).isGreaterThanOrEqualTo(0L);
    }

    @Test
    @DisplayName("check — single allow permission grant → allow")
    void check_singleAllowPermission() {
        SysGrant g = baseGrant("allow", SysGrant.Target.PERMISSION, permissionId, 100);
        when(grantService.listActiveBySubject("user", subjectId, tenantId, appId))
                .thenReturn(List.of(g));
        SysPolicyVersion pv = new SysPolicyVersion();
        pv.setVersion("v20260924-001");
        when(policyVersionService.getActive(tenantId, appId)).thenReturn(pv);

        Decision d = service.check(baseRequest());

        assertThat(d.getEffect()).isEqualTo("allow");
        assertThat(d.getPolicyVersion()).isEqualTo("v20260924-001");
    }

    @Test
    @DisplayName("check — deny wins on equal priority")
    void check_denyWinsOnTie() {
        SysGrant allow = baseGrant("allow", SysGrant.Target.PERMISSION, permissionId, 100);
        SysGrant deny = baseGrant("deny", SysGrant.Target.PERMISSION, UUID.randomUUID(), 100);
        when(grantService.listActiveBySubject("user", subjectId, tenantId, appId))
                .thenReturn(List.of(allow, deny));
        when(policyVersionService.getActive(tenantId, appId)).thenReturn(null);

        Decision d = service.check(baseRequest());

        assertThat(d.getEffect()).isEqualTo("deny");
        assertThat(d.getReason()).contains("deny");
    }

    @Test
    @DisplayName("check — higher priority allow beats lower priority deny")
    void check_higherPriorityAllowWins() {
        SysGrant lowDeny = baseGrant("deny", SysGrant.Target.PERMISSION, UUID.randomUUID(), 50);
        SysGrant highAllow = baseGrant("allow", SysGrant.Target.PERMISSION, permissionId, 200);
        when(grantService.listActiveBySubject("user", subjectId, tenantId, appId))
                .thenReturn(List.of(lowDeny, highAllow));
        when(policyVersionService.getActive(tenantId, appId)).thenReturn(null);

        Decision d = service.check(baseRequest());

        assertThat(d.getEffect()).isEqualTo("allow");
        assertThat(d.getReason()).contains("allow");
    }

    @Test
    @DisplayName("check — role-target grant expands to permission codes via role's permissions")
    void check_roleGrantExpansion() {
        SysGrant roleGrant = baseGrant("allow", SysGrant.Target.ROLE, roleId, 100);
        when(grantService.listActiveBySubject("user", subjectId, tenantId, appId))
                .thenReturn(List.of(roleGrant));
        when(policyVersionService.getActive(tenantId, appId)).thenReturn(null);

        SysPermission perm = new SysPermission();
        perm.setId(permissionId);
        perm.setPermissionCode("project.read");
        when(permissionMapper.findPermissionsByRoleId(roleId)).thenReturn(List.of(perm));

        Decision d = service.check(baseRequest());

        assertThat(d.getEffect()).isEqualTo("allow");
        verify(permissionMapper, times(1)).findPermissionsByRoleId(roleId);
    }

    @Test
    @DisplayName("check — resource-target grant: resource_type_filter mismatch → grant ignored")
    void check_resourceTypeFilterMismatch() {
        SysGrant rg = baseGrant("allow", SysGrant.Target.RESOURCE, UUID.randomUUID(), 100);
        rg.setResourceTypeFilter("INVOICE"); // doesn't match request's PROJECT
        when(grantService.listActiveBySubject("user", subjectId, tenantId, appId))
                .thenReturn(List.of(rg));
        when(policyVersionService.getActive(tenantId, appId)).thenReturn(null);

        Decision d = service.check(baseRequest());

        assertThat(d.getEffect()).isEqualTo("deny");
    }

    @Test
    @DisplayName("check — resource-target grant: action mismatch when grant.action set")
    void check_resourceActionMismatch() {
        SysGrant rg = baseGrant("allow", SysGrant.Target.RESOURCE, UUID.randomUUID(), 100);
        rg.setAction("invoice.approve"); // request action is project.read
        when(grantService.listActiveBySubject("user", subjectId, tenantId, appId))
                .thenReturn(List.of(rg));
        when(policyVersionService.getActive(tenantId, appId)).thenReturn(null);

        Decision d = service.check(baseRequest());

        assertThat(d.getEffect()).isEqualTo("deny");
    }

    @Test
    @DisplayName("check — scope_org_id mismatch when context has no deptId")
    void check_scopeOrgMismatchWithoutContext() {
        SysGrant g = baseGrant("allow", SysGrant.Target.PERMISSION, permissionId, 100);
        g.setScopeOrgId(UUID.randomUUID()); // grant scoped to specific org
        when(grantService.listActiveBySubject("user", subjectId, tenantId, appId))
                .thenReturn(List.of(g));
        when(policyVersionService.getActive(tenantId, appId)).thenReturn(null);

        Decision d = service.check(baseRequest());

        assertThat(d.getEffect()).isEqualTo("deny");
    }

    @Test
    @DisplayName("check — scope_org_id matches when context.deptId equals grant.scope_org_id")
    void check_scopeOrgMatch() {
        UUID dept = UUID.randomUUID();
        SysGrant g = baseGrant("allow", SysGrant.Target.PERMISSION, permissionId, 100);
        g.setScopeOrgId(dept);
        when(grantService.listActiveBySubject("user", subjectId, tenantId, appId))
                .thenReturn(List.of(g));
        when(policyVersionService.getActive(tenantId, appId)).thenReturn(null);

        CheckRequest req = baseRequest();
        Map<String, Object> ctx = new java.util.HashMap<>(req.getContext());
        ctx.put("deptId", dept.toString());
        req.setContext(ctx);

        Decision d = service.check(req);

        assertThat(d.getEffect()).isEqualTo("allow");
    }

    @Test
    @DisplayName("check — null request returns deny")
    void check_nullRequest_returnsDeny() {
        Decision d = service.check(null);
        assertThat(d.getEffect()).isEqualTo("deny");
        assertThat(d.getReason()).contains("missing");
    }

    @Test
    @DisplayName("check — missing subjectId returns deny")
    void check_missingSubject_returnsDeny() {
        CheckRequest req = CheckRequest.builder().subjectType("user").build();
        Decision d = service.check(req);
        assertThat(d.getEffect()).isEqualTo("deny");
    }

    @Test
    @DisplayName("check — DecisionRecorder records allow event")
    void check_recordsAllowEvent() {
        SysGrant g = baseGrant("allow", SysGrant.Target.PERMISSION, permissionId, 100);
        when(grantService.listActiveBySubject("user", subjectId, tenantId, appId))
                .thenReturn(List.of(g));
        when(policyVersionService.getActive(tenantId, appId)).thenReturn(null);

        Decision d = service.check(baseRequest());

        assertThat(d.getEffect()).isEqualTo("allow");
        // verify recorder buffered an event
        assertThat(decisionRecorder.bufferedCount()).isEqualTo(1);
    }

    @Test
    @DisplayName("batchCheck — iterates each request and preserves order")
    void batchCheck_iteratesAndPreservesOrder() {
        when(grantService.listActiveBySubject(any(), any(), any(), any()))
                .thenReturn(List.of());
        when(policyVersionService.getActive(any(), any())).thenReturn(null);

        CheckRequest a = baseRequest();
        CheckRequest b = CheckRequest.builder()
                .subjectType("user").subjectId(UUID.randomUUID())
                .action("doc.read").build();

        List<Decision> out = service.batchCheck(List.of(a, b));

        assertThat(out).hasSize(2);
        assertThat(out.get(0).getEffect()).isEqualTo("deny");
        assertThat(out.get(1).getEffect()).isEqualTo("deny");
    }

    @Test
    @DisplayName("batchCheck — empty list returns empty list")
    void batchCheck_empty_returnsEmpty() {
        assertThat(service.batchCheck(List.of())).isEmpty();
        verify(grantService, never()).listActiveBySubject(any(), any(), any(), any());
    }

    @Test
    @DisplayName("getEffectivePermissions — aggregates role + permission grants")
    void getEffectivePermissions_aggregates() {
        SysGrant roleGrant = baseGrant("allow", SysGrant.Target.ROLE, roleId, 100);
        SysGrant permGrant = baseGrant("allow", SysGrant.Target.PERMISSION, permissionId, 100);
        when(grantService.listActiveBySubject("user", subjectId, tenantId, null))
                .thenReturn(List.of(roleGrant, permGrant));

        SysPermission p1 = new SysPermission();
        p1.setId(UUID.randomUUID());
        p1.setPermissionCode("user.read");
        SysPermission p2 = new SysPermission();
        p2.setId(permissionId);
        p2.setPermissionCode("project.read");
        when(permissionMapper.findPermissionsByRoleId(roleId)).thenReturn(List.of(p1));
        when(permissionMapper.selectById(permissionId)).thenReturn(p2);

        Set<String> perms = service.getEffectivePermissions(subjectId, "user");

        assertThat(perms).containsExactlyInAnyOrder("user.read", "project.read");
    }

    @Test
    @DisplayName("getEffectivePermissions — permission-target deny grant excludes code")
    void getEffectivePermissions_denyGrantExcludes() {
        SysGrant denyGrant = baseGrant("deny", SysGrant.Target.PERMISSION, permissionId, 100);
        when(grantService.listActiveBySubject("user", subjectId, tenantId, null))
                .thenReturn(List.of(denyGrant));

        Set<String> perms = service.getEffectivePermissions(subjectId, "user");

        assertThat(perms).isEmpty();
    }

    @Test
    @DisplayName("getEffectivePermissions — null subjectId returns empty set")
    void getEffectivePermissions_nullSubject() {
        assertThat(service.getEffectivePermissions(null, "user")).isEmpty();
        assertThat(service.getEffectivePermissions(subjectId, null)).isEmpty();
    }
}