package com.frog.system.service.Impl;

import com.frog.common.exception.BusinessException;
import com.frog.system.domain.entity.SysResource;
import com.frog.system.mapper.SysResourceMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * SysResourceServiceImpl unit tests — Phase 1.7.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("SysResourceServiceImpl Tests")
class SysResourceServiceImplTest {

    @Mock
    private SysResourceMapper resourceMapper;

    @InjectMocks
    private SysResourceServiceImpl resourceService;

    private UUID tenantId;
    private UUID appId;
    private SysResource sample;

    @BeforeEach
    void setUp() {
        tenantId = UUID.randomUUID();
        appId = UUID.randomUUID();
        sample = new SysResource();
        sample.setId(UUID.randomUUID());
        sample.setTenantId(tenantId);
        sample.setAppId(appId);
        sample.setResourceCode("PROJECT");
        sample.setResourceName("Project");
        sample.setResourceType("PROJECT");
        sample.setStatus(1);
    }

    @Test
    @DisplayName("listByTenantAndApp — returns mapper list when both ids set")
    void listByTenantAndApp_returns() {
        when(resourceMapper.findByTenantAndApp(tenantId, appId)).thenReturn(List.of(sample));

        List<SysResource> result = resourceService.listByTenantAndApp(tenantId, appId);

        assertThat(result).hasSize(1);
        assertThat(result.get(0).getResourceCode()).isEqualTo("PROJECT");
    }

    @Test
    @DisplayName("listByTenantAndApp — returns empty when tenant or app is null")
    void listByTenantAndApp_shortCircuitsOnNull() {
        assertThat(resourceService.listByTenantAndApp(null, appId)).isEmpty();
        assertThat(resourceService.listByTenantAndApp(tenantId, null)).isEmpty();
        verify(resourceMapper, never()).findByTenantAndApp(any(), any());
    }

    @Test
    @DisplayName("listByTenantAppType — returns mapper list when all params valid")
    void listByTenantAppType_returns() {
        when(resourceMapper.findByTenantAppType(tenantId, appId, "PROJECT"))
                .thenReturn(List.of(sample));

        List<SysResource> result =
                resourceService.listByTenantAppType(tenantId, appId, "PROJECT");

        assertThat(result).hasSize(1);
    }

    @Test
    @DisplayName("listByTenantAppType — returns empty when resourceType blank")
    void listByTenantAppType_shortCircuitsOnBlankType() {
        assertThat(resourceService.listByTenantAppType(tenantId, appId, ""))
                .isEmpty();
        assertThat(resourceService.listByTenantAppType(tenantId, appId, null))
                .isEmpty();
        verify(resourceMapper, never()).findByTenantAppType(any(), any(), any());
    }

    @Test
    @DisplayName("getByTenantAppCode — delegates to mapper")
    void getByTenantAppCode_delegates() {
        when(resourceMapper.findByTenantAppCode(tenantId, appId, "PROJECT"))
                .thenReturn(sample);

        SysResource result = resourceService.getByTenantAppCode(tenantId, appId, "PROJECT");

        assertThat(result).isSameAs(sample);
    }

    @Test
    @DisplayName("addResource — rejects when tenantId missing")
    void addResource_rejectsMissingTenant() {
        SysResource input = new SysResource();
        input.setAppId(appId);
        input.setResourceCode("X");
        input.setResourceName("X");
        input.setResourceType("X");

        assertThatThrownBy(() -> resourceService.addResource(input))
                .isInstanceOf(BusinessException.class)
                .hasMessageContaining("租户ID");
        verify(resourceMapper, never()).insert(any());
    }

    @Test
    @DisplayName("addResource — rejects when appId missing")
    void addResource_rejectsMissingApp() {
        SysResource input = new SysResource();
        input.setTenantId(tenantId);
        input.setResourceCode("X");
        input.setResourceName("X");
        input.setResourceType("X");

        assertThatThrownBy(() -> resourceService.addResource(input))
                .isInstanceOf(BusinessException.class)
                .hasMessageContaining("应用ID");
        verify(resourceMapper, never()).insert(any());
    }

    @Test
    @DisplayName("addResource — rejects when resourceCode missing")
    void addResource_rejectsMissingCode() {
        SysResource input = new SysResource();
        input.setTenantId(tenantId);
        input.setAppId(appId);
        input.setResourceName("X");
        input.setResourceType("X");

        assertThatThrownBy(() -> resourceService.addResource(input))
                .isInstanceOf(BusinessException.class)
                .hasMessageContaining("资源编码");
        verify(resourceMapper, never()).insert(any());
    }

    @Test
    @DisplayName("addResource — rejects when resourceType missing")
    void addResource_rejectsMissingType() {
        SysResource input = new SysResource();
        input.setTenantId(tenantId);
        input.setAppId(appId);
        input.setResourceCode("X");
        input.setResourceName("X");

        assertThatThrownBy(() -> resourceService.addResource(input))
                .isInstanceOf(BusinessException.class)
                .hasMessageContaining("资源类型");
        verify(resourceMapper, never()).insert(any());
    }

    @Test
    @DisplayName("addResource — rejects duplicate (tenant, app, code)")
    void addResource_rejectsDuplicate() {
        SysResource input = new SysResource();
        input.setTenantId(tenantId);
        input.setAppId(appId);
        input.setResourceCode("PROJECT");
        input.setResourceName("Project");
        input.setResourceType("PROJECT");

        when(resourceMapper.existsByTenantAppCode(tenantId, appId, "PROJECT"))
                .thenReturn(true);

        assertThatThrownBy(() -> resourceService.addResource(input))
                .isInstanceOf(BusinessException.class)
                .hasMessageContaining("资源编码已存在");
        verify(resourceMapper, never()).insert(any());
    }

    @Test
    @DisplayName("addResource — assigns UUID and default status when missing")
    void addResource_assignsDefaults() {
        SysResource input = new SysResource();
        input.setTenantId(tenantId);
        input.setAppId(appId);
        input.setResourceCode("DOCUMENT");
        input.setResourceName("Document");
        input.setResourceType("DOCUMENT");

        when(resourceMapper.existsByTenantAppCode(tenantId, appId, "DOCUMENT"))
                .thenReturn(false);
        when(resourceMapper.insert(any(SysResource.class))).thenAnswer(inv -> {
            SysResource r = inv.getArgument(0);
            assertThat(r.getId()).isNotNull();
            assertThat(r.getStatus()).isEqualTo(1);
            return 1;
        });

        resourceService.addResource(input);

        verify(resourceMapper, times(1)).insert(any(SysResource.class));
    }

    @Test
    @DisplayName("updateResource — nulls identity columns (tenant, app, code, type)")
    void updateResource_preservesIdentity() {
        SysResource patch = new SysResource();
        patch.setId(sample.getId());
        patch.setResourceName("New Name");
        patch.setTenantId(UUID.randomUUID());
        patch.setAppId(UUID.randomUUID());
        patch.setResourceCode("changed");
        patch.setResourceType("changed");

        when(resourceMapper.selectById(sample.getId())).thenReturn(sample);
        when(resourceMapper.updateById(any(SysResource.class))).thenReturn(1);

        resourceService.updateResource(patch);

        verify(resourceMapper).updateById(any(SysResource.class));
    }

    @Test
    @DisplayName("updateResource — throws when resource missing")
    void updateResource_throwsWhenMissing() {
        SysResource patch = new SysResource();
        patch.setId(UUID.randomUUID());
        patch.setResourceName("Anything");

        when(resourceMapper.selectById(patch.getId())).thenReturn(null);

        assertThatThrownBy(() -> resourceService.updateResource(patch))
                .isInstanceOf(BusinessException.class);
    }

    @Test
    @DisplayName("deleteResource — soft-deletes by id")
    void deleteResource_delegates() {
        when(resourceMapper.selectById(sample.getId())).thenReturn(sample);
        when(resourceMapper.deleteById(sample.getId())).thenReturn(1);

        resourceService.deleteResource(sample.getId());

        verify(resourceMapper).deleteById(sample.getId());
    }

    @Test
    @DisplayName("deleteResource — throws when missing")
    void deleteResource_throwsWhenMissing() {
        when(resourceMapper.selectById(sample.getId())).thenReturn(null);

        assertThatThrownBy(() -> resourceService.deleteResource(sample.getId()))
                .isInstanceOf(BusinessException.class);
        verify(resourceMapper, never()).deleteById(any());
    }

    @Test
    @DisplayName("SysResource.isActive — true when status==1")
    void entityIsActive() {
        sample.setStatus(1);
        assertThat(sample.isActive()).isTrue();
        sample.setStatus(0);
        assertThat(sample.isActive()).isFalse();
        sample.setStatus(null);
        assertThat(sample.isActive()).isFalse();
    }
}