package com.frog.system.service.Impl;

import com.frog.common.exception.BusinessException;
import com.frog.system.domain.entity.SysApplication;
import com.frog.system.mapper.SysApplicationMapper;
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
 * SysApplicationServiceImpl unit tests — Phase 1.1.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("SysApplicationServiceImpl Tests")
class SysApplicationServiceImplTest {

    @Mock
    private SysApplicationMapper applicationMapper;

    @InjectMocks
    private SysApplicationServiceImpl applicationService;

    private UUID tenantId;
    private SysApplication sample;

    @BeforeEach
    void setUp() {
        tenantId = UUID.randomUUID();
        sample = new SysApplication();
        sample.setId(UUID.randomUUID());
        sample.setTenantId(tenantId);
        sample.setAppCode("erp");
        sample.setAppName("ERP System");
        sample.setAppType(SysApplication.Type.WEB);
        sample.setStatus(1);
    }

    @Test
    @DisplayName("listByTenantId — returns mapper list")
    void listByTenantId_delegates() {
        when(applicationMapper.findByTenantId(tenantId)).thenReturn(List.of(sample));

        List<SysApplication> result = applicationService.listByTenantId(tenantId);

        assertThat(result).hasSize(1);
        assertThat(result.get(0).getAppCode()).isEqualTo("erp");
    }

    @Test
    @DisplayName("getByTenantAndCode — returns app when found")
    void getByTenantAndCode_found() {
        when(applicationMapper.findByTenantAndCode(tenantId, "erp")).thenReturn(sample);

        SysApplication result = applicationService.getByTenantAndCode(tenantId, "erp");

        assertThat(result).isNotNull();
        assertThat(result.getId()).isEqualTo(sample.getId());
    }

    @Test
    @DisplayName("getByTenantAndCode — throws when missing")
    void getByTenantAndCode_missing() {
        when(applicationMapper.findByTenantAndCode(tenantId, "erp")).thenReturn(null);

        assertThatThrownBy(() -> applicationService.getByTenantAndCode(tenantId, "erp"))
                .isInstanceOf(BusinessException.class)
                .hasMessageContaining("应用不存在");
    }

    @Test
    @DisplayName("addApplication — rejects when tenantId missing")
    void addApplication_rejectsMissingTenant() {
        SysApplication input = new SysApplication();
        input.setAppCode("erp");

        assertThatThrownBy(() -> applicationService.addApplication(input))
                .isInstanceOf(BusinessException.class)
                .hasMessageContaining("租户ID");

        verify(applicationMapper, never()).insert(any());
    }

    @Test
    @DisplayName("addApplication — rejects duplicate (tenantId, appCode)")
    void addApplication_rejectsDuplicate() {
        SysApplication input = new SysApplication();
        input.setTenantId(tenantId);
        input.setAppCode("erp");

        when(applicationMapper.existsByTenantAndCode(tenantId, "erp")).thenReturn(true);

        assertThatThrownBy(() -> applicationService.addApplication(input))
                .isInstanceOf(BusinessException.class)
                .hasMessageContaining("应用编码已存在");

        verify(applicationMapper, never()).insert(any());
    }

    @Test
    @DisplayName("addApplication — assigns UUID, default type and status when missing")
    void addApplication_assignsDefaults() {
        SysApplication input = new SysApplication();
        input.setTenantId(tenantId);
        input.setAppCode("crm");

        when(applicationMapper.existsByTenantAndCode(tenantId, "crm")).thenReturn(false);
        when(applicationMapper.insert(any(SysApplication.class))).thenAnswer(inv -> {
            SysApplication a = inv.getArgument(0);
            assertThat(a.getId()).isNotNull();
            assertThat(a.getStatus()).isEqualTo(1);
            assertThat(a.getAppType()).isEqualTo(SysApplication.Type.WEB);
            return 1;
        });

        applicationService.addApplication(input);

        verify(applicationMapper, times(1)).insert(any(SysApplication.class));
    }

    @Test
    @DisplayName("updateApplication — nulls tenantId and appCode to preserve identity")
    void updateApplication_preservesIdentity() {
        SysApplication patch = new SysApplication();
        patch.setId(sample.getId());
        patch.setAppName("New Name");
        patch.setTenantId(UUID.randomUUID());
        patch.setAppCode("changed-ignored");

        when(applicationMapper.selectById(sample.getId())).thenReturn(sample);
        when(applicationMapper.updateById(any(SysApplication.class))).thenReturn(1);

        applicationService.updateApplication(patch);

        verify(applicationMapper).updateById(any(SysApplication.class));
    }

    @Test
    @DisplayName("updateApplication — throws when app missing")
    void updateApplication_throwsWhenMissing() {
        SysApplication patch = new SysApplication();
        patch.setId(UUID.randomUUID());

        when(applicationMapper.selectById(patch.getId())).thenReturn(null);

        assertThatThrownBy(() -> applicationService.updateApplication(patch))
                .isInstanceOf(BusinessException.class);
    }

    @Test
    @DisplayName("deleteApplication — soft-deletes by id")
    void deleteApplication_delegates() {
        when(applicationMapper.selectById(sample.getId())).thenReturn(sample);
        when(applicationMapper.deleteById(sample.getId())).thenReturn(1);

        applicationService.deleteApplication(sample.getId());

        verify(applicationMapper).deleteById(sample.getId());
    }

    @Test
    @DisplayName("SysApplication.isActive — true when status==1")
    void entityIsActive() {
        sample.setStatus(1);
        assertThat(sample.isActive()).isTrue();
        sample.setStatus(0);
        assertThat(sample.isActive()).isFalse();
        sample.setStatus(null);
        assertThat(sample.isActive()).isFalse();
    }
}
