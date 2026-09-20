package com.frog.system.service.Impl;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.frog.common.exception.BusinessException;
import com.frog.system.domain.entity.SysTenant;
import com.frog.system.mapper.SysTenantMapper;
import com.frog.system.service.ISysTenantService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * SysTenantServiceImpl unit tests — Phase 1.1.
 *
 * <p>Verifies CRUD semantics, duplicate-code rejection, and default value assignment
 * using a mocked {@link SysTenantMapper}. Integration with the database is exercised
 * separately by Flyway + repository tests.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("SysTenantServiceImpl Tests")
class SysTenantServiceImplTest {

    @Mock
    private SysTenantMapper tenantMapper;

    @InjectMocks
    private SysTenantServiceImpl tenantService;

    private SysTenant sample;

    @BeforeEach
    void setUp() {
        sample = new SysTenant();
        sample.setId(UUID.randomUUID());
        sample.setTenantCode("acme");
        sample.setTenantName("Acme Corp");
        sample.setStatus(1);
        sample.setIsolationLevel(SysTenant.Isolation.SHARED);
        sample.setContactEmail("[email protected]");
        sample.setCreateTime(LocalDateTime.now());
    }

    @AfterEach
    void tearDown() {
        // Reset any shared state — currently none
    }

    @Test
    @DisplayName("addTenant — assigns UUID and default isolation/status when missing")
    void addTenant_assignsDefaults() {
        SysTenant input = new SysTenant();
        input.setTenantCode("newcorp");
        input.setTenantName("New Corp");

        when(tenantMapper.existsByTenantCode("newcorp")).thenReturn(false);
        when(tenantMapper.insert(any(SysTenant.class))).thenAnswer(inv -> {
            SysTenant t = inv.getArgument(0);
            assertThat(t.getId()).isNotNull();
            assertThat(t.getStatus()).isEqualTo(1);
            assertThat(t.getIsolationLevel()).isEqualTo(SysTenant.Isolation.SHARED);
            return 1;
        });

        SysTenant result = tenantService.addTenant(input);

        assertThat(result).isNotNull();
        verify(tenantMapper, times(1)).insert(any(SysTenant.class));
    }

    @Test
    @DisplayName("addTenant — rejects duplicate tenantCode")
    void addTenant_rejectsDuplicate() {
        SysTenant input = new SysTenant();
        input.setTenantCode("acme");

        when(tenantMapper.existsByTenantCode("acme")).thenReturn(true);

        assertThatThrownBy(() -> tenantService.addTenant(input))
                .isInstanceOf(BusinessException.class)
                .hasMessageContaining("租户编码已存在");

        verify(tenantMapper, never()).insert(any(SysTenant.class));
    }

    @Test
    @DisplayName("addTenant — rejects blank tenantCode")
    void addTenant_rejectsBlankCode() {
        SysTenant input = new SysTenant();
        input.setTenantCode("  ");

        assertThatThrownBy(() -> tenantService.addTenant(input))
                .isInstanceOf(BusinessException.class)
                .hasMessageContaining("不能为空");

        verify(tenantMapper, never()).existsByTenantCode(any());
    }

    @Test
    @DisplayName("updateTenant — nulls tenantCode to preserve identity")
    void updateTenant_preservesIdentity() {
        SysTenant patch = new SysTenant();
        patch.setId(sample.getId());
        patch.setTenantName("Updated Name");
        patch.setTenantCode("changed-and-ignored");

        when(tenantMapper.selectById(sample.getId())).thenReturn(sample);
        when(tenantMapper.updateById(any(SysTenant.class))).thenReturn(1);
        when(tenantMapper.selectById(sample.getId())).thenReturn(sample);

        tenantService.updateTenant(patch);

        verify(tenantMapper).updateById(any(SysTenant.class));
    }

    @Test
    @DisplayName("updateTenant — throws when tenant not found")
    void updateTenant_throwsWhenMissing() {
        SysTenant patch = new SysTenant();
        patch.setId(UUID.randomUUID());

        when(tenantMapper.selectById(patch.getId())).thenReturn(null);

        assertThatThrownBy(() -> tenantService.updateTenant(patch))
                .isInstanceOf(BusinessException.class)
                .hasMessageContaining("租户不存在");
    }

    @Test
    @DisplayName("disableTenant — sets status=0")
    void disableTenant_setsZeroStatus() {
        when(tenantMapper.selectById(sample.getId())).thenReturn(sample);
        when(tenantMapper.updateById(any(SysTenant.class))).thenReturn(1);

        tenantService.disableTenant(sample.getId());

        verify(tenantMapper).updateById(any(SysTenant.class));
    }

    @Test
    @DisplayName("enableTenant — sets status=1")
    void enableTenant_setsOneStatus() {
        sample.setStatus(0);
        when(tenantMapper.selectById(sample.getId())).thenReturn(sample);
        when(tenantMapper.updateById(any(SysTenant.class))).thenReturn(1);

        tenantService.enableTenant(sample.getId());

        verify(tenantMapper).updateById(any(SysTenant.class));
    }

    @Test
    @DisplayName("deleteTenant — calls deleteById when tenant exists")
    void deleteTenant_callsDelete() {
        when(tenantMapper.selectById(sample.getId())).thenReturn(sample);
        when(tenantMapper.deleteById(eq(sample.getId()))).thenReturn(1);

        tenantService.deleteTenant(sample.getId());

        verify(tenantMapper).deleteById(sample.getId());
    }

    @Test
    @DisplayName("deleteTenant — throws when tenant not found")
    void deleteTenant_throwsWhenMissing() {
        when(tenantMapper.selectById(sample.getId())).thenReturn(null);

        assertThatThrownBy(() -> tenantService.deleteTenant(sample.getId()))
                .isInstanceOf(BusinessException.class);
    }

    @Test
    @DisplayName("listTenants — delegates to mapper with conditional filters")
    void listTenants_delegatesWithFilters() {
        Page<SysTenant> empty = new Page<>(1, 10);
        when(tenantMapper.selectPage(any(Page.class), any(LambdaQueryWrapper.class)))
                .thenReturn(empty);

        Page<SysTenant> result = tenantService.listTenants(1, 10, "acm", 1);

        assertThat(result).isNotNull();
        verify(tenantMapper).selectPage(any(Page.class), any(LambdaQueryWrapper.class));
    }

    @Test
    @DisplayName("SysTenant.isActive — true when status==1")
    void entityIsActive() {
        sample.setStatus(1);
        assertThat(sample.isActive()).isTrue();
        sample.setStatus(0);
        assertThat(sample.isActive()).isFalse();
        sample.setStatus(null);
        assertThat(sample.isActive()).isFalse();
    }

    @Test
    @DisplayName("SysTenant.isExpired — true when expiresAt is past")
    void entityIsExpired() {
        sample.setExpiresAt(LocalDateTime.now().minusDays(1));
        assertThat(sample.isExpired()).isTrue();
        sample.setExpiresAt(LocalDateTime.now().plusDays(1));
        assertThat(sample.isExpired()).isFalse();
        sample.setExpiresAt(null);
        assertThat(sample.isExpired()).isFalse();
    }
}
