package com.frog.system.service.Impl;

import com.frog.common.exception.BusinessException;
import com.frog.system.domain.entity.SysRegisteredClient;
import com.frog.system.mapper.SysRegisteredClientMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * SysRegisteredClientServiceImpl unit tests — Phase 1.4.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("SysRegisteredClientServiceImpl Tests")
class SysRegisteredClientServiceImplTest {

    @Mock
    private SysRegisteredClientMapper clientMapper;

    @InjectMocks
    private SysRegisteredClientServiceImpl clientService;

    private UUID tenantId;
    private SysRegisteredClient sample;

    @BeforeEach
    void setUp() {
        tenantId = UUID.randomUUID();
        sample = new SysRegisteredClient();
        sample.setId(UUID.randomUUID());
        sample.setTenantId(tenantId);
        sample.setClientId("erp-web");
        sample.setClientSecretHash("hash");
        sample.setStatus(1);
        sample.setAccessTokenTtlSeconds(7200);
        sample.setRefreshTokenTtlSeconds(604800);
    }

    @Test
    @DisplayName("findByClientId — delegates to mapper")
    void findByClientId_delegates() {
        when(clientMapper.findByClientId("erp-web")).thenReturn(sample);

        SysRegisteredClient result = clientService.findByClientId("erp-web");

        assertThat(result).isNotNull();
        assertThat(result.getClientId()).isEqualTo("erp-web");
    }

    @Test
    @DisplayName("findOptionalByClientId — empty when missing")
    void findOptionalByClientId_empty() {
        when(clientMapper.findByClientId("ghost")).thenReturn(null);

        assertThat(clientService.findOptionalByClientId("ghost")).isEmpty();
    }

    @Test
    @DisplayName("addClient — rejects when tenantId missing")
    void addClient_rejectsMissingTenant() {
        SysRegisteredClient input = new SysRegisteredClient();
        input.setClientId("crm-web");

        assertThatThrownBy(() -> clientService.addClient(input))
                .isInstanceOf(BusinessException.class)
                .hasMessageContaining("租户ID");

        verify(clientMapper, never()).insert(any());
    }

    @Test
    @DisplayName("addClient — rejects when clientId missing")
    void addClient_rejectsMissingClientId() {
        SysRegisteredClient input = new SysRegisteredClient();
        input.setTenantId(tenantId);

        assertThatThrownBy(() -> clientService.addClient(input))
                .isInstanceOf(BusinessException.class)
                .hasMessageContaining("client_id");

        verify(clientMapper, never()).insert(any());
    }

    @Test
    @DisplayName("addClient — rejects when clientId already exists")
    void addClient_rejectsDuplicate() {
        SysRegisteredClient input = new SysRegisteredClient();
        input.setTenantId(tenantId);
        input.setClientId("dup");

        when(clientMapper.findByClientId("dup")).thenReturn(sample);

        assertThatThrownBy(() -> clientService.addClient(input))
                .isInstanceOf(BusinessException.class)
                .hasMessageContaining("已存在");

        verify(clientMapper, never()).insert(any());
    }

    @Test
    @DisplayName("addClient — assigns id + defaults when missing")
    void addClient_assignsDefaults() {
        SysRegisteredClient input = new SysRegisteredClient();
        input.setTenantId(tenantId);
        input.setClientId("crm-web");

        when(clientMapper.findByClientId("crm-web")).thenReturn(null);
        when(clientMapper.insert(any(SysRegisteredClient.class))).thenAnswer(inv -> {
            SysRegisteredClient c = inv.getArgument(0);
            assertThat(c.getId()).isNotNull();
            assertThat(c.getStatus()).isEqualTo(1);
            assertThat(c.getAccessTokenTtlSeconds()).isEqualTo(7200);
            assertThat(c.getRefreshTokenTtlSeconds()).isEqualTo(604800);
            assertThat(c.getRequireAuthorizationConsent()).isFalse();
            assertThat(c.getRequireProofKey()).isFalse();
            return 1;
        });

        clientService.addClient(input);

        verify(clientMapper, times(1)).insert(any(SysRegisteredClient.class));
    }

    @Test
    @DisplayName("updateClient — nulls tenantId + clientId to preserve identity")
    void updateClient_preservesIdentity() {
        SysRegisteredClient patch = new SysRegisteredClient();
        patch.setId(sample.getId());
        patch.setClientSecretHash("new-hash");

        when(clientMapper.selectById(sample.getId())).thenReturn(sample);
        when(clientMapper.updateById(any(SysRegisteredClient.class))).thenReturn(1);
        when(clientMapper.selectById(sample.getId())).thenReturn(sample);

        clientService.updateClient(patch);

        verify(clientMapper).updateById(any(SysRegisteredClient.class));
    }

    @Test
    @DisplayName("updateClient — throws when missing")
    void updateClient_throwsWhenMissing() {
        SysRegisteredClient patch = new SysRegisteredClient();
        patch.setId(UUID.randomUUID());

        when(clientMapper.selectById(patch.getId())).thenReturn(null);

        assertThatThrownBy(() -> clientService.updateClient(patch))
                .isInstanceOf(BusinessException.class);
    }

    @Test
    @DisplayName("deleteClient — soft-deletes by id")
    void deleteClient_delegates() {
        when(clientMapper.selectById(sample.getId())).thenReturn(sample);
        when(clientMapper.deleteById(sample.getId())).thenReturn(1);

        clientService.deleteClient(sample.getId());

        verify(clientMapper).deleteById(sample.getId());
    }

    @Test
    @DisplayName("SysRegisteredClient.isActive — true when status==1")
    void entityIsActive() {
        sample.setStatus(1);
        assertThat(sample.isActive()).isTrue();
        sample.setStatus(0);
        assertThat(sample.isActive()).isFalse();
        sample.setStatus(null);
        assertThat(sample.isActive()).isFalse();
    }
}
