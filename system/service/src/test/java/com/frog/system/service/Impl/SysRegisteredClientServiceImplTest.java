package com.frog.system.service.Impl;

import com.frog.common.exception.BusinessException;
import com.frog.common.security.oauth2.SysRegisteredClientDTO;
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
 *
 * <p>对外契约在 Phase 1.4 之后改为 {@link SysRegisteredClientDTO},
 * 因此 service 输入/输出断言使用 DTO;内部 mapper 仍使用
 * {@link SysRegisteredClient} 实体,所以 mapper mock 参数仍是实体。
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("SysRegisteredClientServiceImpl Tests")
class SysRegisteredClientServiceImplTest {

    @Mock
    private SysRegisteredClientMapper clientMapper;

    @InjectMocks
    private SysRegisteredClientServiceImpl clientService;

    private UUID tenantId;
    private SysRegisteredClient sampleEntity;
    private SysRegisteredClientDTO sampleDto;

    @BeforeEach
    void setUp() {
        tenantId = UUID.randomUUID();
        UUID id = UUID.randomUUID();

        sampleEntity = new SysRegisteredClient();
        sampleEntity.setId(id);
        sampleEntity.setTenantId(tenantId);
        sampleEntity.setClientId("erp-web");
        sampleEntity.setClientSecretHash("hash");
        sampleEntity.setStatus(1);
        sampleEntity.setAccessTokenTtlSeconds(7200);
        sampleEntity.setRefreshTokenTtlSeconds(604800);

        sampleDto = SysRegisteredClientDTO.builder()
                .id(id)
                .tenantId(tenantId)
                .clientId("erp-web")
                .clientSecretHash("hash")
                .status(1)
                .accessTokenTtlSeconds(7200)
                .refreshTokenTtlSeconds(604800)
                .build();
    }

    @Test
    @DisplayName("findByClientId — delegates to mapper and maps to DTO")
    void findByClientId_delegates() {
        when(clientMapper.findByClientId("erp-web")).thenReturn(sampleEntity);

        SysRegisteredClientDTO result = clientService.findByClientId("erp-web");

        assertThat(result).isNotNull();
        assertThat(result.getClientId()).isEqualTo("erp-web");
        assertThat(result.getId()).isEqualTo(sampleEntity.getId());
    }

    @Test
    @DisplayName("findByClientId — null when missing")
    void findByClientId_null() {
        when(clientMapper.findByClientId("ghost")).thenReturn(null);

        assertThat(clientService.findByClientId("ghost")).isNull();
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
        SysRegisteredClientDTO input = SysRegisteredClientDTO.builder()
                .clientId("crm-web")
                .build();

        assertThatThrownBy(() -> clientService.addClient(input))
                .isInstanceOf(BusinessException.class)
                .hasMessageContaining("租户ID");

        verify(clientMapper, never()).insert(any(SysRegisteredClient.class));
    }

    @Test
    @DisplayName("addClient — rejects when clientId missing")
    void addClient_rejectsMissingClientId() {
        SysRegisteredClientDTO input = SysRegisteredClientDTO.builder()
                .tenantId(tenantId)
                .build();

        assertThatThrownBy(() -> clientService.addClient(input))
                .isInstanceOf(BusinessException.class)
                .hasMessageContaining("client_id");

        verify(clientMapper, never()).insert(any(SysRegisteredClient.class));
    }

    @Test
    @DisplayName("addClient — rejects when clientId already exists")
    void addClient_rejectsDuplicate() {
        SysRegisteredClientDTO input = SysRegisteredClientDTO.builder()
                .tenantId(tenantId)
                .clientId("dup")
                .build();

        when(clientMapper.findByClientId("dup")).thenReturn(sampleEntity);

        assertThatThrownBy(() -> clientService.addClient(input))
                .isInstanceOf(BusinessException.class)
                .hasMessageContaining("已存在");

        verify(clientMapper, never()).insert(any(SysRegisteredClient.class));
    }

    @Test
    @DisplayName("addClient — assigns id + defaults when missing")
    void addClient_assignsDefaults() {
        SysRegisteredClientDTO input = SysRegisteredClientDTO.builder()
                .tenantId(tenantId)
                .clientId("crm-web")
                .build();

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
    @DisplayName("updateClient — preserves identity fields, updates mutable ones")
    void updateClient_preservesIdentity() {
        SysRegisteredClientDTO patch = SysRegisteredClientDTO.builder()
                .id(sampleEntity.getId())
                .clientSecretHash("new-hash")
                .build();

        when(clientMapper.selectById(sampleEntity.getId()))
                .thenReturn(sampleEntity)
                .thenReturn(sampleEntity);
        when(clientMapper.updateById(any(SysRegisteredClient.class))).thenReturn(1);

        clientService.updateClient(patch);

        verify(clientMapper).updateById(any(SysRegisteredClient.class));
    }

    @Test
    @DisplayName("updateClient — throws when missing")
    void updateClient_throwsWhenMissing() {
        UUID missingId = UUID.randomUUID();
        SysRegisteredClientDTO patch = SysRegisteredClientDTO.builder()
                .id(missingId)
                .build();

        when(clientMapper.selectById(missingId)).thenReturn(null);

        assertThatThrownBy(() -> clientService.updateClient(patch))
                .isInstanceOf(BusinessException.class);
    }

    @Test
    @DisplayName("deleteClient — soft-deletes by id")
    void deleteClient_delegates() {
        when(clientMapper.selectById(sampleEntity.getId())).thenReturn(sampleEntity);
        when(clientMapper.deleteById(sampleEntity.getId())).thenReturn(1);

        clientService.deleteClient(sampleEntity.getId());

        verify(clientMapper).deleteById(sampleEntity.getId());
    }

    @Test
    @DisplayName("SysRegisteredClient.isActive — true when status==1")
    void entityIsActive() {
        sampleEntity.setStatus(1);
        assertThat(sampleEntity.isActive()).isTrue();
        sampleEntity.setStatus(0);
        assertThat(sampleEntity.isActive()).isFalse();
        sampleEntity.setStatus(null);
        assertThat(sampleEntity.isActive()).isFalse();
    }
}
