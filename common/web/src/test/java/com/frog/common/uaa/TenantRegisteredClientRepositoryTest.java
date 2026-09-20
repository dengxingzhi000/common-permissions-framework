package com.frog.common.uaa;

import com.frog.common.security.oauth2.SysRegisteredClientDTO;
import com.frog.system.api.ISysRegisteredClientService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * TenantRegisteredClientRepository unit tests — Phase 1.4.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("TenantRegisteredClientRepository Tests")
class TenantRegisteredClientRepositoryTest {

    @Mock
    private ISysRegisteredClientService clientService;

    @InjectMocks
    private TenantRegisteredClientRepository repository;

    private SysRegisteredClientDTO activeRecord;

    @BeforeEach
    void setUp() {
        UUID id = UUID.randomUUID();
        activeRecord = SysRegisteredClientDTO.builder()
                .id(id)
                .tenantId(UUID.randomUUID())
                .clientId("erp-web")
                .clientSecretHash("hash")
                .clientAuthMethods(new String[]{"client_secret_basic"})
                .grantTypes(new String[]{"authorization_code", "refresh_token"})
                .redirectUris(new String[]{"http://localhost/callback"})
                .scopes(new String[]{"openid", "user.read"})
                .requireAuthorizationConsent(false)
                .requireProofKey(false)
                .accessTokenTtlSeconds(7200)
                .refreshTokenTtlSeconds(604800)
                .status(1)
                .build();
    }

    @Test
    @DisplayName("findByClientId — returns RegisteredClient when active")
    void findByClientId_active() {
        when(clientService.findByClientId("erp-web")).thenReturn(activeRecord);

        RegisteredClient result = repository.findByClientId("erp-web");

        assertThat(result).isNotNull();
        assertThat(result.getClientId()).isEqualTo("erp-web");
        assertThat(result.getClientAuthenticationMethods())
                .contains(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
        assertThat(result.getAuthorizationGrantTypes())
                .contains(AuthorizationGrantType.AUTHORIZATION_CODE,
                        AuthorizationGrantType.REFRESH_TOKEN);
        assertThat(result.getRedirectUris()).contains("http://localhost/callback");
        assertThat(result.getScopes()).contains("openid", "user.read");
        assertThat(result.getTokenSettings().getAccessTokenTimeToLive())
                .hasSeconds(7200);
        assertThat(result.getTokenSettings().getRefreshTokenTimeToLive())
                .hasSeconds(604800);
    }

    @Test
    @DisplayName("findByClientId — null when record missing")
    void findByClientId_missing() {
        when(clientService.findByClientId("ghost")).thenReturn(null);

        assertThat(repository.findByClientId("ghost")).isNull();
    }

    @Test
    @DisplayName("findByClientId — null when clientId blank")
    void findByClientId_blank() {
        assertThat(repository.findByClientId(null)).isNull();
        assertThat(repository.findByClientId("")).isNull();
        assertThat(repository.findByClientId("   ")).isNull();
    }

    @Test
    @DisplayName("findByClientId — null when record is disabled")
    void findByClientId_disabled() {
        activeRecord.setStatus(0);
        when(clientService.findByClientId("erp-web")).thenReturn(activeRecord);

        assertThat(repository.findByClientId("erp-web")).isNull();
    }

    @Test
    @DisplayName("findById — delegates to service when id is UUID-string")
    void findById_delegates() {
        when(clientService.findOptionalByClientId(activeRecord.getId().toString()))
                .thenReturn(Optional.of(activeRecord));

        RegisteredClient result = repository.findById(activeRecord.getId().toString());

        assertThat(result).isNotNull();
        assertThat(result.getId()).isEqualTo(activeRecord.getId().toString());
    }

    @Test
    @DisplayName("findById — null for blank id")
    void findById_blank() {
        assertThat(repository.findById(null)).isNull();
        assertThat(repository.findById("")).isNull();
    }

    @Test
    @DisplayName("save — throws UnsupportedOperationException (Phase 1.4 read-only)")
    void save_unsupported() {
        assertThatThrownBy(() -> repository.save(null))
                .isInstanceOf(UnsupportedOperationException.class)
                .hasMessageContaining("Phase 1.4");
    }

    @Test
    @DisplayName("resolveClientAuthMethod — known values")
    void resolveClientAuthMethod_known() {
        assertThat(TenantRegisteredClientRepository
                .resolveClientAuthMethod("client_secret_basic"))
                .isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
        assertThat(TenantRegisteredClientRepository
                .resolveClientAuthMethod("client_secret_post"))
                .isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_POST);
        assertThat(TenantRegisteredClientRepository
                .resolveClientAuthMethod("none"))
                .isEqualTo(ClientAuthenticationMethod.NONE);
        assertThat(TenantRegisteredClientRepository
                .resolveClientAuthMethod("CLIENT_SECRET_BASIC"))
                .isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
    }

    @Test
    @DisplayName("resolveClientAuthMethod — unknown returns null")
    void resolveClientAuthMethod_unknown() {
        assertThat(TenantRegisteredClientRepository
                .resolveClientAuthMethod("bogus")).isNull();
        assertThat(TenantRegisteredClientRepository
                .resolveClientAuthMethod(null)).isNull();
    }

    @Test
    @DisplayName("resolveGrantType — known values")
    void resolveGrantType_known() {
        assertThat(TenantRegisteredClientRepository
                .resolveGrantType("authorization_code"))
                .isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
        assertThat(TenantRegisteredClientRepository
                .resolveGrantType("client_credentials"))
                .isEqualTo(AuthorizationGrantType.CLIENT_CREDENTIALS);
        assertThat(TenantRegisteredClientRepository
                .resolveGrantType("refresh_token"))
                .isEqualTo(AuthorizationGrantType.REFRESH_TOKEN);
        assertThat(TenantRegisteredClientRepository
                .resolveGrantType("password"))
                .isEqualTo(new AuthorizationGrantType("password"));
    }

    @Test
    @DisplayName("resolveGrantType — unknown returns null")
    void resolveGrantType_unknown() {
        assertThat(TenantRegisteredClientRepository
                .resolveGrantType("ghost-grant")).isNull();
        assertThat(TenantRegisteredClientRepository
                .resolveGrantType(null)).isNull();
    }

    @Test
    @DisplayName("splitCsv — splits on comma / semicolon / whitespace")
    void splitCsv_basic() {
        assertThat(TenantRegisteredClientRepository.splitCsv("a,b,c"))
                .containsExactly("a", "b", "c");
        assertThat(TenantRegisteredClientRepository.splitCsv("a;b;c"))
                .containsExactly("a", "b", "c");
        assertThat(TenantRegisteredClientRepository.splitCsv("a b c"))
                .containsExactly("a", "b", "c");
        assertThat(TenantRegisteredClientRepository.splitCsv("a, b ,c"))
                .containsExactly("a", "b", "c");
    }

    @Test
    @DisplayName("splitCsv — empty/null returns empty array")
    void splitCsv_empty() {
        assertThat(TenantRegisteredClientRepository.splitCsv(null))
                .isEmpty();
        assertThat(TenantRegisteredClientRepository.splitCsv(""))
                .isEmpty();
        assertThat(TenantRegisteredClientRepository.splitCsv("   "))
                .isEmpty();
    }
}
