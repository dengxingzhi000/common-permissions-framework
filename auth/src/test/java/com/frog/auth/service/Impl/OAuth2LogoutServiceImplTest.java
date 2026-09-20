package com.frog.auth.service.Impl;

import com.frog.common.exception.BusinessException;
import com.frog.common.log.service.ISysAuditLogService;
import com.frog.common.security.util.JwtUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.data.redis.core.SetOperations;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class OAuth2LogoutServiceImplTest {

    @Mock OAuth2AuthorizationService authorizationService;
    @Mock JwtUtils jwtUtils;
    @Mock ISysAuditLogService auditLogService;
    @Mock StringRedisTemplate redisTemplate;

    @InjectMocks OAuth2LogoutServiceImpl service;

    private final UUID callerUserId = UUID.fromString("019a0aee-3b74-7bfc-b34f-48b5428d48a1");
    private final String accessToken = "valid.jwt.token";
    private final String clientId = "internal-service";

    private OAuth2Authorization givenAuth() {
        return OAuth2Authorization.withRegisteredClient(
                RegisteredClient.withId("client-1")
                        .clientId(clientId)
                        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                        .build())
                .principalName("alice")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .build();
    }

    @Test
    void revokeByClient_happyPath_removesAuthorization() {
        when(jwtUtils.getUserIdFromToken(accessToken)).thenReturn(callerUserId);
        OAuth2Authorization auth = givenAuth();
        when(authorizationService.findByToken(accessToken, OAuth2TokenType.ACCESS_TOKEN))
                .thenReturn(auth);

        service.revokeByClient(accessToken, clientId, callerUserId);

        verify(authorizationService).remove(auth);
        verify(auditLogService, never()).recordLogout(any(), any());
    }

    @Test
    void revokeByClient_tokenUserIdMismatch_throws4001() {
        UUID otherUser = UUID.fromString("019a0aee-3b74-7bfc-b34f-48b5428d48a2");
        when(jwtUtils.getUserIdFromToken(accessToken)).thenReturn(otherUser);

        assertThatThrownBy(() -> service.revokeByClient(accessToken, clientId, callerUserId))
                .isInstanceOf(BusinessException.class)
                .hasMessageContaining("不属于当前用户");

        verify(authorizationService, never()).remove(any());
        verify(auditLogService, never()).recordLogout(any(), any());
    }

    @Test
    void revokeByClient_tokenInvalid_throws4001() {
        when(jwtUtils.getUserIdFromToken(accessToken))
                .thenThrow(new IllegalArgumentException("bad token"));

        assertThatThrownBy(() -> service.revokeByClient(accessToken, clientId, callerUserId))
                .isInstanceOf(BusinessException.class)
                .hasMessageContaining("令牌无效");
    }

    @Test
    void revokeByClient_authorizationNotFound_throws4004() {
        when(jwtUtils.getUserIdFromToken(accessToken)).thenReturn(callerUserId);
        when(authorizationService.findByToken(accessToken, OAuth2TokenType.ACCESS_TOKEN))
                .thenReturn(null);

        assertThatThrownBy(() -> service.revokeByClient(accessToken, clientId, callerUserId))
                .isInstanceOf(BusinessException.class)
                .hasMessageContaining("未找到");
    }

    @Test
    void revokeGlobal_emptyIndex_returnsZeroAndAudits() {
        SetOperations<String, String> setOps = mock(SetOperations.class);
        when(redisTemplate.opsForSet()).thenReturn(setOps);
        when(setOps.members("oauth2:user:auths:" + callerUserId)).thenReturn(Set.of());

        int removed = service.revokeGlobal(callerUserId, "test", "admin");

        assertThat(removed).isEqualTo(0);
        verify(auditLogService).recordLogout(eq(callerUserId), anyString());
        verify(authorizationService, never()).remove(any());
    }

    @Test
    void revokeGlobal_withAuthorizations_removesAllAndAuditsCount() {
        SetOperations<String, String> setOps = mock(SetOperations.class);
        when(redisTemplate.opsForSet()).thenReturn(setOps);
        Set<String> authIds = Set.of("auth-1", "auth-2");
        when(setOps.members("oauth2:user:auths:" + callerUserId)).thenReturn(authIds);

        OAuth2Authorization a1 = givenAuth();
        OAuth2Authorization a2 = givenAuth();
        when(authorizationService.findById("auth-1")).thenReturn(a1);
        when(authorizationService.findById("auth-2")).thenReturn(a2);

        int removed = service.revokeGlobal(callerUserId, "compromised account", "admin");

        assertThat(removed).isEqualTo(2);
        verify(authorizationService).remove(a1);
        verify(authorizationService).remove(a2);
        verify(redisTemplate).delete("oauth2:user:auths:" + callerUserId);
        verify(auditLogService).recordLogout(eq(callerUserId), anyString());
    }
}