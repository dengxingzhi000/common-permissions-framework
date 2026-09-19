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
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class OAuth2LogoutServiceImplTest {

    @Mock OAuth2AuthorizationService authorizationService;
    @Mock JwtUtils jwtUtils;
    @Mock ISysAuditLogService auditLogService;

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
                .build();
    }

    @Test
    void revokeByClient_happyPath_removesAuthorizationAndAudits() {
        when(jwtUtils.getUserIdFromToken(accessToken)).thenReturn(callerUserId);
        OAuth2Authorization auth = givenAuth();
        when(authorizationService.findByToken(accessToken, OAuth2TokenType.ACCESS_TOKEN))
                .thenReturn(auth);

        service.revokeByClient(accessToken, clientId, callerUserId);

        verify(authorizationService).remove(auth);
        verify(auditLogService).recordLogout(eq(callerUserId), anyString());
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
}