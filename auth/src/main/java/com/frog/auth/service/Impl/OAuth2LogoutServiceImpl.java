package com.frog.auth.service.Impl;

import com.frog.auth.service.IOAuth2LogoutService;
import com.frog.common.exception.BusinessException;
import com.frog.common.log.service.ISysAuditLogService;
import com.frog.common.security.util.JwtUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class OAuth2LogoutServiceImpl implements IOAuth2LogoutService {

    private final OAuth2AuthorizationService authorizationService;
    private final JwtUtils jwtUtils;
    private final ISysAuditLogService auditLogService;

    @Override
    public void revokeByClient(String accessToken, String clientId, UUID callerUserId) {
        UUID tokenUserId;
        try {
            tokenUserId = jwtUtils.getUserIdFromToken(accessToken);
        } catch (Exception ex) {
            throw new BusinessException(4001, "令牌无效或已过期");
        }
        if (!tokenUserId.equals(callerUserId)) {
            throw new BusinessException(4001, "令牌不属于当前用户");
        }
        OAuth2Authorization authorization = authorizationService.findByToken(accessToken, OAuth2TokenType.ACCESS_TOKEN);
        if (authorization == null) {
            throw new BusinessException(4004, "OAuth2 授权未找到");
        }
        authorizationService.remove(authorization);
        auditLogService.recordLogout(callerUserId, "OAuth2 单客户端登出: clientId=" + clientId);
        log.info("OAuth2 single-client revocation: userId={} clientId={}", callerUserId, clientId);
    }

    @Override
    public int revokeGlobal(UUID targetUserId, String reason, String callerUsername) {
        return 0;
    }
}