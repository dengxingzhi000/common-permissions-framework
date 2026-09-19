package com.frog.auth.security;

import com.frog.common.security.util.JwtUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.stereotype.Service;

import java.util.UUID;

/**
 * 装饰器:在 Spring 默认 {@link OAuth2AuthorizationService} 之上维护 Redis 侧索引
 * <p>索引 key: <code>oauth2:user:auths:{userId}</code> -> Set&lt;String authorizationId&gt;</p>
 * <p>用途:全局登出时按 userId 反查该用户所有 OAuth2 授权 ID,逐条删除。</p>
 *
 * @since 2026-09-19
 */
@Slf4j
// NOTE: When OAuth2AuthorizationServiceConfig (Task 6) declares a @Primary @Bean factory
// with the same name, drop @Service to avoid BeanDefinitionOverrideException.
@Service
public class SideIndexingOAuth2AuthorizationService implements OAuth2AuthorizationService {

    private static final String INDEX_KEY_PREFIX = "oauth2:user:auths:";

    private final OAuth2AuthorizationService delegate;
    private final StringRedisTemplate redisTemplate;
    private final JwtUtils jwtUtils;

    public SideIndexingOAuth2AuthorizationService(
            OAuth2AuthorizationService delegate,
            StringRedisTemplate redisTemplate,
            JwtUtils jwtUtils) {
        this.delegate = delegate;
        this.redisTemplate = redisTemplate;
        this.jwtUtils = jwtUtils;
    }

    @Override
    public void save(OAuth2Authorization authorization) {
        delegate.save(authorization);
        addToIndex(authorization);
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        delegate.remove(authorization);
        removeFromIndex(authorization);
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        return delegate.findByToken(token, tokenType);
    }

    @Override
    public OAuth2Authorization findById(String id) {
        return delegate.findById(id);
    }

    private void addToIndex(OAuth2Authorization authorization) {
        UUID userId = extractUserId(authorization);
        if (userId == null) return;
        String key = INDEX_KEY_PREFIX + userId;
        redisTemplate.opsForSet().add(key, authorization.getId());
    }

    private void removeFromIndex(OAuth2Authorization authorization) {
        UUID userId = extractUserId(authorization);
        if (userId == null) return;
        String key = INDEX_KEY_PREFIX + userId;
        redisTemplate.opsForSet().remove(key, authorization.getId());
        Long size = redisTemplate.opsForSet().size(key);
        if (size != null && size == 0L) {
            redisTemplate.delete(key);
        }
    }

    private UUID extractUserId(OAuth2Authorization authorization) {
        OAuth2Authorization.Token<OAuth2AccessToken> accessToken = authorization.getAccessToken();
        if (accessToken == null) return null;
        try {
            return jwtUtils.getUserIdFromToken(accessToken.getToken().getTokenValue());
        } catch (Exception ex) {
            log.debug("Cannot extract userId from access token for auth {}", authorization.getId());
            return null;
        }
    }
}