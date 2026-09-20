package com.frog.auth.security;

import com.frog.common.security.util.JwtUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;

/**
 * 装配 {@link OAuth2AuthorizationService}:声明一个 {@code InMemoryOAuth2AuthorizationService}
 * 后端 Bean,并用 {@link SideIndexingOAuth2AuthorizationService} 装饰为 {@code @Primary},
 * 以便 {@code OAuth2LogoutServiceImpl} / {@code CustomAuthorizationServiceImpl} /
 * {@code OAuth2LogoutController} 通过按类型注入时拿到带侧索引能力的版本。
 *
 * <p>Spring Authorization Server 1.x 不提供 {@code OAuth2AuthorizationService} 自动装配,
 * 因此这里显式创建后端 Bean。</p>
 *
 * @since 2026-09-19
 */
@Slf4j
@Configuration
public class OAuth2AuthorizationServiceConfig {

    @Bean
    public InMemoryOAuth2AuthorizationService inMemoryOAuth2AuthorizationService() {
        log.info("Creating InMemoryOAuth2AuthorizationService backend bean");
        return new InMemoryOAuth2AuthorizationService();
    }

    @Bean
    @Primary
    public SideIndexingOAuth2AuthorizationService sideIndexingOAuth2AuthorizationService(
            @Qualifier("inMemoryOAuth2AuthorizationService") OAuth2AuthorizationService delegate,
            StringRedisTemplate stringRedisTemplate,
            JwtUtils jwtUtils) {

        log.info("Wrapping default OAuth2AuthorizationService with SideIndexingOAuth2AuthorizationService");
        return new SideIndexingOAuth2AuthorizationService(delegate, stringRedisTemplate, jwtUtils);
    }
}
