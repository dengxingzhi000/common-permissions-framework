package com.frog.auth.security;

import com.frog.common.security.util.JwtUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.SetOperations;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SideIndexingOAuth2AuthorizationServiceTest {

    @Mock OAuth2AuthorizationService delegate;
    @Mock StringRedisTemplate redisTemplate;
    @Mock JwtUtils jwtUtils;

    SideIndexingOAuth2AuthorizationService service;

    private final UUID userId = UUID.fromString("019a0aee-3b74-7bfc-b34f-48b5428d48a1");

    @BeforeEach
    void setUp() {
        service = new SideIndexingOAuth2AuthorizationService(delegate, redisTemplate, jwtUtils);
    }

    private OAuth2Authorization authWithAccessToken(String authId, String accessToken) {
        return OAuth2Authorization.withRegisteredClient(
                RegisteredClient.withId("client").clientId("internal")
                        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).build())
                .principalName("alice").id(authId)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .accessToken(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, accessToken,
                        Instant.now(), Instant.now().plusSeconds(3600)))
                .build();
    }

    @Test
    void save_addsAuthorizationIdToUserIndex() {
        OAuth2Authorization auth = authWithAccessToken("auth-1", "jwt.token.value");
        when(jwtUtils.getUserIdFromToken("jwt.token.value")).thenReturn(userId);
        @SuppressWarnings("unchecked")
        SetOperations<String, String> setOps = mock(SetOperations.class);
        when(redisTemplate.opsForSet()).thenReturn(setOps);

        service.save(auth);

        verify(delegate).save(auth);
        verify(setOps).add("oauth2:user:auths:" + userId, "auth-1");
    }

    @Test
    void save_withoutAccessToken_skipsIndexUpdate() {
        OAuth2Authorization auth = OAuth2Authorization.withRegisteredClient(
                RegisteredClient.withId("c").clientId("x")
                        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).build())
                .principalName("alice").id("auth-2")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .build();

        service.save(auth);

        verify(delegate).save(auth);
        verify(redisTemplate, never()).opsForSet();
    }

    @Test
    void remove_decrementsIndexAndDeletesEmptyKey() {
        OAuth2Authorization auth = authWithAccessToken("auth-1", "jwt.token.value");
        when(jwtUtils.getUserIdFromToken("jwt.token.value")).thenReturn(userId);
        @SuppressWarnings("unchecked")
        SetOperations<String, String> setOps = mock(SetOperations.class);
        when(redisTemplate.opsForSet()).thenReturn(setOps);
        when(setOps.size("oauth2:user:auths:" + userId)).thenReturn(0L);

        service.remove(auth);

        verify(delegate).remove(auth);
        verify(setOps).remove("oauth2:user:auths:" + userId, "auth-1");
        verify(setOps).size("oauth2:user:auths:" + userId);
        verify(redisTemplate).delete("oauth2:user:auths:" + userId);
    }

    @Test
    void findByToken_andFindById_passThrough() {
        OAuth2Authorization auth = authWithAccessToken("auth-1", "jwt.token.value");
        when(delegate.findByToken("t", org.springframework.security.oauth2.server.authorization.OAuth2TokenType.ACCESS_TOKEN))
                .thenReturn(auth);
        when(delegate.findById("auth-1")).thenReturn(auth);

        assertThat(service.findByToken("t", org.springframework.security.oauth2.server.authorization.OAuth2TokenType.ACCESS_TOKEN))
                .isSameAs(auth);
        assertThat(service.findById("auth-1")).isSameAs(auth);
    }
}