package com.frog.common.security.revocation;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.HashOperations;
import org.springframework.data.redis.core.RedisTemplate;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class UserRevocationServiceTest {

    @SuppressWarnings("unchecked")
    RedisTemplate<String, Object> redis = mock(RedisTemplate.class);
    @SuppressWarnings("unchecked")
    HashOperations<String, Object, Object> hashOps = mock(HashOperations.class);
    UserRevocationService service;

    @BeforeEach
    void setup() {
        when(redis.opsForHash()).thenReturn(hashOps);
        service = new UserRevocationService(redis);
    }

    @Test
    void revokeUser_incrementsVersion() {
        UUID userId = UUID.randomUUID();
        when(hashOps.increment(eq("jwt:revoked_ver:" + userId), eq("_global"), anyLong()))
                .thenReturn(7L);
        long v = service.revokeUser(userId, "test");
        assertThat(v).isEqualTo(7L);
    }

    @Test
    void getCurrentVersion_returnsMap() {
        UUID userId = UUID.randomUUID();
        Map<Object, Object> backing = new HashMap<>();
        backing.put("dev-1", "5");
        backing.put("dev-2", "3");
        when(hashOps.entries("jwt:revoked_ver:" + userId)).thenReturn(backing);
        Map<String, Long> v = service.getAllVersions(userId);
        assertThat(v).containsEntry("dev-1", 5L).containsEntry("dev-2", 3L);
    }
}