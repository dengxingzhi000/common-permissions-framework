package com.frog.common.security.revocation;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.HashOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Redis-backed version counter for JWT revocation.
 *
 * <p>Each user has an entry storing the current revocation version per device
 * (and a synthetic {@code _global} key for whole-user revocation). When a token
 * is presented, the caller compares the token's {@code iat} to the current
 * version for the device — if {@code iat < version}, the token was issued
 * before the revocation event and must be rejected.
 *
 * <p>This service does NOT track individual JWTs; it stores a monotonic counter
 * keyed by {@code jwt:revoked_ver:{userId}} with hash fields being device ids.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class UserRevocationService {

    private static final String KEY_PREFIX = "jwt:revoked_ver:";
    private static final String GLOBAL = "_global";

    private final RedisTemplate<String, Object> redisTemplate;

    public long revokeUser(UUID userId, String reason) {
        long v = incrementVersion(userId, GLOBAL);
        log.info("User revocation issued userId={} version={} reason={}", userId, v, reason);
        return v;
    }

    public long revokeUserDevice(UUID userId, String deviceId, String reason) {
        long v = incrementVersion(userId, deviceId);
        log.info("User-device revocation issued userId={} deviceId={} version={} reason={}",
                userId, deviceId, v, reason);
        return v;
    }

    public long getCurrentVersion(UUID userId, String deviceId) {
        HashOperations<String, Object, Object> ops = redisTemplate.opsForHash();
        Object v = ops.get(KEY_PREFIX + userId, deviceId);
        return v == null ? 0L : Long.parseLong(v.toString());
    }

    public Map<String, Long> getAllVersions(UUID userId) {
        HashOperations<String, Object, Object> ops = redisTemplate.opsForHash();
        Map<Object, Object> raw = ops.entries(KEY_PREFIX + userId);
        Map<String, Long> result = new HashMap<>();
        raw.forEach((k, v) -> result.put(k.toString(), Long.parseLong(v.toString())));
        return result;
    }

    private long incrementVersion(UUID userId, String key) {
        return redisTemplate.opsForHash().increment(KEY_PREFIX + userId, key, 1L);
    }
}