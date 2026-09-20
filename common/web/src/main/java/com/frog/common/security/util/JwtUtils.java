package com.frog.common.security.util;

import com.frog.common.exception.UnauthorizedException;
import com.frog.common.security.properties.JwtProperties;
import com.frog.common.util.UUIDv7Util;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;

/**
 * Jwt 工具类
 *
 * @author Deng
 * createData 2025/10/11 11:08
 * @version 1.0
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class JwtUtils {
    private final JwtProperties jwtProperties;
    private final RedisTemplate<String, Object> redisTemplate;

    private SecretKey signingKey;

    private static final String TOKEN_BLACKLIST_PREFIX = "jwt:blacklist:";
    private static final String USER_TOKENS_HASH = "jwt:user:tokens:";  // Hash key per user
    private static final String TOKEN_FINGERPRINT_PREFIX = "jwt:fingerprint:";
    private static final String REFRESH_LOCK_PREFIX = "jwt:refresh:lock:";

    @PostConstruct
    public void init() {
        String secret = jwtProperties.getSecret();
        if (secret == null || secret.isEmpty()) {
            throw new IllegalStateException("jwt.secret must be configured via Nacos/ENV (JWT_SECRET)");
        }

        byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
        if (keyBytes.length < 64) {
            throw new IllegalArgumentException(
                    "JWT secret must be at least 512 bits, current: " + keyBytes.length);
        }
        this.signingKey = Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * 生成访问令牌
     */
    public String generateAccessToken(UUID userId, String username,
                                      Set<String> roles, Set<String> permissions,
                                      String deviceId, String ipAddress) {
        String jti = UUID.randomUUID().toString();
        String tokenType = "access";

        Map<String, Object> claims = buildClaims(
                userId, username, roles, permissions,
                tokenType, deviceId, ipAddress, jti
        );

        String token = createToken(claims, userId.toString(),
                jwtProperties.getExpiration());

        // 存储 Token元数据
        storeTokenMetadata(userId, deviceId, token, jti, ipAddress,
                jwtProperties.getExpiration());

        return token;
    }

    /**
     * 生成访问令牌（可指定 AMR）
     */
    public String generateAccessToken(UUID userId, String username,
                                      Set<String> roles, Set<String> permissions,
                                      String deviceId, String ipAddress,
                                      List<String> amr) {
        String jti = UUIDv7Util.generate().toString();
        String tokenType = "access";

        Map<String, Object> claims = buildClaims(
                userId, username, roles, permissions,
                tokenType, deviceId, ipAddress, jti
        );
        claims.put("amr", amr);

        String token = createToken(claims, userId.toString(),
                jwtProperties.getExpiration());

        // 存储 Token元数据
        storeTokenMetadata(userId, deviceId, token, jti, ipAddress,
                jwtProperties.getExpiration());

        return token;
    }

    /**
     * 生成刷新令牌
     */
    public String generateRefreshToken(UUID userId, String username, String deviceId) {
        String jti = UUIDv7Util.generate().toString();

        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userId);
        claims.put("username", username);
        claims.put("tokenType", "refresh");
        claims.put("deviceId", deviceId);
        claims.put("jti", jti);

        return createToken(claims, userId.toString(),
                jwtProperties.getRefreshExpiration());
    }

    /**
     * 验证Token - 拆分为多个小方法
     */
    public boolean validateToken(String token, String currentIp, String currentDeviceId) {
        try {
            // 1. 解析Token
            Claims claims = parseToken(token);

            // 2. 基础验证
            if (!validateBasicClaims(claims)) {
                return false;
            }

            // 3. 黑名单检查
            if (isTokenBlacklisted(getJti(claims))) {
                log.warn("Token is blacklisted");
                return false;
            }

            // 4. 设备验证
            if (!validateDevice(claims, currentDeviceId)) {
                return false;
            }

            // 5. IP验证（可配置）
            if (jwtProperties.isStrictIpCheck() &&
                    !validateIpAddress(claims, currentIp)) {
                return false;
            }

            // 6. 指纹验证
            return validateFingerprint(claims);
        } catch (ExpiredJwtException e) {
            log.debug("Token expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.error("Token unsupported: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            log.error("Token malformed: {}", e.getMessage());
        } catch (Exception e) {
            log.error("Token validation failed: {}", e.getMessage());
        }
        return false;
    }

    /**
     * 检查刷新令牌是否无效
     *
     * @param token 刷新令牌
     * @return true 如果令牌无效，false 如果令牌有效
     */
    public boolean isRefreshTokenInvalid(String token) {
        try {
            Claims claims = parseToken(token);
            String tokenType = (String) claims.get("tokenType");
            Date expiration = claims.getExpiration();
            return !"refresh".equals(tokenType) || !expiration.after(new Date());
        } catch (Exception e) {
            return true;
        }
    }

    /**
     * 刷新Token - 添加并发控制
     */
    public String refreshToken(String refreshToken, Set<String> roles,
                               Set<String> permissions,
                               String deviceId, String ipAddress) {
        if (isRefreshTokenInvalid(refreshToken)) {
            throw new UnauthorizedException("Invalid refresh token");
        }

        UUID userId = getUserIdFromToken(refreshToken);
        String lockKey = REFRESH_LOCK_PREFIX + userId;

        try {
            // 分布式锁，防止并发刷新
            Boolean acquired = redisTemplate.opsForValue()
                    .setIfAbsent(lockKey, "1", Duration.ofSeconds(5));

            if (Boolean.FALSE.equals(acquired)) {
                throw new UnauthorizedException("Token refresh in progress");
            }

            String username = getUsernameFromToken(refreshToken);

            // 撤销旧的访问令牌
            revokeUserAccessTokens(userId, deviceId);

            // 生成新的访问令牌
            return generateAccessToken(userId, username, roles, permissions,
                    deviceId, ipAddress);
        } finally {
            redisTemplate.delete(lockKey);
        }
    }

    /**
     * 撤销 Token
     */
    public void revokeToken(String token, String reason) {
        try {
            Claims claims = parseToken(token);
            String jti = getJti(claims);
            Date expiration = claims.getExpiration();
            UUID userId = UUID.fromString(claims.getSubject());
            String deviceId = (String) claims.get("deviceId");

            long ttl = expiration.getTime() - System.currentTimeMillis();
            if (ttl > 0) {
                // 加入黑名单
                addToBlacklist(jti, userId, reason, ttl);

                // 删除 Token缓存
                deleteTokenCache(userId, deviceId);

                // 删除指纹
                deleteFingerprint(jti);

                log.info("Token revoked: userId={}, reason={}", userId, reason);
            }
        } catch (Exception e) {
            log.error("Failed to revoke token: {}", e.getMessage());
        }
    }

    /**
     * Revokes all tokens for a given user across all devices.
     * PERFORMANCE: Uses Redis Hash instead of KEYS command for O(1) lookup.
     * Each user has a hash: jwt:user:tokens:{userId} -> { deviceId: token }
     */
    public void revokeAllUserTokens(UUID userId) {
        String hashKey = USER_TOKENS_HASH + userId;

        // Get all device tokens for this user (O(N) where N = devices per user, typically < 10)
        Map<Object, Object> deviceTokens = redisTemplate.opsForHash().entries(hashKey);

        if (deviceTokens != null && !deviceTokens.isEmpty()) {
            log.info("Revoking {} token(s) for user {}", deviceTokens.size(), userId);

            for (Map.Entry<Object, Object> entry : deviceTokens.entrySet()) {
                String deviceId = (String) entry.getKey();
                String token = (String) entry.getValue();

                if (token != null) {
                    try {
                        revokeToken(token, "Admin forced logout");
                        log.debug("Revoked token for user {} device {}", userId, deviceId);
                    } catch (Exception e) {
                        log.error("Failed to revoke token for user {} device {}: {}",
                                 userId, deviceId, e.getMessage());
                    }
                }
            }

            // Clean up the hash
            redisTemplate.delete(hashKey);
        } else {
            log.debug("No active tokens found for user {}", userId);
        }
    }

    /**
     * 从 Token中提取角色
     */
    @SuppressWarnings("unchecked")
    public Set<String> getRolesFromToken(String token) {
        Claims claims = parseToken(token);
        if (claims == null) return Collections.emptySet();
        List<String> roleList = (List<String>) claims.get("roles");
        return roleList != null ? new HashSet<>(roleList) : Collections.emptySet();
    }

    /**
     * 从 Token中提取权限
     */
    @SuppressWarnings("unchecked")
    public Set<String> getPermissionsFromToken(String token) {
        Claims claims = parseToken(token);
        if (claims == null) return Collections.emptySet();
        List<String> permList = (List<String>) claims.get("permissions");
        return permList != null ? new HashSet<>(permList) : Collections.emptySet();
    }


    public UUID getUserIdFromToken(String token) {
        Claims claims = parseToken(token);
        Object userId = claims.get("userId");
        return userId instanceof UUID ? (UUID) userId :
                UUID.fromString(userId.toString());
    }

    public String getUsernameFromToken(String token) {
        Claims claims = parseToken(token);
        return (String) claims.get("username");
    }

    /**
     * 从Token中提取 AMR（认证方法引用）
     */
    @SuppressWarnings("unchecked")
    public java.util.Set<String> getAmrFromToken(String token) {
        Claims claims = parseToken(token);
        if (claims == null) return java.util.Collections.emptySet();
        java.util.List<String> amr = (java.util.List<String>) claims.get("amr");
        return amr != null ? new java.util.HashSet<>(amr) : java.util.Collections.emptySet();
    }

    // ==================== 私有方法 ====================

    private Claims parseToken(String token) {
        return Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private String createToken(Map<String, Object> claims, String subject, long expiration) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expiration);

        return Jwts.builder()
                .claims(claims)
                .subject(subject)
                .issuedAt(now)
                .expiration(expiryDate)
                .issuer(jwtProperties.getIssuer())
                .signWith(signingKey, Jwts.SIG.HS512)
                .compact();
    }

    private Map<String, Object> buildClaims(UUID userId, String username,
                                            Set<String> roles, Set<String> permissions,
                                            String tokenType, String deviceId,
                                            String ipAddress, String jti) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userId);
        claims.put("username", username);
        claims.put("roles", roles);
        claims.put("permissions", permissions);
        claims.put("tokenType", tokenType);
        claims.put("deviceId", deviceId);
        claims.put("ipAddress", ipAddress);
        claims.put("jti", jti);
        return claims;
    }

    private boolean validateBasicClaims(Claims claims) {
        String tokenType = (String) claims.get("tokenType");
        Date expiration = claims.getExpiration();

        if (!"access".equals(tokenType)) {
            log.warn("Invalid token type: {}", tokenType);
            return false;
        }

        if (expiration.before(new Date())) {
            log.debug("Token expired");
            return false;
        }

        return true;
    }

    private boolean validateDevice(Claims claims, String currentDeviceId) {
        String tokenDeviceId = (String) claims.get("deviceId");
        if (tokenDeviceId != null && !tokenDeviceId.equals(currentDeviceId)) {
            log.warn("Device mismatch: expected={}, actual={}",
                    tokenDeviceId, currentDeviceId);
            return false;
        }
        return true;
    }

    private boolean validateIpAddress(Claims claims, String currentIp) {
        String tokenIp = (String) claims.get("ipAddress");
        if (tokenIp != null && !tokenIp.equals(currentIp)) {
            log.warn("IP changed: {} -> {}", tokenIp, currentIp);
            return false;
        }
        return true;
    }

    private boolean validateFingerprint(Claims claims) {
        String jti = getJti(claims);
        String fingerprintKey = TOKEN_FINGERPRINT_PREFIX + jti;
        return redisTemplate.hasKey(fingerprintKey);
    }

    /**
     * Stores token metadata in Redis using Hash structure for efficient lookups.
     * PERFORMANCE OPTIMIZATION:
     * - User tokens stored in Hash: jwt:user:tokens:{userId} -> {deviceId: token}
     * - Allows O(1) lookup and O(N) revocation where N = devices (typically < 10)
     * - Avoids O(N) KEYS scan where N = total tokens in Redis
     */
    private void storeTokenMetadata(UUID userId, String deviceId, String token,
                                    String jti, String ipAddress, long ttl) {
        // Store token in user's Hash (deviceId -> token mapping)
        String userTokensHash = USER_TOKENS_HASH + userId;
        redisTemplate.opsForHash().put(userTokensHash, deviceId, token);
        redisTemplate.expire(userTokensHash, Duration.ofMillis(ttl));

        // Store token fingerprint (for validation)
        String fingerprintKey = TOKEN_FINGERPRINT_PREFIX + jti;
        Map<String, Object> fingerprint = new HashMap<>();
        fingerprint.put("userId", userId.toString());
        fingerprint.put("deviceId", deviceId);
        fingerprint.put("ipAddress", ipAddress);
        fingerprint.put("issueTime", System.currentTimeMillis());

        redisTemplate.opsForHash().putAll(fingerprintKey, fingerprint);
        redisTemplate.expire(fingerprintKey, Duration.ofMillis(ttl));
    }

    private void addToBlacklist(String jti, UUID userId, String reason, long ttl) {
        String blacklistKey = TOKEN_BLACKLIST_PREFIX + jti;
        Map<String, Object> info = new HashMap<>();
        info.put("revokeTime", System.currentTimeMillis());
        info.put("reason", reason);
        info.put("userId", userId.toString());

        redisTemplate.opsForHash().putAll(blacklistKey, info);
        redisTemplate.expire(blacklistKey, Duration.ofMillis(ttl));
    }

    /**
     * Deletes token cache for a specific user device.
     * Uses Hash deletion (HDEL) instead of key deletion.
     */
    private void deleteTokenCache(UUID userId, String deviceId) {
        String userTokensHash = USER_TOKENS_HASH + userId;
        redisTemplate.opsForHash().delete(userTokensHash, deviceId);
        log.debug("Deleted token cache for user {} device {}", userId, deviceId);
    }

    private void deleteFingerprint(String jti) {
        String fingerprintKey = TOKEN_FINGERPRINT_PREFIX + jti;
        redisTemplate.delete(fingerprintKey);
        log.debug("Deleted fingerprint for jti {}", jti);
    }

    private boolean isTokenBlacklisted(String jti) {
        String blacklistKey = TOKEN_BLACKLIST_PREFIX + jti;
        return Boolean.TRUE.equals(redisTemplate.hasKey(blacklistKey));
    }

    /**
     * Revokes access tokens for a specific user device.
     * Uses Hash lookup (HGET) instead of key lookup.
     */
    private void revokeUserAccessTokens(UUID userId, String deviceId) {
        String userTokensHash = USER_TOKENS_HASH + userId;
        String oldToken = (String) redisTemplate.opsForHash().get(userTokensHash, deviceId);
        if (oldToken != null) {
            revokeToken(oldToken, "Token refreshed");
            log.debug("Revoked old token for user {} device {}", userId, deviceId);
        }
    }

    public String getDeviceIdFromToken(String token) {
        Claims claims = parseToken(token);
        return (String) claims.get("deviceId");
    }

    /**
     * Returns the JWT {@code iat} (issued-at) claim as a Unix epoch second.
     * Used by the revocation checker to compare a token's age against the
     * current revocation version counter.
     */
    public long getIssuedAtFromToken(String token) {
        Claims claims = parseToken(token);
        Date issuedAt = claims.getIssuedAt();
        return issuedAt == null ? 0L : issuedAt.toInstant().getEpochSecond();
    }

    private String getJti(Claims claims) {
        return (String) claims.get("jti");
    }
}
