package com.frog.sdk.authz;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.Nullable;

import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * Local cache wrapper around an {@link HttpAuthzClient}.
 *
 * <p>Caching policy:
 * <ul>
 *   <li>Keyed on {@code (subjectType, subjectId, action, resourceType, resourceId, context)}</li>
 *   <li>{@code expireAfterWrite(ttl)} — no read-through refresh</li>
 *   <li>{@code maximumSize(maxSize)} with W-TinyLFU eviction</li>
 * </ul>
 *
 * <p>{@link #batchCheck(List)} delegates directly to the underlying HTTP client
 * (cache pollution from bulk requests would dilute the hot path).
 *
 * @author Deng
 * @since 2026-09-20
 */
@Slf4j
public class LocalAuthzClient implements AuthzClient {

    private final HttpAuthzClient http;
    private final Cache<String, Decision> cache;

    public LocalAuthzClient(HttpAuthzClient http, Duration ttl, long maxSize) {
        Objects.requireNonNull(http, "http");
        Objects.requireNonNull(ttl, "ttl");
        if (maxSize <= 0) {
            throw new IllegalArgumentException("maxSize must be positive");
        }
        this.http = http;
        this.cache = Caffeine.newBuilder()
                .expireAfterWrite(ttl)
                .maximumSize(maxSize)
                .recordStats()
                .build();
    }

    @Override
    public Decision check(CheckRequest req) {
        if (req == null) {
            throw new IllegalArgumentException("CheckRequest must not be null");
        }
        String key = cacheKey(req);
        Decision cached = cache.getIfPresent(key);
        if (cached != null) {
            return cached;
        }
        Decision fresh = http.check(req);
        if (fresh != null) {
            cache.put(key, fresh);
        }
        return fresh;
    }

    @Override
    public List<Decision> batchCheck(List<CheckRequest> reqs) {
        return http.batchCheck(reqs);
    }

    @Override
    public void invalidateCache() {
        cache.invalidateAll();
        http.invalidateCache();
    }

    @Override
    public Set<String> getEffectivePermissions(String subjectType, UUID subjectId) {
        return http.getEffectivePermissions(subjectType, subjectId);
    }

    /**
     * Cache statistics (hit count, miss count, …). Useful for observability
     * tests; production code should rely on the metrics emitted by the platform.
     */
    public com.github.benmanes.caffeine.cache.stats.CacheStats cacheStats() {
        return cache.stats();
    }

    public long cacheSize() {
        return cache.estimatedSize();
    }

    static String cacheKey(CheckRequest req) {
        StringBuilder sb = new StringBuilder(128);
        sb.append(safe(req.getSubjectType())).append('|');
        sb.append(safe(req.getSubjectId())).append('|');
        sb.append(safe(req.getAction())).append('|');
        sb.append(safe(req.getResourceType())).append('|');
        sb.append(safe(req.getResourceId())).append('|');
        sb.append(contextFingerprint(req.getContext()));
        return sb.toString();
    }

    private static String safe(@Nullable Object value) {
        return value == null ? "" : value.toString();
    }

    /**
     * Compact, stable representation of the ABAC context. We deliberately
     * avoid Java serialization (slow + insecure) and instead concatenate
     * keys/values with a separator that won't appear in practice.
     */
    private static String contextFingerprint(@Nullable java.util.Map<String, Object> ctx) {
        if (ctx == null || ctx.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        ctx.entrySet().stream()
                .sorted(java.util.Map.Entry.comparingByKey())
                .forEach(e -> sb.append(e.getKey()).append('=').append(e.getValue()).append(';'));
        return sb.toString();
    }
}