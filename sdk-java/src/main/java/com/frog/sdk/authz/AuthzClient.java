package com.frog.sdk.authz;

import org.jspecify.annotations.Nullable;

import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * Public client API for the authorization service.
 *
 * <p>Implementations:
 * <ul>
 *   <li>{@link HttpAuthzClient} — Spring {@code RestClient} transport</li>
 *   <li>{@link LocalAuthzClient} — wraps an {@link HttpAuthzClient} with a
 *       Caffeine local cache for sub-millisecond hot-path lookups</li>
 * </ul>
 *
 * <p>Use {@link AuthzClientBuilder} to construct a ready-to-use client.
 *
 * @author Deng
 * @since 2026-09-20
 */
public interface AuthzClient {

    /**
     * Single decision. Result is cached locally for {@link AuthzClientBuilder#cacheTtl}
     * when going through a caching wrapper.
     */
    Decision check(CheckRequest req);

    /**
     * Bulk check. Maximum 100 requests per call; results are NOT cached.
     */
    List<Decision> batchCheck(List<CheckRequest> reqs);

    /**
     * Force-refresh the local cache. No-op for non-caching implementations.
     */
    void invalidateCache();

    /**
     * Get the effective permission set for a subject — used for SDK hydration
     * (preload local caches when a user logs in).
     *
     * @return unmodifiable set; never null
     */
    Set<String> getEffectivePermissions(String subjectType, UUID subjectId);
}