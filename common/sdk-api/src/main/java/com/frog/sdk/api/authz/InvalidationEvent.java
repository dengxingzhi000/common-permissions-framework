package com.frog.sdk.api.authz;

import java.time.Instant;
import java.util.UUID;

/**
 * Push-based cache invalidation event.
 *
 * <p>Emitted by the authz service whenever a permission-bearing entity changes
 * (grant add/revoke, user-role link, role-permission link, user disable). The
 * SDK consumes these events and invalidates its local Caffeine cache so the next
 * {@code check()} call re-reads from the source of truth.
 *
 * <p>{@code subjectId}, {@code appId}, {@code tenantId} and {@code resourceType}
 * are nullable — only populated when the publisher knows enough to scope the
 * invalidation. For Phase 2 the SDK ignores the scope fields and invalidates
 * the whole cache (safe default); Phase 2.5 will key the cache per
 * {@code subjectId} so we can do partial eviction.
 *
 * @author Deng
 * @since 2026-09-20
 */
public record InvalidationEvent(
        InvalidationType type,
        String subjectType,
        UUID subjectId,
        UUID appId,
        UUID tenantId,
        String resourceType,
        Instant timestamp) {
}