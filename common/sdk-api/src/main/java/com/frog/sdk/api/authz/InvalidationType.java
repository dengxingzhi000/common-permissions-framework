package com.frog.sdk.api.authz;

/**
 * Invalidation scope — which cache entries an {@link InvalidationEvent}
 * is allowed to evict.
 *
 * @author Deng
 * @since 2026-09-21
 */
public enum InvalidationType {
    /** A subject's own state changed (e.g. user disabled). */
    SUBJECT,
    /** A direct grant was added or revoked. */
    GRANT,
    /** A user↔role link was added or removed. */
    ROLE,
    /** A role↔permission link was added or removed. */
    PERMISSION,
    /** Nuclear option — invalidate every cache entry. */
    ALL
}
