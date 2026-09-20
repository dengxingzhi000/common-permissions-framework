package com.frog.sdk.api.authz;

import java.util.Set;

/**
 * Listener for push-based cache invalidation events.
 *
 * <p>Implementations are registered with a {@code LocalAuthzClient} via
 * {@code registerInvalidationSubscriber}. When a new {@link InvalidationEvent}
 * arrives the client iterates registered subscribers and dispatches each one.
 *
 * <p>{@link #patterns()} is metadata about what the subscriber listens on
 * (Kafka topic, WebSocket path, etc). The local client does not currently
 * filter by pattern; filtering is the responsibility of the transport layer.
 *
 * @author Deng
 * @since 2026-09-20
 */
public interface InvalidationSubscriber {

    /**
     * Topics or URI patterns this subscriber receives events from.
     * Returned set may be empty if the subscriber doesn't care about
     * external bookkeeping.
     */
    Set<String> patterns();

    /**
     * Apply the incoming invalidation event.
     *
     * <p>Implementations should be thread-safe; multiple subscribers may be
     * invoked concurrently from network threads (Kafka consumer, WebSocket
     * I/O). Exceptions are caught and logged by the dispatcher.
     */
    void onInvalidation(InvalidationEvent event);
}