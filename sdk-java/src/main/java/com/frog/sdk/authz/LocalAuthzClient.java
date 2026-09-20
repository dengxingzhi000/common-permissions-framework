package com.frog.sdk.authz;

import com.frog.sdk.authz.invalidate.InvalidationEvent;
import com.frog.sdk.authz.invalidate.InvalidationSubscriber;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.Nullable;

import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

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
 * <p>Push-based invalidation (Phase 2):
 * <ul>
 *   <li>{@link #registerInvalidationSubscriber(InvalidationSubscriber)} lets a
 *       Kafka / WebSocket subscriber attach to this client.</li>
 *   <li>{@link #dispatchInvalidation(InvalidationEvent)} fans the event out to
 *       every registered subscriber. Transport-layer filtering already happened
 *       upstream; the dispatcher is responsible for fan-out and exception
 *       isolation only.</li>
 * </ul>
 *
 * @author Deng
 * @since 2026-09-20
 */
@Slf4j
public class LocalAuthzClient implements AuthzClient {

    private final HttpAuthzClient http;
    private final Cache<String, Decision> cache;
    private final List<InvalidationSubscriber> subscribers = new CopyOnWriteArrayList<>();

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
     * Register a subscriber that will receive every event dispatched by
     * {@link #dispatchInvalidation(InvalidationEvent)}. Typically wired by
     * {@code KafkaInvalidationSubscriber} / {@code WebSocketInvalidationSubscriber}
     * constructors — direct callers are usually tests or admin tooling.
     */
    public void registerInvalidationSubscriber(InvalidationSubscriber subscriber) {
        if (subscriber == null) {
            throw new IllegalArgumentException("subscriber must not be null");
        }
        subscribers.add(subscriber);
        log.debug("Registered invalidation subscriber: {} (total={})",
                subscriber.getClass().getSimpleName(), subscribers.size());
    }

    /**
     * Fan out an invalidation event to every registered subscriber. Used by
     * the network subscribers when they receive an event and by callers that
     * want to propagate a programmatically-constructed event.
     *
     * <p>Exceptions thrown by a subscriber are caught and logged so a misbehaving
     * observer can't poison the dispatch loop.
     */
    protected void dispatchInvalidation(InvalidationEvent event) {
        if (event == null) {
            return;
        }
        for (InvalidationSubscriber subscriber : subscribers) {
            try {
                subscriber.onInvalidation(event);
            } catch (RuntimeException ex) {
                log.warn("Invalidation subscriber {} failed for event type={}: {}",
                        subscriber.getClass().getSimpleName(), event.type(), ex.getMessage());
            }
        }
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