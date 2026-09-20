package com.frog.common.metrics;

import com.frog.common.tenant.TenantContext;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.UUID;

/**
 * Per-tenant + per-app metrics — Phase 1.10.
 *
 * <p>{@link BusinessMetrics} aggregates all counters/timers in a flat tag space;
 * operators cannot tell which tenant is consuming which resource. This component
 * adds a {@code tenant} (and where available, {@code app}) tag to the decision
 * pipeline so dashboards can split {@code authz_decision_total} and
 * {@code authz_decision_latency} by tenant.
 *
 * <p>Tags are derived from thread-local context ({@link TenantContext}); when
 * the context is not bound (e.g. async/scheduler threads, test harness),
 * a sentinel value of {@code _unknown} is used so cardinality stays bounded.
 *
 * @author Deng
 * @since 2026-09-20
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class TenantMetrics {

    private static final String UNKNOWN = "_unknown";
    private static final String AUTHZ_DECISION_TOTAL = "authz_decision_total";
    private static final String AUTHZ_DECISION_LATENCY = "authz_decision_latency";
    private static final String CACHE_ACCESS_TOTAL = "authz_cache_access_total";
    private static final String GRANT_CREATED_TOTAL = "authz_grant_created_total";

    private final MeterRegistry registry;

    /**
     * Record a single decision. Called after every {@code DecisionService.check}.
     *
     * @param effect     "allow" | "deny"
     * @param action     the requested action (e.g. {@code project.read}); may be null
     * @param latencyMs  evaluation latency in milliseconds
     */
    public void recordDecision(String effect, String action, long latencyMs) {
        try {
            String tenant = currentTenantTag();
            String app = currentAppTag();
            String normalizedAction = action == null ? UNKNOWN : action;

            Counter.builder(AUTHZ_DECISION_TOTAL)
                    .tag("tenant", tenant)
                    .tag("app", app)
                    .tag("effect", effect == null ? UNKNOWN : effect)
                    .tag("action", normalizedAction)
                    .register(registry)
                    .increment();

            Timer.builder(AUTHZ_DECISION_LATENCY)
                    .tag("tenant", tenant)
                    .tag("app", app)
                    .tag("effect", effect == null ? UNKNOWN : effect)
                    .register(registry)
                    .record(Duration.ofMillis(Math.max(latencyMs, 0L)));
        } catch (Exception e) {
            log.debug("TenantMetrics.recordDecision failed: {}", e.getMessage());
        }
    }

    /**
     * Record a cache hit. Tagged by tenant + cache name.
     */
    public void recordCacheHit(String cacheName) {
        recordCacheAccess(cacheName, true);
    }

    /**
     * Record a cache miss. Tagged by tenant + cache name.
     */
    public void recordCacheMiss(String cacheName) {
        recordCacheAccess(cacheName, false);
    }

    private void recordCacheAccess(String cacheName, boolean hit) {
        try {
            Counter.builder(CACHE_ACCESS_TOTAL)
                    .tag("tenant", currentTenantTag())
                    .tag("app", currentAppTag())
                    .tag("cache", cacheName == null ? UNKNOWN : cacheName)
                    .tag("hit", String.valueOf(hit))
                    .register(registry)
                    .increment();
        } catch (Exception e) {
            log.debug("TenantMetrics.recordCacheAccess failed: {}", e.getMessage());
        }
    }

    /**
     * Record a grant creation. Tagged by tenant + target type
     * ({@code role}, {@code permission}, {@code resource}).
     */
    public void recordGrantCreated(String targetType) {
        try {
            Counter.builder(GRANT_CREATED_TOTAL)
                    .tag("tenant", currentTenantTag())
                    .tag("app", currentAppTag())
                    .tag("target", targetType == null ? UNKNOWN : targetType)
                    .register(registry)
                    .increment();
        } catch (Exception e) {
            log.debug("TenantMetrics.recordGrantCreated failed: {}", e.getMessage());
        }
    }

    private String currentTenantTag() {
        UUID tid = TenantContext.get();
        return tid == null ? UNKNOWN : tid.toString();
    }

    private String currentAppTag() {
        // No AppContext exists in the codebase yet; fall back to the sentinel value.
        // When AppContext is introduced, replace this with AppContext.get().
        return UNKNOWN;
    }
}