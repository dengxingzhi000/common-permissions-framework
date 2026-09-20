package com.frog.common.security.decision;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/**
 * Authorization / authentication decision event captured for audit and observability.
 *
 * <p>Persistence to {@code sys_decision_log} is wired in a later wave; this record is the
 * canonical in-memory representation shared across the framework.
 */
public record DecisionEvent(
        UUID decisionId,
        String subjectType,
        UUID subjectId,
        String action,
        String resourceType,
        String resourceId,
        Map<String, Object> context,
        String effect,
        String reason,
        String policyVersion,
        String requestId,
        long latencyMs,
        String sourceModule,
        Instant timestamp
) {
    public static DecisionEvent allow(UUID subjectId, String action, long latencyMs,
                                       String sourceModule, String requestId) {
        return new DecisionEvent(UUID.randomUUID(), "user", subjectId, action,
                null, null, Map.of(), "allow", null, null, requestId, latencyMs, sourceModule,
                Instant.now());
    }

    public static DecisionEvent deny(UUID subjectId, String action, String reason,
                                      String sourceModule, String requestId,
                                      Map<String, Object> context) {
        Map<String, Object> ctx = context == null ? Map.of() : context;
        return new DecisionEvent(UUID.randomUUID(), "user", subjectId, action,
                null, null, ctx, "deny", reason, null, requestId, 0L, sourceModule,
                Instant.now());
    }
}