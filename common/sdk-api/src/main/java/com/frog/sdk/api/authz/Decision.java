package com.frog.sdk.api.authz;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.jspecify.annotations.Nullable;

import java.util.UUID;

/**
 * Authorization decision result — SDK DTO (Phase 2 starter).
 *
 * <p>Self-contained copy of {@code com.frog.system.decision.Decision}; the SDK
 * has no compile-time dependency on {@code system/service} so the DTOs are
 * duplicated. Field semantics match the server-side definition.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Decision {

    /** {@code "allow"} or {@code "deny"}. */
    private String effect;

    /** Human-readable reason for the decision. */
    @Nullable
    private String reason;

    /** Active policy version at evaluation time. */
    @Nullable
    private String policyVersion;

    /** Unique id for this evaluation, useful for audit tracing. */
    @Nullable
    private UUID decisionId;

    /** Evaluation latency in milliseconds (server-measured). */
    private long latencyMs;
}