package com.frog.sdk.api.authz;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.jspecify.annotations.Nullable;

import java.util.Map;
import java.util.UUID;

/**
 * Authorization check request — SDK DTO (Phase 2 starter).
 *
 * <p>Self-contained copy of {@code com.frog.system.decision.CheckRequest}; the SDK
 * has no compile-time dependency on {@code system/service} so the DTOs are
 * duplicated. Field semantics match the server-side definition.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CheckRequest {

    /** Subject type, e.g. {@code user} / {@code service_account}. */
    private String subjectType;

    /** Subject identifier. */
    private UUID subjectId;

    /** Requested action (e.g. {@code project.read}); nullable. */
    @Nullable
    private String action;

    /** Optional resource type (for resource-scoped checks). */
    @Nullable
    private String resourceType;

    /** Optional resource instance id. */
    @Nullable
    private String resourceId;

    /** Optional ABAC context (IP, dept, time-of-day, …). */
    @Nullable
    private Map<String, Object> context;
}