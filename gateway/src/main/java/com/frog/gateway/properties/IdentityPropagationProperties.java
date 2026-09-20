package com.frog.gateway.properties;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration for propagating authenticated identity to downstream services.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "security.identity")
public class IdentityPropagationProperties {

    /**
     * Enable downstream identity propagation.
     */
    private boolean enabled = true;

    /**
     * Header carrying the signed identity payload.
     */
    private String identityTokenHeader = "X-Identity-Token";

    private String userIdHeader = "X-User-Id";
    private String usernameHeader = "X-User-Name";
    private String deviceIdHeader = "X-Device-Id";
    private String rolesHeader = "X-User-Roles";
    /**
     * Phase 1.5 — 租户 ID header 名称,默认值 {@code X-Tenant-Id}。
     */
    private String tenantIdHeader = "X-Tenant-Id";
    /**
     * Phase 1.5 — 应用 ID header 名称,默认值 {@code X-App-Id}。
     */
    private String appIdHeader = "X-App-Id";

    /**
     * Claims names read from the JWT.
     */
    private String userIdClaim = "userId";
    private String usernameClaim = "username";
    private String deviceIdClaim = "deviceId";
    /**
     * Phase 1.5 — JWT 中租户 ID 的 claim 名,默认 {@code tenant_id}。
     */
    private String tenantIdClaim = "tenant_id";
    /**
     * Phase 1.5 — JWT 中应用 ID 的 claim 名,默认 {@code app_id}。
     */
    private String appIdClaim = "app_id";

    /**
     * Shared secret for signing identity headers. Should be rotated regularly.
     * MUST be set via environment variable IDENTITY_SIGNATURE_SECRET in production.
     */
    private String signatureSecret;
}
