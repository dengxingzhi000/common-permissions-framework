package com.frog.sdk.authz;

import org.jspecify.annotations.Nullable;

import java.time.Duration;

/**
 * Fluent builder for {@link AuthzClient}.
 *
 * <p>Defaults:
 * <ul>
 *   <li>{@link #cacheTtl}: 30 seconds</li>
 *   <li>{@link #cacheMaxSize}: 100,000 entries</li>
 *   <li>{@link #batchPath}: {@code /v1/decision/batch-check}</li>
 *   <li>{@link #checkPath}: {@code /v1/decision/check}</li>
 *   <li>{@link #permissionsPath}: {@code /v1/decision/permissions}</li>
 * </ul>
 *
 * @author Deng
 * @since 2026-09-20
 */
public class AuthzClientBuilder {

    @Nullable
    private String baseUrl;
    @Nullable
    private String tenantId;
    @Nullable
    private String appId;
    @Nullable
    private String bearerToken;

    private Duration cacheTtl = Duration.ofSeconds(30);
    private long cacheMaxSize = 100_000L;

    private String checkPath = "/v1/decision/check";
    private String batchPath = "/v1/decision/batch-check";
    private String permissionsPath = "/v1/decision/permissions";

    public AuthzClientBuilder baseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
        return this;
    }

    public AuthzClientBuilder tenantId(String tenantId) {
        this.tenantId = tenantId;
        return this;
    }

    public AuthzClientBuilder appId(String appId) {
        this.appId = appId;
        return this;
    }

    public AuthzClientBuilder bearerToken(String bearerToken) {
        this.bearerToken = bearerToken;
        return this;
    }

    public AuthzClientBuilder cacheTtl(Duration ttl) {
        this.cacheTtl = ttl;
        return this;
    }

    public AuthzClientBuilder cacheMaxSize(long maxSize) {
        this.cacheMaxSize = maxSize;
        return this;
    }

    public AuthzClientBuilder checkPath(String path) {
        this.checkPath = path;
        return this;
    }

    public AuthzClientBuilder batchPath(String path) {
        this.batchPath = path;
        return this;
    }

    public AuthzClientBuilder permissionsPath(String path) {
        this.permissionsPath = path;
        return this;
    }

    /**
     * Build a cached {@link AuthzClient} backed by an {@link HttpAuthzClient}.
     */
    public AuthzClient build() {
        HttpAuthzClient http = new HttpAuthzClient(
                requireNonNull(baseUrl, "baseUrl"),
                tenantId,
                appId,
                bearerToken,
                checkPath,
                batchPath,
                permissionsPath);
        return new LocalAuthzClient(http, cacheTtl, cacheMaxSize);
    }

    /**
     * Build a non-cached HTTP-only client. Useful in tests or where caching
     * is undesired (e.g. permission-editing tools).
     */
    public AuthzClient buildUncached() {
        return new HttpAuthzClient(
                requireNonNull(baseUrl, "baseUrl"),
                tenantId,
                appId,
                bearerToken,
                checkPath,
                batchPath,
                permissionsPath);
    }

    private static <T> T requireNonNull(@Nullable T value, String name) {
        if (value == null) {
            throw new IllegalArgumentException(name + " is required");
        }
        return value;
    }
}