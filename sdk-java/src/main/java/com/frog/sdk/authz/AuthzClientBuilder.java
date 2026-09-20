package com.frog.sdk.authz;

import com.frog.sdk.authz.invalidate.InvalidationSubscriber;
import com.frog.sdk.authz.invalidate.KafkaInvalidationSubscriber;
import com.frog.sdk.authz.invalidate.WebSocketInvalidationSubscriber;
import org.jspecify.annotations.Nullable;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

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
 *   <li>{@link #invalidationMode}: {@code "none"} (push invalidation disabled)</li>
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

    @Nullable
    private String invalidationMode;
    @Nullable
    private String kafkaBootstrapServers;
    @Nullable
    private String kafkaGroupId;
    @Nullable
    private String webSocketUrl;
    private final Map<String, String> webSocketAuthHeaders = new HashMap<>();

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
     * Enable push-based cache invalidation.
     *
     * @param mode {@code "kafka"} (consume {@code authz.invalidations} topic),
     *             {@code "websocket"} (open {@code /v1/events/permissions} socket),
     *             or {@code "none"} / {@code null} (no subscriber — TTL only).
     */
    public AuthzClientBuilder invalidationMode(String mode) {
        this.invalidationMode = mode;
        return this;
    }

    public AuthzClientBuilder kafkaBootstrapServers(String bootstrapServers) {
        this.kafkaBootstrapServers = bootstrapServers;
        return this;
    }

    public AuthzClientBuilder kafkaGroupId(String groupId) {
        this.kafkaGroupId = groupId;
        return this;
    }

    public AuthzClientBuilder webSocketUrl(String url) {
        this.webSocketUrl = url;
        return this;
    }

    public AuthzClientBuilder webSocketAuthHeader(String name, String value) {
        if (name != null && value != null) {
            this.webSocketAuthHeaders.put(name, value);
        }
        return this;
    }

    /**
     * Build a cached {@link AuthzClient} backed by an {@link HttpAuthzClient}.
     * If an {@code invalidationMode} was configured a matching subscriber is
     * created and registered with the local client. The subscriber is also
     * returned so the caller can {@code start()} / {@code stop()} it.
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
        LocalAuthzClient local = new LocalAuthzClient(http, cacheTtl, cacheMaxSize);

        InvalidationSubscriber subscriber = createSubscriber(local);
        if (subscriber instanceof KafkaInvalidationSubscriber kafka) {
            kafka.start();
        } else if (subscriber instanceof WebSocketInvalidationSubscriber ws) {
            ws.start();
        }
        return local;
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

    @Nullable
    private InvalidationSubscriber createSubscriber(LocalAuthzClient local) {
        if (invalidationMode == null || invalidationMode.isBlank()
                || "none".equalsIgnoreCase(invalidationMode)) {
            return null;
        }
        if ("kafka".equalsIgnoreCase(invalidationMode)) {
            return new KafkaInvalidationSubscriber(
                    requireNonNull(kafkaBootstrapServers, "kafkaBootstrapServers"),
                    kafkaGroupId,
                    appId,
                    local);
        }
        if ("websocket".equalsIgnoreCase(invalidationMode)) {
            Map<String, String> headers = new HashMap<>(webSocketAuthHeaders);
            if (bearerToken != null && !bearerToken.isBlank() && !headers.containsKey("Authorization")) {
                headers.put("Authorization", "Bearer " + bearerToken);
            }
            return new WebSocketInvalidationSubscriber(
                    requireNonNull(webSocketUrl, "webSocketUrl"),
                    headers,
                    local);
        }
        throw new IllegalArgumentException(
                "Unknown invalidationMode: " + invalidationMode + " (expected: kafka | websocket | none)");
    }

    private static <T> T requireNonNull(@Nullable T value, String name) {
        if (value == null) {
            throw new IllegalArgumentException(name + " is required");
        }
        return value;
    }
}