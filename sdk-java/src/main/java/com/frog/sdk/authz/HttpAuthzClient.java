package com.frog.sdk.authz;

import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;

import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * Spring {@link RestClient}-backed implementation of {@link AuthzClient}.
 *
 * <p>Constructed internally by {@link AuthzClientBuilder}; do not instantiate
 * directly from application code unless you need fine-grained transport control.
 *
 * <p>Request signing is delegated to a configurable bearer token plus
 * {@code X-Tenant-Id} / {@code X-App-Id} headers — the platform's identity
 * layer validates them upstream.
 *
 * @author Deng
 * @since 2026-09-20
 */
public class HttpAuthzClient implements AuthzClient {

    private final RestClient restClient;
    private final String checkPath;
    private final String batchPath;
    private final String permissionsPath;
    @Nullable
    private final String tenantId;
    @Nullable
    private final String appId;
    @Nullable
    private final String bearerToken;

    public HttpAuthzClient(String baseUrl,
                           @Nullable String tenantId,
                           @Nullable String appId,
                           @Nullable String bearerToken,
                           String checkPath,
                           String batchPath,
                           String permissionsPath) {
        this(RestClient.builder()
                        .baseUrl(baseUrl)
                        .defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                        .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                        .build(),
                tenantId,
                appId,
                bearerToken,
                checkPath,
                batchPath,
                permissionsPath);
    }

    /**
     * Test-friendly constructor that accepts a pre-built {@link RestClient}.
     * Useful with {@code MockRestServiceServer.bindTo(restClientBuilder)}.
     */
    HttpAuthzClient(RestClient restClient,
                    @Nullable String tenantId,
                    @Nullable String appId,
                    @Nullable String bearerToken,
                    String checkPath,
                    String batchPath,
                    String permissionsPath) {
        this.restClient = restClient;
        this.tenantId = tenantId;
        this.appId = appId;
        this.bearerToken = bearerToken;
        this.checkPath = checkPath;
        this.batchPath = batchPath;
        this.permissionsPath = permissionsPath;
    }

    @Override
    public Decision check(CheckRequest req) {
        if (req == null) {
            throw new IllegalArgumentException("CheckRequest must not be null");
        }
        return restClient.post()
                .uri(checkPath)
                .headers(this::applyCommonHeaders)
                .body(req)
                .retrieve()
                .body(Decision.class);
    }

    @Override
    public List<Decision> batchCheck(List<CheckRequest> reqs) {
        if (reqs == null) {
            throw new IllegalArgumentException("reqs must not be null");
        }
        if (reqs.size() > 100) {
            throw new IllegalArgumentException("batchCheck accepts at most 100 requests per call");
        }
        Decision[] arr = restClient.post()
                .uri(batchPath)
                .headers(this::applyCommonHeaders)
                .body(reqs)
                .retrieve()
                .body(Decision[].class);
        if (arr == null) {
            return List.of();
        }
        return List.of(arr);
    }

    @Override
    public void invalidateCache() {
        // No-op for the HTTP-only client. Caching lives in LocalAuthzClient.
    }

    @Override
    public Set<String> getEffectivePermissions(String subjectType, UUID subjectId) {
        if (subjectType == null || subjectId == null) {
            throw new IllegalArgumentException("subjectType and subjectId must not be null");
        }
        String[] arr = restClient.get()
                .uri(uriBuilder -> uriBuilder
                        .path(permissionsPath)
                        .queryParam("subjectType", subjectType)
                        .queryParam("subjectId", subjectId)
                        .build())
                .headers(this::applyCommonHeaders)
                .retrieve()
                .body(String[].class);
        if (arr == null) {
            return Set.of();
        }
        return Set.copyOf(List.of(arr));
    }

    private void applyCommonHeaders(HttpHeaders headers) {
        if (tenantId != null) {
            headers.add("X-Tenant-Id", tenantId);
        }
        if (appId != null) {
            headers.add("X-App-Id", appId);
        }
        if (bearerToken != null && !bearerToken.isBlank()) {
            headers.setBearerAuth(bearerToken);
        }
    }
}