package com.frog.sdk.authz;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Builder validation tests — Phase 2 starter.
 */
@DisplayName("AuthzClientBuilder Tests")
class AuthzClientBuilderTest {

    @Test
    @DisplayName("build() — returns a cached LocalAuthzClient by default")
    void build_returnsCachedClient() {
        AuthzClient client = new AuthzClientBuilder()
                .baseUrl("http://localhost:8081")
                .build();
        assertThat(client).isInstanceOf(LocalAuthzClient.class);
    }

    @Test
    @DisplayName("buildUncached() — returns a plain HttpAuthzClient")
    void buildUncached_returnsHttpClient() {
        AuthzClient client = new AuthzClientBuilder()
                .baseUrl("http://localhost:8081")
                .buildUncached();
        assertThat(client).isInstanceOf(HttpAuthzClient.class);
    }

    @Test
    @DisplayName("build() — missing baseUrl throws IllegalArgumentException")
    void build_missingBaseUrlThrows() {
        AuthzClientBuilder builder = new AuthzClientBuilder();
        assertThatThrownBy(builder::build)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("baseUrl");
    }

    @Test
    @DisplayName("custom TTL and maxSize are propagated to LocalAuthzClient")
    void build_propagatesCacheSettings() {
        LocalAuthzClient client = (LocalAuthzClient) new AuthzClientBuilder()
                .baseUrl("http://localhost:8081")
                .cacheTtl(Duration.ofSeconds(120))
                .cacheMaxSize(42L)
                .build();
        assertThat(client.cacheSize()).isZero();
        // Stats object should be fresh and non-null.
        assertThat(client.cacheStats()).isNotNull();
    }

    @Test
    @DisplayName("tenantId / appId / bearerToken are accepted but not validated at build time")
    void build_acceptsTenantAndAppHints() {
        AuthzClient client = new AuthzClientBuilder()
                .baseUrl("http://localhost:8081")
                .tenantId("tenant-a")
                .appId("app-1")
                .bearerToken("token")
                .build();
        assertThat(client).isNotNull();
    }
}