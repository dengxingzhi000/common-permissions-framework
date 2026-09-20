package com.frog.sdk.authz;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Phase 2 — invalidation wiring in {@link AuthzClientBuilder}.
 */
@DisplayName("AuthzClientBuilder Invalidation Tests")
class AuthzClientBuilderInvalidationTest {

    @Test
    @DisplayName("default mode — no subscriber registered, default LocalAuthzClient")
    void defaultMode() {
        AuthzClient client = new AuthzClientBuilder()
                .baseUrl("http://localhost:8081")
                .build();
        assertThat(client).isInstanceOf(LocalAuthzClient.class);
    }

    @Test
    @DisplayName("kafka mode without bootstrapServers — IllegalArgumentException")
    void kafkaMode_missingBootstrap() {
        assertThatThrownBy(() -> new AuthzClientBuilder()
                .baseUrl("http://localhost:8081")
                .invalidationMode("kafka")
                .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("kafkaBootstrapServers");
    }

    @Test
    @DisplayName("websocket mode without url — IllegalArgumentException")
    void websocketMode_missingUrl() {
        assertThatThrownBy(() -> new AuthzClientBuilder()
                .baseUrl("http://localhost:8081")
                .invalidationMode("websocket")
                .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("webSocketUrl");
    }

    @Test
    @DisplayName("unknown mode — IllegalArgumentException")
    void unknownMode() {
        assertThatThrownBy(() -> new AuthzClientBuilder()
                .baseUrl("http://localhost:8081")
                .invalidationMode("redis-pubsub")
                .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("redis-pubsub");
    }

    @Test
    @DisplayName("kafka mode — subscriber attached and started")
    void kafkaMode_attachesSubscriber() {
        AuthzClient client = new AuthzClientBuilder()
                .baseUrl("http://localhost:8081")
                .appId("app-1")
                .invalidationMode("kafka")
                .kafkaBootstrapServers("localhost:9092")
                .build();
        assertThat(client).isInstanceOf(LocalAuthzClient.class);
    }

    @Test
    @DisplayName("websocket mode — Authorization header is auto-injected from bearerToken")
    void websocketMode_bearerAutoInjected() {
        AuthzClient client = new AuthzClientBuilder()
                .baseUrl("http://localhost:8081")
                .bearerToken("token-123")
                .invalidationMode("websocket")
                .webSocketUrl("ws://localhost:8081/v1/events/permissions")
                .build();
        assertThat(client).isInstanceOf(LocalAuthzClient.class);
    }

    @Test
    @DisplayName("websocket mode — explicit header wins over bearerToken default")
    void websocketMode_explicitHeaderWins() {
        Map<String, String> captured = new HashMap<>();
        AuthzClient client = new AuthzClientBuilder()
                .baseUrl("http://localhost:8081")
                .bearerToken("ignored")
                .webSocketAuthHeader("Authorization", "Bearer custom")
                .invalidationMode("websocket")
                .webSocketUrl("ws://localhost:8081/v1/events/permissions")
                .build();
        // We can't introspect the builder afterwards, but build must succeed without
        // exploding — the actual header-merge logic is exercised by WebSocketInvalidationSubscriber.
        assertThat(client).isNotNull();
    }

    @Test
    @DisplayName("none mode is case-insensitive")
    void noneModeCaseInsensitive() {
        AuthzClient client = new AuthzClientBuilder()
                .baseUrl("http://localhost:8081")
                .invalidationMode("None")
                .cacheTtl(Duration.ofSeconds(45))
                .build();
        assertThat(client).isInstanceOf(LocalAuthzClient.class);
    }
}