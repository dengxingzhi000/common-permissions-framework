package com.frog.sdk.authz.invalidate;

import com.frog.sdk.authz.HttpAuthzClient;
import com.frog.sdk.authz.LocalAuthzClient;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

/**
 * Lightweight validation for {@link WebSocketInvalidationSubscriber} — exercises
 * only the constructor / lifecycle paths that don't need a live socket.
 */
@DisplayName("WebSocketInvalidationSubscriber Tests")
class WebSocketInvalidationSubscriberTest {

    @Test
    @DisplayName("constructor — null webSocketUrl rejected")
    void constructor_nullUrlThrows() {
        LocalAuthzClient local = new LocalAuthzClient(mock(HttpAuthzClient.class), Duration.ofSeconds(30), 10);
        assertThatThrownBy(() -> new WebSocketInvalidationSubscriber(null, Map.of(), local))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    @DisplayName("constructor — null local client rejected")
    void constructor_nullLocalThrows() {
        assertThatThrownBy(() -> new WebSocketInvalidationSubscriber("ws://localhost/ws", Map.of(), null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    @DisplayName("constructor — auto-registers with local client")
    void constructor_registersWithLocal() {
        LocalAuthzClient local = new LocalAuthzClient(mock(HttpAuthzClient.class), Duration.ofSeconds(30), 10);
        WebSocketInvalidationSubscriber sub = new WebSocketInvalidationSubscriber(
                "ws://localhost:8081/v1/events/permissions", Map.of(), local);

        assertThat(sub.patterns()).containsExactly("/v1/events/permissions");
    }

    @Test
    @DisplayName("stop — safe to call without start")
    void stop_isSafeWithoutStart() {
        LocalAuthzClient local = new LocalAuthzClient(mock(HttpAuthzClient.class), Duration.ofSeconds(30), 10);
        WebSocketInvalidationSubscriber sub = new WebSocketInvalidationSubscriber(
                "ws://localhost:8081/v1/events/permissions", Map.of(), local);
        sub.stop();
    }
}