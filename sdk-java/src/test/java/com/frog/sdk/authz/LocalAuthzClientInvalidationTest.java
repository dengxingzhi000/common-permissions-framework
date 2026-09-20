package com.frog.sdk.authz;

import com.frog.sdk.api.authz.InvalidationEvent;
import com.frog.sdk.api.authz.InvalidationType;
import com.frog.sdk.api.authz.InvalidationSubscriber;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * Phase 2 — invalidation fan-out through {@link LocalAuthzClient}.
 */
@DisplayName("LocalAuthzClient Invalidation Tests")
class LocalAuthzClientInvalidationTest {

    private HttpAuthzClient http;
    private LocalAuthzClient client;

    @BeforeEach
    void setUp() {
        http = mock(HttpAuthzClient.class);
        client = new LocalAuthzClient(http, java.time.Duration.ofSeconds(60), 1000);
    }

    private CheckRequest sampleRequest() {
        return CheckRequest.builder()
                .subjectType("user")
                .subjectId(UUID.randomUUID())
                .action("project.read")
                .build();
    }

    private Decision sampleDecision() {
        return Decision.builder().effect("allow").build();
    }

    @Test
    @DisplayName("registerInvalidationSubscriber — null subscriber rejected")
    void register_rejectsNull() {
        assertThatThrownBy(() -> client.registerInvalidationSubscriber(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("dispatchInvalidation — iterates every registered subscriber")
    void dispatch_invokesAllSubscribers() {
        AtomicInteger counter = new AtomicInteger();
        InvalidationSubscriber sub1 = new InvalidationSubscriber() {
            @Override public Set<String> patterns() { return Set.of("authz.invalidations"); }
            @Override public void onInvalidation(InvalidationEvent event) { counter.incrementAndGet(); }
        };
        InvalidationSubscriber sub2 = new InvalidationSubscriber() {
            @Override public Set<String> patterns() { return Set.of("authz.invalidations"); }
            @Override public void onInvalidation(InvalidationEvent event) { counter.addAndGet(10); }
        };
        client.registerInvalidationSubscriber(sub1);
        client.registerInvalidationSubscriber(sub2);

        client.dispatchInvalidation(new InvalidationEvent(InvalidationType.ALL, null, null, null, null, null, Instant.now()));

        assertThat(counter.get()).isEqualTo(11);
    }

    @Test
    @DisplayName("dispatchInvalidation — one failing subscriber does not stop the others")
    void dispatch_isolatesExceptions() {
        AtomicInteger counter = new AtomicInteger();
        client.registerInvalidationSubscriber(event -> { throw new RuntimeException("boom"); });
        client.registerInvalidationSubscriber(event -> counter.incrementAndGet());

        client.dispatchInvalidation(new InvalidationEvent(InvalidationType.GRANT, "user", UUID.randomUUID(), null, null, null, Instant.now()));

        assertThat(counter.get()).isEqualTo(1);
    }

    @Test
    @DisplayName("dispatchInvalidation — null event is a no-op")
    void dispatch_nullIsNoop() {
        AtomicInteger counter = new AtomicInteger();
        client.registerInvalidationSubscriber(event -> counter.incrementAndGet());

        client.dispatchInvalidation(null);

        assertThat(counter.get()).isZero();
    }

    @Test
    @DisplayName("registerInvalidationSubscriber — plug-in subscriber can drive invalidateCache")
    void dispatch_triggersHttpInvalidate() {
        // Pre-populate cache
        CheckRequest req = sampleRequest();
        org.mockito.Mockito.when(http.check(req)).thenReturn(sampleDecision());
        client.check(req);

        // Subscriber that mimics the production wiring (KafkaInvalidationSubscriber,
        // WebSocketInvalidationSubscriber both do this)
        client.registerInvalidationSubscriber(event -> client.invalidateCache());

        client.dispatchInvalidation(new InvalidationEvent(InvalidationType.SUBJECT, "user", UUID.randomUUID(),
                null, null, null, Instant.now()));

        verify(http, times(1)).check(req);
        verify(http, times(1)).invalidateCache();
        verify(http, never()).check(org.mockito.ArgumentMatchers.argThat(r -> r != req));
    }
}