package com.frog.sdk.authz;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * LocalAuthzClient cache behaviour tests — Phase 2 starter.
 */
@DisplayName("LocalAuthzClient Tests")
class LocalAuthzClientTest {

    private HttpAuthzClient http;
    private LocalAuthzClient client;

    @BeforeEach
    void setUp() {
        http = mock(HttpAuthzClient.class);
        client = new LocalAuthzClient(http, Duration.ofSeconds(60), 1000);
    }

    private CheckRequest sampleRequest() {
        return CheckRequest.builder()
                .subjectType("user")
                .subjectId(UUID.randomUUID())
                .action("project.read")
                .build();
    }

    private Decision sampleDecision() {
        return Decision.builder()
                .effect("allow")
                .latencyMs(5L)
                .build();
    }

    @Test
    @DisplayName("check — first call hits HTTP, second call served from cache")
    void check_cacheHitOnSecondCall() {
        CheckRequest req = sampleRequest();
        Decision decision = sampleDecision();
        when(http.check(req)).thenReturn(decision);

        Decision first = client.check(req);
        Decision second = client.check(req);

        assertThat(first).isSameAs(decision);
        assertThat(second).isSameAs(decision);
        verify(http, times(1)).check(req);
        assertThat(client.cacheStats().hitCount()).isEqualTo(1L);
        assertThat(client.cacheStats().missCount()).isEqualTo(1L);
    }

    @Test
    @DisplayName("check — different requests miss the cache independently")
    void check_differentRequestsIndependentCache() {
        CheckRequest req1 = sampleRequest();
        CheckRequest req2 = CheckRequest.builder()
                .subjectType("user")
                .subjectId(UUID.randomUUID())
                .action("invoice.approve")
                .build();
        when(http.check(any())).thenReturn(sampleDecision());

        client.check(req1);
        client.check(req2);

        verify(http, times(1)).check(req1);
        verify(http, times(1)).check(req2);
        assertThat(client.cacheStats().missCount()).isEqualTo(2L);
    }

    @Test
    @DisplayName("invalidateCache — clears local cache")
    void invalidateCache_clears() {
        CheckRequest req = sampleRequest();
        when(http.check(req)).thenReturn(sampleDecision());

        client.check(req);
        assertThat(client.cacheStats().missCount()).isEqualTo(1L);

        client.invalidateCache();

        client.check(req);
        assertThat(client.cacheStats().missCount()).isEqualTo(2L);
        verify(http, times(2)).check(req);
    }

    @Test
    @DisplayName("check — HTTP returning null is not cached")
    void check_nullResponseNotCached() {
        CheckRequest req = sampleRequest();
        when(http.check(req)).thenReturn(null);

        Decision first = client.check(req);
        Decision second = client.check(req);

        assertThat(first).isNull();
        assertThat(second).isNull();
        verify(http, times(2)).check(req);
    }

    @Test
    @DisplayName("batchCheck — delegates to HTTP without caching")
    void batchCheck_delegatesToHttp() {
        var reqs = java.util.List.of(sampleRequest(), sampleRequest());
        var decisions = java.util.List.of(sampleDecision(), sampleDecision());
        when(http.batchCheck(reqs)).thenReturn(decisions);

        java.util.List<Decision> result = client.batchCheck(reqs);

        assertThat(result).isSameAs(decisions);
        verify(http, times(1)).batchCheck(reqs);
        assertThat(client.cacheStats().missCount()).isZero();
    }

    @Test
    @DisplayName("constructor — rejects null http / ttl and non-positive maxSize")
    void constructor_rejectsInvalidArgs() {
        assertThatThrownBy(() -> new LocalAuthzClient(null, Duration.ofSeconds(1), 10))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new LocalAuthzClient(http, null, 10))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new LocalAuthzClient(http, Duration.ofSeconds(1), 0))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("check — context fingerprint differentiates requests with different ABAC context")
    void check_contextFingerprint() {
        CheckRequest base = sampleRequest();
        CheckRequest withIp = CheckRequest.builder()
                .subjectType(base.getSubjectType())
                .subjectId(base.getSubjectId())
                .action(base.getAction())
                .context(java.util.Map.of("ip", "1.2.3.4"))
                .build();
        when(http.check(any())).thenReturn(sampleDecision());

        client.check(base);
        client.check(withIp);

        verify(http, times(1)).check(base);
        verify(http, times(1)).check(withIp);
    }

    @Test
    @DisplayName("check — null CheckRequest throws IllegalArgumentException")
    void check_nullRequestThrows() {
        assertThatThrownBy(() -> client.check(null))
                .isInstanceOf(IllegalArgumentException.class);
        verify(http, never()).check(any());
    }
}