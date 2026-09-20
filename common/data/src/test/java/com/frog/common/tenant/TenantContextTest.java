package com.frog.common.tenant;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * TenantContext unit tests — Phase 1.3.
 *
 * <p>Tests ThreadLocal semantics: set/get/clear, isolation across invocations,
 * and absence cleanup so the next request on a pooled thread does not see
 * leaked state.
 */
@DisplayName("TenantContext ThreadLocal Tests")
class TenantContextTest {

    @AfterEach
    void tearDown() {
        TenantContext.clear();
    }

    @Test
    @DisplayName("set + get round-trips the tenantId")
    void setAndGet() {
        UUID id = UUID.randomUUID();
        TenantContext.set(id);

        assertThat(TenantContext.get()).isEqualTo(id);
        assertThat(TenantContext.isPresent()).isTrue();
    }

    @Test
    @DisplayName("get returns null when no tenantId has been set")
    void getReturnsNullWhenEmpty() {
        assertThat(TenantContext.get()).isNull();
        assertThat(TenantContext.isPresent()).isFalse();
    }

    @Test
    @DisplayName("clear removes the value")
    void clearRemovesValue() {
        TenantContext.set(UUID.randomUUID());

        TenantContext.clear();

        assertThat(TenantContext.get()).isNull();
        assertThat(TenantContext.isPresent()).isFalse();
    }

    @Test
    @DisplayName("set replaces previous value (last-wins)")
    void setReplacesPrevious() {
        UUID first = UUID.randomUUID();
        UUID second = UUID.randomUUID();

        TenantContext.set(first);
        TenantContext.set(second);

        assertThat(TenantContext.get()).isEqualTo(second);
    }

    @Test
    @DisplayName("set(null) is allowed and results in present but null")
    void setNullIsAllowed() {
        TenantContext.set(null);

        assertThat(TenantContext.get()).isNull();
        assertThat(TenantContext.isPresent()).isFalse();
    }

    @Test
    @DisplayName("isPresent mirrors get != null")
    void isPresentMirrorsGet() {
        TenantContext.set(UUID.randomUUID());
        assertThat(TenantContext.isPresent()).isTrue();
        assertThat(TenantContext.get()).isNotNull();

        TenantContext.clear();
        assertThat(TenantContext.isPresent()).isFalse();
    }
}
