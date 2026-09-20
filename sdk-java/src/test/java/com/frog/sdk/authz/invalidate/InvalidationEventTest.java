package com.frog.sdk.authz.invalidate;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * JSON round-trip tests for the wire format that the server publishes
 * and the SDK consumes.
 */
@DisplayName("InvalidationEvent Serialization Tests")
class InvalidationEventTest {

    private final ObjectMapper mapper = new ObjectMapper()
            .findAndRegisterModules();

    @Test
    @DisplayName("Jackson round-trip — full payload survives serialization")
    void roundTrip_full() throws Exception {
        InvalidationEvent original = new InvalidationEvent(
                InvalidationEvent.InvalidationType.ROLE,
                UUID.fromString("11111111-1111-7111-8111-111111111111"),
                UUID.fromString("22222222-2222-7222-8222-222222222222"),
                UUID.fromString("33333333-3333-7333-8333-333333333333"),
                "user",
                Instant.parse("2026-09-20T10:15:30Z"));

        String json = mapper.writeValueAsString(original);
        InvalidationEvent restored = mapper.readValue(json, InvalidationEvent.class);

        assertThat(restored).isEqualTo(original);
        assertThat(json).contains("\"type\":\"ROLE\"");
        assertThat(json).contains("\"subjectId\":\"11111111-1111-7111-8111-111111111111\"");
        assertThat(json).contains("\"resourceType\":\"user\"");
    }

    @Test
    @DisplayName("Jackson round-trip — nullable fields preserved as null")
    void roundTrip_nulls() throws Exception {
        InvalidationEvent original = new InvalidationEvent(
                InvalidationEvent.InvalidationType.ALL, null, null, null, null, Instant.now());

        String json = mapper.writeValueAsString(original);
        InvalidationEvent restored = mapper.readValue(json, InvalidationEvent.class);

        assertThat(restored.type()).isEqualTo(InvalidationEvent.InvalidationType.ALL);
        assertThat(restored.subjectId()).isNull();
        assertThat(restored.appId()).isNull();
        assertThat(restored.tenantId()).isNull();
        assertThat(restored.resourceType()).isNull();
        assertThat(restored.timestamp()).isNotNull();
    }

    @Test
    @DisplayName("InvalidationType enum serialises as uppercase string")
    void enumSerialisation() throws Exception {
        String json = mapper.writeValueAsString(InvalidationEvent.InvalidationType.PERMISSION);
        assertThat(json).isEqualTo("\"PERMISSION\"");
    }
}