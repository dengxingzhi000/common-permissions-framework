package com.frog.sdk.authz.invalidate;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.frog.sdk.authz.HttpAuthzClient;
import com.frog.sdk.authz.LocalAuthzClient;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.common.TopicPartition;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * Unit-level coverage for {@link KafkaInvalidationSubscriber}.
 *
 * <p>We exercise {@link KafkaInvalidationSubscriber#consumeBatch(ConsumerRecords)}
 * directly so the test stays free of a live broker.
 */
@DisplayName("KafkaInvalidationSubscriber Tests")
class KafkaInvalidationSubscriberTest {

    private final ObjectMapper mapper = new ObjectMapper().findAndRegisterModules();

    @Test
    @DisplayName("constructor — null bootstrapServers rejected")
    void constructor_nullBootstrapThrows() {
        LocalAuthzClient local = new LocalAuthzClient(mock(HttpAuthzClient.class), Duration.ofSeconds(30), 10);
        assertThatThrownBy(() -> new KafkaInvalidationSubscriber(null, "g", "app", local))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    @DisplayName("constructor — null local client rejected")
    void constructor_nullLocalThrows() {
        assertThatThrownBy(() -> new KafkaInvalidationSubscriber("localhost:9092", "g", "app", null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    @DisplayName("constructor — auto-registers with local client")
    void constructor_registersWithLocal() {
        LocalAuthzClient local = new LocalAuthzClient(mock(HttpAuthzClient.class), Duration.ofSeconds(30), 10);
        KafkaInvalidationSubscriber sub = new KafkaInvalidationSubscriber("localhost:9092", "g", "app", local);
        assertThat(sub.patterns()).containsExactly(KafkaInvalidationSubscriber.DEFAULT_TOPIC);
    }

    @Test
    @DisplayName("groupId fallback — explicit group wins; otherwise authz-sdk-<appId>")
    void groupIdResolution() {
        LocalAuthzClient local = new LocalAuthzClient(mock(HttpAuthzClient.class), Duration.ofSeconds(30), 10);

        KafkaInvalidationSubscriber explicit = new KafkaInvalidationSubscriber("h:9092", "my-group", "app-1", local);
        KafkaInvalidationSubscriber defaulted = new KafkaInvalidationSubscriber("h:9092", null, "app-2", local);

        assertThat(explicit.groupId()).isEqualTo("my-group");
        assertThat(defaulted.groupId()).isEqualTo("authz-sdk-app-2");
    }

    @Test
    @DisplayName("consumeBatch — well-formed payload triggers local invalidateCache")
    void consumeBatch_invokesInvalidation() throws Exception {
        HttpAuthzClient http = mock(HttpAuthzClient.class);
        LocalAuthzClient local = new LocalAuthzClient(http, Duration.ofSeconds(30), 10);
        KafkaInvalidationSubscriber sub = new KafkaInvalidationSubscriber(
                "localhost:9092", "g", "app", local, "authz.invalidations", mapper);

        InvalidationEvent event = new InvalidationEvent(
                InvalidationType.SUBJECT,
                "user",
                UUID.randomUUID(), null, null, null, Instant.now());
        byte[] payload = mapper.writeValueAsBytes(event);

        TopicPartition tp = new TopicPartition("authz.invalidations", 0);
        ConsumerRecord<String, byte[]> record = new ConsumerRecord<>(
                "authz.invalidations", 0, 0L, event.subjectId().toString(), payload);
        ConsumerRecords<String, byte[]> records = new ConsumerRecords<>(Map.of(tp, List.of(record)));

        sub.consumeBatch(records);

        verify(http, times(1)).invalidateCache();
    }

    @Test
    @DisplayName("consumeBatch — malformed JSON is logged, does not throw")
    void consumeBatch_malformedIsSwallowed() {
        HttpAuthzClient http = mock(HttpAuthzClient.class);
        LocalAuthzClient local = new LocalAuthzClient(http, Duration.ofSeconds(30), 10);
        KafkaInvalidationSubscriber sub = new KafkaInvalidationSubscriber(
                "localhost:9092", "g", "app", local, mapper);

        TopicPartition tp = new TopicPartition("authz.invalidations", 0);
        ConsumerRecord<String, byte[]> record = new ConsumerRecord<>(
                "authz.invalidations", 0, 0L, "k",
                "not-json".getBytes(StandardCharsets.UTF_8));
        ConsumerRecords<String, byte[]> records = new ConsumerRecords<>(Map.of(tp, List.of(record)));

        sub.consumeBatch(records);

        verify(http, times(0)).invalidateCache();
    }

    @Test
    @DisplayName("start/stop — idempotent")
    void startStopIdempotent() {
        HttpAuthzClient http = mock(HttpAuthzClient.class);
        LocalAuthzClient local = new LocalAuthzClient(http, Duration.ofSeconds(30), 10);
        AtomicInteger invalidated = new AtomicInteger();
        local.registerInvalidationSubscriber(event -> invalidated.incrementAndGet());

        KafkaInvalidationSubscriber sub = new KafkaInvalidationSubscriber("localhost:9092", "g", "app", local);
        sub.start();
        sub.start();
        sub.stop();
        sub.stop();

        // Subscriber never received a real event — counter stays at zero.
        assertThat(invalidated.get()).isZero();
    }
}