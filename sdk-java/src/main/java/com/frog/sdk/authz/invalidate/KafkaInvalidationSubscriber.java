package com.frog.sdk.authz.invalidate;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.frog.sdk.api.authz.InvalidationEvent;
import com.frog.sdk.api.authz.InvalidationSubscriber;
import com.frog.sdk.api.authz.InvalidationType;
import com.frog.sdk.authz.LocalAuthzClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.common.serialization.ByteArrayDeserializer;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.springframework.kafka.core.DefaultKafkaConsumerFactory;
import org.springframework.kafka.listener.ContainerProperties;
import org.springframework.kafka.listener.KafkaMessageListenerContainer;
import org.springframework.kafka.listener.MessageListener;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Push-based invalidation subscriber backed by Kafka.
 *
 * <p>Listens on the {@code authz.invalidations} topic with a per-app consumer
 * group ({@code authz-sdk-<appId>}). Each event triggers
 * {@link LocalAuthzClient#invalidateCache()} — Phase 2.5 will add per-subject
 * keying.
 *
 * <p>Registration model:
 * <ul>
 *   <li>Constructor wires the listener container and registers itself with the
 *       local client.</li>
 *   <li>{@link #start()} begins polling; {@link #stop()} shuts the container
 *       down cleanly.</li>
 *   <li>Thread-safe; {@link #onInvalidation(InvalidationEvent)} may be invoked
 *       from any of the listener container's consumer threads.</li>
 * </ul>
 *
 * @author Deng
 * @since 2026-09-20
 */
public class KafkaInvalidationSubscriber implements InvalidationSubscriber {

    private static final Logger log = LoggerFactory.getLogger(KafkaInvalidationSubscriber.class);

    public static final String DEFAULT_TOPIC = "authz.invalidations";
    public static final String DEFAULT_GROUP_PREFIX = "authz-sdk-";

    private final LocalAuthzClient local;
    private final String topic;
    private final String groupId;
    private final ObjectMapper objectMapper;
    private final KafkaMessageListenerContainer<String, byte[]> container;
    private final AtomicBoolean running = new AtomicBoolean(false);

    /**
     * @param bootstrapServers Kafka bootstrap servers (host:port[,host:port])
     * @param groupId          full consumer group id, e.g. {@code authz-sdk-app-1}
     * @param appId            app id used to default the group id when not provided
     * @param local            the local client whose cache gets invalidated
     */
    public KafkaInvalidationSubscriber(String bootstrapServers,
                                       String groupId,
                                       String appId,
                                       LocalAuthzClient local) {
        this(bootstrapServers, groupId, appId, local, DEFAULT_TOPIC, new ObjectMapper());
    }

    public KafkaInvalidationSubscriber(String bootstrapServers,
                                       String groupId,
                                       String appId,
                                       LocalAuthzClient local,
                                       String topic,
                                       ObjectMapper objectMapper) {
        Objects.requireNonNull(bootstrapServers, "bootstrapServers");
        Objects.requireNonNull(local, "local");
        Objects.requireNonNull(objectMapper, "objectMapper");

        this.local = local;
        this.topic = topic == null || topic.isBlank() ? DEFAULT_TOPIC : topic;
        this.groupId = resolveGroupId(groupId, appId);
        this.objectMapper = objectMapper;

        Map<String, Object> props = new HashMap<>();
        props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        props.put(ConsumerConfig.GROUP_ID_CONFIG, this.groupId);
        props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
        props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, ByteArrayDeserializer.class);
        props.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "latest");
        props.put(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, Boolean.TRUE);
        props.put(ConsumerConfig.CLIENT_ID_CONFIG, this.groupId + "-" + UUID.randomUUID());

        DefaultKafkaConsumerFactory<String, byte[]> factory = new DefaultKafkaConsumerFactory<>(props);
        ContainerProperties containerProps = new ContainerProperties(this.topic);
        containerProps.setPollTimeout(Duration.ofSeconds(2).toMillis());

        this.container = new KafkaMessageListenerContainer<>(factory, containerProps);
        this.container.setupMessageListener((MessageListener<String, byte[]>) this::onRawMessage);

        // Auto-register so the local client knows about us.
        local.registerInvalidationSubscriber(this);
    }

    private static String resolveGroupId(String explicit, String appId) {
        if (explicit != null && !explicit.isBlank()) {
            return explicit;
        }
        if (appId != null && !appId.isBlank()) {
            return DEFAULT_GROUP_PREFIX + appId;
        }
        return DEFAULT_GROUP_PREFIX + "default";
    }

    /**
     * Start polling. Idempotent — repeated calls are a no-op once running.
     */
    public void start() {
        if (running.compareAndSet(false, true)) {
            container.start();
            log.info("KafkaInvalidationSubscriber started: topic={}, groupId={}", topic, groupId);
        }
    }

    /**
     * Stop polling. Idempotent.
     */
    public void stop() {
        if (running.compareAndSet(true, false)) {
            container.stop();
            log.info("KafkaInvalidationSubscriber stopped: topic={}, groupId={}", topic, groupId);
        }
    }

    @Override
    public Set<String> patterns() {
        return Set.of(topic);
    }

    @Override
    public void onInvalidation(InvalidationEvent event) {
        applyInvalidation(event);
    }

    private void onRawMessage(org.apache.kafka.clients.consumer.ConsumerRecord<String, byte[]> record) {
        try {
            InvalidationEvent event = objectMapper.readValue(record.value(), InvalidationEvent.class);
            log.debug("Received invalidation event: type={}, subjectId={}, tenantId={}",
                    event.type(), event.subjectId(), event.tenantId());
            local.dispatchInvalidation(event);
        } catch (Exception ex) {
            log.warn("Failed to deserialize invalidation event from topic={}, offset={}: {}",
                    record.topic(), record.offset(), ex.getMessage());
        }
    }

    private void applyInvalidation(InvalidationEvent event) {
        // Delegate to LocalAuthzClient.dispatchInvalidation which applies selective
        // per-subject eviction for SUBJECT events and full eviction otherwise.
        local.dispatchInvalidation(event);
    }

    /**
     * Bridge for tests / legacy code paths that have a {@link ConsumerRecords}
     * batch but no live container.
     */
    public void consumeBatch(ConsumerRecords<String, byte[]> records) {
        records.forEach(this::onRawMessage);
    }
}