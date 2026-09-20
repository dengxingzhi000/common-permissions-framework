package com.frog.system.notification;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.frog.sdk.api.authz.InvalidationEvent;
import com.frog.sdk.api.authz.InvalidationType;
import com.frog.system.controller.PermissionEventWebSocketController;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.UUID;

/**
 * Server-side publisher for authz cache invalidation events (Phase 2).
 *
 * <p>Each business mutation (grant add/revoke, user-role link, role-permission
 * link, user disable) goes through this component. It fans the event out to:
 * <ol>
 *   <li>The Kafka topic {@code authz.invalidations} — for distributed SDK caches
 *       on other nodes.</li>
 *   <li>Connected WebSocket clients on {@code /v1/events/permissions} — for
 *       low-latency push to local SDK consumers in the same process.</li>
 * </ol>
 *
 * <p>Transports are wired with {@link ObjectProvider} so the component still
 * starts when Kafka or the WebSocket endpoint isn't configured (dev / test).
 *
 * @author Deng
 * @since 2026-09-20
 */
@Slf4j
@Component
public class InvalidationPublisher {

    public static final String DEFAULT_TOPIC = "authz.invalidations";

    private final ObjectProvider<KafkaTemplate<String, String>> kafkaTemplateProvider;
    private final ObjectProvider<PermissionEventWebSocketController> webSocketHandlerProvider;
    private final ObjectMapper objectMapper;
    private final String topic;

    public InvalidationPublisher(ObjectProvider<KafkaTemplate<String, String>> kafkaTemplateProvider,
                                 ObjectProvider<PermissionEventWebSocketController> webSocketHandlerProvider,
                                 ObjectMapper objectMapper,
                                 @Value("${authz.invalidations.topic:" + DEFAULT_TOPIC + "}") String topic) {
        this.kafkaTemplateProvider = kafkaTemplateProvider;
        this.webSocketHandlerProvider = webSocketHandlerProvider;
        this.objectMapper = objectMapper;
        this.topic = topic == null || topic.isBlank() ? DEFAULT_TOPIC : topic;
    }

    /**
     * Build and dispatch an event with the given type for the named subject.
     * Convenience method for callers that already know the scope.
     */
    public void publish(InvalidationType type, String subjectType, UUID subjectId,
                        UUID appId, UUID tenantId, String resourceType) {
        publish(new InvalidationEvent(type, subjectType, subjectId, appId, tenantId, resourceType, Instant.now()));
    }

    /** Backwards-compatible overload — subjectType defaults to {@code "user"}. */
    public void publish(InvalidationType type, UUID subjectId,
                        UUID appId, UUID tenantId, String resourceType) {
        publish(type, "user", subjectId, appId, tenantId, resourceType);
    }

    /**
     * Dispatch a fully-formed event to all configured transports.
     * Never throws — failures are logged so the calling business operation
     * isn't rolled back because of an invalidation hiccup.
     */
    public void publish(InvalidationEvent event) {
        if (event == null) {
            return;
        }
        broadcastWebSocket(event);
        publishKafka(event);
    }

    private void broadcastWebSocket(InvalidationEvent event) {
        PermissionEventWebSocketController handler = webSocketHandlerProvider.getIfAvailable();
        if (handler == null) {
            return;
        }
        try {
            handler.broadcast(event);
        } catch (RuntimeException ex) {
            log.warn("WebSocket broadcast failed for event type={}: {}",
                    event.type(), ex.getMessage());
        }
    }

    private void publishKafka(InvalidationEvent event) {
        KafkaTemplate<String, String> kafkaTemplate = kafkaTemplateProvider.getIfAvailable();
        if (kafkaTemplate == null) {
            log.debug("KafkaTemplate<String, String> not configured — skipping Kafka publish for event type={}",
                    event.type());
            return;
        }
        String payload;
        try {
            payload = objectMapper.writeValueAsString(event);
        } catch (JsonProcessingException ex) {
            log.warn("Failed to serialize invalidation event for Kafka: {}", ex.getMessage());
            return;
        }
        String key = event.tenantId() != null ? event.tenantId().toString() : "default";
        try {
            kafkaTemplate.send(topic, key, payload);
            log.debug("Published invalidation event to Kafka: topic={}, key={}, type={}",
                    topic, key, event.type());
        } catch (RuntimeException ex) {
            log.warn("Kafka send failed for invalidation event type={}: {}",
                    event.type(), ex.getMessage());
        }
    }
}