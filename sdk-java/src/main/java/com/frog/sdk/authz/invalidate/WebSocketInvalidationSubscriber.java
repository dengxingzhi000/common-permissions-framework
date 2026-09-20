package com.frog.sdk.authz.invalidate;

import com.frog.sdk.api.authz.InvalidationEvent;
import com.frog.sdk.api.authz.InvalidationSubscriber;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.frog.sdk.authz.LocalAuthzClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.client.standard.StandardWebSocketClient;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Push-based invalidation subscriber backed by a server-side WebSocket.
 *
 * <p>Connects to {@code ws://<baseUrl>/v1/events/permissions} with the same
 * auth headers as HTTP check calls. Each JSON-encoded {@link InvalidationEvent}
 * arriving on the socket triggers {@link LocalAuthzClient#invalidateCache()}.
 *
 * <p>Reconnect strategy: exponential backoff (1s → 2s → 4s → …) capped at 30s.
 * The scheduler is a single daemon thread so the JVM can exit cleanly even if
 * the subscriber hasn't been {@link #stop() stopped}.
 *
 * @author Deng
 * @since 2026-09-20
 */
public class WebSocketInvalidationSubscriber implements InvalidationSubscriber {

    private static final Logger log = LoggerFactory.getLogger(WebSocketInvalidationSubscriber.class);

    public static final String DEFAULT_PATH = "/v1/events/permissions";
    public static final long MAX_RECONNECT_DELAY_MS = 30_000L;
    public static final long INITIAL_RECONNECT_DELAY_MS = 1_000L;
    public static final int MAX_RECONNECT_SHIFT = 5;

    private final String webSocketUrl;
    private final Map<String, String> authHeaders;
    private final LocalAuthzClient local;
    private final ObjectMapper objectMapper;
    private final StandardWebSocketClient client;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicInteger reconnectAttempts = new AtomicInteger(0);
    private final ScheduledExecutorService scheduler;
    private volatile ScheduledFuture<?> reconnectTask;
    private volatile WebSocketSession session;

    public WebSocketInvalidationSubscriber(String webSocketUrl,
                                           Map<String, String> authHeaders,
                                           LocalAuthzClient local) {
        this(webSocketUrl, authHeaders, local, new ObjectMapper());
    }

    public WebSocketInvalidationSubscriber(String webSocketUrl,
                                           Map<String, String> authHeaders,
                                           LocalAuthzClient local,
                                           ObjectMapper objectMapper) {
        this.webSocketUrl = Objects.requireNonNull(webSocketUrl, "webSocketUrl");
        this.authHeaders = authHeaders == null ? new HashMap<>() : new HashMap<>(authHeaders);
        this.local = Objects.requireNonNull(local, "local");
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper");
        this.client = new StandardWebSocketClient();
        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "authz-ws-reconnect");
            t.setDaemon(true);
            return t;
        });

        local.registerInvalidationSubscriber(this);
    }

    /**
     * Begin (or resume) connecting to the WebSocket endpoint. Safe to call
     * multiple times — only the first call kicks off the connection loop.
     */
    public void start() {
        if (running.compareAndSet(false, true)) {
            reconnectAttempts.set(0);
            connect();
        }
    }

    /**
     * Stop the reconnect loop and tear down the active session. Safe to call
     * even if {@link #start()} was never invoked.
     */
    public void stop() {
        if (!running.compareAndSet(true, false)) {
            return;
        }
        ScheduledFuture<?> pending = reconnectTask;
        if (pending != null) {
            pending.cancel(false);
        }
        scheduler.shutdownNow();
        closeActiveSession(CloseStatus.NORMAL);
    }

    @Override
    public Set<String> patterns() {
        return Set.of(extractPath(webSocketUrl));
    }

    @Override
    public void onInvalidation(InvalidationEvent event) {
        applyInvalidation(event);
    }

    private void connect() {
        if (!running.get()) {
            return;
        }
        URI uri;
        try {
            uri = URI.create(webSocketUrl);
        } catch (IllegalArgumentException ex) {
            log.error("Invalid WebSocket URL '{}': {}", webSocketUrl, ex.getMessage());
            return;
        }

        WebSocketClientHandler wsHandler = new WebSocketClientHandler();
        try {
            log.info("Connecting to WebSocket: {}", webSocketUrl);
            org.springframework.web.socket.WebSocketHttpHeaders headers =
                    new org.springframework.web.socket.WebSocketHttpHeaders();
            authHeaders.forEach(headers::set);
            client.execute(wsHandler, headers, uri).get();
        } catch (Exception ex) {
            log.warn("WebSocket connection to {} failed: {}", webSocketUrl, ex.getMessage());
            scheduleReconnect();
        }
    }

    private void scheduleReconnect() {
        if (!running.get()) {
            return;
        }
        int attempt = reconnectAttempts.getAndIncrement();
        long delay = Math.min(MAX_RECONNECT_DELAY_MS,
                INITIAL_RECONNECT_DELAY_MS * (1L << Math.min(attempt, MAX_RECONNECT_SHIFT)));
        log.info("Scheduling WebSocket reconnect in {}ms (attempt {})", delay, attempt + 1);
        reconnectTask = scheduler.schedule(this::connect, delay, TimeUnit.MILLISECONDS);
    }

    private void onConnected(WebSocketSession session) {
        this.session = session;
        this.reconnectAttempts.set(0);
        log.info("WebSocket connected: {} (id={})", webSocketUrl, session.getId());
    }

    private void onTextMessage(WebSocketSession session, TextMessage message) {
        try {
            InvalidationEvent event = objectMapper.readValue(message.getPayload(), InvalidationEvent.class);
            log.debug("WS invalidation event: type={}, subjectId={}", event.type(), event.subjectId());
            local.dispatchInvalidation(event);
        } catch (Exception ex) {
            log.warn("Failed to parse WS invalidation payload: {}", ex.getMessage());
        }
    }

    private void onClosed(WebSocketSession session, CloseStatus status) {
        log.info("WebSocket closed: id={}, status={}", session.getId(), status);
        if (this.session == session) {
            this.session = null;
        }
        if (running.get() && !CloseStatus.NORMAL.equals(status)) {
            scheduleReconnect();
        }
    }

    private void onError(WebSocketSession session, Throwable error) {
        log.warn("WebSocket error on session {}: {}", session.getId(), error.getMessage());
    }

    private void closeActiveSession(CloseStatus status) {
        WebSocketSession s = this.session;
        this.session = null;
        if (s != null && s.isOpen()) {
            try {
                s.close(status);
            } catch (Exception ex) {
                log.debug("Error closing WebSocket session: {}", ex.getMessage());
            }
        }
    }

    private void applyInvalidation(InvalidationEvent event) {
        // Delegate to LocalAuthzClient.dispatchInvalidation which applies selective
        // per-subject eviction for SUBJECT events and full eviction otherwise.
        local.dispatchInvalidation(event);
    }

    private static String extractPath(String url) {
        int q = url.indexOf('?');
        String stripped = q >= 0 ? url.substring(0, q) : url;
        int slash = stripped.indexOf("//");
        int pathStart = slash >= 0 ? stripped.indexOf('/', slash + 2) : stripped.indexOf('/');
        return pathStart >= 0 ? stripped.substring(pathStart) : stripped;
    }

    /**
     * Spring {@code WebSocketHandler} bridge used by the {@link StandardWebSocketClient}.
     * Delegates back to the enclosing subscriber so reconnect / parsing logic
     * stays in one place.
     */
    private final class WebSocketClientHandler extends org.springframework.web.socket.handler.TextWebSocketHandler {

        @Override
        public void afterConnectionEstablished(WebSocketSession session) {
            onConnected(session);
        }

        @Override
        protected void handleTextMessage(WebSocketSession session, TextMessage message) {
            onTextMessage(session, message);
        }

        @Override
        public void afterConnectionClosed(WebSocketSession session, CloseStatus status) {
            onClosed(session, status);
        }

        @Override
        public void handleTransportError(WebSocketSession session, Throwable exception) {
            onError(session, exception);
        }
    }
}