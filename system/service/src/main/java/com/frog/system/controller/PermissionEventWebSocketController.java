package com.frog.system.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.frog.sdk.authz.invalidate.InvalidationEvent;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Server-side WebSocket handler that pushes authz invalidation events to SDK
 * clients subscribed at {@code /v1/events/permissions} (Phase 2).
 *
 * <p>Behaviour:
 * <ul>
 *   <li>{@link #afterConnectionEstablished(WebSocketSession)} validates the
 *       JWT from the {@code Authorization} header (falls back to
 *       {@code Sec-WebSocket-Protocol} then {@code ?token=...}). Missing or
 *       invalid tokens close the session with {@code POLICY_VIOLATION} (1008).</li>
 *   <li>{@link #broadcast(InvalidationEvent)} sends the JSON-encoded event to
 *       every connected session, removing sessions whose send fails.</li>
 * </ul>
 *
 * <p>Despite the {@code Controller} suffix the class is a Spring
 * {@link TextWebSocketHandler}; the file path matches the commit convention.
 *
 * @author Deng
 * @since 2026-09-20
 */
@Slf4j
@Component
public class PermissionEventWebSocketController extends TextWebSocketHandler {

    public static final String PATH = "/v1/events/permissions";
    private static final String USER_ID_ATTR = "authz.ws.userId";
    private static final String TENANT_ID_ATTR = "authz.ws.tenantId";

    private final Set<WebSocketSession> sessions = ConcurrentHashMap.newKeySet();
    private final ObjectMapper objectMapper;
    private final String jwtSecret;
    private SecretKey signingKey;

    public PermissionEventWebSocketController(
            ObjectMapper objectMapper,
            @Value("${JWT_SECRET:}") String jwtSecret) {
        this.objectMapper = objectMapper;
        this.jwtSecret = jwtSecret;
    }

    @PostConstruct
    void init() {
        if (jwtSecret != null && !jwtSecret.isBlank()) {
            byte[] keyBytes = jwtSecret.getBytes(StandardCharsets.UTF_8);
            try {
                this.signingKey = Keys.hmacShaKeyFor(keyBytes);
            } catch (IllegalArgumentException ex) {
                log.warn("JWT_SECRET too short for HS512 — WS handshake will require tokens but reject all");
            }
        } else {
            log.warn("JWT_SECRET not set — WS endpoint will accept all connections without auth. "
                    + "Configure JWT_SECRET in production.");
        }
    }

    @Override
    public void afterConnectionEstablished(WebSocketSession session) throws Exception {
        String token = extractToken(session);
        if (signingKey != null) {
            if (token == null || token.isBlank()) {
                log.info("WS connection rejected (no token): id={}", session.getId());
                session.close(CloseStatus.POLICY_VIOLATION.withReason("missing token"));
                return;
            }
            try {
                Claims claims = Jwts.parser()
                        .verifyWith(signingKey)
                        .build()
                        .parseSignedClaims(token)
                        .getPayload();
                session.getAttributes().put(USER_ID_ATTR, claims.get("userId", String.class));
                session.getAttributes().put(TENANT_ID_ATTR, claims.get("tenantId", String.class));
            } catch (JwtException ex) {
                log.info("WS connection rejected (invalid token): id={}, reason={}",
                        session.getId(), ex.getMessage());
                session.close(CloseStatus.POLICY_VIOLATION.withReason("invalid token"));
                return;
            }
        } else {
            session.getAttributes().put(USER_ID_ATTR, "anonymous");
            session.getAttributes().put(TENANT_ID_ATTR, "anonymous");
        }
        sessions.add(session);
        log.info("WS connection established: id={}, userId={}, total={}",
                session.getId(), session.getAttributes().get(USER_ID_ATTR), sessions.size());
    }

    @Override
    public void afterConnectionClosed(WebSocketSession session, CloseStatus status) {
        sessions.remove(session);
        log.info("WS connection closed: id={}, status={}, remaining={}",
                session.getId(), status, sessions.size());
    }

    /**
     * Push a single event to every connected client. Failures are logged and
     * the offending session is dropped — never propagated, since the caller
     * is a business service that already committed the DB write.
     */
    public void broadcast(InvalidationEvent event) {
        if (event == null || sessions.isEmpty()) {
            return;
        }
        String payload;
        try {
            payload = objectMapper.writeValueAsString(event);
        } catch (JsonProcessingException ex) {
            log.warn("Failed to serialize invalidation event for WS broadcast: {}", ex.getMessage());
            return;
        }
        TextMessage message = new TextMessage(payload);
        for (WebSocketSession session : sessions) {
            if (!session.isOpen()) {
                sessions.remove(session);
                continue;
            }
            try {
                synchronized (session) {
                    session.sendMessage(message);
                }
            } catch (Exception ex) {
                log.warn("WS send failed, dropping session id={}: {}",
                        session.getId(), ex.getMessage());
                sessions.remove(session);
                try {
                    session.close(CloseStatus.SERVER_ERROR);
                } catch (Exception ignored) {
                    // already closed
                }
            }
        }
    }

    public int connectedSessionCount() {
        return sessions.size();
    }

    private static String extractToken(WebSocketSession session) {
        var headers = session.getHandshakeHeaders();
        String auth = headers.getFirst("Authorization");
        if (auth != null && auth.startsWith("Bearer ")) {
            return auth.substring("Bearer ".length()).trim();
        }
        String subprotocol = headers.getFirst("Sec-WebSocket-Protocol");
        if (subprotocol != null) {
            int dot = subprotocol.indexOf('.');
            if (dot > 0) {
                return subprotocol.substring(dot + 1).trim();
            }
            return subprotocol.trim();
        }
        var uri = session.getUri();
        if (uri != null && uri.getQuery() != null) {
            for (String pair : uri.getQuery().split("&")) {
                int eq = pair.indexOf('=');
                if (eq > 0 && "token".equals(pair.substring(0, eq))) {
                    return java.net.URLDecoder.decode(pair.substring(eq + 1),
                            StandardCharsets.UTF_8);
                }
            }
        }
        return null;
    }
}