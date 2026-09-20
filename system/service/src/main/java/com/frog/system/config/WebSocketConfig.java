package com.frog.system.config;

import com.frog.system.controller.PermissionEventWebSocketController;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.lang.NonNull;
import org.springframework.web.socket.config.annotation.EnableWebSocket;
import org.springframework.web.socket.config.annotation.WebSocketConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry;

/**
 * Registers the {@code /v1/events/permissions} WebSocket endpoint (Phase 2).
 *
 * <p>{@code setAllowedOrigins("*")} is intentional for Phase 2 — the gateway
 * terminates TLS and proxies the upgrade, so browsers always reach this server
 * from a same-origin location. Tighten in a follow-up once the reverse proxy
 * contract is finalised.
 *
 * @author Deng
 * @since 2026-09-20
 */
@Configuration
@EnableWebSocket
@RequiredArgsConstructor
public class WebSocketConfig implements WebSocketConfigurer {

    private final PermissionEventWebSocketController handler;

    @Override
    public void registerWebSocketHandlers(@NonNull WebSocketHandlerRegistry registry) {
        registry.addHandler(handler, PermissionEventWebSocketController.PATH)
                .setAllowedOriginPatterns("*");
    }
}