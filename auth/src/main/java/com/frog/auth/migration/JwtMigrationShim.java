package com.frog.auth.migration;

import com.frog.common.security.util.JwtUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.UUID;

/**
 * 临时 shim:解析旧 HS512 token,过渡期内与 OAuth2 AS 并存。
 * Phase 0.9b 后废弃。
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtMigrationShim {

    private final JwtUtils jwtUtils;

    public UUID extractUserIdFromLegacyHs512(String token) {
        try {
            return jwtUtils.getUserIdFromToken(token);
        } catch (Exception e) {
            log.debug("Legacy HS512 parse failed: {}", e.getMessage());
            return null;
        }
    }
}