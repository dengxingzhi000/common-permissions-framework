package com.frog.common.security.filter;

import com.frog.common.security.identity.IdentityTokenProperties;
import com.frog.common.security.identity.IdentityTokenVerifier;
import com.frog.common.security.util.SecurityErrorResponseWriter;
import jakarta.annotation.Nonnull;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * Verifies the {@code X-Identity-Token} header propagated by the gateway before
 * the request reaches any controller. Closes P0-3 (token generated but never verified).
 *
 * <p>The filter is fail-closed: a missing, malformed, or invalid token yields a 401
 * with a stable error code suitable for the gateway to log and surface to clients.
 *
 * <p>Public endpoints aligned with {@code SecurityConfig.permitAll} are bypassed
 * (they have no propagated identity).
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class IdentityTokenVerificationFilter extends OncePerRequestFilter {

    private static final AntPathMatcher MATCHER = new AntPathMatcher();

    private static final List<String> WHITELIST = List.of(
            "/v1/api/auth/login",
            "/v1/api/auth/register",
            "/v1/api/auth/refresh",
            "/v1/api/auth/logout",
            "/api/auth/login",
            "/api/auth/register",
            "/api/auth/refresh",
            "/api/auth/logout",
            "/api/public/**",
            "/oauth2/**",
            "/v3/api-docs/**",
            "/swagger-ui/**",
            "/swagger-resources/**",
            "/webjars/**",
            "/doc.html",
            "/actuator/health",
            "/actuator/info"
    );

    private static final String TOKEN_HEADER = "X-Identity-Token";
    private static final String USER_ID_HEADER = "X-User-Id";
    private static final String ROLES_HEADER = "X-User-Roles";

    private final IdentityTokenVerifier verifier;
    private final IdentityTokenProperties properties;

    @Override
    protected boolean shouldNotFilter(@Nonnull HttpServletRequest request) {
        String path = request.getRequestURI();
        return WHITELIST.stream().anyMatch(p -> MATCHER.match(p, path));
    }

    @Override
    protected void doFilterInternal(@Nonnull HttpServletRequest request,
                                    @Nonnull HttpServletResponse response,
                                    @Nonnull FilterChain chain) throws ServletException, IOException {
        String token = request.getHeader(TOKEN_HEADER);
        String claimedUserId = request.getHeader(USER_ID_HEADER);
        String claimedRoles = request.getHeader(ROLES_HEADER);

        IdentityTokenVerifier.VerifyResult result =
                verifier.verify(token, claimedUserId, claimedRoles);

        if (!result.ok()) {
            String reasonCode = result.reason() == null
                    ? "UNKNOWN"
                    : result.reason().split(":", 2)[0];
            log.warn("Identity token rejected path={} reason={} from={}",
                    request.getRequestURI(), result.reason(), request.getRemoteAddr());
            SecurityErrorResponseWriter.write(request, response,
                    HttpServletResponse.SC_UNAUTHORIZED,
                    "IDENTITY_TOKEN_" + reasonCode,
                    "Identity token " + reasonCode.toLowerCase());
            return;
        }

        chain.doFilter(request, response);
    }
}
