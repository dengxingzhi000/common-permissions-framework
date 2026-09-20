package com.frog.auth.controller;

import com.frog.auth.service.IOAuth2LogoutService;
import com.frog.common.security.util.HttpServletRequestUtils;
import com.frog.common.web.domain.SecurityUser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Structural smoke test for {@link OAuth2LogoutController}.
 *
 * <p><strong>Why this suite is intentionally thin (single test):</strong></p>
 * <ul>
 *   <li>This module's entry point is {@code AuthApplication}, which uses a
 *       broad {@code @ComponentScan} that pulls in {@code SysAuthController},
 *       {@code WebAuthnCredentialController}, and the full WebAuthn / JWT
 *       configuration chain. {@code @WebMvcTest} cannot isolate just this
 *       controller without dragging that cascade in, and a full
 *       {@code @SpringBootTest} requires Nacos + Redis at test time.</li>
 *   <li>So this test uses {@code MockMvcBuilders.standaloneSetup(...)} —
 *       no Spring {@code ApplicationContext} is started, and no Spring
 *       Security filter chain is wired.</li>
 * </ul>
 *
 * <p><strong>What this test does NOT cover (intentional gaps):</strong></p>
 * <ul>
 *   <li>{@code @PreAuthorize("isAuthenticated()")} on
 *       {@link OAuth2LogoutController#revokeByClient} — silently passes in
 *       standalone mode because Spring Security's
 *       {@code MethodSecurityInterceptor} is not installed. Anonymous
 *       requests would still reach the handler.</li>
 *   <li>{@code @PreAuthorize("hasAuthority('oauth2:logout:global')")} on
 *       {@link OAuth2LogoutController#revokeGlobal} — same problem; the
 *       authority check is not enforced, so a forbidden case cannot be
 *       asserted here.</li>
 *   <li>{@code @AuthenticationPrincipal SecurityUser caller} — the
 *       principal resolves to {@code null} in standalone mode. Calling
 *       {@code caller.getUserId()} or {@code caller.getUsername()} would
 *       throw {@code NullPointerException} before reaching the service
 *       layer, so the positive-path assertions cannot live here.</li>
 *   <li>{@code @NotBlank} on the {@code reason} parameter of
 *       {@code revokeGlobal} — the {@code clientId} case below is tested
 *       for parity; the {@code reason} case was dropped for the same
 *       reason.</li>
 * </ul>
 *
 * <p><strong>Right tool for full coverage:</strong> an integration test
 * using {@code TestRestTemplate} or
 * {@code @SpringBootTest(webEnvironment = RANDOM_PORT)} with the real
 * Spring Security filter chain and {@code MethodSecurityInterceptor}
 * wired. See {@code auth/src/integration-test/} for the planned suite
 * (P0-9c follow-up).</p>
 */
class OAuth2LogoutControllerTest {

    MockMvc mockMvc;
    IOAuth2LogoutService oauth2LogoutService;
    HttpServletRequestUtils httpServletRequestUtils;

    @BeforeEach
    void setUp() {
        oauth2LogoutService = mock(IOAuth2LogoutService.class);
        httpServletRequestUtils = mock(HttpServletRequestUtils.class);
        OAuth2LogoutController controller = new OAuth2LogoutController(oauth2LogoutService, httpServletRequestUtils);
        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();
    }

    @Test
    void revokeByClient_missingClientId_returns400() throws Exception {
        UUID callerId = UUID.fromString("019a0aee-3b74-7bfc-b34f-48b5428d48a1");
        SecurityUser principal = SecurityUser.builder()
                .userId(callerId).username("alice")
                .build();
        when(httpServletRequestUtils.getTokenFromRequest(any())).thenReturn("valid.jwt.token");

        mockMvc.perform(post("/v1/oauth2/logout")
                        .with(user(principal))
                        .with(csrf()))
                .andExpect(status().isBadRequest());

        verify(oauth2LogoutService, times(0)).revokeByClient(any(), any(), any());
    }
}
