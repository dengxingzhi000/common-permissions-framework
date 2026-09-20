package com.frog.auth.controller;

import com.frog.auth.service.IOAuth2LogoutService;
import com.frog.common.security.util.HttpServletRequestUtils;
import com.frog.common.web.domain.SecurityUser;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Set;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = OAuth2LogoutController.class)
@Import(OAuth2LogoutControllerTest.TestMethodSecurityConfig.class)
class OAuth2LogoutControllerTest {

    @Autowired MockMvc mockMvc;
    @MockitoBean IOAuth2LogoutService oauth2LogoutService;
    @MockitoBean HttpServletRequestUtils httpServletRequestUtils;

    @Test
    @WithMockUser(username = "alice", authorities = "ROLE_USER")
    void revokeByClient_callsServiceWithCallerUserId() throws Exception {
        UUID callerId = UUID.fromString("019a0aee-3b74-7bfc-b34f-48b5428d48a1");
        SecurityUser principal = SecurityUser.builder()
                .userId(callerId).username("alice").authorities(Set.of()).build();
        when(httpServletRequestUtils.getTokenFromRequest(any())).thenReturn("valid.jwt.token");

        mockMvc.perform(post("/oauth2/logout")
                        .param("clientId", "internal-service")
                        .with(user(principal))
                        .with(csrf()))
                .andExpect(status().isOk());

        verify(oauth2LogoutService, times(1))
                .revokeByClient(eq("valid.jwt.token"), eq("internal-service"), eq(callerId));
    }

    @Test
    @WithMockUser(username = "alice", authorities = {"ROLE_USER"})
    void revokeByClient_missingClientId_returns400() throws Exception {
        UUID callerId = UUID.fromString("019a0aee-3b74-7bfc-b34f-48b5428d48a1");
        SecurityUser principal = SecurityUser.builder()
                .userId(callerId).username("alice").authorities(Set.of()).build();
        when(httpServletRequestUtils.getTokenFromRequest(any())).thenReturn("valid.jwt.token");

        mockMvc.perform(post("/oauth2/logout")
                        .with(user(principal))
                        .with(csrf()))
                .andExpect(status().isBadRequest());

        verify(oauth2LogoutService, times(0)).revokeByClient(any(), any(), any());
    }

    @Test
    @WithMockUser(username = "admin", authorities = "oauth2:logout:global")
    void revokeGlobal_withAuthority_callsService() throws Exception {
        UUID callerId = UUID.fromString("019a0aee-3b74-7bfc-b34f-48b5428d48a1");
        UUID targetId = UUID.fromString("019a0aee-3b74-7bfc-b34f-48b5428d48a2");
        SecurityUser principal = SecurityUser.builder()
                .userId(callerId).username("admin")
                .authorities(Set.of(new SimpleGrantedAuthority("oauth2:logout:global")))
                .build();
        when(oauth2LogoutService.revokeGlobal(eq(targetId), eq("test"), eq("admin"))).thenReturn(3);

        mockMvc.perform(post("/oauth2/logout/all")
                        .param("userId", targetId.toString())
                        .param("reason", "test")
                        .with(user(principal))
                        .with(csrf()))
                .andExpect(status().isOk());

        verify(oauth2LogoutService).revokeGlobal(targetId, "test", "admin");
    }

    @Test
    @WithMockUser(username = "alice", authorities = "ROLE_USER")
    void revokeGlobal_withoutAuthority_returns403() throws Exception {
        UUID callerId = UUID.fromString("019a0aee-3b74-7bfc-b34f-48b5428d48a1");
        UUID targetId = UUID.fromString("019a0aee-3b74-7bfc-b34f-48b5428d48a2");
        SecurityUser principal = SecurityUser.builder()
                .userId(callerId).username("alice").authorities(Set.of()).build();

        mockMvc.perform(post("/oauth2/logout/all")
                        .param("userId", targetId.toString())
                        .param("reason", "test")
                        .with(user(principal))
                        .with(csrf()))
                .andExpect(status().isForbidden());
    }

    @TestConfiguration
    @EnableMethodSecurity
    static class TestMethodSecurityConfig {
    }
}
