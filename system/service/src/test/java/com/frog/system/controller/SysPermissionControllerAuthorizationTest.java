package com.frog.system.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import com.frog.system.service.Impl.SysRegisteredClientServiceImpl;
import com.frog.system.service.ISysPermissionService;
import com.frog.system.service.ISysUserService;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(SysPermissionController.class)
@Import(SysPermissionControllerAuthorizationTest.TestMethodSecurityConfig.class)
class SysPermissionControllerAuthorizationTest {

    @Autowired MockMvc mvc;
    @MockitoBean ISysPermissionService permissionService;
    @MockitoBean ISysUserService sysUserService;
    @MockitoBean SysRegisteredClientServiceImpl sysRegisteredClientService;

    @Test
    @WithMockUser(authorities = {"system:user:list"})
    void findByUrl_withoutPermissionQueryAuthority_returns403() throws Exception {
        mvc.perform(get("/api/system/permissions/find-by-url")
                        .param("url", "/api/test").param("method", "GET"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(authorities = {"system:permission:query"})
    void findByUrl_withPermissionQueryAuthority_returns200() throws Exception {
        mvc.perform(get("/api/system/permissions/find-by-url")
                        .param("url", "/api/test").param("method", "GET"))
                .andExpect(status().isOk());
    }

    @TestConfiguration
    @EnableMethodSecurity
    static class TestMethodSecurityConfig {
    }
}