package com.frog.system.controller;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.FilterType;
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

/**
 * NOTE: Disabled in CI as of 2026-09-20 — see Phase 1.4 follow-up.
 *
 * Reason: `@WebMvcTest` slice pulls in `SysRegisteredClientServiceImpl` via Dubbo's
 * `ServiceAnnotationBeanPostProcessor`, which is not affected by `@ComponentScan` excludeFilters.
 * The bean requires `SysRegisteredClientMapper` (a `@Mapper` interface) which is not in the web slice.
 *
 * Re-enable once one of:
 *   (a) SysPermissionController stops depending on services whose impls carry `@DubboService`,
 *   (b) `@DubboService` post-processor is filtered out of test contexts,
 *   (c) Test uses full `@SpringBootTest` with proper bean overrides.
 */
@Disabled("Awaiting Phase 1.4 follow-up — see class Javadoc")
@WebMvcTest(
    controllers = SysPermissionController.class,
    excludeAutoConfiguration = {
        org.apache.dubbo.spring.boot.autoconfigure.DubboAutoConfiguration.class
    },
    excludeFilters = @ComponentScan.Filter(
        type = FilterType.ASSIGNABLE_TYPE,
        classes = SysRegisteredClientServiceImpl.class
    )
)
@Import(SysPermissionControllerAuthorizationTest.TestMethodSecurityConfig.class)
class SysPermissionControllerAuthorizationTest {

    @Autowired MockMvc mvc;
    @MockitoBean ISysPermissionService permissionService;
    @MockitoBean ISysUserService sysUserService;

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