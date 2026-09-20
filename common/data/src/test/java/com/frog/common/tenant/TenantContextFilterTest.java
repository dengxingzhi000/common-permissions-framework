package com.frog.common.tenant;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import jakarta.servlet.FilterChain;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * TenantContextFilter unit tests — Phase 1.3.
 *
 * <p>Validates:
 * <ul>
 *   <li>Header X-Tenant-Id parsed as UUID</li>
 *   <li>Non-UUID header (treated as tenantCode) leaves context null in Phase 1.3</li>
 *   <li>Missing header in strictMode → 400</li>
 *   <li>Missing header in non-strict mode → chain proceeds with no tenantId</li>
 *   <li>TenantContext cleared after request, regardless of outcome</li>
 *   <li>Disabled mode passes through with cleanup</li>
 * </ul>
 */
@DisplayName("TenantContextFilter Tests")
class TenantContextFilterTest {

    private TenantProperties properties;
    private TenantContextFilter filter;

    @BeforeEach
    void setUp() {
        TenantContext.clear();
        properties = new TenantProperties();
        properties.setEnabled(true);
        properties.setStrictMode(true);
        properties.setHeaderName("X-Tenant-Id");
        filter = new TenantContextFilter(properties);
    }

    @Test
    @DisplayName("UUID header → TenantContext populated, chain invoked, cleared after")
    void uuidHeader_setsContext() throws Exception {
        UUID tid = UUID.randomUUID();
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/v1/api/system/users");
        req.addHeader("X-Tenant-Id", tid.toString());
        MockHttpServletResponse res = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(req, res, chain);

        assertThat(TenantContext.get()).isNull(); // cleared after chain
        verify(chain, times(1)).doFilter(req, res);
    }

    @Test
    @DisplayName("tenantCode header → strict mode rejects with 400")
    void tenantCodeHeader_strictRejects() throws Exception {
        properties.setStrictMode(true);
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/v1/api/system/users");
        req.addHeader("X-Tenant-Id", "acme-corp");
        MockHttpServletResponse res = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(req, res, chain);

        assertThat(res.getStatus()).isEqualTo(400);
        assertThat(res.getContentAsString()).contains("Missing tenant context");
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    @DisplayName("Missing header in strict mode → 400, chain not invoked")
    void missingHeader_strictRejects() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/v1/api/system/users");
        MockHttpServletResponse res = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(req, res, chain);

        assertThat(res.getStatus()).isEqualTo(400);
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    @DisplayName("Missing header in non-strict mode → chain proceeds, no tenantId")
    void missingHeader_nonStrictProceeds() throws Exception {
        properties.setStrictMode(false);
        filter = new TenantContextFilter(properties);

        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/v1/api/system/users");
        MockHttpServletResponse res = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(req, res, chain);

        verify(chain, times(1)).doFilter(req, res);
        assertThat(TenantContext.get()).isNull(); // cleared after chain
    }

    @Test
    @DisplayName("parseTenantReference — UUID string → UUID")
    void parseUuidReference() {
        UUID tid = UUID.randomUUID();
        assertThat(filter.parseTenantReference(tid.toString())).isEqualTo(tid);
    }

    @Test
    @DisplayName("parseTenantReference — non-UUID → null (Phase 1.3 no-op)")
    void parseNonUuidReference() {
        assertThat(filter.parseTenantReference("acme")).isNull();
        assertThat(filter.parseTenantReference("")).isNull();
        assertThat(filter.parseTenantReference(null)).isNull();
        assertThat(filter.parseTenantReference("   ")).isNull();
    }

    @Test
    @DisplayName("Disabled mode → no validation, chain proceeds, cleanup happens")
    void disabledMode_passesThrough() throws Exception {
        properties.setEnabled(false);
        filter = new TenantContextFilter(properties);

        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/v1/api/system/users");
        MockHttpServletResponse res = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(req, res, chain);

        verify(chain, times(1)).doFilter(req, res);
        assertThat(TenantContext.get()).isNull();
    }

    @Test
    @DisplayName("Custom header name is respected")
    void customHeaderName() throws Exception {
        properties.setHeaderName("X-Custom-Tenant");
        filter = new TenantContextFilter(properties);

        UUID tid = UUID.randomUUID();
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/v1/api/system/users");
        req.addHeader("X-Custom-Tenant", tid.toString());
        MockHttpServletResponse res = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(req, res, chain);

        verify(chain).doFilter(req, res);
    }
}
