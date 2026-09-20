package com.frog.sdk.authz;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/**
 * HttpAuthzClient transport tests using {@link MockRestServiceServer}.
 *
 * <p>The server is bound to the {@link RestClient.Builder} used by
 * {@link HttpAuthzClient}'s test-friendly constructor, so expectations fire
 * against actual outgoing requests without spinning up an HTTP listener.
 */
@DisplayName("HttpAuthzClient Tests")
class HttpAuthzClientTest {

    private RestClient.Builder builder;
    private MockRestServiceServer server;

    @BeforeEach
    void setUp() {
        builder = RestClient.builder().baseUrl("http://localhost:8081");
        server = MockRestServiceServer.bindTo(builder).build();
    }

    private HttpAuthzClient newClient() {
        return new HttpAuthzClient(
                builder.build(),
                "tenant-a",
                "app-1",
                "bearer-token",
                "/v1/decision/check",
                "/v1/decision/batch-check",
                "/v1/decision/permissions");
    }

    private CheckRequest sampleRequest() {
        return CheckRequest.builder()
                .subjectType("user")
                .subjectId(UUID.randomUUID())
                .action("project.read")
                .build();
    }

    @Test
    @DisplayName("check — POSTs to checkPath with tenant + app + bearer headers")
    void check_postsWithHeaders() {
        HttpAuthzClient client = newClient();
        server.expect(requestTo("/v1/decision/check"))
                .andExpect(method(org.springframework.http.HttpMethod.POST))
                .andExpect(header("X-Tenant-Id", "tenant-a"))
                .andExpect(header("X-App-Id", "app-1"))
                .andExpect(header("Authorization", "Bearer bearer-token"))
                .andRespond(withSuccess(
                        "{\"effect\":\"allow\",\"reason\":\"granted\",\"policyVersion\":\"v1\",\"decisionId\":\"" + UUID.randomUUID() + "\",\"latencyMs\":7}",
                        MediaType.APPLICATION_JSON));

        Decision decision = client.check(sampleRequest());

        assertThat(decision.getEffect()).isEqualTo("allow");
        assertThat(decision.getReason()).isEqualTo("granted");
        assertThat(decision.getPolicyVersion()).isEqualTo("v1");
        assertThat(decision.getLatencyMs()).isEqualTo(7L);
    }

    @Test
    @DisplayName("batchCheck — POSTs list, returns matching decisions")
    void batchCheck_returnsList() {
        HttpAuthzClient client = newClient();
        server.expect(requestTo("/v1/decision/batch-check"))
                .andExpect(method(org.springframework.http.HttpMethod.POST))
                .andRespond(withSuccess(
                        "[{\"effect\":\"allow\",\"latencyMs\":1},{\"effect\":\"deny\",\"latencyMs\":2}]",
                        MediaType.APPLICATION_JSON));

        List<Decision> out = client.batchCheck(List.of(sampleRequest(), sampleRequest()));

        assertThat(out).hasSize(2);
        assertThat(out.get(0).getEffect()).isEqualTo("allow");
        assertThat(out.get(1).getEffect()).isEqualTo("deny");
    }

    @Test
    @DisplayName("batchCheck — rejects more than 100 requests per call")
    void batchCheck_rejectsOversized() {
        HttpAuthzClient client = newClient();
        var tooMany = java.util.stream.IntStream.range(0, 101)
                .mapToObj(i -> sampleRequest())
                .toList();

        assertThatThrownBy(() -> client.batchCheck(tooMany))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("100");
    }

    @Test
    @DisplayName("getEffectivePermissions — GET with query params, returns permission set")
    void getEffectivePermissions_returnsSet() {
        HttpAuthzClient client = newClient();
        UUID subject = UUID.randomUUID();
        server.expect(requestTo(uri ->
                uri.getPath().equals("/v1/decision/permissions")
                        && uri.getQuery().contains("subjectType=user")
                        && uri.getQuery().contains("subjectId=" + subject)))
                .andExpect(method(org.springframework.http.HttpMethod.GET))
                .andRespond(withSuccess(
                        "[\"project.read\",\"invoice.approve\"]",
                        MediaType.APPLICATION_JSON));

        Set<String> perms = client.getEffectivePermissions("user", subject);

        assertThat(perms).containsExactlyInAnyOrder("project.read", "invoice.approve");
    }

    @Test
    @DisplayName("check — null CheckRequest throws IllegalArgumentException")
    void check_nullRequestThrows() {
        HttpAuthzClient client = newClient();
        assertThatThrownBy(() -> client.check(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("getEffectivePermissions — null subjectType / subjectId throws")
    void getEffectivePermissions_nullArgsThrow() {
        HttpAuthzClient client = newClient();
        assertThatThrownBy(() -> client.getEffectivePermissions(null, UUID.randomUUID()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> client.getEffectivePermissions("user", null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("invalidateCache — no-op for HTTP-only client")
    void invalidateCache_noOp() {
        HttpAuthzClient client = newClient();
        // Should not throw; should be a no-op for the HTTP client.
        client.invalidateCache();
    }
}