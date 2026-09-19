package com.frog.common.security.filter;

import com.frog.common.security.identity.IdentityTokenPayload;
import com.frog.common.security.identity.IdentityTokenPayloadCodec;
import com.frog.common.security.identity.IdentityTokenProperties;
import com.frog.common.security.identity.IdentityTokenVerifier;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class IdentityTokenVerificationFilterTest {

    private static final String SECRET =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    private IdentityTokenVerificationFilter filter;
    private IdentityTokenVerifier verifier;
    private FilterChain chain;

    @BeforeEach
    void setup() {
        IdentityTokenProperties props = new IdentityTokenProperties();
        props.setEnabled(true);
        props.setSharedSecret(SECRET);
        props.setMaxSkewSeconds(30);
        verifier = new IdentityTokenVerifier(props);
        filter = new IdentityTokenVerificationFilter(verifier, props);
        chain = mock(FilterChain.class);
    }

    @Test
    void doFilter_missingToken_returns401AndDoesNotForward() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/api/system/users");
        MockHttpServletResponse res = new MockHttpServletResponse();

        filter.doFilter(req, res, chain);

        assertThat(res.getStatus()).isEqualTo(401);
        assertThat(res.getContentAsString()).contains("IDENTITY_TOKEN_MISSING");
        verify(chain, never()).doFilter(req, res);
    }

    @Test
    void doFilter_whitelistedAuthLoginPath_passesThrough() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/auth/login");
        MockHttpServletResponse res = new MockHttpServletResponse();

        filter.doFilter(req, res, chain);

        assertThat(res.getStatus()).isEqualTo(200);
        verify(chain).doFilter(req, res);
    }

    @Test
    void doFilter_whitelistedPublicPath_passesThrough() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/api/public/health");
        MockHttpServletResponse res = new MockHttpServletResponse();

        filter.doFilter(req, res, chain);

        verify(chain).doFilter(req, res);
    }

    @Test
    void doFilter_whitelistedActuatorPath_passesThrough() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/actuator/health");
        MockHttpServletResponse res = new MockHttpServletResponse();

        filter.doFilter(req, res, chain);

        verify(chain).doFilter(req, res);
    }

    @Test
    void doFilter_validToken_passesThrough() throws Exception {
        UUID userId = UUID.randomUUID();
        String token = signedTokenFor(userId, Instant.now().getEpochSecond());

        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/api/system/users");
        req.addHeader("X-Identity-Token", token);
        req.addHeader("X-User-Id", userId.toString());
        MockHttpServletResponse res = new MockHttpServletResponse();

        filter.doFilter(req, res, chain);

        verify(chain).doFilter(req, res);
        assertThat(res.getStatus()).isEqualTo(200);
    }

    @Test
    void doFilter_tamperedToken_returns401() throws Exception {
        UUID userId = UUID.randomUUID();
        String token = signedTokenFor(userId, Instant.now().getEpochSecond());
        String tampered = token.substring(0, token.length() - 4) + "0000";

        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/api/system/users");
        req.addHeader("X-Identity-Token", tampered);
        req.addHeader("X-User-Id", userId.toString());
        MockHttpServletResponse res = new MockHttpServletResponse();

        filter.doFilter(req, res, chain);

        assertThat(res.getStatus()).isEqualTo(401);
        assertThat(res.getContentAsString()).contains("IDENTITY_TOKEN_INVALID");
        verify(chain, never()).doFilter(req, res);
    }

    @Test
    void doFilter_disabled_passesThroughEvenWithoutToken() throws Exception {
        IdentityTokenProperties props = new IdentityTokenProperties();
        props.setEnabled(false);
        props.setSharedSecret(SECRET);
        IdentityTokenVerifier v = new IdentityTokenVerifier(props);
        IdentityTokenVerificationFilter disabled = new IdentityTokenVerificationFilter(v, props);

        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/api/system/users");
        MockHttpServletResponse res = new MockHttpServletResponse();

        disabled.doFilter(req, res, chain);

        verify(chain).doFilter(req, res);
    }

    private String signedTokenFor(UUID userId, long issuedAt) {
        IdentityTokenPayload p = new IdentityTokenPayload(
                userId, "alice", "dev", List.of("user.read"),
                issuedAt, UUID.randomUUID().toString());
        String payload = IdentityTokenPayloadCodec.encode(p);
        return payload + "." + hmacHex(payload);
    }

    private String hmacHex(String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(SECRET.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return HexFormat.of().formatHex(mac.doFinal(data.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
