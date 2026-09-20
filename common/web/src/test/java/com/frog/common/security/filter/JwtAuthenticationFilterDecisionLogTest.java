package com.frog.common.security.filter;

import com.frog.common.security.decision.DecisionEvent;
import com.frog.common.security.decision.DecisionRecorder;
import com.frog.common.security.decision.DecisionRecorderProperties;
import com.frog.common.security.metrics.SecurityMetrics;
import com.frog.common.security.util.HttpServletRequestUtils;
import com.frog.common.security.util.JwtUtils;
import com.frog.common.security.util.SecurityErrorResponseWriter;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class JwtAuthenticationFilterDecisionLogTest {

    @Test
    void invalidToken_recordsDecision() throws Exception {
        DecisionRecorderProperties props = new DecisionRecorderProperties();
        props.setEnabled(true);
        RecordingDecisionRecorder recorder = new RecordingDecisionRecorder(props);

        JwtUtils jwtUtils = mock(JwtUtils.class);
        when(jwtUtils.validateToken(any(), any(), any())).thenReturn(false);

        JwtAuthenticationFilter filter = new JwtAuthenticationFilter(
                jwtUtils, mock(HttpServletRequestUtils.class),
                mock(SecurityMetrics.class), recorder);

        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/api/test");
        req.addHeader("Authorization", "Bearer fake");
        MockHttpServletResponse res = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(req, res, chain);

        assertThat(recorder.events).hasSize(1);
        assertThat(recorder.events.get(0).effect()).isEqualTo("deny");
        assertThat(recorder.events.get(0).reason()).isEqualTo("INVALID_TOKEN");
    }

    static class RecordingDecisionRecorder extends DecisionRecorder {
        List<DecisionEvent> events = new ArrayList<>();
        RecordingDecisionRecorder(DecisionRecorderProperties p) { super(p); }
        @Override public void record(DecisionEvent e) { events.add(e); }
    }
}