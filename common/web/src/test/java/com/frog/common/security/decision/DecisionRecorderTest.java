package com.frog.common.security.decision;

import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class DecisionRecorderTest {

    @Test
    void record_acceptsEventAndDoesNotThrow() {
        DecisionRecorderProperties props = new DecisionRecorderProperties();
        props.setEnabled(true);
        DecisionRecorder r = new DecisionRecorder(props);
        DecisionEvent e = DecisionEvent.allow(UUID.randomUUID(), "user.read",
                5L, "system-service", "req-1");
        r.record(e);
        assertThat(r.bufferedCount()).isEqualTo(1);
    }

    @Test
    void record_whenDisabled_dropsEvent() {
        DecisionRecorderProperties props = new DecisionRecorderProperties();
        props.setEnabled(false);
        DecisionRecorder r = new DecisionRecorder(props);
        r.record(DecisionEvent.allow(UUID.randomUUID(), "user.read", 1L, "system", "req"));
        assertThat(r.bufferedCount()).isEqualTo(0);
    }

    @Test
    void record_nullEvent_doesNotThrow() {
        DecisionRecorderProperties props = new DecisionRecorderProperties();
        DecisionRecorder r = new DecisionRecorder(props);
        r.record(null);
        assertThat(r.bufferedCount()).isEqualTo(0);
    }

    @Test
    void flush_emptyBuffer_isNoOp() {
        DecisionRecorderProperties props = new DecisionRecorderProperties();
        DecisionRecorder r = new DecisionRecorder(props);
        r.flush();
        assertThat(r.bufferedCount()).isEqualTo(0);
    }
}